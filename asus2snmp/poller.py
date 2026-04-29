"""Background poller. Logs into the router over telnet on a persistent connection,
scrapes a wide set of values on each interval, and atomically replaces the
OID cache contents.

Failures of individual commands are tolerated — only telnet I/O errors abort
the poll and trigger a reconnect. After N consecutive failed polls the cache
is flushed to a clearly-marked UNREACHABLE state so stale data doesn't keep
flowing to monitors.
"""

import logging
import re
import threading
import time
from datetime import datetime, timezone

from . import mibs, parsers, snmp
from .telnet import TelnetClient, TelnetError

log = logging.getLogger(__name__)


class Poller(threading.Thread):
    def __init__(self, host, port, user, password, cache, interval=60.0,
                 flush_after_failures=3):
        super().__init__(name="asus-poller", daemon=True)
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.cache = cache
        self.interval = float(interval)
        self.flush_after_failures = int(flush_after_failures)
        self._stop = threading.Event()
        self._client = None
        self._prev_cpu_total = None     # for CPU% delta
        self._consecutive_failures = 0
        self._flushed = False           # True once we've flushed for the current outage

    def stop(self):
        self._stop.set()
        if self._client is not None:
            try:
                self._client.close()
            except OSError:
                pass

    def run(self):
        backoff = 1.0
        while not self._stop.is_set():
            try:
                if self._client is None:
                    self._connect()
                self._poll_once()
                backoff = 1.0
                self._consecutive_failures = 0
                self._flushed = False
            except TelnetError as e:
                self._on_failure(reason=str(e))
                self._drop_client()
                if self._stop.wait(backoff):
                    return
                backoff = min(backoff * 2, self.interval)
                continue
            except Exception:
                log.exception("unexpected poller error; reconnecting")
                self._on_failure(reason="unexpected poller error")
                self._drop_client()
                if self._stop.wait(backoff):
                    return
                backoff = min(backoff * 2, self.interval)
                continue

            if self._stop.wait(self.interval):
                return

    def _on_failure(self, reason):
        self._consecutive_failures += 1
        log.warning("poll failed (#%d): %s",
                    self._consecutive_failures, reason)
        if (not self._flushed
                and self.flush_after_failures > 0
                and self._consecutive_failures >= self.flush_after_failures):
            self._flush_cache_unreachable()
            self._flushed = True

    def _flush_cache_unreachable(self):
        """Replace the cache with a minimal unreachable-marker so monitors
        stop ingesting stale data. Keeps SNMP responsive (system group still
        answers) but every other table goes empty."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        msg = (f"ASUS (via asus2snmp) -- UNREACHABLE at "
               f"{self.host}:{self.port} since {ts} "
               f"({self._consecutive_failures} consecutive failed polls)")
        self.cache.bulk_replace({
            mibs.SYS_DESCR:     snmp.octet_string(msg),
            mibs.SYS_OBJECT_ID: snmp.oid(mibs.LINUX_SYS_OBJECT_ID),
            mibs.SYS_UPTIME:    snmp.timeticks(0),
            mibs.SYS_CONTACT:   snmp.octet_string(""),
            mibs.SYS_NAME:      snmp.octet_string(""),
            mibs.SYS_LOCATION:  snmp.octet_string(""),
            mibs.SYS_SERVICES:  snmp.integer(mibs.SYS_SERVICES_ASUS),
        })
        log.error("cache flushed: %d consecutive failures; SNMP now reports "
                  "UNREACHABLE until next successful poll",
                  self._consecutive_failures)

    def _connect(self):
        log.info("connecting to ASUS router at %s:%d", self.host, self.port)
        client = TelnetClient(self.host, self.port)
        client.connect()
        client.login(self.user, self.password)
        self._client = client

    def _drop_client(self):
        if self._client is not None:
            try:
                self._client.close()
            except OSError:
                pass
            self._client = None

    # --- run/parse helpers ---

    def _try(self, cmd, timeout=8.0, default=""):
        """Run a command. Return stdout text on success; `default` on non-zero
        exit. Re-raise TelnetError so the outer loop can reconnect."""
        out, ec = self._client.run(cmd, timeout=timeout)
        if ec != 0:
            return default
        return out

    # --- the actual scrape ---

    def _poll_once(self):
        # ----- core data -----
        uname        = self._try("uname -a", 8.0).strip()
        version_text = self._try("cat /proc/version", 5.0).strip()
        proc_uptime  = self._try("cat /proc/uptime", 5.0).strip()
        loadavg_txt  = self._try("cat /proc/loadavg", 5.0).strip()
        proc_stat    = self._try("cat /proc/stat", 5.0)
        meminfo_txt  = self._try("cat /proc/meminfo", 5.0)
        net_dev_txt  = self._try("cat /proc/net/dev", 5.0)
        ifconfig_txt = self._try("ifconfig", 8.0)
        iw_dev_txt   = self._try("iw dev 2>/dev/null", 5.0)
        arp_txt      = self._try("cat /proc/net/arp", 5.0)
        df_txt       = self._try("df", 5.0)
        brctl_txt    = self._try("brctl showmacs br0 2>/dev/null", 8.0)
        diskstats_txt = self._try("cat /proc/diskstats 2>/dev/null", 5.0)
        cpuinfo_txt  = self._try("cat /proc/cpuinfo", 5.0)

        hostname     = self._try("cat /proc/sys/kernel/hostname", 5.0).strip()
        lan_hostname = self._try("nvram get lan_hostname 2>/dev/null", 5.0).strip()
        contact      = self._try("nvram get router_contact 2>/dev/null", 5.0).strip()
        location     = self._try("nvram get router_location 2>/dev/null", 5.0).strip()
        board        = self._try("nvram get productid 2>/dev/null", 5.0).strip()
        model        = self._try("nvram get model 2>/dev/null", 5.0).strip()

        # Conntrack (ASUS path; the older DD-WRT path is not used here)
        ct_count_txt = self._try("cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null", 4.0)
        ct_max_txt   = self._try("cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null", 4.0)

        # ----- parse -----
        net_dev    = parsers.parse_proc_net_dev(net_dev_txt)
        ifc        = parsers.parse_ifconfig(ifconfig_txt)
        iw_devs    = parsers.parse_iw_dev(iw_dev_txt)
        wl_iface_names = [d["iface"] for d in iw_devs]
        cpu_model  = parsers.parse_cpuinfo_model(cpuinfo_txt)
        ct_count   = parsers.parse_conntrack_count(ct_count_txt)
        ct_max     = parsers.parse_conntrack_count(ct_max_txt)
        meminfo    = parsers.parse_meminfo(meminfo_txt)
        loadavg    = parsers.parse_loadavg(loadavg_txt)
        stat       = parsers.parse_proc_stat(proc_stat)
        df_entries = parsers.parse_df(df_txt)
        bridge     = parsers.parse_brctl_showmacs(brctl_txt)
        arp        = parsers.parse_proc_net_arp(arp_txt)
        ut         = parsers.parse_uptime(proc_uptime)
        diskstats  = parsers.parse_proc_diskstats(diskstats_txt)
        # Filter out the 16 always-idle ramdisk minor nodes; keep mtdblock* etc.
        diskstats  = [d for d in diskstats
                      if not (d["name"].startswith("ram")
                              and d["reads_done"] == 0
                              and d["writes_done"] == 0)]

        # ----- temperature probe (every plausible source) -----
        temps = self._probe_temperatures(iw_devs)

        # ----- wireless clients per radio -----
        wl_clients = self._probe_wireless_clients(iw_devs)

        # ----- per-radio channel utilization / noise -----
        chan_stats = self._probe_channel_stats(iw_devs)

        # ----- AiMesh (cfg_device_list + per-slave backhaul stats) -----
        mesh_nodes, backhaul_links = self._probe_mesh(iw_devs)

        # ----- derived values -----
        uptime_secs = ut["seconds"] if ut else 0.0

        # CPU% per CPU (delta against previous /proc/stat)
        cpu_loads = self._compute_cpu_loads(stat)
        self._prev_cpu_total = stat["cpu_total"]

        # Connected client count: bridge MAC entries that are not local (ports).
        num_clients = sum(1 for e in bridge if not e["is_local"])

        num_procs = loadavg["procs_total"] if loadavg else 0

        # ARP -> IP-by-MAC map for enriching bridge entries
        ip_by_mac = {a["mac"]: a["ip"] for a in arp}

        # ----- assemble OID -> SNMPValue dict -----
        update = {}
        update.update(mibs.build_system_group(
            uname=uname,
            name=lan_hostname or hostname,
            contact=contact,
            location=location,
            uptime_centi=int(uptime_secs * 100),
        ))
        update.update(mibs.build_if_table(net_dev, ifc, wl_iface_names))
        update.update(mibs.build_ip_addr_table(ifc, net_dev))
        update.update(mibs.build_load_table(loadavg))
        update.update(mibs.build_ucd_memory(meminfo))
        update.update(mibs.build_ucd_cpu_raw(stat["cpu_total"]))
        update.update(mibs.build_ucd_disk_table(df_entries))
        update.update(mibs.build_ucd_diskio_table(diskstats))
        update.update(mibs.build_host_resources(
            uptime_secs=uptime_secs,
            num_users=num_clients,
            num_procs=num_procs,
            meminfo=meminfo,
            df_entries=df_entries,
            cpu_loads=cpu_loads or [0],
        ))
        update.update(mibs.build_asus_router(board, model, version_text, cpu_model))
        update.update(mibs.build_temperatures(temps))
        update.update(mibs.build_wireless_clients(wl_clients))
        update.update(mibs.build_bridge_macs(bridge, ip_by_mac))
        update.update(mibs.build_conntrack(ct_count, ct_max))
        update.update(mibs.build_channel_stats(chan_stats))
        update.update(mibs.build_mesh_nodes(mesh_nodes))
        update.update(mibs.build_backhaul_links(backhaul_links))

        # Atomic swap.
        self.cache.bulk_replace(update)
        log.info("poll OK: %d OIDs (ifs=%d wl=%d clients=%d temps=%d fs=%d "
                 "mesh=%d bh=%d ct=%s)",
                 len(update), len(net_dev), len(iw_devs),
                 num_clients, len(temps), len(df_entries),
                 len(mesh_nodes), len(backhaul_links), ct_count)

    # --- probes ---

    def _probe_temperatures(self, iw_devs):
        """Try every potential source. Return list of {name, source, celsius, raw}.

        iw_devs is the rich list from parse_iw_dev. Per-radio temps are
        deduped by phy (one probe per unique PHY) — guest VAPs share the
        radio so they'd return the same value as the primary BSS."""
        out = []

        # 1) wl phy_tempsense per unique phy (one representative iface per radio)
        for phy, iface, channel in self._unique_per_phy(iw_devs):
            text, ec = self._client.run(
                f"wl -i {iface} phy_tempsense 2>/dev/null", timeout=5.0)
            if ec != 0:
                continue
            v = parsers.parse_wl_temp(text)
            if v is None:
                continue
            band = self._band_for_channel(channel) or f"phy{phy}"
            out.append({
                "name":    f"Radio {band} ({iface})",
                "source":  f"wl -i {iface} phy_tempsense",
                "celsius": v,  # already degrees C on this firmware
                "raw":     v,
            })

        # 2) /sys/class/thermal/thermal_zone*/temp (generic kernel thermal zones)
        # Use shell glob expansion via `echo` to dodge `ls` aliases that emit
        # ANSI color codes; busybox echo always returns plain text.
        zones_text, ec = self._client.run(
            "cd /sys/class/thermal 2>/dev/null && echo thermal_zone*",
            timeout=5.0)
        if ec == 0:
            for zone in zones_text.split():
                # If the glob didn't expand (no zones) shell returns the literal
                # pattern "thermal_zone*" — skip that.
                if zone == "thermal_zone*" or not zone.startswith("thermal_zone"):
                    continue
                val_text, ec2 = self._client.run(
                    f"cat /sys/class/thermal/{zone}/temp 2>/dev/null", timeout=5.0)
                if ec2 != 0:
                    continue
                m = re.match(r"\s*(-?\d+)", val_text)
                if not m:
                    continue
                raw = int(m.group(1))
                # Kernel reports millidegrees C when |value| > 200.
                celsius = raw // 1000 if abs(raw) >= 200 else raw
                type_text, _ = self._client.run(
                    f"cat /sys/class/thermal/{zone}/type 2>/dev/null", timeout=3.0)
                label = type_text.strip() or zone
                out.append({
                    "name":    f"{label} ({zone})",
                    "source":  f"/sys/class/thermal/{zone}/temp",
                    "celsius": celsius,
                    "raw":     raw,
                })

        # 3) /proc/dmu/temperature (Broadcom CPU temp on some platforms)
        dmu_text, ec = self._client.run(
            "cat /proc/dmu/temperature 2>/dev/null", timeout=3.0)
        if ec == 0 and dmu_text.strip():
            m = re.search(r"(-?\d+)", dmu_text)
            if m:
                raw = int(m.group(1))
                out.append({
                    "name":    "CPU (DMU)",
                    "source":  "/proc/dmu/temperature",
                    "celsius": raw,
                    "raw":     raw,
                })

        return out

    def _probe_wireless_clients(self, iw_devs):
        """Per BSS: associated stations with signal/RSSI/byte counters.

        Prefers `iw <iface> station dump` (single round-trip per BSS,
        includes rx/tx bytes). Falls back to `wl assoclist` + per-station
        `wl rssi` only if iw is unavailable. On boxes with both tools
        installed (ASUS-Broadcom), the iw path wins."""
        clients = []
        for d in iw_devs:
            wif = d["iface"]
            iw_text, ec = self._client.run(
                f"iw {wif} station dump 2>/dev/null", timeout=5.0)
            if ec == 0 and iw_text.strip():
                for sta in parsers.parse_iw_station_dump(iw_text):
                    clients.append({
                        "mac":      sta["mac"],
                        "iface":    wif,
                        "rssi":     sta.get("signal"),
                        "rx_bytes": sta.get("rx_bytes"),
                        "tx_bytes": sta.get("tx_bytes"),
                    })
                continue
            # Broadcom-only fallback
            assoc_text, ec = self._client.run(
                f"wl -i {wif} assoclist 2>/dev/null", timeout=5.0)
            if ec == 0 and assoc_text.strip():
                for mac in parsers.parse_wl_assoclist(assoc_text):
                    rssi = None
                    rssi_text, ec2 = self._client.run(
                        f"wl -i {wif} rssi {mac} 2>/dev/null", timeout=5.0)
                    if ec2 == 0:
                        rssi = parsers.parse_wl_rssi(rssi_text)
                    clients.append({
                        "mac": mac, "iface": wif, "rssi": rssi,
                        "rx_bytes": None, "tx_bytes": None,
                    })
        return clients

    def _probe_channel_stats(self, iw_devs):
        """One row per unique phy (radio): noise floor + chanim_stats.
        Uses the primary BSS as the representative iface."""
        rows = []
        for phy, iface, channel in self._unique_per_phy(iw_devs):
            noise_text, ec = self._client.run(
                f"wl -i {iface} noise 2>&1", timeout=4.0)
            noise = parsers.parse_wl_noise(noise_text) if ec == 0 else None
            chanim_text, ec = self._client.run(
                f"wl -i {iface} chanim_stats 2>&1", timeout=4.0)
            chanim = parsers.parse_wl_chanim_stats(chanim_text) if ec == 0 else {}
            rows.append({
                "iface":   iface,
                "phy":     phy,
                "channel": channel,
                "noise":   noise,
                "busy":    chanim.get("busy"),
                "txop":    chanim.get("txop"),
                "glitch":  chanim.get("glitch"),
                "badplcp": chanim.get("badplcp"),
            })
        return rows

    def _probe_mesh(self, iw_devs):
        """Returns (mesh_nodes, backhaul_links).
        mesh_nodes: from `nvram get cfg_device_list`.
        backhaul_links: per remote node, look up its per-band station MAC
        from /tmp/relist.json, then `wl -i <ap_iface> sta_info <sta_mac>`."""
        cfg_text = self._try("nvram get cfg_device_list 2>/dev/null", 5.0)
        nodes = parsers.parse_cfg_device_list(cfg_text)
        if not nodes:
            return [], []

        relist_text = self._try("cat /tmp/relist.json 2>/dev/null", 4.0)
        relist = parsers.parse_relist_json(relist_text)

        # Map band -> primary AP iface on master.
        ap_iface_by_band = {}
        for d in iw_devs:
            if d.get("phy") is None or d.get("channel") is None:
                continue
            if "." in d["iface"]:  # skip guest VAPs
                continue
            band = self._band_for_channel(d["channel"])
            if band and band not in ap_iface_by_band:
                ap_iface_by_band[band] = d["iface"]

        backhaul = []
        for n in nodes:
            if n.get("role") == "1":
                continue  # master itself — no backhaul to query
            node_mac = n.get("mac") or ""
            if not node_mac:
                continue
            bands_for_node = relist.get(node_mac, {}) or {}
            for band, key in (("2.4G", "sta2g"), ("5G", "sta5g"), ("6G", "sta6g")):
                sta_mac = bands_for_node.get(key)
                if not sta_mac:
                    continue
                ap_iface = ap_iface_by_band.get(band)
                if not ap_iface:
                    continue
                text, ec = self._client.run(
                    f"wl -i {ap_iface} sta_info {sta_mac} 2>&1", timeout=5.0)
                if ec != 0 or not text.strip():
                    continue
                info = parsers.parse_wl_sta_info(text)
                if not info:
                    continue
                backhaul.append({
                    "node_mac":         node_mac,
                    "sta_mac":          sta_mac,
                    "ap_iface":         ap_iface,
                    "band":             band,
                    "rssi":             info.get("smoothed_rssi"),
                    "link_uptime_secs": info.get("in_network_secs"),
                    "tx_bytes":         info.get("tx_total_bytes"),
                    "rx_bytes":         info.get("rx_data_bytes"),
                    "bw_mhz":           info.get("link_bw_mhz"),
                })
        return nodes, backhaul

    @staticmethod
    def _unique_per_phy(iw_devs):
        """Yield (phy_int, iface, channel) one per unique phy. Prefers
        primary BSS (no '.') over guest VAPs ('wl0.1' etc.)."""
        chosen = {}
        for d in iw_devs:
            phy = d.get("phy")
            if phy is None:
                continue
            cur = chosen.get(phy)
            is_primary = "." not in d["iface"]
            if cur is None or (is_primary and "." in cur["iface"]):
                chosen[phy] = d
        for phy in sorted(chosen):
            d = chosen[phy]
            yield phy, d["iface"], d.get("channel")

    @staticmethod
    def _band_for_channel(ch):
        # Channel-only heuristic. 6 GHz overlaps 2.4 GHz channel numbers
        # and would need the frequency to disambiguate; not handled here.
        if ch is None:
            return None
        if 1 <= ch <= 14:
            return "2.4G"
        if 32 <= ch <= 196:
            return "5G"
        return None

    def _compute_cpu_loads(self, stat):
        """Return list of CPU load percentages, one per CPU. Returns [0..]
        on the first poll (no delta yet)."""
        loads = []
        for cpu in stat["cpus"]:
            prev = self._prev_cpu_total
            if (prev is None or len(prev) != len(cpu)
                    or len(cpu) < 4):
                loads.append(0)
                continue
            idle_delta  = cpu[3] - prev[3]
            total_delta = sum(cpu) - sum(prev)
            if total_delta <= 0:
                loads.append(0)
            else:
                loads.append(int((1 - idle_delta / total_delta) * 100))
        return loads
