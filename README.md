# asus2snmp

A standalone SNMPv1/v2c agent that scrapes an ASUS router (stock
firmware) over telnet and serves the data on the SNMP wire. One
process per router.

The stock ASUS firmware's built-in SNMP support (when present at all) is limited
and inconsistent across firmware revisions — per-radio temperatures,
wireless association lists with RSSI, bridge FDB with port mapping, and
similar low-level data are typically missing. This bridges the gap:
telnet in, parse the same files / nvram keys / `wl` / `iw` outputs the
admin UI itself reads, and expose the values under standard MIBs (plus
a private subtree for ASUS-specific data) on a UDP port any network
monitor can poll.

Sister project of `ddwrt2snmp` — same architecture, same private OID
layout, different shell environment.

## Requirements

- Python 3.8+
- An ASUS router with telnet enabled (Administration -> System ->
  Enable Telnet: Yes). SSH is also supported by the same admin
  interface, but this agent uses telnet by default. See *SSH instead*
  below.
- No third-party packages. Pure stdlib: `socket`, `selectors`,
  `threading`, `re`, `argparse`. The whole agent including the SNMP
  codec is hand-rolled.

## Tested against

- **RT-AX57** (productid `RT-AX3000N`), firmware 3.0.0.4 build 386,
  Linux 4.19.183 ARMv7, Broadcom-based (both `wl` and `iw` present).

The same code should work on any stock-firmware ASUS router that exposes a busybox
shell over telnet/SSH. Per-platform quirks (which `nvram` keys exist,
which thermal zones, which wireless tooling) are handled by soft-fail
probes — missing values just don't appear in the cache that cycle.

## Quick start

Linux / macOS:
```sh
chmod +x asus2snmp.sh
./asus2snmp.sh --target 192.168.1.1 \
               --user admin --password 'YOURPASS' \
               --bind 0.0.0.0:1163
```

Windows:
```bat
asus2snmp.bat --target 192.168.1.1 --user admin --password YOURPASS --bind 0.0.0.0:1163
```

Then point any SNMP manager at `host:1163`, community `public`,
version `2c`.

For a quick smoke test there's a stdlib snmpwalk/snmpget client
included:
```sh
./walk.sh 127.0.0.1:1163 1.3.6.1.2.1.1                   # walk system group
./walk.sh --get 127.0.0.1:1163 1.3.6.1.2.1.1.5.0         # get sysName
./walk.sh 127.0.0.1:1163 1.3.6.1.4.1.99999.1.2           # walk temperatures
```

Two routers? Run two instances on different ports:
```sh
./asus2snmp.sh --target 192.168.1.1 --user admin --password A --bind 0.0.0.0:1163 &
./asus2snmp.sh --target 192.168.1.2 --user admin --password B --bind 0.0.0.0:1164 &
```

## CLI options

```
--target HOST[:PORT]    ASUS router telnet target (default port 23)
--user USER             telnet username (the web-admin username)
--password PASSWORD     telnet password
--bind HOST[:PORT]      SNMP listen address (default 127.0.0.1:161)
--snmp-version {1,2c}   SNMP version to serve (default 2c)
--community STR         SNMP community (default 'public')
--poll-interval SECONDS seconds between telnet polls (default 60)
--flush-after-failures N flush cache to UNREACHABLE marker after N
                        consecutive failed polls (default 3, 0 to disable)
--log-level LEVEL       DEBUG | INFO | WARNING | ERROR (default INFO)
```

Port 161 is privileged on Linux. Either run as root, grant the bind
capability once with `sudo setcap 'cap_net_bind_service=+ep'
"$(command -v python3)"`, or use a high port like 1163.

## How it works

```
+-------------+    telnet     +-----------+   bulk_replace   +-------+    UDP    +-------------+
|  ASUS       | <-----------> |  Poller   | ---------------> | Cache | <-------> | SNMP agent  |
|  (BusyBox)  |   shell cmds  |  (thread) |  ~2000 OIDs/poll | (lex) |  Get/     | (UDP loop)  |
+-------------+   per minute  +-----------+                  +-------+  GetNext/ +-------------+
                                                                        GetBulk
```

The poller runs in a daemon thread on a persistent telnet session.
Each tick:
1. Runs ~25 commands: standard Linux probes (`uname`, `/proc/*`,
   `ifconfig`, `df`, `brctl showmacs`), ASUS-specific nvram reads
   (`productid`, `lan_hostname`, `cfg_device_list`), Broadcom/mac80211
   wireless probes (`iw dev`, `wl phy_tempsense`, `wl chanim_stats`,
   `wl noise`, `iw <iface> station dump`, `wl sta_info <mac>`), and
   AiMesh state (`lldpcli show neighbors`, `cat /tmp/relist.json`).
2. Parses each output via a pure function in `parsers.py`.
3. Builds a flat `{oid_tuple: SNMPValue}` dict via builders in `mibs.py`.
4. Atomically swaps the cache via `bulk_replace`.

Per-command failures (non-zero exit, missing tool, missing file) are
soft: the value just doesn't appear in the cache that cycle. Only
telnet I/O errors trigger a reconnect with exponential backoff
(1s, 2s, 4s, ..., capped at the poll interval).

After `--flush-after-failures` consecutive failed polls (default 3) the
cache is replaced with a minimal "UNREACHABLE" marker: the system group
has sysDescr set to a string like
`ASUS (via asus2snmp) -- UNREACHABLE at HOST:PORT since TIMESTAMP`,
and every other table is empty. This stops stale interface counters,
temperatures, and CPU values from continuing to look like live data to
your monitor. The first successful poll after recovery rebuilds the
full cache.

The SNMP agent serves Get / GetNext / GetBulk from the cache.
Lexicographic OID order is preserved by the cache's sorted index so
`snmpwalk` traversal works correctly. SetRequest returns `noAccess`;
this is a read-only agent.

The telnet client is a raw socket with an IAC state machine that
refuses every option (stays in NVT mode), auto-detects login/password
prompts case-insensitively, and brackets each command with a unique
sentinel (`__SX_XXXXXX_YYYY__=$?=` followed by the shell prompt) so
output parsing is robust regardless of the router's banner, prompt, or
shell echo state.

## OIDs exposed

### Standard MIBs

`SNMPv2-MIB::system` (1.3.6.1.2.1.1) - sysDescr, sysObjectID (Linux),
sysUpTime, sysContact, sysName, sysLocation, sysServices.

`IF-MIB::ifTable` (1.3.6.1.2.1.2.2) and `ifXTable` (1.3.6.1.2.1.31.1.1) -
all interfaces from `/proc/net/dev` cross-referenced with `ifconfig`.
Includes ifIndex, ifDescr, ifType, ifMtu, ifPhysAddress (MAC),
ifAdminStatus, ifOperStatus, ifInOctets/ifOutOctets (Counter32) and
HC counterparts (Counter64), and per-interface drop/error counters.

`IP-MIB::ipAddrTable` (1.3.6.1.2.1.4.20) - one row per IPv4 address
found in `ifconfig`; maps IP -> ifIndex and netmask. Aliases (e.g.
`br0:0`) map to the parent interface's ifIndex.

`HOST-RESOURCES-MIB` (1.3.6.1.2.1.25) - hrSystemUptime,
hrSystemNumUsers (connected client count from bridge FDB),
hrSystemProcesses, hrMemorySize, hrStorageTable (one row for RAM + one
per filesystem from `df`), hrProcessorTable (one row per CPU, percent
load computed from delta of `/proc/stat` between polls).

`UCD-SNMP-MIB` (1.3.6.1.4.1.2021):
- `laTable` (.10.1) - 1, 5, and 15-minute load averages (string + integer).
- memory (.4) - memTotalReal, memAvailReal, memTotalFree, memBuffer, memCached.
- ssCpuRaw (.11) - User, Nice, System, Idle, Wait, Kernel, Intr (Counter32).
- `dskTable` (.9.1) - filesystem usage (dskPath, dskDevice, dskTotal,
  dskAvail, dskUsed, dskPercent).
- `diskIOTable` (.13.15.1) - per-block-device I/O from `/proc/diskstats`
  (Counter32 + Counter64). Idle ramdisks are filtered out.

### Private subtree (1.3.6.1.4.1.99999.1)

Unregistered PEN. Fine for self-hosted monitoring of your own gear.
Same root and column layout as `ddwrt2snmp` — Cacti templates created
for one project work for the other (identity scalars and the
temperature/wireless-client/bridge tables are positionally identical).

#### .1 router identity (scalars)

- `.1.1.0` asusBoard - `nvram get productid` (e.g. "RT-AX3000N").
- `.1.2.0` asusModel - `nvram get model`.
- `.1.3.0` asusBuild - `cat /proc/version`.
- `.1.4.0` asusCpuModel - first `model name` from `/proc/cpuinfo`.

#### .2 temperature table — `asusTempTable`

Columns: Index / Name / Source / Celsius / Raw. Probes:
- Broadcom: `wl -i <iface> phy_tempsense` per **unique radio (PHY)** —
  guest VAPs share the radio so they're deduped to avoid repeats.
- Generic kernel: every `/sys/class/thermal/thermal_zone*/temp`
  (CPU/SoC, etc. — whatever the kernel exposes).
- Broadcom legacy: `/proc/dmu/temperature`.

Discovery-driven — a router with N distinct sensors gets N rows. On
RT-AX57 this yields 3 rows (2.4 GHz radio, 5 GHz radio, SoC).

#### .3 wireless client table — `asusWlClientTable`

Per-station data for every BSS (main + guest VAPs). Columns:
Index / MAC (PhysAddress) / Interface / RSSI (dBm) /
RxBytes (Counter64, AP rx from station) /
TxBytes (Counter64, AP tx to station).

Wireless interfaces are discovered via `iw dev` (the canonical source
on ASUS — `/proc/net/wireless` is not present on this kernel). The
prober prefers `iw <iface> station dump` (single round-trip per BSS,
includes rx/tx bytes), falling back to Broadcom's `wl assoclist` +
per-station `wl rssi` only if `iw` is unavailable.

#### .4 bridge MAC FDB — `asusBrMacTable`

Full bridge FDB from `brctl showmacs br0`, one row per MAC the router
has seen. Columns: Index / MAC / Port / IsLocal / AgingMs /
IPv4 (cross-referenced from `/proc/net/arp`). This is the canonical
"every connected client" source — covers wired and wireless together.

#### .5 conntrack scalars

- `.5.1.0` asusConntrackCount - Gauge32, current entries from
  `/proc/sys/net/netfilter/nf_conntrack_count`.
- `.5.2.0` asusConntrackMax - Integer, table size from
  `/proc/sys/net/netfilter/nf_conntrack_max`.

(On AP-mode devices that bridge rather than NAT, count typically reads
0 — that's expected, not a bug.)

#### .6 per-radio channel stats — `asusChanStatsTable`

One row per radio (PHY). Probes `wl noise` and `wl chanim_stats` on
the primary BSS for each PHY. Columns:
Index / Iface / Phy / Channel / NoiseDbm / BusyPct (gauge) /
TxopPct (gauge) / Glitch (gauge) / BadPlcp (gauge).

Useful for graphing channel saturation over time.

#### .7 AiMesh node table — `asusMeshNodeTable`

One row per node from `nvram get cfg_device_list`. Columns:
Index / Model (string) / IP (string) / MAC (PhysAddress) /
Role (1 = master/CAP, 0 = re/slave).

Empty on standalone (non-mesh) deployments.

#### .8 AiMesh backhaul link stats — `asusBackhaulTable`

One row per remote node, derived from the master's view of each slave's
backhaul radio (per-band station MAC looked up from `/tmp/relist.json`,
then `wl -i <ap_iface> sta_info <sta_mac>`). Columns:
Index / NodeMac (slave's primary MAC) / StationMac (slave's per-radio
MAC the master sees) / ApIface (master AP iface, e.g. `eth3`) /
Band (string: "2.4G" / "5G" / "6G") / Rssi (Integer dBm) /
LinkUptimeSecs (Gauge32) / TxBytes (Counter64, master→slave) /
RxBytes (Counter64, slave→master) / BandwidthMhz (Gauge32).

This is the marquee mesh-health metric — graph RSSI and tx/rx bytes
over time to spot backhaul degradation before users feel it.

## Cacti integration

Standard-MIB coverage means most of Cacti's built-in templates work
out of the box once you add the device:
- "Net-SNMP - Load Average", "Net-SNMP - Memory Usage" (UCD-SNMP).
- "Host MIB - CPU Utilization", "Host MIB - Logged in Users",
  "Host MIB - Processes" (HOST-RESOURCES).
- Interface traffic via the SNMP Interface Statistics data query
  (ifTable / ifXTable).
- "Net-SNMP - Get Mounted Partitions" (dskTable).
- "Net-SNMP - Get Device I/O" (diskIOTable).

For private-subtree metrics, use Cacti's "SNMP - Generic OID Template"
data + graph templates and point each at a specific OID. To label
graphs, walk the relevant `Name`/`Iface` column first to see which row
is which (varies by hardware / mesh topology).

**Cacti gotcha:** Cacti hides a graph template from the
`graphs_new.php` dropdown after its first use on a device, *unless* the
template has **Multiple Instances** enabled. Before creating multiple
private-subtree graphs from "SNMP - Generic OID Template" on the same
device, edit the template (Templates → Graph Templates → "SNMP -
Generic OID Template") and tick the **Multiple Instances** checkbox.
The "DD-WRT - Temperature" template (used for the temperature
instances) already has it enabled.

Per-instance scalar OIDs worth graphing:

| OID | Type | Description |
|---|---|---|
| `.1.3.6.1.4.1.99999.1.2.1.1.4.<N>` | Integer | Temperature row N, Celsius |
| `.1.3.6.1.4.1.99999.1.5.1.0` | Gauge32 | Conntrack count |
| `.1.3.6.1.4.1.99999.1.6.1.1.5.<P>` | Integer | Radio P noise floor (dBm) |
| `.1.3.6.1.4.1.99999.1.6.1.1.6.<P>` | Gauge32 | Radio P channel busy % |
| `.1.3.6.1.4.1.99999.1.6.1.1.7.<P>` | Gauge32 | Radio P txop % |
| `.1.3.6.1.4.1.99999.1.6.1.1.8.<P>` | Gauge32 | Radio P glitch count |
| `.1.3.6.1.4.1.99999.1.6.1.1.9.<P>` | Gauge32 | Radio P bad PLCP count |
| `.1.3.6.1.4.1.99999.1.8.1.1.6.<L>` | Integer | Backhaul link L RSSI (dBm) |
| `.1.3.6.1.4.1.99999.1.8.1.1.7.<L>` | Gauge32 | Backhaul link L uptime (s) |
| `.1.3.6.1.4.1.99999.1.8.1.1.8.<L>` | Counter64 | Backhaul link L tx bytes |
| `.1.3.6.1.4.1.99999.1.8.1.1.9.<L>` | Counter64 | Backhaul link L rx bytes |

For Counter64 columns set the Cacti data source to type **DERIVE** (or
COUNTER) so graphs show bytes/sec rather than monotonically-rising
totals.

A Cacti **Data Query XML** for the temperature and channel-stats
tables would let one template auto-discover all sensors per device on
device-add (instead of per-instance graph creation). Not yet written;
sketch lives in the project notes.

## Notes

- **AiMesh — point at the master only.** Mesh slaves expose a telnet
  daemon that advertises the master's identity in the banner but
  rejects every admin login (the slave's auth is brokered by the master
  via internal cfg_mnt channels, not exposed to user logins). Point
  `asus2snmp` at the master and you get the slaves' presence + per-band
  backhaul stats (RSSI, link uptime, tx/rx bytes — see the
  `asusBackhaulTable` above) from the master's view of each slave's
  WiFi radio. Slave-internal CPU/temp aren't directly accessible
  without a real shell on the slave — open problem.
- **Telnet vs SSH.** ASUS firmware enables both from the same admin page.
  Telnet is plaintext; fine for a wired monitoring host on a trusted
  LAN, not great anywhere else. The current client is telnet-only;
  swapping to an SSH-via-subprocess client is straightforward and
  preserves the same `connect/login/run/close` interface.
- **ANSI color codes in busybox `ls`.** The ASUS busybox emits ANSI
  escapes for `ls` of `/sys/class/thermal` and `/sys/class/net`. The
  temperature probe sidesteps this by using
  `cd ... && echo thermal_zone*` — busybox `echo` never emits color
  codes. Anywhere you add a probe that parses `ls` output, prefer the
  same trick.
- **Wireless interface naming on Broadcom ASUS hardware.** The primary
  BSSes live on `eth*` interfaces (e.g. `eth2` = 2.4 GHz, `eth3` =
  5 GHz on RT-AX57); guest VAPs live on `wl0.1` / `wl1.1`. Per-radio
  probes (temperature, channel stats) dedupe by PHY to avoid querying
  guest VAPs for data that's identical to the primary BSS.

## Project layout

```
asus2snmp/                  package
|-- __init__.py
|-- __main__.py             entry point: python -m asus2snmp
|-- ber.py                  ASN.1 BER encode/decode (INTEGER, OID, etc.)
|-- snmp.py                 SNMPv1/v2c message + PDU layer on top of BER
|-- agent.py                UDP server loop; Get / GetNext / GetBulk
|-- cache.py                thread-safe OID -> SNMPValue store; lex GetNext
|-- telnet.py               raw-socket telnet client; IAC; flexible login
|-- parsers.py              pure-function parsers for /proc, ifconfig, wl, iw
|-- mibs.py                 OID constants + builder functions
|-- poller.py               background thread; orchestrates poll cycle
|-- cli.py                  argparse + main()
`-- walk.py                 stdlib snmpget/snmpwalk client
asus2snmp.sh / .bat         launcher
walk.sh / walk.bat          launcher for the walk client
```
