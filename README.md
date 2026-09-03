# nftable-router

Software Policy Router for nftables — GeoIP/domain based policy routing via
NFQUEUE, with a built-in web admin, transparent-proxy process supervision,
PowerDNS Recursor management and SNMP switch ARP/MAC collectors.

## Install

### Requirements

| | |
|---|---|
| Python | >= 3.8 (3.13 tested; see note on pysnmp below) |
| Kernel | nftables + NFQUEUE (`nfnetlink_queue`) |
| Services | redis (the UI stream, ARP/MAC cache and cross-process state board) |
| Build deps | `build-essential`, `libnetfilter-queue-dev` (for `NetfilterQueue`) |

**One dependency cannot come from pip:** the `nftables` Python binding ships
with the nftables project itself, not PyPI (the PyPI name `nftables` is an
unrelated project — do not install it).

```bash
apt install python3-nftables build-essential libnetfilter-queue-dev
```

### Install the package

```bash
pip install .
# or from a built wheel
pip install dist/nftable_router-*.whl
```

If you install into a **venv created without `--system-site-packages`**, link
the distro-provided binding in, otherwise `import nftables` fails:

```bash
ln -s /usr/lib/python3/dist-packages/nftables \
      /path/to/venv/lib/python3.*/site-packages/
```

`nft-router` checks this at startup and prints the exact command if missing.

### Console scripts

| command | what it runs |
|---|---|
| `nft-router` | the router itself (reads `nft_route.json` from CWD, or `$NFT_ROUTE_CONFIG`) |
| `nft-router-webadmin` | the web admin standalone (normally supervised by the router) |
| `nft-router-arp` | one switch's SNMP collector (normally supervised by the router) |

### A note on `ipdb`

The GeoIP reader imported as `ipdb` comes from **`ipip-ipdb-hp`** (IPIP.net
database format, C extension). Do **not** `pip install ipdb` — that is the
IPython debugger and will shadow it with a package that has no `City` class.

**Requires >= 0.1.2.** Earlier versions do not compile on GCC 14+ (Debian
trixie, Ubuntu 24.04+), which turned `-Wincompatible-pointer-types` and
`-Wimplicit-function-declaration` into errors.

The pure-Python `ipip-ipdb` exposes the same `City` / `find_map` / `is_ipv6`
API and works as a fallback if the extension cannot be built — but it is
**~11x slower** (40k vs 450k lookups/s, measured against a 175 MB database),
and this lookup runs for every new connection, so prefer the C reader.

### A note on `pysnmp`

The switch collectors need pysnmp, and there are two incompatible
generations in the wild:

* **pysnmp >= 7** (lextudio, actively maintained, asyncio API) — required on
  Python >= 3.12.
* **pysnmp 4.4.x** (2019, unmaintained, sync API) — imports `asyncore`,
  which was **removed in Python 3.12**, so it only works on older
  interpreters.

`arp_snmp.py` speaks both and picks automatically, and the dependency
markers install the right one for the running interpreter. The collectors are
separate child processes, so they can run under a *different* interpreter
than the router via `switches.python` in the config — useful when only that
interpreter has a working pysnmp.

### Replaced dependencies

Two long-unmaintained packages were dropped in favour of `compat.py`:

| was | last release | now |
|---|---|---|
| `netifaces` | 2021-05 | `psutil` (already required); only `interfaces()` was used |
| `python-prctl` | 2020-11, needs libcap headers | `setproctitle` + a ctypes `prctl(PR_SET_NAME)` call |
| `pytput` | 2020-05, imports the removed `pkg_resources` | `compat.TputFormatter`, same `{x:spec,style}` syntax |

`pytput` is not merely stale — it raises `ModuleNotFoundError` on import
under a Python 3.13 venv, since setuptools 81 dropped `pkg_resources` and
new venvs do not ship setuptools at all.

## Running

```bash
cd /etc/network        # wherever nft_route.json lives
nft-router             # needs root: nftables, NFQUEUE, SO_MARK
```

The web admin starts automatically as a supervised child (see the
`webadmin` config section) — by default on `http://127.0.0.1:8788`.

Reload after editing config: `kill -USR1 $(cat /run/nft_route.pid)`, or the
「重载主进程」button on the UI's 状态 page.

## Tests

Offline, no root / kernel / switches / redis needed:

```bash
cd nftable_router
for t in test_*.py; do python3 "$t"; done
```

# Icon Means
## Status ICON
### ALIVE:
> 🟩   - Global Lock Idle
>
> 🔴   - Process Dead
>
> 🟡   - Process Busying
>
> 🟩   - Process Idle > 30s
>
> 🟢   - Process Idle

### Proxy Test Status:
> ⚫ for Line
>
> ⬛ for Proxy
>
> ⚫   - N/A
>
> 🔴   - Failed
>
> 🟢   - <= 100ms
>
> 🔵   - <= 200ms
>
> 🟣   - <= 400ms
>
> 🟡   - <= 600ms
>
> 🟠   - <= 800ms
>
> 🟤   - > 800ms

# Config.json

- `ipdb_v4`				- Path for IPDB IPv4
- `ipdb_v6`				- Path for IPDB IPv6
- `nat_interfaces` 		- Interface for internal network (from this interfaces will be nat)
- `tunnel_ip`			- Tunnel IP, would be ignore to software router
- `allow_ecmp`			- Allow Equal Cost multi-path CIDR (TODO)
- `allow_ecmp_port` 	- Allow Equal Cost multi-path Ports (TODO)
- `ignore_print_domain`	- No output for Print domain
- `ignore_list`			- Ignore source CIDR for software router (such as internal router)
- `proxy`				- Line List
- `rules`				- Rules array for process (array for priority)
	- `from`			- match by source ip (highest priority)
	- `any`				- match any traffic
	- `resolve`			- match by resolved domain name
	- `cidr`			- match by target ip CIDR
	- `country_name`	- match by country name
	- `region_name`		- match by region name (such as `ALIDNS.COM`)
	- `city_name`		- match by city
	- `owner_domain`	- match by owner domain (such as `github.com`, `twitter.com`)
	- `isp_domain`		- match by ISP (such as `阿里云`, `阿里云/电信/联通/移动/教育网`)
	- `country_code`	- match by 2 char country code (such as `CN`)
	- `anycast`			- match by is anycast ip (only ` ` or `ANYCAST`)
	- `idc`				- match by is idc ip (only ` ` or `IDC`)
	- `base_station`	- match by is base_station ip (only ` ` or `基站`)

## `webadmin` section

```json
"webadmin": {
  "enabled": true, "host": "127.0.0.1", "port": 8788,
  "redis_host": "127.0.0.1", "redis_port": 6379, "redis_db": 1,
  "log": "/var/log/nft_webadmin.log",
  "restart": {"max": 5, "window": 300},

  "pdns_config": "/etc/powerdns/pdns-recursor.json",
  "pdns_poison_list": "/etc/powerdns/dns_posion_list.txt",
  "pdns_host": "user@192.168.30.2",
  "rec_control": "rec_control"
}
```

`pdns_host` routes all PowerDNS file I/O and `rec_control` over ssh (keys /
`~/.ssh/config` of the invoking user; nothing is managed by this package).
Omit it when the recursor is local. Omit `pdns_config` to hide the DNS tab.

## `switches` section — SNMP ARP/MAC collectors

One supervised child process per switch, polling ARP / MAC / interface tables
into redis (`ARP::MAPPING`, `MAC::TABLE::<sysname>`, `SW::INT::<sysname>`),
which is what the flow view's 源设备 column resolves against.

```json
"switches": {
  "enabled": true,
  "python": "python3.9",
  "log_dir": "/var/log/nft_route",
  "poll_interval": 300,
  "iface_interval": 1800,
  "restart": {"max": 5, "window": 300},
  "devices": [
    {"name": "sw-core", "ip": "192.168.11.1",
     "user": "monitor", "auth_key": "...", "priv_key": "..."},
    {"name": "sw-acc", "ip": "192.168.11.4", "community": "public"}
  ]
}
```

- `python` — interpreter for the collector children; omit to use the
  router's own. Set it when only another interpreter has a working pysnmp.
- per device: `community` (v2c) **or** `user` + `auth_key` (+`priv_key`) for
  v3 (HMAC192SHA256 / AES128), `enabled: false` to keep the entry but stop
  polling.

Both Huawei ARP MIBs are handled automatically: the standard
`ipNetToPhysical` table on VRP8/CloudEngine, and `HUAWEI-ETHARP-MIB` on VRP5
(S5700 family), whose index layout differs.
