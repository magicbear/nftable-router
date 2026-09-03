#!/usr/bin/env python3
"""
nftable-router web admin -- SEPARATE PROCESS (never imported by router.py).

Hard isolation rules:
  * does NOT touch nftables/netfilter/kernel network at all
  * only writes the config file (atomic + .bak via iface_bind.save_config)
  * tells the router master to reload by SIGUSR1 to /run/nft_route.pid
    (pid sanity-checked against /proc/<pid>/cmdline before signalling)
  * live traffic comes from the router's redis pubsub channel "pr_stream"
    (fire-and-forget publisher inside PrintResultThread); this process just
    subscribes -- if webadmin dies the router cannot notice

Web stack: pure stdlib (selectors/ThreadingHTTPServer) + hand-written
RFC6455 WebSocket (no pip dependencies beyond redis which the router
already requires). Server keeps a bounded ring of the last 1000 flow
events; the browser caps its table at 1000 rows as well.

run:  python3 -m nftable_router.webadmin --config /etc/network/nft_route.json \
          --host 127.0.0.1 --port 8788
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from queue import Queue, Empty
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

module_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.dirname(module_dir))
sys.path.insert(0, module_dir)

try:
    from nftable_router import iface_bind as ib
    from nftable_router import netinfo
except ImportError:                      # flat-file deployment (same dir copy)
    import iface_bind as ib
    import netinfo

try:
    from nftable_router import proxy_mgr as pmm
except Exception:
    try:
        import proxy_mgr as pmm
    except Exception:
        pmm = None

try:
    from nftable_router import pdns_admin as pa
except Exception:
    try:
        import pdns_admin as pa
    except Exception:
        pa = None

try:
    from nftable_router.arp_snmp import pick_mac_port
except Exception:
    try:
        from arp_snmp import pick_mac_port
    except Exception:
        pick_mac_port = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import redis
except ImportError:
    print("redis python package is required", file=sys.stderr)
    raise

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
STREAM_CHANNEL = "pr_stream"
RING_MAX = 1000
# generous per-client buffer: bursts on busy lines used to overflow a
# small queue and silently drop rows (console kept showing them)
CLIENT_QMAX = 8192
MASTER_PID_FILE = "/run/nft_route.pid"
PIDFILE_ARG = None  # set from args


# ---------------------------------------------------------------------------
# websocket codec (RFC6455)
# ---------------------------------------------------------------------------

def ws_accept_key(sec_key):
    return base64.b64encode(hashlib.sha1((sec_key + WS_GUID).encode()).digest()).decode()


def ws_encode(payload, opcode=0x1):
    if isinstance(payload, str):
        data = payload.encode("utf-8")
    else:
        data = payload
    head = bytearray([0x80 | opcode])
    n = len(data)
    if n < 126:
        head.append(n)
    elif n < 65536:
        head.append(126)
        head += struct.pack("!H", n)
    else:
        head.append(127)
        head += struct.pack("!Q", n)
    return bytes(head) + data


class WSParser:
    """feed() bytes -> yields opcode ints with payloads (str for text)."""

    def __init__(self):
        self.buf = b""

    def feed(self, data):
        self.buf += data
        out = []
        while True:
            frame = self._one()
            if frame is None:
                break
            out.append(frame)
        return out

    def _one(self):
        b = self.buf
        if len(b) < 2:
            return None
        fin_op, mlen = b[0], b[1]
        masked = mlen & 0x80
        ln = mlen & 0x7F
        pos = 2
        if ln == 126:
            if len(b) < 4:
                return None
            ln = struct.unpack("!H", b[2:4])[0]
            pos = 4
        elif ln == 127:
            if len(b) < 10:
                return None
            ln = struct.unpack("!Q", b[2:10])[0]
            pos = 10
        if masked:
            if len(b) < pos + 4:
                return None
            key = b[pos:pos + 4]
            pos += 4
        if len(b) < pos + ln:
            return None
        payload = bytearray(b[pos:pos + ln])
        self.buf = b[pos + ln:]
        if masked:
            for i in range(len(payload)):
                payload[i] ^= key[i & 3]
        return fin_op & 0x0F, bytes(payload)


# ---------------------------------------------------------------------------
# ring + hub
# ---------------------------------------------------------------------------

class RingBuffer:
    def __init__(self, maxlen=RING_MAX):
        self._d = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def push(self, item):
        with self._lock:
            self._d.append(item)

    def snapshot(self):
        with self._lock:
            return list(self._d)

    def __len__(self):
        return len(self._d)


class Hub:
    def __init__(self):
        self.clients = set()
        self.lock = threading.Lock()

    def add(self, q):
        with self.lock:
            self.clients.add(q)

    def remove(self, q):
        with self.lock:
            self.clients.discard(q)

    def broadcast(self, raw):
        with self.lock:
            targets = list(self.clients)
        for q in targets:
            try:
                q.put_nowait(raw)
            except Exception:
                try:                       # slow consumer: drop its oldest
                    q.get_nowait()
                    q.put_nowait(raw)
                    q.dropped = getattr(q, "dropped", 0) + 1
                except Exception:
                    pass

    def count(self):
        with self.lock:
            return len(self.clients)


# ---------------------------------------------------------------------------
# redis subscriber (router -> webadmin IPC)
# ---------------------------------------------------------------------------

class Streamer(threading.Thread):
    def __init__(self, ring, hub, host, port, db):
        threading.Thread.__init__(self, daemon=True)
        self.ring, self.hub = ring, hub
        self.host, self.port, self.db = host, port, db
        self.alive = False
        self.stop_evt = threading.Event()

    def run(self):
        while not self.stop_evt.is_set():
            try:
                r = redis.Redis(host=self.host, port=self.port, db=self.db,
                                socket_timeout=3, socket_connect_timeout=3)
                pub = r.pubsub()
                pub.subscribe(STREAM_CHANNEL)
                self.alive = True
                for msg in pub.listen():
                    if self.stop_evt.is_set():
                        break
                    if msg.get("type") != "message" or not isinstance(msg.get("data"), bytes):
                        continue
                    raw = msg["data"]
                    try:
                        self.ring.push(json.loads(raw))
                    except ValueError:
                        continue
                    self.hub.broadcast(raw)
            except Exception:
                self.alive = False
                self.stop_evt.wait(1.0)
            finally:
                self.alive = False

    def shutdown(self):
        self.stop_evt.set()


# ---------------------------------------------------------------------------
# master signalling
# ---------------------------------------------------------------------------

def signal_master(sig=signal.SIGUSR1, pidfile=None):
    path = pidfile or PIDFILE_ARG or MASTER_PID_FILE
    try:
        with open(path) as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        return {"ok": False, "error": "master pidfile missing (%s) -- router not started by this repo?" % path}
    try:
        cmdline = open("/proc/%d/cmdline" % pid, "rb").read().decode("utf-8", "replace")
    except OSError:
        return {"ok": False, "error": "pid %d not running (stale pidfile)" % pid}
    if "nft_route" not in cmdline and "router.py" not in cmdline:
        return {"ok": False, "error": "pid %d is NOT the router (cmdline: %s)" % (pid, cmdline[:80])}
    try:
        os.kill(pid, sig)
        return {"ok": True, "pid": pid, "signal": int(sig)}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def switch_status(app, cfg=None):
    """Configured switches joined with each collector's live SW::STATUS
    heartbeat (written by arp_snmp.py) and the redis entry counts it
    produced. A collector process can be 'alive' while its SNMP walks all
    fail, so process liveness alone would be misleading -- last_poll age is
    what actually tells you the data is fresh."""
    out = {"ok": True, "devices": [], "enabled": False}
    try:
        sw = (cfg or {}).get("switches") or {}
        if isinstance(sw, bool):
            sw = {"enabled": sw}
        out["enabled"] = bool(sw.get("enabled", True)) and bool(sw.get("devices"))
        out["python"] = sw.get("python") or sys.executable
        out["log_dir"] = sw.get("log_dir")
        devices = sw.get("devices") or []
    except Exception as e:
        return {"ok": False, "error": str(e), "devices": []}

    live = {}
    try:
        r = redis.Redis(host=app.args.redis_host, port=app.args.redis_port,
                        db=app.args.redis_db, socket_timeout=2, socket_connect_timeout=2)
        raw = r.hgetall("SW::STATUS") or {}
        for k, v in raw.items():
            try:
                live[k.decode("utf-8", "replace")] = json.loads(v.decode("utf-8", "replace"))
            except (ValueError, AttributeError):
                pass
        for d in devices:
            name = str(d.get("name") or d.get("ip") or "")
            st = live.get(name) or {}
            sysname = st.get("sysname") or ""
            counts = {}
            for label, key in (("arp", "ARP::MAPPING::%s" % (sysname or name)),
                               ("mac", "MAC::TABLE::%s" % (sysname or name)),
                               ("int", "SW::INT::%s" % (sysname or name))):
                try:
                    counts[label] = r.hlen(key)
                except Exception:
                    counts[label] = None
            counts["sta"] = st.get("stas")
            out["devices"].append({
                "name": name, "ip": d.get("ip"),
                "enabled": d.get("enabled", True),
                "auth": "v3" if d.get("user") else ("v2c" if d.get("community") else "-"),
                "sysname": sysname,
                "state": st.get("state"), "pid": st.get("pid"),
                "last_poll": st.get("last_poll"), "error": st.get("error"),
                "vrp": st.get("vrp"), "wlan": st.get("wlan"), "counts": counts,
            })
    except Exception as e:
        out["ok"] = False
        out["error"] = "redis: %s" % e
        for d in devices:
            out["devices"].append({"name": d.get("name") or d.get("ip"), "ip": d.get("ip"),
                                   "enabled": d.get("enabled", True), "counts": {}})
    return out


def arp_table(app, limit=4000):
    """Merged ARP::MAPPING view (what router.py resolves the flow view's
    源设备 column against), joined with each MAC's switch port from
    MAC::TABLE::<sysname> so the UI can answer "which switch port is this
    IP on" in one place."""
    try:
        r = redis.Redis(host=app.args.redis_host, port=app.args.redis_port,
                        db=app.args.redis_db, socket_timeout=3, socket_connect_timeout=3)
        raw = r.hgetall("ARP::MAPPING") or {}
        mac_tables = {}
        for key in (r.keys("MAC::TABLE::*") or []):
            kname = key.decode("utf-8", "replace")[len("MAC::TABLE::"):]
            if not kname:
                continue          # legacy empty-sysname key (old arp.py bug)
            try:
                mac_tables[kname] = {
                    m.decode("utf-8", "replace"): json.loads(v.decode("utf-8", "replace"))
                    for m, v in (r.hgetall(key) or {}).items()}
            except (ValueError, AttributeError):
                pass
        rows = []
        for ip_b, blob in raw.items():
            ip = ip_b.decode("utf-8", "replace")
            try:
                e = json.loads(blob.decode("utf-8", "replace"))
            except (ValueError, AttributeError):
                continue
            mac = e.get("mac") or ""
            # Score every MAC-table hit (access port > named edge trunk
            # like "To NAS" > inter-switch uplink). Blindly skipping
            # Eth-Trunk used to leave hosts such as 192.168.11.14 stuck
            # on Vlanif1 even though CE6881 learned them on Eth-Trunk3.
            hits = []
            for sw, table in mac_tables.items():
                hit = table.get(mac)
                if hit:
                    hits.append((sw, hit))
            if e.get("ifName_L2"):
                hits.append((e.get("sysname") or "", {
                    "ifName": e["ifName_L2"], "ifDescr": e["ifName_L2"]}))
            if e.get("ap_name"):
                hits.append((e.get("sysname") or "", {
                    "ifName": e["ap_name"], "ifDescr": e["ap_name"]}))
            picked = pick_mac_port(hits) if pick_mac_port else None
            if picked:
                port_sw, ifName, ifDescr = picked
                port = ifDescr or ifName
            else:
                port, port_sw = "", ""
            rows.append({"ip": ip, "mac": mac, "sysname": e.get("sysname") or "",
                         "ifName_L3": e.get("ifName_L3") or "", "vlan": e.get("vlan"),
                         "ap_name": e.get("ap_name") or "", "ssid": e.get("ssid") or "",
                         "source": e.get("source") or "",
                         "port": port, "port_sw": port_sw})
        rows.sort(key=lambda x: x["ip"])
        return {"ok": True, "total": len(rows), "rows": rows[:limit],
                "switches": sorted(mac_tables)}
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e), "rows": []}


def reload_dnsmasq(run=None, timeout=8):
    """`systemctl reload dnsmasq` -- LOCAL only (this box, not the remote
    pdns_host): re-reads config/hosts, including /etc/dnsmasq.d/nft_route.conf
    which router.py's load_config() rewrites (PTR records mapping each
    proxy line's mark to a hostname) on every config load/SIGUSR1 reload.
    `reload` (not `restart`) so existing DHCP leases aren't dropped.
    `run` is injectable for tests."""
    runner = run or subprocess.run
    try:
        p = runner(["systemctl", "reload", "dnsmasq"], capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        return {"ok": p.returncode == 0, "returncode": p.returncode, "output": out.strip()}
    except FileNotFoundError:
        return {"ok": False, "error": "systemctl 未找到"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "systemctl reload dnsmasq 超时 (%ss)" % timeout}
    except OSError as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# config validation (pure, reuses router-side logic modules)
# ---------------------------------------------------------------------------

def validate_config(cfg):
    """returns list of error strings (empty == valid)"""
    errors = []
    if not isinstance(cfg, dict):
        return ["config must be a JSON object"]
    for key in ("proxy", "rules"):
        if key not in cfg:
            errors.append("missing required key: %s" % key)
    proxy = cfg.get("proxy", {})
    if not isinstance(proxy, dict):
        errors.append("proxy must be an object")
        proxy = {}
    marks = {}
    for name, line in proxy.items():
        if not isinstance(line, dict):
            errors.append("proxy %s must be an object" % name)
            continue
        m = line.get("mark")
        if m is None or not isinstance(m, int) or not (0 < m < 2 ** 32):
            errors.append("proxy %s: invalid mark %r" % (name, m))
        else:
            marks.setdefault(m, []).append(name)
        if line.get("daemon") and not line.get("uid"):
            # run-user is an OPTIONAL line identity: empty = the process runs
            # as the current user and gets no skuid rules (mark-type upstream
            # chains inherit the UPSTREAM line's user instead). The one
            # structural exception: a PORT-type upstream chain builds its
            # redirect loop-guard keyed on THIS line's skuid -- impossible
            # without a run-user (router fail-closes the line; reject early).
            up = line.get("upstream")
            upl = (cfg.get("proxy") or {}).get(up) if up else None
            if isinstance(upl, dict) and upl.get("port"):
                errors.append("proxy %s: 上游 %s 是透明端口(port)线路，端口链必须由本线路指定"
                              "运行用户(skuid)才能生成 redirect 防环规则 -- 请设置运行用户或改用 mark 型上游"
                              % (name, up))
        if "ipv4" not in line and "ipv6" not in line:
            errors.append("proxy %s: 缺少 ipv4/ipv6 标记（若你并未编辑过该线路，多半是页面快照过旧：先点 刷新/读取配置 再试）" % name)
        p = line.get("port")
        if p is not None and not (isinstance(p, int) and 1 <= p <= 65535):
            errors.append("proxy %s: invalid port %r" % (name, p))
    for m, names in marks.items():
        if len(names) > 1:
            errors.append("duplicate proxy mark %d used by %s" % (m, ",".join(names)))
    for err in ib.validate_bindings(cfg):
        errors.append(err)
    w = cfg.get("webadmin", {})
    if w and not isinstance(w, dict):
        errors.append("webadmin must be an object")
    elif isinstance(w, dict):
        for k in ("port", "redis_port", "redis_db"):
            if k in w and not (isinstance(w[k], int) and 0 < w[k] < 65536):
                errors.append("webadmin.%s invalid: %r" % (k, w[k]))
        for k in ("host", "redis_host"):
            if k in w and not isinstance(w[k], str):
                errors.append("webadmin.%s must be a string" % k)
        if "enabled" in w and not isinstance(w["enabled"], bool):
            errors.append("webadmin.enabled must be true/false")
    sw = cfg.get("switches", {})
    if sw and not isinstance(sw, dict):
        errors.append("switches must be an object")
    elif isinstance(sw, dict) and sw:
        devs = sw.get("devices")
        if devs is not None and not isinstance(devs, list):
            errors.append("switches.devices must be a list")
        else:
            seen_names, seen_ips = {}, {}
            for i, d in enumerate(devs or []):
                if not isinstance(d, dict):
                    errors.append("switches.devices[%d] must be an object" % i)
                    continue
                ip = d.get("ip")
                if not ip or not isinstance(ip, str):
                    errors.append("switches.devices[%d]: ip 必填" % i)
                    continue
                name = str(d.get("name") or ip)
                # duplicate names collide on SW::STATUS / the per-switch log
                # file; duplicate IPs mean two collectors walking one switch
                if name in seen_names:
                    errors.append("switches: 交换机名重复 %s (设备 #%d 与 #%d)" % (name, seen_names[name], i))
                seen_names.setdefault(name, i)
                if ip in seen_ips:
                    errors.append("switches: 同一 IP 配置了两次 %s (设备 #%d 与 #%d)" % (ip, seen_ips[ip], i))
                seen_ips.setdefault(ip, i)
                if not d.get("community") and not (d.get("user") and (d.get("auth_key") or d.get("authKey"))):
                    errors.append("switches.devices[%s]: 需要 community(v2c) 或 user+auth_key(v3)" % name)
                p = d.get("snmp_port")
                if p is not None and not (isinstance(p, int) and 0 < p < 65536):
                    errors.append("switches.devices[%s]: snmp_port 无效 %r" % (name, p))
        for k in ("poll_interval", "iface_interval"):
            if k in sw and not (isinstance(sw[k], int) and sw[k] > 0):
                errors.append("switches.%s must be a positive int" % k)
        if "enabled" in sw and not isinstance(sw["enabled"], bool):
            errors.append("switches.enabled must be true/false")
    if pmm is not None:
        try:
            pmm.validate_chain(proxy)
        except Exception as e:
            errors.append("proxy chain: %s" % e)
        _dup_names, dup_msgs = pmm.duplicate_users(proxy)
        for m in dup_msgs:
            errors.append("proxy chain: %s" % m)
        # loops are a hard SAVE error here (validate_chain no longer raises for
        # them, so one bad 'upstream' cannot disable the whole router at boot);
        # the runtime still quarantines a leftover loop by line.
        for name, path in sorted(pmm.find_chain_loops(proxy).items()):
            errors.append("proxy chain loop: %s (%s) -- 回源链成环,请修正 upstream" % (name, path))
    return errors


PROXY_STATE_FILE = "/run/nft_route_proxies.json"


def proxy_states():
    try:
        with open(PROXY_STATE_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def proxy_log_tail(key, tail=16384):
    safe = re.sub(r"[^A-Za-z0-9._#\-]", "", str(key))
    if not safe:
        return {"ok": False, "error": "bad key"}
    path = os.path.join("/var/log/nft-route", safe.replace("/", "_") + ".log")
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > tail:
                f.seek(size - tail)
            data = f.read(tail)
        return {"ok": True, "path": path, "size": size, "text": data.decode("utf-8", "replace")}
    except OSError as e:
        return {"ok": False, "path": path, "error": str(e)}


def health_snapshot(app):
    """read-only process + line-test state; never raises (errors -> fields)"""
    res = {"ts": round(time.time(), 1), "master": None, "workers": [], "dns": None,
           "webadmin": {"pid": os.getpid(), "uptime": round(time.time() - app.started),
                        "ring": len(app.ring), "ws_clients": app.hub.count(),
                        "redis_stream": app.streamer.alive},
           "proxies": {"managed": [], "external": []}, "test": None, "error": None}
    if psutil is None:
        res["error"] = "python3-psutil not installed on this host"
    cfg = None
    try:
        cfg = ib.load_config(app.args.config)
    except Exception as e:
        res["error"] = (res["error"] or "") + " load config: %s" % e
    # --- master + children
    procs = {}
    if psutil is not None:
        pidfile = app.args.pidfile or MASTER_PID_FILE
        mpid = None
        try:
            mpid = int(open(pidfile).read().strip())
            mp = psutil.Process(mpid)
            with mp.oneshot():
                res["master"] = {"pid": mpid, "status": mp.status(),
                                 "cmdline": " ".join(mp.cmdline())[:120],
                                 "uptime": round(time.time() - mp.create_time()),
                                 "rss_mb": round(mp.memory_info().rss / 1e6, 1),
                                 "threads": mp.num_threads()}
            kids = mp.children(recursive=False)
            res["master"]["children"] = len(kids)
        except Exception as e:
            res["master"] = {"pid": mpid, "status": "down", "error": str(e)}
            kids = []
        for p in kids:
            procs[p.pid] = p
            cl = []
            try:
                with p.oneshot():
                    cl = p.cmdline()
                    label = " ".join(cl)[:60] if cl else p.name()
                    ent = {"pid": p.pid, "name": label, "status": p.status(),
                           "cpu": round(p.cpu_percent(interval=0.05), 1),
                           "rss_mb": round(p.memory_info().rss / 1e6, 1),
                           "uptime": round(time.time() - p.create_time())}
            except Exception as e:
                ent = {"pid": p.pid, "name": "?", "status": "error", "error": str(e)}
            label_l = ent["name"]
            if "webadmin.py" in label_l or p.pid == os.getpid():
                res["webadmin"]["name"] = label_l
            elif "Route - DNS" in label_l:
                res["dns"] = ent
            elif "Policy Route - W" in label_l:
                res["workers"].append(ent)
            else:
                base = os.path.basename(cl[0]) if cl else ""
                if base in ("ss-redir", "ss-local", "v2ray", "sing-box"):
                    ent["kind"] = "proxy"          # managed/adopted child proxy
                res["workers"].append(ent)
    # --- managed proxies expected from config
    if cfg and psutil is not None and pmm is not None:
        proxy_state = proxy_states()
        managed = {k: v for k, v in cfg.get("proxy", {}).items() if pmm.is_managed(v)}
        claimed = set()
        for name, c in managed.items():
            try:
                insts = pmm.instances_of(name, c) if hasattr(pmm, "instances_of") else [("", c)]
            except Exception:
                insts = [("", c)]
            want = {"managed": name, "daemon": c.get("daemon"), "port": c.get("port"),
                    "upstream": c.get("upstream"), "autostart": c.get("autostart", True),
                    "instances": []}
            for tag, icfg in insts:
                ent = {"tag": tag or "default", "port": icfg.get("port"),
                       "mode": icfg.get("mode", "tcp"), "plugin": icfg.get("plugin"),
                       "pid": None, "state": "not running", "uptime": None, "cpu": None}
                if c.get("autostart", True) is False:
                    ent["state"] = "autostart off"
                for pid, p in procs.items():
                    if pid in claimed:
                        continue
                    try:
                        cl = p.cmdline()
                    except Exception:
                        continue
                    if not cl:
                        continue
                    port_i = cl.index("-l") + 1 if "-l" in cl else None
                    base = os.path.basename(cl[0])
                    if (base in ("ss-redir", "ss-local", "v2ray", "sing-box", str(icfg.get("binary") or ""))
                            and port_i and port_i < len(cl) and str(ent["port"]) == cl[port_i]):
                        try:
                            with p.oneshot():
                                ent.update({"pid": pid, "state": "running",
                                            "uptime": round(time.time() - p.create_time()),
                                            "cpu": round(p.cpu_percent(0.05), 1)})
                                claimed.add(pid)
                        except Exception as e:
                            ent["state"] = "error %s" % e
                        break
                key = name if (ent["tag"] in ("default", None, "")) else "%s#%s" % (name, ent["tag"])
                st0 = (proxy_state or {}).get(key) or (proxy_state or {}).get(name)
                if st0:
                    ent["sup"] = st0
                    if st0.get("state") in ("deferred", "gaveup", "backoff", "external", "error") and ent["state"] != "running":
                        ent["state"] = st0.get("state")
                        ent["why"] = "查看日志 (%s)" % key
                want["instances"].append(ent)
            run_n = sum(1 for e in want["instances"] if e["state"] == "running")
            want["running"] = "%d/%d" % (run_n, len(want["instances"]))
            res["proxies"]["managed"].append(want)
        # external proxy-ish procs NOT under the router master
        try:
            for p in psutil.process_iter(["pid", "name", "cmdline", "ppid", "username"]):
                cl = p.info.get("cmdline") or []
                if cl and os.path.basename(cl[0]) in ("ss-redir", "ss-local", "v2ray", "sing-box") \
                        and p.info["pid"] not in procs:
                    ppname = ""
                    try:
                        ppname = psutil.Process(p.info["ppid"]).name()
                    except Exception:
                        pass
                    res["proxies"]["external"].append({"pid": p.info["pid"], "ppid": p.info["ppid"],
                                                       "ppname": ppname,
                                                       "user": p.info.get("username"),
                                                       "cmd": " ".join(cl)[:100]})
        except Exception:
            pass
    # --- test results from redis
    caps = {}
    try:
        if cfg:
            for nmc, c in (cfg.get("proxy") or {}).items():
                caps[nmc] = {"v4": bool(c.get("ipv4")), "v6": bool(c.get("ipv6")),
                             "mark": c.get("mark"), "tproxy": bool(c.get("port"))}
    except Exception:
        pass
    try:
        r = redis.Redis(host=app.args.redis_host, port=app.args.redis_port, db=app.args.redis_db,
                        socket_timeout=2, socket_connect_timeout=2)
        at = r.get("test_at")
        pend = r.exists("test_now")
        def parse(hashname):
            out = {}
            for k, v in (r.hgetall(hashname) or {}).items():
                k = k.decode() if isinstance(k, bytes) else str(k)
                v = v.decode() if isinstance(v, bytes) else str(v)
                parts = v.split(" ", 1)
                try:
                    ms = float(parts[0])
                except ValueError:
                    ms = None
                out[k] = {"ms": ms, "ip": parts[1].strip() if len(parts) > 1 else ""}
            return out
        res["test"] = {"round_at": (float(at) if at else None),
                       "pending_now": bool(pend), "caps": caps,
                       "v4": parse("test_v4"), "v6": parse("test_v6")}
    except Exception as e:
        res["test"] = {"error": str(e), "caps": caps}
    return res




# ---------------------------------------------------------------------------
# mtr per-line path test (SO_MARK via markexec LD_PRELOAD; async jobs)
# ---------------------------------------------------------------------------
import itertools

MTR_BIN = None
MARKSO = os.path.join(module_dir, "markexec.so")
MARKSRC = os.path.join(module_dir, "markexec.c")
mtr_jobs = {}
mtr_seq = itertools.count(1)
mtr_running = [0]
MTR_LOCK = threading.Lock()
TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,253}$")


def mtr_find_bin():
    global MTR_BIN
    if MTR_BIN is None:
        MTR_BIN = shutil.which("mtr") or "/usr/sbin/mtr"
    return MTR_BIN


def ensure_markso():
    """delegate to proxy_mgr shared builder (single source of truth)"""
    if pmm is not None and hasattr(pmm, "ensure_markso"):
        return pmm.ensure_markso()
    if os.path.exists(MARKSO) and os.path.getmtime(MARKSO) >= os.path.getmtime(MARKSRC):
        return MARKSO, None
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        return None, "no cc/gcc to build markexec.so"
    try:
        p = subprocess.run([cc, "-shared", "-fPIC", "-O2", "-o", MARKSO, MARKSRC],
                           capture_output=True, timeout=20, text=True)
        if p.returncode != 0:
            return None, "compile failed: " + p.stderr[-200:]
        return MARKSO, None
    except Exception as e:
        return None, str(e)


def mtr_line_marks(cfg):
    """candidate lines -> mark: proxy lines + egress bindings (deduped)."""
    out = {}
    for name, c in cfg.get("proxy", {}).items():
        m = c.get("mark")
        if isinstance(m, int) and m > 0 and m not in (0x99, 0x100):
            out["line:" + name] = {"mark": m, "name": name,
                                   "kind": "proxy" + (" (managed)" if c.get("daemon") else ""),
                                   "via": c.get("server") or c.get("proxy_ip") or ""}
    for b in cfg.get("egress_marks", []):
        if isinstance(b.get("mark"), int):
            key = "egress:" + (b.get("iface") or b.get("ip", ""))
            out.setdefault(key, {"mark": b["mark"], "name": b.get("iface") or b.get("ip"),
                                 "kind": "egress", "via": b.get("ip") or "(dynamic)"})
    return out


def _mtr_parse(text):
    hops = []
    for ln in text.splitlines():
        if ".|--" not in ln:
            continue
        idx, _, rest = ln.partition(".|--")
        toks = rest.split()
        if len(toks) < 5:
            continue
        nums = toks[-7:] if len(toks) > 1 else toks
        host = " ".join(toks[:len(toks) - len(nums)]) or "?"
        hops.append({"hop": idx.strip(), "host": host, "loss": nums[0], "snt": nums[1],
                     "last": nums[2], "avg": nums[3], "best": nums[4], "wrst": nums[5],
                     "stdev": nums[6] if len(nums) > 6 else ""})
    return hops


def _num(tok):
    try:
        return float(str(tok).rstrip("%"))
    except (ValueError, TypeError):
        return 0.0


def _agg_merge(agg, hops):
    """merge one pass hop-list into cumulative agg {hop: {...}}"""
    for h in hops:
        a = agg.setdefault(h["hop"], {"host": h["host"], "snt": 0, "lost": 0.0,
                                      "best": 1e9, "wrst": 0.0, "avgw": 0.0, "last": h["last"]})
        if h["host"] and h["host"] != "???":
            a["host"] = h["host"]
        snt = _num(h["snt"])
        loss = _num(h["loss"])
        a["snt"] += snt
        a["lost"] += snt * loss / 100.0
        last, avg, best, wrst = _num(h["last"]), _num(h["avg"]), _num(h["best"]), _num(h["wrst"])
        a["avgw"] += avg * snt
        if 0 < best < a["best"]:
            a["best"] = best
        if wrst > a["wrst"]:
            a["wrst"] = wrst
        a["last"] = last


def _agg_rows(agg):
    def key(h):
        try:
            return int(h)
        except ValueError:
            return 999
    rows = []
    for hop in sorted(agg, key=key):
        a = agg[hop]
        snt = a["snt"] or 1
        rows.append({"hop": hop, "host": a["host"],
                     "loss": "%.1f%%" % (100.0 * a["lost"] / snt),
                     "snt": "%d" % snt, "last": "%.1f" % a["last"],
                     "avg": "%.1f" % (a["avgw"] / snt),
                     "best": ("%.1f" % a["best"]) if a["best"] < 1e9 else "0.0",
                     "wrst": "%.1f" % a["wrst"], "stdev": ""})
    return rows


def _mtr_broadcast(obj):
    raw = json.dumps(obj).encode("utf-8")
    _MTR_HUB.broadcast(raw)


_MTR_HUB = Hub()


def mtr_job_run(jid, base_argv, env, hard_to, total_passes):
    j = mtr_jobs[jid]
    agg = {}
    raw_last = ""
    t0 = time.time()
    try:
        for k in range(1, total_passes + 1):
            argv = base_argv + ["--report-cycles", "1"]
            try:
                p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env=env, timeout=hard_to)
                text = p.stdout.decode("utf-8", "replace")
            except subprocess.TimeoutExpired:
                text = "[pass %d timeout]" % k
            except Exception as e:
                text = "[pass %d error: %s]" % (k, e)
            raw_last = text
            hops = _mtr_parse(text)
            _agg_merge(agg, hops)
            rows = _agg_rows(agg)
            j.update({"status": "running", "pass": k, "total": total_passes,
                      "hops": rows, "raw": raw_last,
                      "ms": int((time.time() - t0) * 1000)})
            _mtr_broadcast({"t": "mtr", "id": jid, "status": "running", "pass": k,
                            "total": total_passes, "hops": rows,
                            "ms": j["ms"], "target": j["target"], "line": j["line"],
                            "mark": j["mark"]})
        j.update({"status": "done", "rc": 0,
                  "ms": int((time.time() - t0) * 1000)})
    except Exception as e:
        j.update({"status": "error", "error": str(e)})
    finally:
        with MTR_LOCK:
            mtr_running[0] -= 1
        _mtr_broadcast({"t": "mtr", "id": jid, "status": j["status"],
                        "pass": j.get("pass", 0), "total": total_passes,
                        "hops": j.get("hops", []), "ms": j.get("ms"),
                        "target": j["target"], "line": j["line"], "mark": j["mark"]})


def mtr_start(body, cfg):
    tgt = str(body.get("target", "")).strip().strip("[]")
    if not tgt or tgt.startswith("-") or not TARGET_RE.match(tgt):
        return {"ok": False, "error": "非法目标地址/域名"}
    line = str(body.get("line", ""))
    cycles = min(50, max(1, int(body.get("cycles", 10))))
    maxttl = min(30, max(2, int(body.get("max_ttl", 18))))
    interval = min(2.0, max(0.1, float(body.get("interval", 0.2))))
    lines = mtr_line_marks(cfg)
    mark = 0
    if line and line != "default":
        if line not in lines:
            return {"ok": False, "error": "未知线路 %r" % line}
        mark = lines[line]["mark"]
    binm = mtr_find_bin()
    env = dict(os.environ)
    argv = [binm, "-n", "-r", "-m", str(maxttl), "-i", str(interval), "-G", "2", tgt]
    fam = str(body.get("family", "auto"))
    if fam == "4":
        argv.insert(1, "-4")
    elif fam == "6":
        argv.insert(1, "-6")
    elif ":" in tgt:
        argv.insert(1, "-6")
    if mark:
        so, err = ensure_markso()
        if not so:
            return {"ok": False, "error": "markexec.so: %s (线路测试需要它; default线路不受影响)" % err}
        env["LD_PRELOAD"] = so
        env["MARK"] = str(mark)
    with MTR_LOCK:
        if mtr_running[0] >= 2:
            return {"ok": False, "error": "并发MTR已满(2),稍后再试"}
        mtr_running[0] += 1
        jid = str(next(mtr_seq))
        mtr_jobs[jid] = {"id": jid, "status": "running", "target": tgt, "line": line or "default",
                         "mark": mark, "cycles": cycles, "started": time.time()}
        if len(mtr_jobs) > 50:
            for k in sorted(mtr_jobs, key=lambda x: mtr_jobs[x]["started"])[:len(mtr_jobs) - 50]:
                if mtr_jobs[k]["status"] != "running":
                    del mtr_jobs[k]
    hard_to = maxttl * (interval + 3) + 10
    threading.Thread(target=mtr_job_run,
                     args=(jid, argv, env, hard_to, cycles), daemon=True).start()
    return {"ok": True, "id": jid}



# ---------------------------------------------------------------------------
# network tools (网络工具 tab): ping (live via WS) / dig / whois / ip query
# ---------------------------------------------------------------------------
ping_jobs = {}
ping_seq = itertools.count(1)
PING_LOCK = threading.Lock()
ping_running = [0]
DIG_TYPES = ("A", "AAAA", "MX", "TXT", "CNAME", "NS", "PTR", "SOA", "SRV")


def _tool_env(cfg, line):
    """line key ('default' or mtr_line_marks key) -> (env, mark, err):
    SO_MARK via markexec exactly like mtr/test_line, so every tool answers
    'through this line', not just from this host."""
    env = dict(os.environ)
    mark = 0
    line = str(line or "")
    if line and line != "default":
        lines = mtr_line_marks(cfg)
        if line not in lines:
            return None, 0, "未知线路 %r" % line
        mark = lines[line]["mark"]
    if mark:
        so, err = ensure_markso()
        if not so:
            return None, mark, "markexec.so: %s" % err
        env["LD_PRELOAD"] = so
        env["MARK"] = str(mark)
    return env, mark, None


def _tool_target(body, field="target"):
    tgt = str(body.get(field, "")).strip().strip("[]")
    if not tgt or tgt.startswith("-") or not TARGET_RE.match(tgt):
        return None, "非法目标地址/域名"
    return tgt, None


def ping_start(body, cfg):
    tgt, err = _tool_target(body)
    if err:
        return {"ok": False, "error": err}
    env, mark, err = _tool_env(cfg, body.get("line"))
    if err:
        return {"ok": False, "error": err}
    try:
        count = min(200, max(1, int(body.get("count", 20))))
        interval = min(5.0, max(0.2, float(body.get("interval", 1))))
        size = min(65000, max(1, int(body.get("size", 56))))
    except (TypeError, ValueError):
        return {"ok": False, "error": "count/interval/size 需为数字"}
    argv = ["ping", "-n", "-c", str(count), "-i", str(interval), "-s", str(size), "-W", "2"]
    fam = str(body.get("family", "auto"))
    if fam == "4":
        argv.append("-4")
    elif fam == "6":
        argv.append("-6")
    elif ":" in tgt:
        argv.append("-6")
    argv.append(tgt)
    with PING_LOCK:
        if ping_running[0] >= 4:
            return {"ok": False, "error": "并发 ping 已满(4)，稍后再试"}
        ping_running[0] += 1
        jid = str(next(ping_seq))
        ping_jobs[jid] = {"id": jid, "status": "running", "target": tgt,
                          "line": str(body.get("line") or "default"), "mark": mark,
                          "count": count, "started": time.time(), "out": []}
        if len(ping_jobs) > 40:
            for k in sorted(ping_jobs, key=lambda x: ping_jobs[x]["started"])[:len(ping_jobs) - 40]:
                if ping_jobs[k]["status"] != "running":
                    del ping_jobs[k]
    threading.Thread(target=ping_job_run, args=(jid, argv, env, count, interval),
                     daemon=True).start()
    return {"ok": True, "id": jid}


def ping_job_run(jid, argv, env, count, interval):
    j = ping_jobs[jid]
    t0 = time.time()
    buf = []
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env=env, text=True, bufsize=1)
        deadline = t0 + count * (interval + 3) + 30
        for ln in iter(p.stdout.readline, ""):
            ln = ln.rstrip()
            buf.append(ln)
            if len(buf) > 400:
                del buf[:len(buf) - 400]
            j["out"] = list(buf)
            _mtr_broadcast({"t": "ping", "id": jid, "line": ln})
            if time.time() > deadline:
                p.kill()
                break
        try:
            rc = p.wait(timeout=5)
        except Exception:
            p.kill()
            rc = -9
        j.update({"status": "done", "rc": rc, "ms": int((time.time() - t0) * 1000)})
    except Exception as e:
        j.update({"status": "error", "error": str(e)})
    finally:
        try:
            p.stdout.close()
        except Exception:
            pass
        with PING_LOCK:
            ping_running[0] -= 1
        _mtr_broadcast({"t": "ping", "id": jid, "status": j["status"],
                        "ms": j.get("ms"), "error": j.get("error")})


def dig_run(body, cfg):
    q, err = _tool_target(body)
    if err:
        return {"ok": False, "error": err}
    typ = str(body.get("type", "A")).upper().strip()
    if typ not in DIG_TYPES:
        return {"ok": False, "error": "type 需为 " + "/".join(DIG_TYPES)}
    env, mark, err = _tool_env(cfg, body.get("line"))
    if err:
        return {"ok": False, "error": err}
    args = ["dig", "+time=2", "+tries=1", "+noall", "+comments", "+answer", "+stats"]
    fam = str(body.get("family", "auto"))
    if fam == "4":
        args.append("-4")
    elif fam == "6":
        args.append("-6")
    srv = str(body.get("server", "")).strip()
    if srv:
        if srv.startswith("-") or not TARGET_RE.match(srv):
            return {"ok": False, "error": "非法 DNS 服务器"}
        args.append("@%s" % srv)
    args += [q, typ]
    t0 = time.time()
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=10, env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "dig 超时"}
    except OSError as e:
        return {"ok": False, "error": "dig 不可用: %s" % e}
    return {"ok": r.returncode == 0, "rc": r.returncode, "ms": round((time.time() - t0) * 1000, 1),
            "mark": mark, "out": (r.stdout or "")[:8000], "err": (r.stderr or "")[:600]}


def whois_run(body):
    tgt, err = _tool_target(body)
    if err:
        return {"ok": False, "error": err}
    binw = shutil.which("whois")
    if not binw:
        return {"ok": False, "error": "whois 未安装（apt install whois）"}
    try:
        r = subprocess.run([binw, tgt], capture_output=True, text=True, timeout=25)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "whois 查询超时(25s)"}
    except OSError as e:
        return {"ok": False, "error": "whois 失败: %s" % e}
    return {"ok": r.returncode == 0, "rc": r.returncode,
            "out": ((r.stdout or "") + (("\n" + r.stderr) if r.stderr else ""))[:65536]}


def ipq_run(body, cfg, cfg_path):
    env, mark, err = _tool_env(cfg, body.get("line"))
    if err:
        return {"ok": False, "error": err}
    raw = str(body.get("ips", "")).replace(",", " ").split()
    ips = []
    for x in raw:
        try:
            ipaddress.ip_address(x)
        except ValueError:
            continue
        if x not in ips:
            ips.append(x)
        if len(ips) >= 16:
            break
    if not ips:
        return {"ok": False, "error": "没有合法 IP（最多 16 个）"}
    g = geo_lookup(cfg_path, ips)
    rows = []
    for ip in ips:
        route = ""
        try:
            args = ["route", "get", ip]
            if mark:
                args += ["mark", str(mark)]
            rc, out = _ip(args, timeout=5)
            route = (out or "").strip().splitlines()[0][:200] if (out or "").strip() else ("rc=%d" % rc)
        except Exception as e:
            route = "ip route get 失败: %s" % e
        rows.append({"ip": ip, "route": route})
    return {"ok": True, "mark": mark, "rows": rows, "geo": (g or {}).get("geo") or {}}


# ---------------------------------------------------------------------------
# bandwidth history (带宽趋势): /proc/net/dev every 5s -> 15 min ring buffer
# ---------------------------------------------------------------------------
BW_INT = 5
BW_SPAN = 900
bw_hist = []
bw_prev = {}
bw_lock = threading.Lock()
_bw_thread = [None]


def bw_snap():
    out = {}
    try:
        with open("/proc/net/dev") as f:
            for ln in f:
                if ":" not in ln:
                    continue
                name, _, rest = ln.partition(":")
                f2 = rest.split()
                if len(f2) >= 16:
                    try:
                        out[name.strip()] = (int(f2[0]), int(f2[8]))
                    except ValueError:
                        pass
    except OSError:
        pass
    return out


def bw_loop():
    global bw_prev
    bw_prev = bw_snap()
    t_prev = time.time()
    while True:
        time.sleep(BW_INT)
        now = bw_snap()
        t_now = time.time()
        dt = max(0.5, t_now - t_prev)
        rates = {}
        for k, (r, t) in now.items():
            pt = bw_prev.get(k)
            if not pt:
                continue
            rx = (r - pt[0]) % (2 ** 64)   # counter wrap safe
            tx = (t - pt[1]) % (2 ** 64)
            rates[k] = [int(rx / dt), int(tx / dt)]
        bw_prev = now
        t_prev = t_now
        with bw_lock:
            bw_hist.append([round(t_now, 1), rates])
            cut = t_now - BW_SPAN
            while bw_hist and bw_hist[0][0] < cut:
                bw_hist.pop(0)
        try:
            _mtr_broadcast(json.dumps({"t": "bw", "ts": round(t_now, 1), "r": rates}).encode())
        except Exception:
            pass


def bw_start():
    if _bw_thread[0] is None:
        _bw_thread[0] = threading.Thread(target=bw_loop, daemon=True, name="bwsamp")
        _bw_thread[0].start()


def bw_json():
    with bw_lock:
        samples = [[ts, dict(r)] for ts, r in bw_hist]
    peak = {}
    for _, r in samples:
        for k, (rx, tx) in r.items():
            a = peak.setdefault(k, [0, 0])
            a[0] = max(a[0], rx)
            a[1] = max(a[1], tx)
    return {"ok": True, "interval": BW_INT, "span": BW_SPAN, "now": time.time(),
            "samples": samples,
            "peak": [{"iface": k, "rx": v[0], "tx": v[1]} for k, v in
                     sorted(peak.items(), key=lambda x: -(x[1][0] + x[1][1]))]}


# ---------------------------------------------------------------------------
# on-demand iftop (IP流量): started by click, each screen broadcast over the
# shared /ws/stream socket (t=iftop frames). Auto-stop: page sends stop via
# button/pagehide/sendBeacon; backstop watchdog kills the session when the WS
# has no subscribers AND no status heartbeat for >25s (webadmin restart also).
# ---------------------------------------------------------------------------
ift_lock = threading.Lock()
ift_sess = [None]
ift_seq = itertools.count(1)


def ift_recommended():
    for x in ift_ifaces():
        if x == "br0":
            return x
    for x in ift_ifaces():
        if os.path.isdir("/sys/class/net/%s/brif" % x):
            return x
    for x in ift_ifaces():
        if x.startswith("bond0") and "." not in x:
            return x
    return "any"


def ift_ifaces():
    try:
        return sorted(x for x in os.listdir("/sys/class/net") if x != "lo")
    except OSError:
        return []


def _ift_num(x):
    m = re.match(r"^([\d.]+)([KMG]?)b$", x)
    if not m:
        return 0
    return int(float(m.group(1)) * {"": 1, "K": 1e3, "M": 1e6, "G": 1e9}[m.group(2)])


def _ift_host(h):
    h = h.strip()
    m = re.match(r"^\[([^\]]+)\](?::\d+)?$", h)
    if m:
        return m.group(1)
    m = re.match(r"^(.*):(\d+)$", h)
    if m:
        return m.group(1)
    return h


def iftop_parse(text):
    """parse 'iftop -n -t' screen dumps (real format, two lines per pair):
        1 183.95.60.178            =>   50.0Kb  25.0Kb  25.0Kb  12.5KB
          192.168.32.2             <=   53.8Kb  26.9Kb  26.9Kb  13.4KB
    host before the arrow is the SENDER of that row's rates
    (=> row: a->b ; <= row: b->a).  last screen wins (reader keeps the tail)."""
    out = {}
    pending = None
    for ln in text.splitlines():
        m = re.match(r"^\s*(?:\d+\s+)?(\S+)\s+(=>|<=)\s+"
                     r"([\d.]+[KMG]?b)\s+([\d.]+[KMG]?b)\s+([\d.]+[KMG]?b)"
                     r"\s*(?:[\d.]+[KMG]?B)?\s*$", ln)
        if not m:
            if ("----" in ln or ln.startswith("Total") or ln.startswith("Peak")
                    or ln.startswith("Cumulative")):
                pending = None
            continue
        host, arr = m.group(1), m.group(2)
        rates = [_ift_num(m.group(i)) for i in (3, 4, 5)]
        if arr == "=>":
            pending = (host, rates)
        elif arr == "<=" and pending:
            a, ab = pending
            pending = None
            if ":" in host and "]" not in host and host.count(":") > 1:
                a, host = host, a          # ipv6 no-brackets swap guard
            out[(a, host)] = {"a": a, "b": host, "ab": ab, "ba": rates}
    return list(out.values())


def ift_frame(s):
    pairs = s.get("pairs") or []
    agg = {}
    for pt in pairs:
        a = _ift_host(pt["a"])
        b = _ift_host(pt["b"])
        ia = agg.setdefault(a, {"ip": a, "out": [0, 0, 0], "in": [0, 0, 0]})
        ib = agg.setdefault(b, {"ip": b, "out": [0, 0, 0], "in": [0, 0, 0]})
        ab = pt.get("ab") or [0, 0, 0]
        ba = pt.get("ba") or [0, 0, 0]
        for i in range(3):
            ia["out"][i] += ab[i]
            ia["in"][i] += ba[i]
            ib["out"][i] += ba[i]
            ib["in"][i] += ab[i]
    ips = sorted(agg.values(), key=lambda x: -(x["in"][0] + x["out"][0]))
    return {"t": "iftop", "status": s["status"], "iface": s["iface"],
            "id": s["id"], "age": round(time.time() - s["screen_ts"], 1),
            "reason": s.get("stop_reason"),
            "ips": ips[:60],
            "pairs": [{"a": pt["a"], "b": pt["b"], "ab": pt.get("ab") or [0, 0, 0],
                       "ba": pt.get("ba") or [0, 0, 0]} for pt in pairs[:80]]}


def _ift_kill(sess):
    try:
        sess["proc"].terminate()
        try:
            sess["proc"].wait(timeout=3)
        except Exception:
            sess["proc"].kill()
    except Exception:
        pass


def ift_stop(reason="stopped"):
    with ift_lock:
        sess = ift_sess[0]
        ift_sess[0] = None
    if not sess:
        return {"ok": True, "note": "未在运行"}
    sess["status"] = "stopped"
    sess["stop_reason"] = reason
    _ift_kill(sess)
    try:
        _mtr_broadcast(ift_frame(sess))
    except Exception:
        pass
    return {"ok": True, "stopped": True, "ran": round(time.time() - sess["started"], 1)}


def ift_reader(sess):
    p = sess["proc"]
    buf = []
    try:
        for ln in iter(p.stdout.readline, ""):
            buf.append(ln)
            if len(buf) > 300:
                del buf[:len(buf) - 300]
            sess["buf"] = list(buf)
    except Exception:
        pass


def ift_ticker(sess):
    while True:
        time.sleep(2)
        if ift_sess[0] is not sess:
            break
        rc = sess["proc"].poll()
        if rc is not None:
            sess["status"] = "exited"
            sess["stop_reason"] = "iftop 退出 rc=%s" % rc
            with ift_lock:
                if ift_sess[0] is sess:
                    ift_sess[0] = None
            try:
                _mtr_broadcast(ift_frame(sess))
            except Exception:
                pass
            break
        sess["pairs"] = iftop_parse("".join(sess.get("buf") or []))
        if sess["pairs"]:
            sess["screen_ts"] = time.time()
        if time.time() - sess["hb"] > 25 and _MTR_HUB.count() == 0:
            ift_stop("页面已关闭 (无心跳/无WS连接)")
            break
        try:
            _mtr_broadcast(ift_frame(sess))
        except Exception:
            pass


def ift_start(body):
    iface = str(body.get("iface", "")).strip() or "any"
    if iface != "any":
        parts = [x for x in re.split(r"[,\s]+", iface) if x]
        if not parts:
            return {"ok": False, "error": "接口为空"}
        avail = set(ift_ifaces())
        for x in parts:
            if not re.match(r"^[A-Za-z0-9._:\-]{1,32}$", x):
                return {"ok": False, "error": "非法接口名 %r" % x}
            if x not in avail:
                return {"ok": False, "error": "未知接口 %r" % x}
        iface = ",".join(parts)
    binw = shutil.which("iftop")
    if not binw:
        return {"ok": False, "error": "iftop 未安装（apt install iftop）"}
    ift_stop("replaced")
    argv = [binw, "-n", "-t", "-s", "86400"]
    if iface != "any":
        argv += ["-i", iface]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except OSError as e:
        return {"ok": False, "error": "iftop 启动失败: %s" % e}
    sess = {"id": next(ift_seq), "proc": proc, "iface": iface, "status": "running",
            "started": time.time(), "screen_ts": time.time(), "hb": time.time(),
            "pairs": [], "buf": []}
    with ift_lock:
        ift_sess[0] = sess
    threading.Thread(target=ift_reader, args=(sess,), daemon=True).start()
    threading.Thread(target=ift_ticker, args=(sess,), daemon=True).start()
    return {"ok": True, "id": sess["id"], "iface": iface}


# ---------------------------------------------------------------------------
# geoip (SAME ipdb library + database as the router policy engine)
# ---------------------------------------------------------------------------
_geo = {"db": None, "tried": False, "error": None}


def geo_db(cfg_path):
    if _geo["db"] is not None or _geo["tried"]:
        return _geo["db"]
    _geo["tried"] = True
    try:
        import ipdb
        cfg = ib.load_config(cfg_path)
        path = cfg.get("ipdb_v4")
        if not path or not os.path.exists(path):
            _geo["error"] = "ipdb file not found"
            return None
        _geo["db"] = ipdb.City(path)
    except Exception as e:
        _geo["error"] = str(e)
        return None
    return _geo["db"]


def geo_lookup(cfg_path, ips):
    db = geo_db(cfg_path)
    out = {}
    if db is None:
        return {"ok": False, "error": _geo["error"] or "ipdb unavailable", "geo": {}}
    for ip in ips[:200]:
        try:
            g = db.find_map(ip, "CN")
        except Exception:
            g = None
        if not g:
            out[ip] = None
            continue
        out[ip] = {"cc": g.get("country_code") or "", "cn": g.get("country_name") or "",
                   "rg": g.get("region_name") or "", "ct": g.get("city_name") or "",
                   "isp": g.get("isp_domain") or "",
                   "ac": 1 if g.get("anycast") == "ANYCAST" else 0,
                   "idc": 1 if g.get("idc") == "IDC" else 0}
    return {"ok": True, "geo": out}



# ---------------------------------------------------------------------------
# routing tables viewer / editor (iproute2 via argv, strict validation)
# ---------------------------------------------------------------------------
RT_TABLE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")
RT_DEV_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,15}$")
RT_TYPE_WORDS = {"default", "unreachable", "prohibit", "blackhole", "nat", "throw"}
RT_KNOWN_KEYS = {"via", "dev", "src", "scope", "proto", "metric", "table", "mtu",
                 "advmss", "onlink", "weight", "pref", "expires", "linkdown", "error"}


def _ip(args, timeout=8):
    p = subprocess.run(["ip"] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout, text=True)
    return p.returncode, p.stdout


def rt_parse_line(line):
    toks = line.split()
    if not toks:
        return None
    out = {"raw": line, "type": "", "dst": "", "opts": {}, "bare": []}
    i = 0
    if toks[0] in RT_TYPE_WORDS:
        if toks[0] == "default":
            out["dst"] = "default"
            i = 1
        else:
            out["type"] = toks[0]
            out["dst"] = toks[1] if len(toks) > 1 else ""
            i = 2
    else:
        out["dst"] = toks[0]
        i = 1
    while i < len(toks):
        tk = toks[i]
        if tk in RT_KNOWN_KEYS and i + 1 < len(toks) and toks[i + 1] not in RT_KNOWN_KEYS:
            out["opts"][tk] = toks[i + 1]
            i += 2
        elif tk in RT_KNOWN_KEYS:
            out["opts"][tk] = True
            i += 1
        else:
            out["bare"].append(tk)
            i += 1
    return out


def rt_tables_list():
    """named + numeric tables seen in rt_tables / ip rule / routes."""
    tables = []
    try:
        for ln in open("/etc/iproute2/rt_tables"):
            ln = ln.split("#")[0].strip()
            if not ln:
                continue
            parts = ln.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                tables.append({"id": int(parts[0]), "name": parts[1].strip(), "src": "rt_tables"})
    except OSError:
        pass
    rc, out = _ip(["-o", "rule", "show"])
    rules = []
    if rc == 0:
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            m = re.match(r"^(\d+):\s+(.*)$", ln)
            if not m:
                continue
            prio, sel = int(m.group(1)), m.group(2)
            tm = re.search(r"lookup\s+(\S+)", sel) or re.search(r"table\s+(\S+)", sel)
            rules.append({"prio": prio, "sel": sel, "table": tm.group(1) if tm else ""})
            if tm and tm.group(1).isdigit() and not any(t["name"] == tm.group(1) for t in tables):
                tables.append({"id": int(tm.group(1)), "name": tm.group(1), "src": "rule"})
    return {"tables": tables, "rules": rules}


def rt_show(table):
    fam4 = _ip(["-o", "-4", "route", "show", "table", table])
    fam6 = _ip(["-o", "-6", "route", "show", "table", table])
    lines = []
    for rc, out in (fam4, fam6):
        if rc != 0:
            continue
        for ln in out.splitlines():
            r = rt_parse_line(ln.strip())
            if r:
                r["family"] = 6 if ":" in r["dst"] else 4
                lines.append(r)
    err = None
    if fam4[0] != 0 and fam6[0] != 0:
        err = (fam4[1] or fam6[1]).strip()[:200]
    return {"ok": err is None, "count": len(lines), "lines": lines, "error": err}


def rt_edit(body):
    op = str(body.get("op", "replace"))
    table = str(body.get("table", "")).strip()
    dst = str(body.get("dst", "")).strip()
    if not RT_TABLE_RE.match(table):
        return {"ok": False, "error": "非法表名"}
    if table == "local":
        return {"ok": False, "error": "local 表禁止编辑"}
    if op not in ("replace", "del") or not dst:
        return {"ok": False, "error": "op/dst 参数"}
    if dst != "default":
        try:
            net = ipaddress.ip_network(dst, strict=False)
            fam = ["-6"] if net.version == 6 else ["-4"]
        except ValueError:
            return {"ok": False, "error": "目标必须是 CIDR/IP/default，收到: %s" % dst}
    else:
        fam = ["-4"] if not (":" in str(body.get("via", ""))) else ["-6"]
    args = fam + ["route", "replace" if op == "replace" else "del", dst, "table", table]
    if op == "replace":
        for key in ("via", "dev", "src", "scope", "proto", "mtu", "advmss", "weight", "pref"):
            v = body.get(key)
            if v in (None, "", False):
                continue
            v = str(v).strip()
            if key in ("via", "src"):
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    return {"ok": False, "error": "%s 不是合法IP" % key}
            elif key == "dev":
                if not RT_DEV_RE.match(v):
                    return {"ok": False, "error": "非法设备名"}
            elif key in ("scope", "proto", "pref"):
                if not re.match(r"^[A-Za-z0-9._\-]{1,16}$", v):
                    return {"ok": False, "error": "%s 非法" % key}
            else:
                if not v.isdigit():
                    return {"ok": False, "error": "%s 需为数字" % key}
            args += [key, v]
        if body.get("onlink"):
            args.append("onlink")
    try:
        rc, out = _ip(args, timeout=10)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "ip命令超时"}
    return {"ok": rc == 0, "rc": rc, "cmd": " ".join(["ip"] + args), "out": out.strip()[:400]}




# ---------------------------------------------------------------------------
# single-line manual test (TCP/UDP), same SO_MARK routing as TestThread probes
# ---------------------------------------------------------------------------
def test_line(cfg_path, name, proto="tcp", family=4, target=None):
    cfg = ib.load_config(cfg_path)
    p = (cfg.get("proxy") or {}).get(name)
    if p is None:
        return {"ok": False, "error": "未知线路 %s" % name}
    if proto not in ("tcp", "udp"):
        proto = "tcp"
    family = int(family)
    out = {"line": name, "proto": proto, "family": family,
           "mark": p.get("mark"), "steps": []}
    env, err = pmm.probe_env(p.get("mark")) if pmm else (dict(os.environ), "proxy_mgr unavailable")
    if err:
        out["mark_err"] = err
    try:
        netloc = urlparse(p.get("test_url", "")).netloc if p.get("test_url") else ""
    except ValueError:
        netloc = ""
    qname = target or netloc or "example.com"
    dns_servers = []
    if p.get("test_dns"):
        dns_servers = [p["test_dns"]] if isinstance(p["test_dns"], str) else list(p["test_dns"])
    rtype = "AAAA" if family == 6 else "A"
    ips = []
    if not dns_servers:
        dns_servers = [None]   # system resolver; honest label so the note is visible
    for srv in dns_servers[:3]:
        args = ["dig", "+time=2", "+tries=1", "+short"]
        if family == 6 and srv and ":" in srv:
            args.append("-6")          # v6 server reachable only via v6 transport
        elif family == 4:
            args.append("-4")
        if proto == "tcp":
            args.append("+tcp")
        if srv:
            args.append("@%s" % srv)
        args += [qname, rtype]
        t0 = time.time()
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=8, env=env)
            got = [x for x in r.stdout.split()
                   if _isver(x, family)]
        except (subprocess.TimeoutExpired, OSError):
            got = []
        ms = round((time.time() - t0) * 1000, 1)
        out["steps"].append({"name": "dig %s %s%s" % (rtype, ("@" + srv) if srv else "(系统DNS,不验证线路解析)", proto.upper()),
                             "ok": bool(got), "ms": ms, "out": " ".join(got)[:80]})
        if got:
            ips = got
            break
    final_ok = bool(ips)
    final_ms = out["steps"][-1]["ms"] if out["steps"] else None
    if proto == "tcp" and p.get("test_url") and ips:
        parse_path = urlparse(p["test_url"])
        hport = 443 if parse_path.scheme == "https" else 80
        probe_ip = ips[0]
        curl = ["curl", "-%d" % family, "-s", "-k", "-m", "3", "-o", "/dev/null"]
        if p.get("port"):
            curl += ["--resolve", "%s:%d:%s" % (netloc, hport, probe_ip), p["test_url"]]
        else:
            xp = probe_ip if family == 4 else "[%s]" % probe_ip
            curl += ["-x", "%s:%d" % (xp, hport), p["test_url"]]
        curl += ["-w", "%{time_total} %{http_code}"]
        t0 = time.time()
        try:
            r = subprocess.run(curl, capture_output=True, text=True, timeout=8, env=env)
            parts = (r.stdout or "").split()
            code_, t_ = (parts[-1], parts[-2]) if len(parts) >= 2 else ("000", "0")
        except (subprocess.TimeoutExpired, OSError):
            code_, t_ = "000", "0"
        cok = code_ in ("200", "204", "301", "302")
        final_ok = cok
        try:
            final_ms = round(float(t_) * 1000, 1)
        except ValueError:
            final_ms = round((time.time() - t0) * 1000, 1)
        out["steps"].append({"name": "curl -%d %s %s" % (family, ("--resolve" if p.get("port") else "-x"), code_),
                             "ok": cok, "ms": final_ms})
    out["ok"] = final_ok
    # mirror into redis so the status table reflects the manual test too
    try:
        rr = redis.Redis(host="127.0.0.1", port=6379, db=1, socket_timeout=2, socket_connect_timeout=2)
        if final_ok:
            rr.hset("test_v%d" % family, name, "%.3f %s" % ((final_ms or 0) / 1000.0, ips[0] if ips else ""))
        else:
            rr.hset("test_v%d" % family, name, "-1 manual %s" % proto)
        rr.set("test_at", "%.3f" % time.time())
    except Exception:
        pass
    return out


def _isver(ip, family):
    try:
        return ipaddress.ip_address(ip).version == family
    except ValueError:
        return False

# ---------------------------------------------------------------------------
# HTTP + WS handler
# ---------------------------------------------------------------------------

class App:
    def __init__(self, args):
        self.args = args
        self.ring = RingBuffer(args.ring_max)
        self.hub = Hub()
        self.streamer = Streamer(self.ring, self.hub, args.redis_host, args.redis_port, args.redis_db)
        self.started = time.time()
        self.last_reload = None   # ts of last explicit /api/reload from this UI


_ui_cache = {"mtimes": {}, "html": None, "ver": None}


def _load_ui():
    """hot reload of webui.py + everything it assembles from webui_parts/
    (mtimes tracked for the FULL file set webui.py itself reported last
    time, so editing any fragment -- not just webui.py -- takes effect
    without restarting this child), plus a per-read UI_VERSION gate."""
    path = os.path.join(module_dir, "webui.py")
    watch = _ui_cache["mtimes"] or {path: None}
    changed = False
    for p, prev in watch.items():
        try:
            cur = os.stat(p).st_mtime
        except OSError:
            cur = None
        if cur != prev:
            changed = True
            break
    if not changed and _ui_cache["html"]:
        return _ui_cache["html"]
    # exec() does not auto-populate __file__ the way a normal import would;
    # webui.py needs it to locate webui_parts/ relative to itself.
    ns = {"__name__": "webui_hot", "__file__": path}
    try:
        exec(compile(open(path, encoding="utf-8").read(), path, "exec"), ns)
    except Exception:
        if _ui_cache["html"]:
            return _ui_cache["html"]
        raise
    src_files = list(ns.get("SOURCE_FILES") or [path])
    if path not in src_files:
        src_files.append(path)
    new_mtimes = {}
    for p in src_files:
        try:
            new_mtimes[p] = os.stat(p).st_mtime
        except OSError:
            new_mtimes[p] = None
    _ui_cache.update(mtimes=new_mtimes, html=ns["INDEX_HTML"], ver=ns.get("UI_VERSION"))
    return ns["INDEX_HTML"]


def current_ui_version():
    try:
        path = os.path.join(module_dir, "webui.py")
        src = open(path, encoding="utf-8").read(2048)
        m = re.search(r'^UI_VERSION\s*=\s*"([^"]+)"', src, re.M)
        return m.group(1) if m else None
    except OSError:
        return None


class Handler(BaseHTTPRequestHandler):
    app: App = None
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        pass

    # -- helpers ------------------------------------------------------------
    def send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 4 * 1024 * 1024:
            raise ValueError("body too large")
        raw = self.rfile.read(n) if n else b""
        return json.loads(raw.decode("utf-8")) if raw else {}

    def cfg_path(self):
        return self.app.args.config

    def pdns_cfg_path(self):
        return getattr(self.app.args, "pdns_config", None)

    def pdns_poison_path(self):
        return getattr(self.app.args, "pdns_poison_list", None)

    def pdns_host(self):
        return getattr(self.app.args, "pdns_host", None)

    def send_pdns_disabled(self):
        self.send_json(404, {"ok": False, "error": "PowerDNS 管理未启用: 启动 webadmin 时需加 --pdns-config <path>"})

    # -- routes -------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            body = _load_ui().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/ws/stream":
            self.handle_ws()
        elif path == "/api/config":
            try:
                st = os.stat(self.cfg_path())
                cfg = ib.load_config(self.cfg_path())
                self.send_json(200, {"path": self.cfg_path(), "mtime": st.st_mtime, "config": cfg})
            except Exception as e:
                self.send_json(500, {"error": str(e)})
        elif path == "/api/interfaces":
            try:
                cfg = ib.load_config(self.cfg_path())
                det = netinfo.detect()
                cands = ib.scan_candidates(det)
                ifs = {}
                for name, r in det.items():
                    ifs[name] = {"index": r["index"], "up": r["up"] and r["lower_up"],
                                 "master": r.get("master"), "methods": r["methods"],
                                 "addrs": ["%s/%d%s" % (a["addr"], a["prefixlen"], "" if a["version"] == 4 else " v6")
                                           for a in r["addrs"]]}
                cand_out = []
                for c in cands:
                    b = ib.find_binding(cfg, c)
                    cand_out.append(dict(c, bound=bool(b), mark=(b or {}).get("mark")))
                self.send_json(200, {"interfaces": ifs, "candidates": cand_out,
                                     "bindings": ib.get_bindings(cfg),
                                     "proxy_lines": {k: v.get("mark") for k, v in cfg.get("proxy", {}).items()}})
            except Exception as e:
                self.send_json(500, {"error": "%s" % e})
        elif path == "/api/mtr/lines":
            try:
                cfg = ib.load_config(self.cfg_path())
                self.send_json(200, {"ok": True, "mtr_bin": mtr_find_bin(),
                                     "lines": mtr_line_marks(cfg)})
            except Exception as e:
                self.send_json(500, {"ok": False, "error": str(e)})
        elif path.startswith("/api/mtr/job/"):
            jid = path.rsplit("/", 1)[-1]
            self.send_json(200 if jid in mtr_jobs else 404, mtr_jobs.get(jid, {"status": "gone"}))
        elif path == "/api/mtr/jobs":
            self.send_json(200, sorted(mtr_jobs.values(), key=lambda j: -j["started"])[:20])
        elif path.startswith("/api/ping/job/"):
            jid = path.rsplit("/", 1)[-1]
            self.send_json(200 if jid in ping_jobs else 404, ping_jobs.get(jid, {"status": "gone"}))
        elif path == "/api/ping/jobs":
            self.send_json(200, sorted(ping_jobs.values(), key=lambda j: -j["started"])[:20])
        elif path == "/api/bw":
            self.send_json(200, bw_json())
        elif path == "/api/iftop/status":
            with ift_lock:
                sess = ift_sess[0]
            if sess:
                sess["hb"] = time.time()
                fr = ift_frame(sess)
                fr.update(running=True, ifaces=ift_ifaces(),
                          recommended=ift_recommended())
                self.send_json(200, fr)
            else:
                self.send_json(200, {"t": "iftop", "running": False, "status": "stopped",
                                     "ifaces": ift_ifaces(),
                                     "recommended": ift_recommended()})
        elif path == "/api/routes/tables":
            try:
                self.send_json(200, dict({"ok": True}, **rt_tables_list()))
            except Exception as e:
                self.send_json(500, {"ok": False, "error": str(e)})
        elif path == "/api/routes":
            q = parse_qs(urlparse(self.path).query)
            tbl = (q.get("table", ["main"])[0] or "main").strip()
            self.send_json(200, rt_show(tbl))
        elif path == "/api/geo":
            q = parse_qs(urlparse(self.path).query)
            ips = (q.get("ips", [""])[0] or "").replace(",", " ").split()
            self.send_json(200, geo_lookup(self.cfg_path(), ips))
        elif path == "/api/proxy_log":
            q = parse_qs(urlparse(self.path).query)
            try:
                tl = max(1024, min(200000, int(q.get("tail", ["16384"])[0])))
            except ValueError:
                tl = 16384
            self.send_json(200, proxy_log_tail(q.get("line", [""])[0], tl))
        elif path == "/api/health":
            try:
                self.send_json(200, health_snapshot(self.app))
            except Exception as e:
                self.send_json(500, {"error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/switches":
            try:
                cfg = ib.load_config(self.cfg_path())
                self.send_json(200, switch_status(self.app, cfg))
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/arp":
            self.send_json(200, arp_table(self.app))
        elif path == "/api/status":
            st = {}
            try:
                st["config_mtime"] = os.stat(self.cfg_path()).st_mtime
            except OSError:
                pass
            st["last_reload"] = self.app.last_reload
            st.update({"master": check_master(),
                       "redis_stream": self.app.streamer.alive,
                       "ws_clients": self.app.hub.count(),
                       "ring": len(self.app.ring), "ring_max": self.app.args.ring_max,
                       "uptime": round(time.time() - self.app.started),
                       "config_path": self.cfg_path()})
            self.send_json(200, st)
        elif path == "/api/pdns/config":
            if pa is None or not self.pdns_cfg_path():
                return self.send_pdns_disabled()
            try:
                host = self.pdns_host()
                cfg, mt = pa.load_config_with_mtime(self.pdns_cfg_path(), host=host)
                self.send_json(200, {"ok": True, "path": self.pdns_cfg_path(), "host": host,
                                     "mtime": mt, "config": cfg})
            except Exception as e:
                self.send_json(500, {"ok": False, "error": str(e)})
        elif path == "/api/pdns/poison":
            if pa is None or not self.pdns_poison_path():
                return self.send_pdns_disabled()
            try:
                p = self.pdns_poison_path()
                host = self.pdns_host()
                ips, mt = pa.load_poison_list_with_mtime(p, host=host)
                self.send_json(200, {"ok": True, "path": p, "host": host, "mtime": mt, "ips": ips})
            except Exception as e:
                self.send_json(500, {"ok": False, "error": str(e)})
        elif path == "/favicon.ico":
            self.send_json(404, {})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        try:
            self._do_POST()
        except Exception as e:
            try:
                self.send_json(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
            except Exception:
                self.close_connection = True

    def _do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self.read_body()
        except Exception as e:
            self.send_json(400, {"error": "bad request body: %s" % e})
            return
        if path == "/api/validate":
            cfg = body.get("config", body)
            self.send_json(200, {"ok": not validate_config(cfg), "errors": validate_config(cfg)})
        elif path == "/api/config":
            cfg = body.get("config")
            # hard-fail saves from older cached UI builds: they may rebuild
            # entries without keys the current form owns (flags were lost once)
            want_ver = current_ui_version()
            if want_ver and str(body.get("ui_ver") or "") != want_ver and not body.get("force"):
                self.send_json(428, {"ok": False, "outdated_ui": True,
                                     "error": "页面脚本版本过旧(%s -> 需 %s)，请 Ctrl+Shift+R 强制刷新后重新编辑保存" % (body.get("ui_ver") or "无版本", want_ver)})
                return
            # FRESHNESS FIRST: an outdated page snapshot normally fails content
            # validation for keys the user never edited -> say "stale" not ghost
            # errors (udp line family-flags confusion root cause)
            base_mtime = body.get("base_mtime")
            try:
                cur_mtime = os.stat(self.cfg_path()).st_mtime
            except OSError:
                cur_mtime = None
            if base_mtime is None and not body.get("force"):
                self.send_json(428, {"ok": False,
                                     "error": "缺少 base_mtime: 页面缓存过旧，请刷新页面（或 Ctrl+Shift+R 强刷）后重新编辑保存"})
                return
            if (base_mtime is not None and cur_mtime is not None
                    and abs(cur_mtime - float(base_mtime)) > 0.001 and not body.get("force")):
                self.send_json(409, {"ok": False, "stale": True, "server_mtime": cur_mtime,
                                     "error": "配置文件在本页面加载后被外部修改过，已阻止覆盖 —— 请点『刷新/读取配置』重新加载最新内容后再编辑保存"})
                return
            errors = validate_config(cfg)
            if errors:
                self.send_json(422, {"ok": False, "errors": errors})
                return
            try:
                ib.save_config(self.cfg_path(), cfg)          # atomic + .bak
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "save failed: %s" % e})
                return
            # config saves NEVER signal implicitly; explicit /api/reload only
            rc = {"ok": None, "error": "use POST /api/reload"}
            if body.get("reload"):
                rc = signal_master()
            try:
                nm = os.stat(self.cfg_path()).st_mtime
            except OSError:
                nm = None
            self.send_json(200, {"ok": True, "reload": rc, "mtime": nm})
        elif path == "/api/bind":
            cfg = ib.load_config(self.cfg_path())
            if not body.get("ifname"):
                self.send_json(422, {"ok": False, "error": "ifname required"})
                return
            ip = str(body.get("ip") or "").strip()
            dyn = bool(body.get("dynamic"))
            if not dyn and not ip:
                self.send_json(422, {"ok": False, "error": "static binding needs an IP"})
                return
            mraw = body.get("mark")
            try:
                mark = int(mraw, 0) if isinstance(mraw, str) else int(mraw)
            except (TypeError, ValueError):
                self.send_json(422, {"ok": False, "error": "bad mark %r" % (mraw,)})
                return
            cand = {"ifname": str(body["ifname"]), "ip": ip,
                    "prefixlen": int(body.get("prefixlen", 32)),
                    "version": 6 if ":" in ip else 4,
                    "dynamic": dyn, "method": "manual"}
            # --- IP <-> NIC consistency against LIVE interfaces (route dev!) ---
            try:
                det = netinfo.detect()
            except Exception:
                det = {}
            def owner_of(addr):
                return [nm for nm, r in det.items()
                        if any(a["addr"] == addr for a in r["addrs"])]
            if cand["ifname"] not in det:
                self.send_json(422, {"ok": False,
                                     "error": "接口 %s 不存在于本机" % cand["ifname"]})
                return
            if ip and not dyn:
                own = owner_of(ip)
                if not own:
                    self.send_json(422, {"ok": False,
                                         "error": "IP %s 当前不在任何接口上（确认是否输错/接口未起来）；如确需预绑定请在服务器上直接改配置" % ip})
                    return
                if cand["ifname"] not in own:
                    self.send_json(422, {"ok": False,
                                         "error": "IP %s 不在接口 %s 上，实际位于 %s —— 路由表 dev 会挂错网卡，已拒绝；请改用正确接口" % (
                                             ip, cand["ifname"], "/".join(own))})
                    return
            if dyn and det[cand["ifname"]].get("master"):
                self.send_json(422, {"ok": False,
                                     "error": "%s 是 %s 的从属网卡，请绑定主接口 %s" % (
                                         cand["ifname"], det[cand["ifname"]]["master"],
                                         det[cand["ifname"]]["master"])})
                return
            if ip and dyn:      # dynamic: iface wins, drop mistyped ip
                ip = ""
                cand["ip"] = ""
            try:
                entry = ib.add_binding(cfg, cand, mark)
            except ValueError as e:
                self.send_json(422, {"ok": False, "error": str(e)})
                return
            gw = (body.get("gateway") or "").strip()
            if gw or cand["dynamic"]:
                entry.setdefault("iprule", {})["gateway"] = gw or "auto"
            ib.save_config(self.cfg_path(), cfg)
            rc = {} if not body.get("reload") else signal_master()
            try:
                nm = os.stat(self.cfg_path()).st_mtime
            except OSError:
                nm = None
            self.send_json(200, {"ok": True, "entry": entry, "reload": rc, "mtime": nm})
        elif path == "/api/unbind":
            cfg = ib.load_config(self.cfg_path())
            ip = str(body.get("ip") or "").strip()
            iface = str(body.get("iface") or "").strip()
            try:
                mark = int(body.get("mark"))
            except (TypeError, ValueError):
                self.send_json(422, {"ok": False, "error": "mark 必填(精确定位绑定条目)"})
                return
            removed, keep = [], []
            for e in cfg.get("egress_marks", []):
                hit = int(e.get("mark", -1)) == mark and (
                    (e.get("ip") == ip and ip) or (e.get("iface") == iface and iface))
                (removed if hit else keep).append(e)
            if not removed:
                self.send_json(404, {"ok": False, "error": "未找到匹配绑定 (mark %d / %s / %s)" % (mark, ip, iface)})
                return
            cfg["egress_marks"] = keep
            try:
                ib.save_config(self.cfg_path(), cfg)
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "save failed: %s" % e})
                return
            try:
                nm = os.stat(self.cfg_path()).st_mtime
            except OSError:
                nm = None
            self.send_json(200, {"ok": True, "removed": removed, "mtime": nm})
        elif path == "/api/routes":
            self.send_json(200, rt_edit(body))
        elif path == "/api/reload":
            r = signal_master()
            if r.get("ok"):
                self.app.last_reload = time.time()
            self.send_json(200, r)
        elif path == "/api/mtr":
            try:
                cfg = ib.load_config(self.cfg_path())
                self.send_json(200, mtr_start(body, cfg))
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/ping":
            try:
                cfg = ib.load_config(self.cfg_path())
                self.send_json(200, ping_start(body, cfg))
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/dig":
            try:
                cfg = ib.load_config(self.cfg_path())
                self.send_json(200, dig_run(body, cfg))
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/whois":
            try:
                self.send_json(200, whois_run(body))
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/ipq":
            try:
                cp = self.cfg_path()
                cfg = ib.load_config(cp)
                self.send_json(200, ipq_run(body, cfg, cp))
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/iftop/start":
            try:
                self.send_json(200, ift_start(body))
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/iftop/stop":
            try:
                self.send_json(200, ift_stop(str(body.get("reason") or "stopped")))
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/test_line":
            try:
                self.send_json(200, test_line(self.cfg_path(),
                                              str(body.get("line") or ""),
                                              str(body.get("proto") or "tcp"),
                                              int(body.get("family") or 4),
                                              (body.get("target") or None) and str(body.get("target")) or None))
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/test_now":
            try:
                r = redis.Redis(host=self.app.args.redis_host, port=self.app.args.redis_port,
                                db=self.app.args.redis_db, socket_timeout=2, socket_connect_timeout=2)
                r.set("test_now", "1")
                self.send_json(200, {"ok": True,
                                     "note": "已置 redis test_now 标志; 主进程 TestThread 轮询到即开测 (需已加载带该支持的router代码)"})
            except Exception as e:
                self.send_json(500, {"ok": False, "error": str(e)})
        elif path == "/api/pdns/validate":
            if pa is None:
                return self.send_pdns_disabled()
            errors = pa.validate_config(body.get("config", body))
            self.send_json(200, {"ok": not errors, "errors": errors})
        elif path == "/api/pdns/config":
            if pa is None or not self.pdns_cfg_path():
                return self.send_pdns_disabled()
            host = self.pdns_host()
            cfg = body.get("config")
            base_mtime = body.get("base_mtime")
            cur_mtime = pa.stat_mtime(self.pdns_cfg_path(), host=host)
            if base_mtime is None and not body.get("force"):
                self.send_json(428, {"ok": False,
                                     "error": "缺少 base_mtime: 页面缓存过旧，请刷新页面后重新编辑保存"})
                return
            if (base_mtime is not None and cur_mtime is not None
                    and abs(cur_mtime - float(base_mtime)) > 0.001 and not body.get("force")):
                self.send_json(409, {"ok": False, "stale": True, "server_mtime": cur_mtime,
                                     "error": "pdns-recursor.json 在本页面加载后被外部修改过，已阻止覆盖 —— 请重新加载后再编辑保存"})
                return
            errors = pa.validate_config(cfg)
            if errors:
                self.send_json(422, {"ok": False, "errors": errors})
                return
            try:
                saved = pa.save_config(self.pdns_cfg_path(), cfg, host=host)
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "save failed: %s" % e})
                return
            rc = None
            if body.get("reload"):
                rc = pa.reload_recursor(rec_control_bin=getattr(self.app.args, "rec_control", "rec_control"), host=host)
            nm = pa.stat_mtime(self.pdns_cfg_path(), host=host)
            self.send_json(200, {"ok": True, "config": saved, "reload": rc, "mtime": nm})
        elif path == "/api/pdns/poison":
            if pa is None or not self.pdns_poison_path():
                return self.send_pdns_disabled()
            p = self.pdns_poison_path()
            host = self.pdns_host()
            base_mtime = body.get("base_mtime")
            cur_mtime = pa.stat_mtime(p, host=host)
            if (base_mtime is not None and cur_mtime is not None
                    and abs(cur_mtime - float(base_mtime)) > 0.001 and not body.get("force")):
                self.send_json(409, {"ok": False, "stale": True, "server_mtime": cur_mtime,
                                     "error": "污染IP列表在本页面加载后被外部修改过，已阻止覆盖 —— 请重新加载后再编辑保存"})
                return
            try:
                clean = pa.save_poison_list(p, body.get("ips") or [], host=host)
            except ValueError as e:
                self.send_json(422, {"ok": False, "error": str(e)})
                return
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "save failed: %s" % e})
                return
            nm = pa.stat_mtime(p, host=host)
            self.send_json(200, {"ok": True, "ips": clean, "mtime": nm,
                                 "note": "转发进程约 1 秒内自动检测文件变化并热加载，也可发 SIGHUP 立即触发"})
        elif path == "/api/pdns/reload":
            if pa is None:
                return self.send_pdns_disabled()
            r = pa.reload_recursor(rec_control_bin=getattr(self.app.args, "rec_control", "rec_control"),
                                   host=self.pdns_host())
            self.send_json(200 if r.get("ok") else 500, r)
        elif path == "/api/dnsmasq/reload":
            r = reload_dnsmasq()
            self.send_json(200 if r.get("ok") else 500, r)
        else:
            self.send_json(404, {"error": "not found"})

    # -- websocket ----------------------------------------------------------
    def handle_ws(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if not key or "websocket" not in (self.headers.get("Upgrade") or "").lower():
            self.send_json(400, {"error": "bad websocket request"})
            return
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws_accept_key(key.strip()))
        self.end_headers()
        self.wfile.flush()            # 101 handshake must reach client before raw frames
        conn = self.connection
        conn.setblocking(False)
        self.close_connection = True
        q = Queue(maxsize=CLIENT_QMAX)
        self.app.hub.add(q)
        _MTR_HUB.add(q)          # live mtr progress frames on the same socket
        parser = WSParser()
        pending = b""          # unsent WS bytes; partial-send safe
        try:
            conn.sendall(ws_encode(json.dumps({"t": "hello", "server": "nft-route webadmin"})))
            conn.sendall(ws_encode(json.dumps({"t": "snap", "rows": self.app.ring.snapshot()})))
            closed = False
            while not closed:
                r, w, _ = select.select([conn], [conn] if pending else [], [], 0.05)
                if r:
                    try:
                        data = conn.recv(4096)
                    except (BlockingIOError, InterruptedError):
                        data = None
                    if data == b"":
                        break
                    for op, payload in (parser.feed(data) if data else []):
                        if op == 0x8:
                            closed = True
                            break
                        if op == 0x9:
                            try:
                                conn.sendall(ws_encode(payload, opcode=0xA))
                            except OSError:
                                closed = True
                if not pending:
                    batch = []
                    try:
                        while len(batch) < 256:
                            batch.append(q.get_nowait())
                    except Empty:
                        pass
                    if batch:
                        lost = getattr(q, "dropped", 0)
                        if lost:
                            q.dropped = 0
                            batch.insert(0, json.dumps({"t": "gap", "n": lost}))
                        pending = b"".join(ws_encode(x) for x in batch)
                if pending and w:
                    try:
                        n = conn.send(pending)   # may write partially
                        pending = pending[n:]
                    except BlockingIOError:      # slow tab (background throttling):
                        pass                     # keep bytes, NEVER drop the socket
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        break
        except (OSError, ConnectionError):
            pass
        finally:
            self.app.hub.remove(q)
            _MTR_HUB.remove(q)
            try:
                conn.sendall(ws_encode(b"", opcode=0x8))
            except OSError:
                pass


def check_master(pidfile=None):
    """non-destructive liveness report of the router master process"""
    path = pidfile or PIDFILE_ARG or MASTER_PID_FILE
    try:
        with open(path) as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        return {"pid": None, "alive": False, "error": "no pidfile: %s" % path}
    try:
        os.kill(pid, 0)
        cmdline = open("/proc/%d/cmdline" % pid, "rb").read().decode("utf-8", "replace").replace("\0", " ")
        good = ("nft_route" in cmdline) or ("router.py" in cmdline)
        return {"pid": pid, "alive": True, "is_router": good, "cmdline": cmdline[:100]}
    except OSError as e:
        return {"pid": pid, "alive": False, "error": str(e)}


# ---------------------------------------------------------------------------

def main(argv=None):
    global PIDFILE_ARG
    ap = argparse.ArgumentParser(description="nftable-router web admin (isolated process)")
    ap.add_argument("--config", required=True, help="path to nft_route.json")
    ap.add_argument("--host", default="127.0.0.1", help="bind addr (default localhost only)")
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--redis-host", default="127.0.0.1")
    ap.add_argument("--redis-port", type=int, default=6379)
    ap.add_argument("--redis-db", type=int, default=1)
    ap.add_argument("--ring-max", type=int, default=RING_MAX)
    ap.add_argument("--pidfile", default=None, help="router master pidfile (default /run/nft_route.pid)")
    ap.add_argument("--pdns-config", default=None,
                    help="path to pdns-recursor.json (omit to disable the DNS tab)")
    ap.add_argument("--pdns-poison-list", default=None,
                    help="path to dns_posion_list.txt (omit to disable poison-list editing)")
    ap.add_argument("--rec-control", default="rec_control",
                    help="rec_control binary for reload-lua-script (default: PATH lookup)")
    ap.add_argument("--pdns-host", default=None,
                    help="PowerDNS Recursor box, if not this machine: 'user@1.2.3.4' or "
                         "'user@1.2.3.4:2222' -- all pdns file I/O + rec_control go over ssh "
                         "using the invoking user's own key/agent/~/.ssh/config (omit for local)")
    args = ap.parse_args(argv)
    PIDFILE_ARG = args.pidfile
    json.load(open(args.config))                    # fail fast on unreadable config

    app = App(args)
    app.streamer.start()
    bw_start()
    Handler.app = app
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("[webadmin] http://%s:%d  config=%s  redis=%s:%d/%d stream=on" % (
        args.host, args.port, args.config, args.redis_host, args.redis_port, args.redis_db))

    def bye(sig, frm):
        threading.Thread(target=srv.shutdown, daemon=True).start()
        app.streamer.shutdown()
        try:
            ift_stop("webadmin 退出")
        except Exception:
            pass
    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    print("[webadmin] stopped")


if __name__ == "__main__":
    main()
