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
import json
import os
import re
import select
import signal
import socket
import struct
import sys
import threading
import time
from collections import deque
from queue import Queue, Empty
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

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
CLIENT_QMAX = 2000
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
    if pmm is not None:
        try:
            pmm.validate_chain(proxy)
        except Exception as e:
            errors.append("proxy chain: %s" % e)
    return errors


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
        managed = {k: v for k, v in cfg.get("proxy", {}).items() if pmm.is_managed(v)}
        for name, c in managed.items():
            want = {"managed": name, "daemon": c.get("daemon"), "port": c.get("port"),
                    "upstream": c.get("upstream"), "autostart": c.get("autostart", True),
                    "pid": None, "state": "not running", "uptime": None, "cpu": None}
            if c.get("autostart", True) is False:
                want["state"] = "autostart off"
            for p in procs.values():
                try:
                    cl = p.cmdline()
                except Exception:
                    continue
                if not cl:
                    continue
                port_i = cl.index("-l") + 1 if "-l" in cl else None
                if (os.path.basename(cl[0]) in ("ss-redir", "v2ray", "sing-box", str(c.get("binary") or ""))
                        and port_i and port_i < len(cl) and str(c.get("port")) == cl[port_i]):
                    try:
                        with p.oneshot():
                            want.update({"pid": p.pid, "state": "running" if p.status() == psutil.STATUS_RUNNING
                                         or p.is_running() else p.status(),
                                         "uptime": round(time.time() - p.create_time()),
                                         "cpu": round(p.cpu_percent(0.05), 1)})
                    except Exception as e:
                        want["state"] = "error %s" % e
                    break
            res["proxies"]["managed"].append(want)
        # external proxy-ish procs NOT under the router master
        try:
            for p in psutil.process_iter(["pid", "name", "cmdline", "ppid", "username"]):
                cl = p.info.get("cmdline") or []
                if cl and os.path.basename(cl[0]) in ("ss-redir", "ss-local", "v2ray", "sing-box") \
                        and p.info["pid"] not in procs:
                    res["proxies"]["external"].append({"pid": p.info["pid"], "ppid": p.info["ppid"],
                                                       "user": p.info.get("username"),
                                                       "cmd": " ".join(cl)[:100]})
        except Exception:
            pass
    # --- test results from redis
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
                       "pending_now": bool(pend),
                       "v4": parse("test_v4"), "v6": parse("test_v6")}
    except Exception as e:
        res["test"] = {"error": str(e)}
    return res


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


def _load_ui():
    try:
        from nftable_router.webui import INDEX_HTML
    except ImportError:
        from webui import INDEX_HTML
    return INDEX_HTML


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

    # -- routes -------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            body = _load_ui().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
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
        elif path == "/api/health":
            try:
                self.send_json(200, health_snapshot(self.app))
            except Exception as e:
                self.send_json(500, {"error": "%s: %s" % (type(e).__name__, e)})
        elif path == "/api/status":
            st = {}
            try:
                st["config_mtime"] = os.stat(self.cfg_path()).st_mtime
            except OSError:
                pass
            st.update({"master": check_master(),
                       "redis_stream": self.app.streamer.alive,
                       "ws_clients": self.app.hub.count(),
                       "ring": len(self.app.ring), "ring_max": self.app.args.ring_max,
                       "uptime": round(time.time() - self.app.started),
                       "config_path": self.cfg_path()})
            self.send_json(200, st)
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
            errors = validate_config(cfg)
            if errors:
                self.send_json(422, {"ok": False, "errors": errors})
                return
            try:
                ib.save_config(self.cfg_path(), cfg)          # atomic + .bak
            except Exception as e:
                self.send_json(500, {"ok": False, "error": "save failed: %s" % e})
                return
            rc = signal_master() if body.get("reload", True) else {"ok": None, "error": "reload suppressed"}
            self.send_json(200, {"ok": True, "reload": rc})
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
            try:
                entry = ib.add_binding(cfg, cand, mark)
            except ValueError as e:
                self.send_json(422, {"ok": False, "error": str(e)})
                return
            gw = (body.get("gateway") or "").strip()
            if gw or cand["dynamic"]:
                entry.setdefault("iprule", {})["gateway"] = gw or "auto"
            ib.save_config(self.cfg_path(), cfg)
            rc = signal_master() if body.get("reload", True) else {}
            self.send_json(200, {"ok": True, "entry": entry, "reload": rc})
        elif path == "/api/reload":
            self.send_json(200, signal_master())
        elif path == "/api/test_now":
            try:
                r = redis.Redis(host=self.app.args.redis_host, port=self.app.args.redis_port,
                                db=self.app.args.redis_db, socket_timeout=2, socket_connect_timeout=2)
                r.set("test_now", "1")
                self.send_json(200, {"ok": True,
                                     "note": "已置 redis test_now 标志; 主进程 TestThread 轮询到即开测 (需已加载带该支持的router代码)"})
            except Exception as e:
                self.send_json(500, {"ok": False, "error": str(e)})
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
        parser = WSParser()
        try:
            conn.sendall(ws_encode(json.dumps({"t": "hello", "server": "nft-route webadmin"})))
            conn.sendall(ws_encode(json.dumps({"t": "snap", "rows": self.app.ring.snapshot()})))
            closed = False
            while not closed:
                r, _, _ = select.select([conn], [], [], 0.05)
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
                try:
                    while True:
                        conn.sendall(ws_encode(q.get_nowait()))
                except Empty:
                    pass
                except (BrokenPipeError, ConnectionResetError, OSError):
                    break
        except (OSError, ConnectionError):
            pass
        finally:
            self.app.hub.remove(q)
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
    args = ap.parse_args(argv)
    PIDFILE_ARG = args.pidfile
    json.load(open(args.config))                    # fail fast on unreadable config

    app = App(args)
    app.streamer.start()
    Handler.app = app
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("[webadmin] http://%s:%d  config=%s  redis=%s:%d/%d stream=on" % (
        args.host, args.port, args.config, args.redis_host, args.redis_port, args.redis_db))

    def bye(sig, frm):
        threading.Thread(target=srv.shutdown, daemon=True).start()
        app.streamer.shutdown()
    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    print("[webadmin] stopped")


if __name__ == "__main__":
    main()
