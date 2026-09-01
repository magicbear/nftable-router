#!/usr/bin/env python3
"""Offline tests for webadmin.py (no redis-server, no router, no root)."""

import base64
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import webadmin as wa
wa.current_ui_version = lambda: "test"

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok   %s" % name)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (name, ("-> " + detail) if detail else ""))


def test_ws_codec():
    print("[1] websocket codec")
    check("RFC6455 accept key",
          wa.ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    for size in (5, 200, 70000):
        payload = "x" * size
        frame = wa.ws_encode(payload)
        p = wa.WSParser()
        out = p.feed(frame)
        check("roundtrip len %d" % size, len(out) == 1 and out[0] == (0x1, payload.encode()), str(out)[:40])
    # client->server masked frame
    key = b"\x37\xfa\x21\x3d"
    data = b"hi"
    masked = bytes(data[i] ^ key[i % 4] for i in range(len(data)))
    frame = bytes([0x81, 0x80 | len(data)]) + key + masked
    p = wa.WSParser()
    out = p.feed(frame)
    check("masked client frame unmasked", out == [(0x1, b"hi")], str(out))
    # split across two reads
    full = wa.ws_encode("abcdef")
    p2 = wa.WSParser()
    check("fragmented feed waits", p2.feed(full[:3]) == [])
    check("second chunk completes", p2.feed(full[3:]) == [(0x1, b"abcdef")])


def test_ring_hub():
    print("[2] ring + hub")
    r = wa.RingBuffer(maxlen=5)
    for i in range(9):
        r.push(i)
    check("ring capped", r.snapshot() == [4, 5, 6, 7, 8])
    h = wa.Hub()
    from queue import Queue
    q1, q2 = Queue(maxsize=3), Queue(maxsize=3)
    for x in (b"a", b"b", b"c"):
        h.broadcast(x)  # no clients yet
    h.add(q1)
    for x in (b"d", b"e", b"f", b"g"):
        h.broadcast(x)          # q1(maxsize 3) full at g -> oldest dropped
    got = []
    while not q1.empty():
        got.append(q1.get())
    check("client got newest, dropped oldest", got == [b"e", b"f", b"g"], str(got))
    check("snapshot delivered only after add", q2.empty())
    h.remove(q1)
    h.broadcast(b"g")
    check("removed client not fed", q1.qsize() == 0 and h.count() == 0)


def test_validate_config():
    print("[3] config validation")
    good = {"proxy": {"A": {"mark": 51, "ipv4": True}, "B": {"mark": 52, "ipv4": True}},
            "rules": [], "egress_marks": [{"iface": "ppp0", "mark": 51, "dynamic": True}]}
    check("good config -> no errors", wa.validate_config(good) == [])
    bad = json.loads(json.dumps(good))
    bad["proxy"]["C"] = {"mark": 51}
    check("duplicate proxy mark caught", any("duplicate proxy mark" in e for e in wa.validate_config(bad)))
    bad2 = json.loads(json.dumps(good))
    for k, port in (("A", 101), ("B", 102)):
        bad2["proxy"][k].update({"daemon": "custom", "port": port,
                                 "uid": "nobody", "cmd": ["/bin/sleep", "1"]})
    bad2["proxy"]["A"]["upstream"] = "B"
    bad2["proxy"]["B"]["upstream"] = "A"
    errs = wa.validate_config(bad2)
    check("proxy chain cycle caught", any("chain" in e and "loop" in e for e in errs), str(errs))
    bad2b = json.loads(json.dumps(good))
    bad2b["proxy"]["A"]["upstream"] = "GHOST"
    check("chain: unknown upstream caught",
          any("chain" in e and "GHOST" in e for e in wa.validate_config(bad2b)))
    bad3 = json.loads(json.dumps(good))
    bad3["egress_marks"].append({"iface": "ppp0", "mark": 77, "dynamic": True})
    check("duplicate iface binding caught",
          any("iface" in e for e in wa.validate_config(bad3)))
    check("missing key caught", any("proxy" in e for e in wa.validate_config({"rules": []})))
    check("port range caught",
          any("port" in e for e in wa.validate_config({"proxy": {"A": {"mark": 5, "port": 99999}}, "rules": []})))


def test_master_signal(tmpdir):
    print("[4] master pidfile / signal safety")
    pf = os.path.join(tmpdir, "not_exist.pid")
    r = wa.signal_master(pidfile=pf)
    check("no pidfile -> ok False", r["ok"] is False and "pidfile" in r["error"])
    with open(pf, "w") as f:
        f.write(str(os.getpid()))
    r2 = wa.signal_master(pidfile=pf)  # this test process is NOT nft_route
    check("wrong cmdline refused (no stray kill)", r2["ok"] is False and "NOT the router" in r2["error"], str(r2))
    st = wa.check_master(pidfile=pf)
    check("check_master alive but is_router False", st["alive"] is True and st["is_router"] is False)
    # fake pid
    with open(pf, "w") as f:
        f.write("99999999")
    check("dead pid -> alive False", wa.check_master(pidfile=pf)["alive"] is False)


# ---------------------------------------------------------------------------
# live HTTP/WS end-to-end (server thread, real sockets)
# ---------------------------------------------------------------------------

def http_req(sock, text):
    sock.sendall(text.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = sock.recv(4096)
        if not d:
            break
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    return head, rest


def read_http_body(sock, head, rest):
    m = [l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")]
    need = int(m[0].split(b":")[1]) - len(rest) if m else 0
    while need > 0:
        d = sock.recv(need)
        if not d:
            break
        rest += d
        need -= len(d)
    return rest


def test_server_e2e():
    print("[5] HTTP + websocket end-to-end (temp config, no redis)")
    cfg = {"proxy": {"A": {"mark": 51, "ipv4": True}}, "rules": [],
           "nat_interfaces": ["eno1"], "tunnel_ip": {"ipv4": [], "ipv6": []},
           "ignore_list": {"ipv4": [], "ipv6": []}}
    with tempfile.TemporaryDirectory() as d:
        cpath = os.path.join(d, "nft_route.json")
        json.dump(cfg, open(cpath, "w"))
        args = type("A", (), {"config": cpath, "ring_max": 1000, "redis_host": "127.0.0.1",
                              "redis_port": 1, "redis_db": 1, "pidfile": os.path.join(d, "no.pid")})()
        wa.PIDFILE_ARG = args.pidfile
        app = wa.App(args)
        app.ring.push({"ts": time.time(), "proto": 6, "src": "1.1.1.1", "dst": "2.2.2.2",
                       "sport": 1, "dport": 2, "line": "A", "mark": 51, "pri": 0, "sess": 0, "ms": 1.0})
        wa.Handler.app = app
        from http.server import ThreadingHTTPServer
        srv = ThreadingHTTPServer(("127.0.0.1", 0), wa.Handler)
        port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            head, rest = http_req(s, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            check("index served", b"200 OK" in head and b"nft-route" in head + read_http_body(s, head, rest))
            s.close()
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            head, rest = http_req(s, "GET /api/config HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            body = json.loads(read_http_body(s, head, rest))
            check("api/config", body["config"]["proxy"]["A"]["mark"] == 51)
            s.close()
            # bad config save rejected
            bad = json.dumps({"config": {"rules": []}})
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.sendall(("POST /api/validate HTTP/1.1\r\nHost: x\r\nContent-Type: application/json"
                       "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(bad), bad)).encode())
            head = b""
            while b"\r\n\r\n" not in head:
                head += s.recv(4096)
            h, r2 = head.split(b"\r\n\r\n", 1)
            v = json.loads(read_http_body(s, h, r2))
            check("validate reports missing proxy", any("proxy" in e for e in v["errors"]))
            s.close()
            # save new valid config (no reload -> no pidfile so would error anyway)
            newcfg = json.loads(json.dumps(cfg))
            newcfg["egress_marks"] = []
            # missing base_mtime -> 428 (stale/cached clients locked out)
            payload = json.dumps({"config": newcfg, "reload": False, "ui_ver": "test"})
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.sendall(("POST /api/config HTTP/1.1\r\nHost: x\r\nContent-Type: application/json"
                       "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(payload), payload)).encode())
            head = b""
            while b"\r\n\r\n" not in head:
                head += s.recv(4096)
            h, r2 = head.split(b"\r\n\r\n", 1)
            res = json.loads(read_http_body(s, h, r2)); s.close()
            check("save without base_mtime -> 428", b"428" in h and res.get("ok") is False
                  and "base_mtime" in res.get("error",""))
            # fresh mtime -> ok
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.sendall(("GET /api/config HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").encode())
            head = b""
            while b"\r\n\r\n" not in head:
                head += s.recv(4096)
            h, r2 = head.split(b"\r\n\r\n", 1)
            got = json.loads(read_http_body(s, h, r2)); s.close()
            mt = got["mtime"]
            payload = json.dumps({"config": newcfg, "reload": False, "base_mtime": mt, "ui_ver": "test"})
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.sendall(("POST /api/config HTTP/1.1\r\nHost: x\r\nContent-Type: application/json"
                       "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(payload), payload)).encode())
            head = b""
            while b"\r\n\r\n" not in head:
                head += s.recv(4096)
            h, r2 = head.split(b"\r\n\r\n", 1)
            res = json.loads(read_http_body(s, h, r2)); s.close()
            check("save ok with fresh base_mtime (reload suppressed)",
                  res.get("ok") is True and res.get("reload", {}).get("ok") is None)
            check("config file rewritten", json.load(open(cpath))["egress_marks"] == [])
            # stale mtime -> 409
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            time.sleep(0.02)
            payload = json.dumps({"config": newcfg, "base_mtime": mt - 5, "ui_ver": "test"})
            s.sendall(("POST /api/config HTTP/1.1\r\nHost: x\r\nContent-Type: application/json"
                       "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(payload), payload)).encode())
            head = b""
            while b"\r\n\r\n" not in head:
                head += s.recv(4096)
            h, r2 = head.split(b"\r\n\r\n", 1)
            res = json.loads(read_http_body(s, h, r2)); s.close()
            check("stale base_mtime -> 409 stale:true", res.get("stale") is True)
            # old/cached UI build -> 428 outdated_ui
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            oldpayload = json.dumps({"config": newcfg, "base_mtime": mt, "ui_ver": "20200101-0000"})
            s.sendall(("POST /api/config HTTP/1.1\r\nHost: x\r\nContent-Type: application/json"
                       "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(oldpayload), oldpayload)).encode())
            oh = b""
            while b"\r\n\r\n" not in oh:
                oh += s.recv(4096)
            hh, rr = oh.split(b"\r\n\r\n", 1)
            ores = json.loads(read_http_body(s, hh, rr)); s.close()
            check("old ui_ver -> 428 outdated_ui", b"428" in hh and ores.get("outdated_ui") is True)
            # bind API
            bpayload = json.dumps({"ifname": "ppp0", "dynamic": True, "mark": 51,
                                   "gateway": "auto", "reload": False, "ui_ver": "test"})
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.sendall(("POST /api/bind HTTP/1.1\r\nHost: x\r\nContent-Type: application/json"
                       "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(bpayload), bpayload)).encode())
            head = b""
            while b"\r\n\r\n" not in head:
                head += s.recv(4096)
            h, r2 = head.split(b"\r\n\r\n", 1)
            res = json.loads(read_http_body(s, h, r2))
            check("bind added egress entry", res.get("ok") and
                  json.load(open(cpath))["egress_marks"][0]["iface"] == "ppp0")
            check("iprule.gateway auto recorded",
                  json.load(open(cpath))["egress_marks"][0]["iprule"]["gateway"] == "auto")
            s.close()
            # websocket flow: handshake -> hello+snap frames -> broadcast -> client close
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            head, rest = http_req(s, "GET /ws/stream HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
                                     "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                     "Sec-WebSocket-Version: 13\r\n\r\n")
            check("101 handshake", b"101" in head and
                  b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" in head)
            # wait for handler registration
            for _ in range(20):
                if app.hub.count():
                    break
                time.sleep(0.05)
            p = wa.WSParser()
            frames = p.feed(rest) if rest else []   # do NOT drop the bytes that trailed the 101 header
            deadline = time.time() + 2
            while len(frames) < 2 and time.time() < deadline:
                s.settimeout(1)
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                frames += p.feed(data)
            kinds = []
            for op, pl in frames:
                try:
                    kinds.append(json.loads(pl).get("t", "row"))
                except ValueError:
                    kinds.append("?")
            check("hello + snap(frames) received", "hello" in kinds and "snap" in kinds, str(kinds))
            # broadcast live event through hub queue
            app.hub.broadcast(json.dumps({"proto": 6, "src": "9.9.9.9", "dst": "8.8.8.8",
                                          "mark": 51, "sess": 0, "ts": time.time(), "ms": 0.1}).encode())
            data = s.recv(4096)
            got = p.feed(data)
            row = json.loads(got[0][1]) if got and got[0][0] == 1 else {}
            check("live event streamed to client", row.get("src") == "9.9.9.9", str(got)[:60])
            # client close frame -> handler cleans up
            key = b"\x01\x02\x03\x04"
            cf = bytes([0x88, 0x80]) + key
            s.sendall(cf)
            s.close()
            for _ in range(20):
                if app.hub.count() == 0:
                    break
                time.sleep(0.05)
            check("hub cleaned after client close", app.hub.count() == 0)
        finally:
            srv.shutdown()
            srv.server_close()


def test_webadmin_service_lifecycle():
    print("[6] WebadminService: spawn / crash-restart / rate-limit / reconcile / disable")
    import webadmin_svc as svc
    logs = []
    # a fake spawn that returns a FakeProc we can drive
    class FP:
        _next = [5000]
        def __init__(self):
            self.pid = FP._next[0]; FP._next[0] += 1
            self._rc = None; self._term = False
        def poll(self):
            return self._rc
        def terminate(self):
            self._term = True; self._rc = -15
        def wait(self, timeout=None):
            return self._rc
        def kill(self):
            self._rc = -9
        alive_procs = []
    procs = []
    def spawn(argv, outfile):
        p = FP(); procs.append(p); return p
    clock = [1000.0]
    srv = svc.WebadminService(spawn=spawn, now=lambda: clock[0], log=logs.append)
    cfg = {"webadmin": {"enabled": True, "port": 8790, "restart": {"max": 2, "window": 100}}}
    path = "/tmp/does-not-matter.json"
    a1 = srv.reconcile(cfg, path)
    check("boot started child", a1 == "started" and srv.state == "running" and len(procs) == 1)
    # unchanged reconcile -> no restart
    a2 = srv.reconcile(cfg, path)
    check("unchanged spec -> no restart", a2 == "unchanged" and len(procs) == 1)
    # crash -> tick restarts
    procs[0]._rc = 1
    srv.tick(path)
    check("crash -> restart", len(procs) == 2 and srv.state == "running")
    # crash again -> over limit -> gaveup (no further spawns)
    clock[0] += 1
    procs[1]._rc = 1
    srv.tick(path); n_after = len(procs)
    procs[-1]._rc = 1
    clock[0] += 1
    srv.tick(path)
    check("rate-limit -> gaveup", srv.state == "gaveup" and len(procs) == n_after, "procs=%d" % len(procs))
    # spec change reconcile resets history and restarts
    cfg2 = {"webadmin": {"enabled": True, "port": 8791}}
    a3 = srv.reconcile(cfg2, path)
    check("spec change -> restarted fresh", a3 == "started" and srv.state == "running" and srv.hist == [])
    # disable
    procs[-1]._term = False
    a4 = srv.reconcile({"webadmin": {"enabled": False}}, path)
    check("disabled -> stopped + terminate sent", a4 == "stopped" and srv.state == "off" and procs[-1]._term)
    check("parse default disabled-by-absence is enabled", svc.parse_spec({}) is not None and svc.parse_spec({}).get("port") == 8788)


def test_webadmin_real_child_smoke():
    print("[7] WebadminService real subprocess (actual webadmin.py) boots & serves")
    import webadmin_svc as svc
    with tempfile.TemporaryDirectory() as d:
        cpath = os.path.join(d, "nft_route.json")
        json.dump({"proxy": {"A": {"mark": 51}}, "rules": []}, open(cpath, "w"))
        pidf = os.path.join(d, "nope.pid")
        srv = svc.WebadminService(log=lambda m: None,
                                  script=os.path.join(os.path.dirname(os.path.abspath(__file__)), "webadmin.py"))
        try:
            srv.reconcile({"webadmin": {"enabled": True, "host": "127.0.0.1", "port": 0}}, cpath, pidf)
            # port 0 -> webadmin binds an ephemeral; find it via /proc is messy, so
            # instead verify the child actually launched (real Popen, real interpreter)
            time.sleep(0.6)
            check("real child spawned & alive", srv.state == "running"
                  and srv.proc is not None and srv.proc.poll() is None)
        finally:
            srv.shutdown()
        time.sleep(0.3)
        check("child reaped after shutdown", srv.proc is None)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        test_master_signal(d)
    for t in (test_ws_codec, test_ring_hub, test_validate_config, test_server_e2e,
              test_webadmin_service_lifecycle, test_webadmin_real_child_smoke):
        t()
    print("\n==== %d passed, %d failed ====" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)

