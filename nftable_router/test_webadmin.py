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
    for k, (port, uid) in (("A", (101, "nobody")), ("B", (102, "nogroup"))):
        bad2["proxy"][k].update({"daemon": "custom", "port": port,
                                 "uid": uid, "cmd": ["/bin/sleep", "1"]})
    bad2["proxy"]["A"]["upstream"] = "B"
    bad2["proxy"]["B"]["upstream"] = "A"
    errs = wa.validate_config(bad2)
    check("proxy chain cycle caught", any("chain" in e and "loop" in e for e in errs), str(errs))
    # same run-user on two lines is a distinct, earlier error
    bad2u = json.loads(json.dumps(good))
    bad2u["proxy"]["A"].update({"daemon": "custom", "port": 101, "uid": "nobody", "cmd": ["/x"]})
    bad2u["proxy"]["B"].update({"daemon": "custom", "port": 102, "uid": "nobody", "cmd": ["/x"]})
    check("duplicate run-user across lines caught",
          any("run-user" in e for e in wa.validate_config(bad2u)), str(wa.validate_config(bad2u)))
    # run-user is OPTIONAL now (empty = current user, no skuid): direct managed
    # or mark-upstream chains without uid must SAVE cleanly (prod regression:
    # a stale hard requirement blocked the whole page edit)
    noud = json.loads(json.dumps(good))
    noud["proxy"]["A"].update({"daemon": "custom", "port": 101, "cmd": ["/x"], "upstream": "B"})
    noud["proxy"]["B"]["uid"] = "nobody"  # B stays a PURE mark line, now carrying the identity
    check("daemon WITHOUT uid accepted (mark-upstream inherits identity)",
          wa.validate_config(noud) == [], str(wa.validate_config(noud)))
    noud_direct = json.loads(json.dumps(good))
    noud_direct["proxy"]["A"].update({"daemon": "custom", "port": 101, "cmd": ["/x"]})
    check("direct daemon without uid accepted", wa.validate_config(noud_direct) == [],
          str(wa.validate_config(noud_direct)))
    # ...but a PORT-type chain consumer without own uid stays rejected
    pchain = json.loads(json.dumps(good))
    pchain["proxy"]["A"].update({"daemon": "custom", "port": 101, "cmd": ["/x"], "upstream": "B"})
    pchain["proxy"]["B"].update({"daemon": "custom", "port": 102, "cmd": ["/x"], "uid": "nobody"})
    pchain["proxy"]["A"]["upstream"] = "B"  # B HAS a port => port-chain needs own uid
    check("port-chain consumer without uid rejected",
          any("端口" in e or "port" in e for e in wa.validate_config(pchain)),
          str(wa.validate_config(pchain)))
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


def test_dnsmasq_reload():
    print("[4b] reload_dnsmasq: local systemctl reload, injectable runner")
    class FakeResult:
        def __init__(self, rc, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err
    calls = []
    def ok_runner(argv, **kw):
        calls.append(argv)
        return FakeResult(0, "ok")
    r = wa.reload_dnsmasq(run=ok_runner)
    check("success path uses systemctl reload dnsmasq",
          r["ok"] is True and calls[0] == ["systemctl", "reload", "dnsmasq"])

    def fail_runner(argv, **kw):
        return FakeResult(1, "", "Unit dnsmasq.service not loaded")
    r2 = wa.reload_dnsmasq(run=fail_runner)
    check("nonzero rc -> ok False, output captured",
          r2["ok"] is False and "not loaded" in r2["output"])

    def missing_runner(argv, **kw):
        raise FileNotFoundError()
    r3 = wa.reload_dnsmasq(run=missing_runner)
    check("missing systemctl -> clear error, no traceback", r3["ok"] is False and "error" in r3)

    import subprocess as sp
    def timeout_runner(argv, **kw):
        raise sp.TimeoutExpired(argv, 8)
    r4 = wa.reload_dnsmasq(run=timeout_runner)
    check("timeout -> clear error", r4["ok"] is False and "超时" in r4["error"])


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


def test_ui_js_syntax():
    print("[6b] every inline <script> in served UI must parse (node --check)")
    import shutil as _sh, re as _re
    node = _sh.which("node")
    if not node:
        print("  skip: node not installed")
        return
    import webui
    blocks = _re.findall(r"<script>(.*?)</script>", webui.INDEX_HTML, _re.S)
    check("script blocks found", len(blocks) >= 1)
    bad = []
    for i, b in enumerate(blocks):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
            f.write(b)
            p = f.name
        import subprocess as _sp
        r = _sp.run([node, "--check", p], capture_output=True, text=True)
        if r.returncode != 0:
            bad.append((i, r.stderr.strip().split("\n")[0:3]))
        os.unlink(p)
    check("all %d script block(s) parse" % len(blocks), not bad, str(bad)[:300])


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
        wa.netinfo.detect = lambda: {
            "lo": {"index": 1, "up": True, "lower_up": True, "loopback": True, "master": None,
                   "methods": ["loopback"], "dhcp": False,
                   "addrs": [{"version": 4, "addr": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
            "ppp0": {"index": 33, "up": True, "lower_up": True, "master": None,
                     "methods": ["ppp"], "dhcp": False, "addrs": []},
            "bond1.9": {"index": 12, "up": True, "lower_up": True, "master": None,
                        "methods": ["static"], "dhcp": False,
                        "addrs": [{"version": 4, "addr": "203.0.113.9", "prefixlen": 31, "scope": "global"}]},
            "bond1.8": {"index": 11, "up": True, "lower_up": True, "master": None, "methods": ["static"],
                        "dhcp": False, "addrs": []},
        }
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
            # consecutive saves: 2nd uses mtime returned by 1st -> must pass
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.sendall(b"GET /api/config HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            head = b""
            while b"\r\n\r\n" not in head:
                head += s.recv(4096)
            h0, r00 = head.split(b"\r\n\r\n", 1)
            mt0 = json.loads(read_http_body(s, h0, r00))["mtime"]; s.close()
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            c3 = json.load(open(cpath)); c3["egress_marks"] = [{"iface": "lo0", "mark": 4321, "dynamic": True}]
            payload = json.dumps({"config": c3, "ui_ver": "test", "base_mtime": mt0})
            s.sendall(("POST /api/config HTTP/1.1\r\nHost: x\r\nContent-Type: application/json"
                       "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(payload), payload)).encode())
            head = b""
            while b"\r\n\r\n" not in head:
                head += s.recv(4096)
            h2, r22 = head.split(b"\r\n\r\n", 1)
            res = json.loads(read_http_body(s, h2, r22)); s.close()
            check("save returns new mtime", res.get("ok") and res.get("mtime"))
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            payload2 = json.dumps({"config": json.load(open(cpath)), "ui_ver": "test",
                                   "base_mtime": res["mtime"]})
            s.sendall(("POST /api/config HTTP/1.1\r\nHost: x\r\nContent-Type: application/json"
                       "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(payload2), payload2)).encode())
            head = b""
            while b"\r\n\r\n" not in head:
                head += s.recv(4096)
            h3, r33 = head.split(b"\r\n\r\n", 1)
            res2 = json.loads(read_http_body(s, h3, r33)); s.close()
            check("consecutive save with returned mtime -> 200", b"200" in h3 and res2.get("ok"))
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
            eb = [e for e in json.load(open(cpath))["egress_marks"] if e.get("iface") == "ppp0"]
            check("bind added egress entry", res.get("ok") and len(eb) == 1)
            check("iprule.gateway auto recorded", eb and eb[0]["iprule"]["gateway"] == "auto")
            s.close()
            def post_json(path_, obj):
                ss = socket.create_connection(("127.0.0.1", port), timeout=3)
                pl = json.dumps(obj)
                ss.sendall(("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json"
                            "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (path_, len(pl), pl)).encode())
                hd = b""
                while b"\r\n\r\n" not in hd:
                    hd += ss.recv(4096)
                hh, rr = hd.split(b"\r\n\r\n", 1)
                r_ = json.loads(read_http_body(ss, hh, rr)); ss.close()
                return hh, r_
            hh, r_ = post_json("/api/bind", {"ifname": "ghost0", "dynamic": True, "mark": 7001, "reload": False})
            check("bind nonexistent iface -> 422", b"422" in hh and "不存在" in r_.get("error", ""))
            hh, r_ = post_json("/api/bind", {"ifname": "bond1.8", "ip": "203.0.113.9", "mark": 7002, "reload": False})
            check("IP not on chosen iface -> 422 names real owner",
                  b"422" in hh and "bond1.9" in r_.get("error", ""))
            hh, r_ = post_json("/api/bind", {"ifname": "bond1.9", "ip": "203.0.113.9", "mark": 7003, "reload": False})
            check("correct iface+ip pair accepted", r_.get("ok") is True)
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
            deadline = time.time() + 12   # health_snapshot can be slow under
            def has(tname):               # load on dev boxes (psutil scan)
                for _, pl in frames:
                    try:
                        if json.loads(pl).get("t") == tname:
                            return True
                    except ValueError:
                        pass
                return False
            while time.time() < deadline and not (has("hello") and has("snap") and has("status")):
                s.settimeout(0.5)
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    continue
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
            check("status frame pushed on connect (no polling)", "status" in kinds, str(kinds))
            _st = None
            for _, _pl in frames:
                try:
                    if json.loads(_pl).get("t") == "status":
                        _st = json.loads(_pl); break
                except ValueError:
                    pass
            check("status frame master compat (alive/is_router present)",
                  _st is not None and isinstance(_st.get("master"), dict)
                  and "alive" in _st["master"] and "is_router" in _st["master"],
                  str(_st.get("master") if _st else None)[:120])

            def read_rows(timeout=6):
                """collect DATA frames, skipping any interleaved push frames
                (status/bw/mtr/ping/iftop/gap) the server now streams freely"""
                out = []
                end = time.time() + timeout
                while time.time() < end and not out:
                    s.settimeout(max(0.1, end - time.time()))
                    try:
                        data = s.recv(4096)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    for op, pl in p.feed(data):
                        try:
                            if json.loads(pl).get("t", "row") in ("hello", "snap", "status",
                                                                  "bw", "mtr", "ping", "iftop", "gap"):
                                continue
                        except ValueError:
                            pass
                        out.append((op, pl))
                return out
            # broadcast live event through hub queue
            app.hub.broadcast(json.dumps({"proto": 6, "src": "9.9.9.9", "dst": "8.8.8.8",
                                          "mark": 51, "sess": 0, "ts": time.time(), "ms": 0.1}).encode())
            got = read_rows()
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
    # pdns_config/pdns_poison_list/rec_control: opt-in passthrough into argv
    spec_nopdns = svc.parse_spec({})
    check("no pdns_config by default", not spec_nopdns.get("pdns_config"))
    argv_nopdns = srv.build_argv(spec_nopdns, "/x/nft_route.json", "/x/pid")
    check("no --pdns-config flag when unset", "--pdns-config" not in argv_nopdns)
    spec_pdns = svc.parse_spec({"webadmin": {"pdns_config": "/etc/powerdns/pdns-recursor.json",
                                             "pdns_poison_list": "/etc/powerdns/dns_posion_list.txt"}})
    check("pdns_config parsed through", spec_pdns["pdns_config"] == "/etc/powerdns/pdns-recursor.json")
    argv_pdns = srv.build_argv(spec_pdns, "/x/nft_route.json", "/x/pid")
    check("--pdns-config flag present with configured path",
          "--pdns-config" in argv_pdns and "/etc/powerdns/pdns-recursor.json" in argv_pdns)
    check("--pdns-poison-list flag present",
          "--pdns-poison-list" in argv_pdns and "/etc/powerdns/dns_posion_list.txt" in argv_pdns)
    check("rec_control defaults to bare binary name", spec_pdns["rec_control"] == "rec_control")
    # pdns_host: PowerDNS Recursor on a different box -> ssh passthrough
    check("no pdns_host by default", not spec_nopdns.get("pdns_host"))
    check("no --pdns-host flag when unset", "--pdns-host" not in argv_nopdns)
    spec_remote = svc.parse_spec({"webadmin": {"pdns_config": "/etc/powerdns/pdns-recursor.json",
                                               "pdns_host": "root@10.0.0.5:2222"}})
    check("pdns_host parsed through", spec_remote["pdns_host"] == "root@10.0.0.5:2222")
    argv_remote = srv.build_argv(spec_remote, "/x/nft_route.json", "/x/pid")
    check("--pdns-host flag present with configured target",
          "--pdns-host" in argv_remote and "root@10.0.0.5:2222" in argv_remote)


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



def test_iife_scope_lint():
    print("[6c] no IIFE-local var referenced from outside (TOOL_HOOK-class bug)")
    for part in sorted(os.listdir(os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "webui_parts"))):
        if not part.endswith(".js"):
            continue
        src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "webui_parts", part)).read()
        i = src.find("(function(){")
        while i != -1:
            j = src.find("})();", i)
            if j == -1:
                break
            body, outside = src[i:j + 5], src[:i] + src[j + 5:]
            for name in set(n for n in __import__("re").findall(r"\bvar\s+(\w+)\s*=", body)
                            if len(n) > 2):          # skip trivial e/x-style locals
                import re as _r
                ext = _r.search(r"(?<![.\w])" + name + r"(?:\s*\.|\s*=|\()", outside)
                if ext:
                    check("%s: %s referenced outside its IIFE" % (part, name),
                          bool(_r.search(r"(?m)^var\s+" + name + r"\b", outside)),
                          "add a global var or move usage inside")
            i = src.find("(function(){", j + 5)
    check("scope lint done", True)


def test_tools_units():
    print("[8] network tools units (iftop parse / bw / arg validation)")
    screen = (
        "   # Host name (port/service if enabled)            last 2s   last 10s   last 40s cumulative\n"
        "--------------------------------------------------------------------------------------------\n"
        "   1 183.95.60.178                            =>     50.0Kb     25.0Kb     25.0Kb     12.5KB\n"
        "     192.168.32.2                             <=     53.8Kb     26.9Kb     26.9Kb     13.4KB\n"
        "   2 192.168.11.5                             =>     3.47Kb     1.73Kb     1.73Kb       888B\n"
        "     192.168.32.32                            <=     3.08Kb     1.54Kb     1.54Kb       788B\n"
        "   3 117.135.184.94                           =>       780b       390b       390b       195B\n"
        "     192.168.32.2                             <=     4.15Kb     2.08Kb     2.08Kb     1.04KB\n"
        "--------------------------------------------------------------------------------------------\n"
        "Total send rate:                                     54.2Kb     27.1Kb     27.1Kb\n"
        "Peak rate (sent/received/total):                     54.2Kb     61.0Kb      115Kb\n")
    pairs = wa.iftop_parse(screen)
    check("three host pairs parsed", len(pairs) == 3, str(pairs))
    p0 = [x for x in pairs if x["a"] == "183.95.60.178"][0]
    check("ab rates parsed (Kb->bytes)", p0["ab"] == [50000, 25000, 25000], str(p0))
    check("ba rates parsed", p0["ba"] == [53800, 26900, 26900], str(p0))
    sess = {"id": 1, "iface": "br0", "status": "running", "started": time.time(),
            "screen_ts": time.time(), "pairs": pairs}
    fr = wa.ift_frame(sess)
    ipa = [x for x in fr["ips"] if x["ip"] == "192.168.32.2"][0]
    check("per-ip out aggregation (53.8K+4.15K)", ipa["out"][0] == 53800 + 4150, str(ipa))
    check("per-ip in aggregation (50.0K+780)", ipa["in"][0] == 50000 + 780, str(ipa))
    check("sorted by live traffic", fr["ips"][0]["ip"] == "192.168.32.2",
          str([x["ip"] for x in fr["ips"]]))
    cfg = {"proxy": {"L1": {"mark": 11, "ipv4": True, "weight": 3, "udp_v4": True},
                     "L2": {"mark": 22, "ipv4": True, "weight": 0, "udp_v4": False},
                     "L3": {"mark": 33, "ipv4": False, "weight": 5}},
           "rules": [{"L1": {"country_code": ["US"]}, "L3": {"any": True}},
                     {"L2": {"cidr": ["10.0.0.0/8"], "from": ["192.168.1.0/24"]}},
                     {"L1": {"resolve": [".taobao.com."]}}]}
    r = wa.ipq_decide(cfg, "8.8.8.8", {"country_code": "US"})
    check("geo country rule hits prio0 with L1 mark",
          r.get("priority") == 0 and r.get("mark") == 11 and r.get("line") == "L1", str(r))
    check("ipv4-unsupported line listed as skip",
          any(x["line"] == "L3" and "ipv4" in x["skip"] for x in r.get("skips", [])), str(r.get("skips")))
    r = wa.ipq_decide(cfg, "1.2.3.4", {"country_code": "JP"}, names={"www.taobao.com"})
    check("resolve suffix matches prio2", r.get("priority") == 2 and r.get("mark") == 11, str(r))
    r = wa.ipq_decide(cfg, "1.2.3.4", {"country_code": "JP"}, names={"g.taobao.co"})
    check("resolve is suffix-anchored not substring", r.get("mark") == 0, str(r))
    r = wa.ipq_decide(cfg, "10.1.1.1", {"country_code": "JP"}, src="192.168.1.5", proto=17)
    check("udp-gated line skipped (L2), falls through", r.get("mark") == 0, str(r))
    r = wa.ipq_decide(cfg, "10.1.1.1", {"country_code": "JP"}, src="192.168.1.5")
    check("from+cidr tcp hits L2 weight0", r.get("priority") == 1 and r.get("mark") == 22, str(r))
    r = wa.ipq_decide(cfg, "10.1.1.1", {"country_code": "JP"})
    check("from-rule noted without src", r.get("mark") == 0, str(r))
    r = wa.ipq_decide(cfg, "8.8.8.8", {"country_code": "US"}, proto=1)
    check("icmp follows same chain (no udp gate on L1)",
          r.get("mark") == 11 and r.get("priority") == 0, str(r))
    r = wa.ipq_decide(cfg, "8.8.8.8", None)
    check("geo miss -> 0x99 bypass like router",
          r.get("mark") == 0x99 and "0x99" in r.get("why", ""), str(r))
    import os as _os
    if _os.path.isdir("/sys/class/net"):
        check("recommended is a real iface or any",
              wa.ift_recommended() in wa.ift_ifaces() + ["any"])
    d = wa.bw_json()
    check("bw api shape", d.get("ok") and d["interval"] == 5 and d["span"] == 900
          and isinstance(d["samples"], list))
    with wa.bw_lock:
        wa.bw_hist.append([time.time(), {"eth0": [1234, 5678], "lo": [9, 9]}])
    d = wa.bw_json()
    check("bw peak max-aggregated", d["peak"][0]["iface"] == "eth0"
          and d["peak"][0]["tx"] == 5678, str(d["peak"]))
    with wa.bw_lock:
        wa.bw_hist.pop()
    r = wa.ift_start({"iface": "no-such-if-9"})
    check("iftop unknown iface rejected", not r["ok"] and "未知接口" in r["error"], str(r))
    r = wa.ift_start({"iface": "; rm -rf /"})
    check("iftop illegal iface name rejected", not r["ok"], str(r))
    r = wa.ift_stop("test")
    check("iftop stop when idle is harmless", r.get("ok"), str(r))
    bad = {"line": "default"}
    for fn, b, why in ((wa.ping_start, dict(bad, target="x; rm -rf /"), "ping target inject"),
                       (wa.dig_run, dict(bad, target="ok.com", type="ANY"), "dig type allowlist"),
                       (wa.whois_run, {"target": "-h evil"}, "whois dash-arg"),
                       (wa.ping_start, dict(bad, target="a b"), "ping space")):
        r = fn(b, {}) if fn is not wa.whois_run else fn(b)
        check("%s rejected" % why, not r.get("ok"), str(r))
    r = wa.dig_run({"target": "example.com", "type": "A", "line": "zzz"}, {})
    check("dig unknown line rejected before spawn", not r["ok"] and "未知线路" in r["error"], str(r))
    r = wa.ipq_run({"ips": "not an ip"}, {}, "")
    check("ipq without valid ips", not r["ok"], str(r))

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        test_master_signal(d)
    for t in (test_ws_codec, test_ring_hub, test_validate_config, test_dnsmasq_reload, test_ui_js_syntax, test_iife_scope_lint,
              test_server_e2e, test_webadmin_service_lifecycle, test_webadmin_real_child_smoke,
              test_tools_units):
        t()
    print("\n==== %d passed, %d failed ====" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)

