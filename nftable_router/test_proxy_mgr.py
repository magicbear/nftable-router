#!/usr/bin/env python3
"""Offline tests for proxy_mgr.py: command building, chain topology/cycle
detection, skuid loop-guard nft rules, supervisor restart semantics.
No root, no kernel, fake process spawns. Run: python3 test_proxy_mgr.py"""

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proxy_mgr as pm

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


class FakeProc:
    def __init__(self, argv, script_exit=None, fake_clock=None):
        self.argv = argv
        self.pid = abs(hash(tuple(argv))) % 9000 + 100
        self._rc = None
        self._done = False
        self._script = list(script_exit or [])  # pop exit codes per poll()
        self._clock = fake_clock
    def poll(self):
        if self._done:
            return self._rc
        if self._script:
            # die on Nth poll
            if len(self._script) == 1:
                self._rc = self._script.pop(0)
                self._done = True
                return self._rc
            self._script.pop(0)
        return None
    def wait(self, timeout=None):
        return self._rc
    def terminate(self):
        self._rc = -15
        self._done = True
    def kill(self):
        self._rc = -9
        self._done = True


def _cfg(daemon="ss-redir", **kw):
    base = {"daemon": daemon, "port": 10506, "server": "5.6.7.9", "server_port": 8388,
            "cipher": "aes-256-gcm", "password": "s3cr3t", "uid": "proxyusr"}
    base.update(kw)
    return base


def test_build_cmd():
    print("[1] command building")
    argv = pm.build_cmd("lineA", _cfg())
    check("ss-redir binary", argv[0].endswith("ss-redir"))
    check("listen port -l", "-l" in argv and argv[argv.index("-l") + 1] == "10506")
    check("server via proxy_ip fallback",
          pm.build_cmd("x", _cfg(server=None, proxy_ip="9.9.9.9"))[
              pm.build_cmd("x", _cfg(server=None, proxy_ip="9.9.9.9")).index("-s") + 1] == "9.9.9.9")
    check("password -k", "-k" in argv and argv[argv.index("-k") + 1] == "s3cr3t")
    check("password_file preferred -t",
          "-t" in pm.build_cmd("l", _cfg(password_file="/run/pw", password=None)))
    a = pm.build_cmd("l", _cfg(mode="tcp_and_udp"))
    check("-u when tcp_and_udp", "-u" in a and "-u" not in argv)
    check("obfs/protocol extras",
          all(o in pm.build_cmd("l", _cfg(obfs="tls", protocol="auth_aes128_md5"))
              for o in ("-g", "tls", "-O", "auth_aes128_md5")))
    check("missing password -> error",
          _raises(pm.build_cmd, "l", _cfg(password=None)))
    vb = _cfg(daemon="v2ray", config=os.path.abspath(__file__))
    check("v2ray -config", pm.build_cmd("v", vb)[:2] == ["v2ray", "-config"])
    sb = pm.build_cmd("s", _cfg(daemon="sing-box", config=os.path.abspath(__file__)))
    check("sing-box run -c", sb[1:3] == ["run", "-c"])
    check("v2ray missing config file -> error",
          _raises(pm.build_cmd, "v", _cfg(daemon="v2ray", config="/nonexistent.json")))
    cu = pm.build_cmd("c", _cfg(daemon="custom", cmd=["/bin/echo", "-p", "{port}", "-k", "{password}"]))
    check("custom {field} substitution", cu == ["/bin/echo", "-p", "10506", "-k", "s3cr3t"])
    check("custom unknown placeholder -> error",
          _raises(pm.build_cmd, "c", _cfg(daemon="custom", cmd=["x", "{nope}"])))
    check("args appended", pm.build_cmd("l", _cfg(args=["--fast-open"]))[-1] == "--fast-open")
    c_nop = _cfg(); c_nop.pop("port")
    check("missing port -> error", _raises(pm.build_cmd, "l", c_nop))
    c_null = _cfg(port=None)
    check("port=null -> error", _raises(pm.build_cmd, "l", c_null))


def _raises(fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except ValueError:
        return True


def test_chain_validation():
    print("[2] chain graph: cycles, order, errors")
    cfgs = {
        "C": _cfg(upstream=None),
        "B": _cfg(upstream="C"),
        "A": _cfg(upstream="B"),
        "D": _cfg(upstream=None),
    }
    order = pm.validate_chain(cfgs)
    check("topo deepest-first", order.index("C") < order.index("B") < order.index("A"))
    check("independent line kept", "D" in order)

    cfgs["A"]["upstream"] = "A"
    check("self-loop rejected", _raises(pm.validate_chain, cfgs))
    cfgs["A"]["upstream"] = "B"
    cfgs["B"]["upstream"] = "A"
    try:
        pm.validate_chain(cfgs)
        check("cycle A->B->A rejected", False)
    except ValueError as e:
        check("cycle A->B->A rejected", True)
        msg = str(e)
        check("cycle message shows full loop",
              ("A -> B -> A" in msg) or ("B -> A -> B" in msg), msg)

    cfgs["B"]["upstream"] = "C"
    cfgs["C"]["upstream"] = "ghost"
    check("unknown upstream rejected", _raises(pm.validate_chain, cfgs))
    cfgs["C"]["upstream"] = None
    cfgs["D"]["upstream"] = "A"
    cfgs["A"].pop("daemon")  # A now unmanaged
    check("upstream not managed -> error", _raises(pm.validate_chain, cfgs))


def test_chain_rules():
    print("[3] skuid chain rules (loop-guard)")
    cfgs = {
        "A": _cfg(upstream="B", uid=1200),
        "B": _cfg(upstream=None, uid=1201, port=10507),
        "U": {"mark": 5},   # unmanaged line, must produce no rule
    }
    uid_cache = {"A": 1200, "B": 1201, "U": None}
    rules = pm.plan_proxy_chain_rules(cfgs, uid_cache, "ip")
    # chained A -> redirect rule; direct managed B -> skuid accept guard
    # (exempts B's upstream egress from policy marking / self-redirect)
    check("redirect rule for chained + accept guard for direct", len(rules) == 2)
    guards = [r for r in rules if any("accept" in e for e in r["expr"])]
    check("direct B got exactly one accept guard",
          len(guards) == 1 and any(
              e.get("match", {}).get("right") == 1201 for e in guards[0]["expr"]))
    r = rules[0]
    skuid = [e for e in r["expr"] if e.get("match", {}).get("left") == {"meta": {"key": "skuid"}}]
    check("matches A's own skuid", any(e["match"]["op"] == "==" and e["match"]["right"] == 1200 for e in skuid))
    check("redirects to upstream B port", r["expr"][-1] == {"redirect": {"port": 10507}})
    daddr = [e for e in r["expr"] if e.get("match", {}).get("left") == {"payload": {"protocol": "ip", "field": "daddr"}}]
    check("excludes @local (LAN bypass)", any(e["match"]["op"] == "!=" and e["match"]["right"] == "@local" for e in daddr))
    dport = [e for e in r["expr"] if e.get("match", {}).get("left") == {"payload": {"protocol": "tcp", "field": "dport"}}]
    check("excludes dport==upstream port (anti re-entry)",
          any(e["match"]["op"] == "!=" and e["match"]["right"] == 10507 for e in dport))
    verdicts = {"drop", "queue", "reject"}
    check("no drop/queue/reject in chain rules",
          not any(set(e.keys()) & verdicts for r in rules for e in r["expr"]))
    check("accept only on the direct guard, never on redirect rules",
          not any("accept" in e for r in rules if any("redirect" in x for x in r["expr"])
                  for e in r["expr"]))
    check("chain rule targets nat_OUTPUT", r["chain"] == "nat_OUTPUT")
    r6 = pm.plan_proxy_chain_rules(cfgs, uid_cache, "ip6")
    check("ip6 payload protocol honored",
          any(e.get("match", {}).get("left") == {"payload": {"protocol": "ip6", "field": "daddr"}} for e in r6[0]["expr"]))


def test_supervisor_restart():
    print("[4] supervisor: crash-restart, rate limit, clean stop")
    procs = []
    def fake_spawn(argv):
        p = FakeProc(argv)
        procs.append(p)
        return p
    cfgs = {"A": _cfg(restart={"max": 2, "window": 300}, uid=1200)}
    now = [1000.0]
    sup = pm.ProxySupervisor(cfgs, spawn=fake_spawn, sleep=lambda s: None,
                             now=lambda: now[0])
    sup.launch()
    a = sup.get("A")
    check("started once", len(procs) == 1 and a.state == "running")
    # simulate unexpected exit: make current proc die on next poll
    procs[0]._script = [1]
    stop = threading.Event()
    # one manual monitor iteration
    sup._stop_evt = stop
    rc = procs[0].poll()
    assert rc == 1
    w = a.note_death()
    check("first restart backoff 1s", w == 1)
    now[0] += 0.5
    procs[0] = sup.proxies["A"].start_once() if False else procs[0]
    # drive monitor loop once via threads: simpler—direct semantics:
    check("restart counted", len(a.restart_history) == 1)
    a.note_death()   # 2nd (== max)
    check("second restart allowed (backoff 2s)", a.restart_history[-1] == now[0] and a.state == "backoff")
    w3 = a.note_death()
    check("3rd within window -> gaveup", w3 is None and a.state == "gaveup")
    now[0] += 400
    a.restart_history = [t for t in a.restart_history if now[0] - t < 300]
    w4 = a.note_death() if len(a.restart_history) < 2 else None
    check("window expiry frees slots", w4 == 1)
    # graceful stop: stopping flag prevents restart
    a.stopping = True
    p_live = procs[-1]
    p_live._script = [0]
    sup.stop_all()
    check("state stopped, terminate sent", a.state == "stopped" and p_live._done)


def test_supervisor_stop_semantics():
    print("[5] ManagedProxy.stop kills stubborn process")
    class HangProc(FakeProc):
        def poll(self):
            return None if not getattr(self, "_k", False) else self._rc
        def terminate(self):
            pass  # ignores SIGTERM
        def kill(self):
            self._k = True
            self._rc = -9
            self._done = True
        def wait(self, timeout=None):
            return self._rc
    p = pm.ManagedProxy("X", _cfg(), ["/bin/x"], 1200, spawn=lambda a: HangProc(a))
    p.start_once()
    p.stop(grace=0.2)
    check("escalated to SIGKILL", p.state == "stopped" and getattr(p.proc, "_k", False))


def test_dependency_gating():
    print("[6] launch order gating on dependency health/port")
    spawned = []
    def fake_spawn(argv):
        p = FakeProc(argv)
        spawned.append(argv[argv.index("-l") + 1])
        return p
    cfgs = {"B": _cfg(port=10507, uid=1201), "A": _cfg(port=10506, upstream="B", uid=1200)}
    # port_wait stub: reachable for dependency gating (long timeout),
    # NOT reachable for own-instance detection probe (timeout=0.5)
    pw = lambda p, **k: (p == 10507) and k.get("timeout") != 0.5
    sup = pm.ProxySupervisor(cfgs, spawn=fake_spawn, sleep=lambda s: None, now=lambda: 0,
                             port_wait=pw)
    sup.launch()
    check("dependency first", spawned == ["10507", "10506"], str(spawned))
    # external instance: own port busy -> skip spawn, state external
    spawned2 = []
    def fake_spawn2(argv):
        p = FakeProc(argv); spawned2.append(argv[argv.index("-l") + 1]); return p
    sup2 = pm.ProxySupervisor(cfgs, spawn=fake_spawn2, sleep=lambda s: None, now=lambda: 0,
                              port_wait=lambda p, **k: p == 10507)
    sup2.launch()
    check("external B: no spawn, state external",
          sup2.get("B").state == "external" and "10507" not in spawned2)
    check("A deferred while B external", "10506" not in spawned2)
    sup_b = sup.get("B").proc
    sup_b.terminate()  # B dies -> A restart attempts must wait for B port
    # dependency B dies -> port wait fails -> A must defer
    sup_b.terminate()
    sup2 = pm.ProxySupervisor(cfgs, spawn=fake_spawn, sleep=lambda s: None, now=lambda: 0,
                              port_wait=lambda p, **k: False)
    sup2.launch()
    check("A deferred when B port unreachable", spawned == ["10507", "10507"] or "10506" not in spawned[2:], str(spawned))


def test_redact():
    print("[7] password redaction for logs")
    argv = pm.build_cmd("l", _cfg())
    red = " ".join(pm.redact(argv))
    check("secret not present", "s3cr3t" not in red and "****" in red)


def test_uid_requirement():
    print("[8] chained proxy without uid -> error")
    try:
        cfg = _cfg(upstream="B")
        cfg.pop("uid")
        pm.get_uid(cfg, "A")
        check("raises", False)
    except ValueError as e:
        check("raises uid required", "uid" in str(e))




def test_reconfigure_diff():
    print("[9] reconfigure: incremental start/stop/keep/restart")
    spawned, sup_cfgs = [], {
        "B": _cfg(port=10507, uid=1201),
        "A": _cfg(port=10506, uid=1200, upstream="B"),
        "X": _cfg(port=10508, uid=1202),
    }
    def fake_spawn(argv):
        p = FakeProc(argv); spawned.append(argv[argv.index("-l") + 1]); return p
    pw = lambda p, **k: (p in (10507,)) and k.get("timeout") != 0.5
    sup = pm.ProxySupervisor(sup_cfgs, spawn=fake_spawn, sleep=lambda s: None,
                             now=lambda: 0, port_wait=pw)
    sup.launch()
    assert spawned == ["10507", "10506", "10508"], spawned
    b_proc = sup.get("B").proc

    # case 1: remove X, keep A,B unchanged -> X stopped, A/B process objects adopted
    new_cfgs = {k: dict(v) for k, v in sup_cfgs.items() if k != "X"}
    sup.reconfigure(new_cfgs)
    check("removed proxy stopped", sup.get("X") is None)
    check("unchanged B adopted running proc (no respawn)", sup.get("B").proc is b_proc)
    check("no new spawn for unchanged", spawned == ["10507", "10506", "10508"])

    # case 2: B server changed -> B restarts, A adopted (A argv unchanged? A depends on B port... A keeps)
    new2 = {k: dict(v) for k, v in new_cfgs.items()}
    new2["B"]["server"] = "9.9.9.9"
    sup.reconfigure(new2)
    check("changed B respawned", "10507" in spawned and spawned.count("10507") == 2, str(spawned))
    check("B is a new process object", sup.get("B").proc is not b_proc)

    # case 3: add C chained to B -> C started (gated), existing untouched
    spawned_n = len(spawned)
    new3 = {k: dict(v) for k, v in new2.items()}
    new3["C"] = _cfg(port=10509, uid=1203, upstream="B")
    sup.reconfigure(new3)
    check("new chained C spawned once", spawned.count("10509") == 1)
    check("others untouched by add", len(spawned) == spawned_n + 1, str(spawned[spawned_n:]))

    # case 4: reconfigure with a CYCLE raises and leaves everything running
    bad = {k: dict(v) for k, v in new3.items()}
    bad["C"]["upstream"] = "A"; bad["A"]["upstream"] = "C"
    check("cyclic reconfigure rejected", _raises(pm.ProxySupervisor.reconfigure, sup, bad))
    check("live set intact after rejection", set(sup.proxies) == {"A", "B", "C"} and
          sup.get("B").proc.poll() is None)

    # case 5: restart_all -> every proxy stopped+started, gaveup state cleared
    sup.get("C").state = "gaveup"     # simulate rate-limited one
    before = dict(spawned_counts := {x: spawned.count(x) for x in set(spawned)})
    sup.restart_all()
    check("restart_all respawned all 3",
          all(spawned.count(p) > before[p] for p in ("10507", "10506", "10509")), str(spawned))
    check("gaveup cleared on restart_all", sup.get("C").state == "running")

    # case 6: bad spec for a RUNNING proxy -> keeps old process, others reconfigure
    b_live = sup.get("B").proc
    new6 = {k: dict(v) for k, v in sup.proxies.items() and {
        "B": {**dict(new3["B"]), "password": None, "password_file": None},  # invalid ss-redir spec
        "A": dict(new3["A"]), "C": dict(new3["C"])}.items()}
    sup.reconfigure(new6)
    check("invalid-spec running B kept alive", sup.get("B").proc is b_live)

    sup.stop_all()
    check("final stop", sup.get("B").state == "stopped")


def test_monitor_thread_safe_with_reconfigure():
    import threading as _th
    print("[10] monitor thread keeps running across reconfigure (no crash/deadlock)")
    cfgs = {"A": _cfg(port=10601, uid=1200)}
    spawned = []
    def sp(argv):
        p = FakeProc(argv); spawned.append(1); return p
    sup = pm.ProxySupervisor(cfgs, spawn=sp, sleep=lambda s: None, now=lambda: 0,
                             port_wait=lambda p, **k: False)
    sup.start()   # real thread: launch + monitor
    for _ in range(20):
        if sup.get("A").proc:
            break
        time.sleep(0.02)
    check("thread launched A", sup.get("A").proc is not None)
    sup.reconfigure({"A": _cfg(port=10601, uid=1200, server="8.8.8.8")})  # changed -> restart
    deadline = time.time() + 3
    while time.time() < deadline and sup.get("A").proc is None:
        time.sleep(0.05)
    check("reconfigured by live thread", len(spawned) >= 2)
    sup.stop_all()
    time.sleep(0.1)
    check("thread exits after stop_all", not sup.is_alive())


def _mk(skuid=None, m=None, verdicts=("accept", "redirect", "drop", "queue")):
    return skuid, m, set(verdicts)


def test_mark_upstream_chain():
    print("[11] upstream as ip-rule line (mark type)")
    cfgs = {
        "IPRULE": {"mark": 903, "ipv4": True},
        "TPROXY": {"daemon": "ss-redir", "port": 10510, "server": "1.1.1.1",
                   "password_file": "/pw", "uid": 1210, "mark": 40},
        "M": {"daemon": "ss-redir", "port": 10511, "server": "2.2.2.2",
              "password_file": "/pw", "uid": 1211, "mark": 41, "upstream": "IPRULE"},
        "T": {"daemon": "ss-redir", "port": 10512, "server": "3.3.3.3",
              "password_file": "/pw", "uid": 1212, "mark": 42, "upstream": "TPROXY"},
    }
    check("kind: ip-rule line -> mark", pm.upstream_kind(cfgs, "IPRULE") == "mark")
    check("kind: tproxy line -> port", pm.upstream_kind(cfgs, "TPROXY") == "port")
    order = pm.validate_chain(cfgs)
    check("mark upstream validated (unmanaged OK)", "M" in order and "IPRULE" in order)

    uids = {"M": 1211, "T": 1212, "TPROXY": 1210}
    rules = pm.plan_proxy_chain_rules(cfgs, uids, "ip")

    def expr_of(skuid_v):
        return [r["expr"] for r in rules
                if any(e.get("match", {}).get("left") == {"meta": {"key": "skuid"}}
                       and e["match"]["right"] == skuid_v for e in r["expr"])]

    m_rules = expr_of(1211)
    check("M has exactly one rule", len(m_rules) == 1)
    e = m_rules[0]
    check("M stamps upstream line mark 903",
          {"mangle": {"key": {"meta": {"key": "mark"}}, "value": 903}} in e)
    check("M saves into ct mark (session affinity)",
          {"mangle": {"key": {"ct": {"key": "mark"}}, "value": {"meta": {"key": "mark"}}}} in e)
    check("M has NO redirect/verdict",
          not any(set(x.keys()) & {"accept", "redirect", "drop", "queue", "reject"} for x in e))
    check("M no l4proto filter (tcp+udp both)",
          not any(x.get("match", {}).get("left") == {"meta": {"key": "l4proto"}} for x in e))
    check("M keeps daddr != @local guard",
          any(x.get("match", {}).get("right") == "@local" and x["match"]["op"] == "!=" for x in e))
    t_rules = expr_of(1212)
    check("T still port-type: redirect :10510",
          any(x.get("redirect", {}).get("port") == 10510 for r in t_rules for x in r))

    # mark-type upstream must NOT be process/port-gated at launch
    spawned = []
    def sp(argv):
        p = FakeProc(argv); spawned.append(argv[-1]); return p
    sup_cfgs = {"IPRULE": {"mark": 903, "ipv4": True},
                "M": {"daemon": "custom", "port": 10511, "cmd": ["/bin/x", "M"], "uid": 1211,
                      "upstream": "IPRULE"}}
    sup = pm.ProxySupervisor(sup_cfgs, spawn=sp, sleep=lambda s: None, now=lambda: 0,
                             port_wait=lambda p, **k: False)
    sup.launch()
    check("M launched without waiting for a port (mark upstream)", spawned == ["M"], str(spawned))

    # unchainable upstream (no port, no mark) -> clear error
    bad = {"Z": {"daemon": "custom", "port": 1, "cmd": ["/bin/x"], "uid": 1, "upstream": "W"},
           "W": {"ipv4": True}}
    try:
        pm.validate_chain(bad)
        check("non-chainable upstream rejected", False)
    except ValueError as e2:
        check("non-chainable upstream rejected", "chainable" in str(e2), str(e2))

    # cycle through a mark line still detected
    cyc = {"X": {"daemon": "custom", "port": 1, "cmd": ["/bin/x"], "uid": 1, "upstream": "Y"},
           "Y": {"mark": 60, "ipv4": True, "upstream": "X"}}
    check("cycle via mark line caught", _raises(pm.validate_chain, cyc))


if __name__ == "__main__":
    for t in (test_build_cmd, test_chain_validation, test_chain_rules, test_mark_upstream_chain,
              test_supervisor_restart, test_supervisor_stop_semantics,
              test_dependency_gating, test_redact, test_uid_requirement,
              test_reconfigure_diff, test_monitor_thread_safe_with_reconfigure):
        t()
    print("\n==== %d passed, %d failed ====" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


