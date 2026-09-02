#!/usr/bin/env python3
"""Offline tests for udp_tproxy.py: rt_tables management, route-table
content, per-mark ip rule reconcile. No root, no kernel -- fake
/etc/iproute2/rt_tables path + a mock pyroute2.IPRoute.
Run: python3 test_udp_tproxy.py"""

import os
import socket
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import udp_tproxy as ut

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


class MockIPRoute:
    """Mirrors test_iface_bind.py's MockIPRoute shape (rule/route/get_rules/
    get_routes/link_lookup), extended with ip_proto on rules."""
    def __init__(self, links=None, rules=None, routes=None):
        self.links = links if links is not None else {"lo": 1}
        self.rules = list(rules or [])
        self.routes = list(routes or [])
        self.calls = []

    def link_lookup(self, ifname=None):
        return [self.links[ifname]] if ifname in self.links else []

    def get_rules(self, family=None):
        return [r for r in self.rules if r.get("family") in (family, None)]

    def rule(self, cmd, **kw):
        self.calls.append(("rule", cmd, kw))
        if cmd == "add":
            self.rules.append(dict(kw))
        elif cmd == "del":
            self.rules = [
                r for r in self.rules
                if not (r.get("priority") == kw.get("priority")
                        and r.get("fwmark") == kw.get("fwmark")
                        and r.get("table") == kw.get("table"))
            ]

    def get_routes(self, table=None, dst=None, family=None):
        return [r for r in self.routes
                if r.get("table") == table and r.get("family") in (family, None)]

    def route(self, cmd, **kw):
        self.calls.append(("route", cmd, kw))
        if cmd == "add":
            self.routes.append(dict(kw))
        elif cmd == "del":
            self.routes = [r for r in self.routes if r.get("table") != kw.get("table")]


def test_rt_table_name():
    print("[1] rt_tables: create / reuse / collision avoidance")
    d = tempfile.mkdtemp()
    path = os.path.join(d, "rt_tables")
    logs = []
    num = ut.ensure_rt_table_name("tproxy", preferred=100, path=path, log=logs.append)
    check("assigned preferred id", num == 100)
    check("file created with entry", "100\ttproxy\n" in open(path).read())
    check("logged the addition", any("100 tproxy" in m for m in logs))

    # idempotent: calling again returns the SAME id, no duplicate line
    num2 = ut.ensure_rt_table_name("tproxy", preferred=100, path=path)
    check("second call reuses existing id", num2 == 100)
    check("no duplicate rt_tables line", open(path).read().count("tproxy") == 1)

    # collision: table id 100 already taken by something ELSE -> skip to next free
    path2 = os.path.join(d, "rt_tables2")
    with open(path2, "w") as f:
        f.write("100\tsomeother\n254\tmain\n255\tlocal\n")
    num3 = ut.ensure_rt_table_name("tproxy", preferred=100, path=path2)
    check("collision -> next free id used", num3 == 101, str(num3))

    # missing file entirely -> still works, creates it
    path3 = os.path.join(d, "does_not_exist_yet", "rt_tables")
    num4 = ut.ensure_rt_table_name("tproxy", preferred=100, path=path3)
    check("missing rt_tables file handled", num4 == 100 and os.path.exists(path3))

    # unwritable directory -> best-effort, still returns a usable numeric id
    ro_dir = os.path.join(d, "ro")
    os.makedirs(ro_dir)
    os.chmod(ro_dir, 0o500)
    path4 = os.path.join(ro_dir, "rt_tables")
    logs2 = []
    try:
        num5 = ut.ensure_rt_table_name("tproxy", preferred=100, path=path4, log=logs2.append)
        check("unwritable path -> still returns numeric id, no crash", num5 == 100)
        check("logged the failure instead of raising", any("could not persist" in m for m in logs2))
    finally:
        os.chmod(ro_dir, 0o700)


def test_local_lo_route():
    print("[2] default dev lo scope link (unicast): add + idempotent")
    ipr = MockIPRoute()
    logs = []
    added = ut.ensure_local_lo_route(ipr, 100, 4, log=logs.append)
    check("route added first time", added is True)
    check("route uses lo ifindex, unicast, scope link",
          ipr.routes[0]["oif"] == 1 and ipr.routes[0]["scope"] == "link"
          and ipr.routes[0].get("type") in (None, "unicast"))
    check("table id correct", ipr.routes[0]["table"] == 100)

    added2 = ut.ensure_local_lo_route(ipr, 100, 4, log=logs.append)
    check("second call is a no-op (idempotent)", added2 is False and len(ipr.routes) == 1)

    # missing lo interface -> clear error, not a silent no-op
    ipr_no_lo = MockIPRoute(links={})
    try:
        ut.ensure_local_lo_route(ipr_no_lo, 100, 4)
        check("missing lo raises", False)
    except ValueError as e:
        check("missing lo raises clear error", "lo" in str(e))


def test_mark_rule_and_sweep():
    print("[3] per-mark ip rule: add / idempotent / stale sweep")
    ipr = MockIPRoute()
    logs = []
    a1 = ut.ensure_mark_rule(ipr, 51, 4, 100, 28051, log=logs.append)
    check("rule added", a1 is True)
    r = ipr.rules[0]
    check("fwmark set", r["fwmark"] == 51)
    check("ip_proto is UDP (17)", r["ip_proto"] == socket.IPPROTO_UDP)
    check("table matches", r["table"] == 100)
    check("logged with fwmark/udp/table wording", "fwmark 51" in logs[-1] and "udp" in logs[-1])

    a2 = ut.ensure_mark_rule(ipr, 51, 4, 100, 28051)
    check("second add is idempotent (no duplicate)", a2 is False and len(ipr.rules) == 1)

    ut.ensure_mark_rule(ipr, 903, 4, 100, 28000 + 903 % 900)  # 903%900=3 -> in-band prio 28003
    check("2 rules present before sweep", len(ipr.rules) == 2)
    removed = ut.sweep_stale_rules(ipr, keep_marks={51}, family=4, table_id=100, log=logs.append)
    check("stale mark 903 removed", removed == [903])
    check("mark 51 kept", {r["fwmark"] for r in ipr.rules} == {51})

    # a rule for the SAME table but OUTSIDE our owned priority band must never be touched
    ipr2 = MockIPRoute(rules=[{"family": socket.AF_INET, "fwmark": 999, "ip_proto": socket.IPPROTO_UDP,
                              "table": 100, "priority": 500}])
    removed2 = ut.sweep_stale_rules(ipr2, keep_marks=set(), family=4, table_id=100)
    check("foreign-priority rule on our table left untouched", removed2 == [] and len(ipr2.rules) == 1)


def test_sync_end_to_end():
    print("[4] sync(): full reconcile, v4+v6 independent, idempotent")
    d = tempfile.mkdtemp()
    path = os.path.join(d, "rt_tables")
    ipr = MockIPRoute()
    logs = []
    # sync()'s default rt_tables path is the real /etc/iproute2/rt_tables;
    # exercise the same pyroute2-facing reconcile steps sync() performs
    # internally against an explicit temp path instead (rt_tables file I/O
    # itself is already covered end-to-end by test 1).
    table_id = ut.ensure_rt_table_name("tproxy", preferred=100, path=path)
    res = {"table_id": table_id,
           "route_added": ut.ensure_local_lo_route(ipr, table_id, 4, log=logs.append)}
    added = [m for m in (51, 903)
             if ut.ensure_mark_rule(ipr, m, 4, table_id, 28000 + m % 900, log=logs.append)]
    check("both marks got rules", sorted(added) == [51, 903])
    check("route added once", res["route_added"] is True)

    # second pass: fully idempotent, and mark 51 removed from config -> swept
    removed = ut.sweep_stale_rules(ipr, keep_marks={903}, family=4, table_id=table_id, log=logs.append)
    check("removed mark no longer configured", removed == [51])
    check("kept mark still present", {r["fwmark"] for r in ipr.rules} == {903})

    # v6 uses a SEPARATE family filter on get_rules/get_routes -- adding a v6
    # mark must not disturb the v4 rule/route just verified above
    ipr.route("add", dst="default", type="local", scope="host", oif=1, table=table_id,
              family=socket.AF_INET6)
    added_v6 = ut.ensure_mark_rule(ipr, 903, 6, table_id, 28903)
    check("v6 rule for same mark coexists with v4 rule (different family)",
          added_v6 is True and
          {(r["fwmark"], r["family"]) for r in ipr.rules} == {(903, socket.AF_INET), (903, socket.AF_INET6)})


def test_sync_full_call():
    print("[5] sync(): the actual public entry point, called directly")
    d = tempfile.mkdtemp()
    path = os.path.join(d, "rt_tables")
    ipr = MockIPRoute()
    res1 = ut.sync(ipr, [51, 903], 4, rt_tables_path=path)
    check("both marks reconciled", sorted(res1["rules_added"]) == [51, 903])
    check("route added", res1["route_added"] is True)
    check("nothing removed on first sync", res1["rules_removed"] == [])

    res2 = ut.sync(ipr, [51, 903], 4, rt_tables_path=path)
    check("second identical sync is fully idempotent",
          res2["rules_added"] == [] and res2["route_added"] is False and res2["rules_removed"] == [])

    res3 = ut.sync(ipr, [51], 4, rt_tables_path=path)
    check("dropping 903 from config removes its rule on next sync",
          res3["rules_removed"] == [903])
    check("uses the SAME table id across calls (rt_tables reused, not re-picked)",
          res1["table_id"] == res2["table_id"] == res3["table_id"])


if __name__ == "__main__":
    for t in (test_rt_table_name, test_local_lo_route, test_mark_rule_and_sweep,
              test_sync_end_to_end, test_sync_full_call):
        t()
    print("\n==== %d passed, %d failed ====" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)
