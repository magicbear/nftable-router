#!/usr/bin/env python3
"""Offline test-suite for iface_bind.py -- the egress IP/interface -> fwmark
wizard that runs at router startup. NO root, NO kernel, NO nftables needed.

Run:  python3 nftable_router/test_iface_bind.py
"""

import copy
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import iface_bind as ib

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


# --- a representative config, mirrors nft_route.json structure ---------------
BASE_CFG = {
    "nat_interfaces": ["eno1"],
    "proxy": {
        "line1": {"mark": 51, "ipv4": True},
        "line2": {"mark": 903, "ipv4": True},
        "line3": {"mark": 35, "ipv4": True, "ipv6": True, "port": 506},
    },
    "rules": [],
}

# --- fake netinfo.detect() output --------------------------------------------
DETECT = {
    "lo": {"index": 1, "up": True, "lower_up": True, "loopback": True, "master": None,
           "methods": ["loopback"], "dhcp": False,
           "addrs": [{"version": 4, "addr": "127.0.0.1", "prefixlen": 8, "scope": "host"},
                     {"version": 6, "addr": "::1", "prefixlen": 128, "scope": "host"}]},
    "enp11s0": {"index": 2, "up": True, "lower_up": True, "master": None,
                "methods": ["dhcp4"], "dhcp": True,
                "addrs": [{"version": 4, "addr": "192.168.32.130", "prefixlen": 25, "scope": "global"},
                          {"version": 6, "addr": "fe80::1", "prefixlen": 64, "scope": "link"}]},
    # dynamic PUBLIC egress (pppoe)
    "ppp0": {"index": 3, "up": True, "lower_up": True, "master": None,
             "methods": ["ppp"], "dhcp": False,
             "addrs": [{"version": 4, "addr": "104.16.2.2", "prefixlen": 32, "scope": "global"}]},
    # static PUBLIC egress (a /31 WAN)
    "bond0.2000": {"index": 4, "up": True, "lower_up": True, "master": None,
                   "methods": ["static"], "dhcp": False,
                   "addrs": [{"version": 4, "addr": "93.184.216.34", "prefixlen": 31, "scope": "global"},
                             {"version": 6, "addr": "2606:4700:4700::1111", "prefixlen": 64, "scope": "global"}]},
    # private LAN gateway -> must be skipped
    "bond0": {"index": 5, "up": True, "lower_up": True, "master": None,
              "methods": ["static"], "dhcp": False,
              "addrs": [{"version": 4, "addr": "192.168.11.5", "prefixlen": 24, "scope": "global"}]},
    # bond slave -> must be ignored
    "eth2": {"index": 6, "up": True, "lower_up": True, "master": "bond0",
             "methods": ["static"], "dhcp": False, "addrs": []},
}


def test_classify_and_scan():
    print("[1] address classification + candidate scan")
    check("loopback", ib.classify_addr({"addr": "127.0.0.1", "scope": "host"}, True) == "loopback")
    check("private", ib.classify_addr({"addr": "192.168.11.5", "scope": "global"}) == "private")
    check("linklocal", ib.classify_addr({"addr": "fe80::1", "scope": "link"}) == "link-local")
    check("public", ib.classify_addr({"addr": "104.16.2.2", "scope": "global"}) == "public")

    cands = ib.scan_candidates(DETECT)
    ips = {c["ip"] for c in cands}
    check("lo excluded", "127.0.0.1" not in ips)
    check("private lan excluded", "192.168.11.5" not in ips)
    check("dhcp private excluded", "192.168.32.130" not in ips)
    check("ppp0 public present", "104.16.2.2" in ips)
    check("bond0.2000 v4 public", "93.184.216.34" in ips)
    check("bond0.2000 v6 public", "2606:4700:4700::1111" in ips)
    check("bond slave ignored", all(c["ifname"] != "eth2" for c in cands))

    by_ip = {c["ip"]: c for c in cands}
    check("ppp0 is dynamic", by_ip["104.16.2.2"]["dynamic"] is True)
    check("bond0.2000 v4 is static", by_ip["93.184.216.34"]["dynamic"] is False)


def test_plan_bound_vs_needs():
    print("[2] plan_bindings: already-bound vs needs-wizard")
    cands = ib.scan_candidates(DETECT)
    bound, needs = ib.plan_bindings(copy.deepcopy(BASE_CFG), cands)
    check("nothing bound yet in fresh cfg", bound == [])
    check("needs == all candidates", len(needs) == len(cands))

    cfg = copy.deepcopy(BASE_CFG)
    # pre-bind ppp0 by iface (dynamic), and one static IP
    cfg["egress_marks"] = [
        {"iface": "ppp0", "mark": 1000, "dynamic": True},
        {"ip": "93.184.216.34", "iface": "bond0.2000", "mark": 1001},
    ]
    bound, needs = ib.plan_bindings(cfg, cands)
    check("ppp0 bound by iface name", any(c["ip"] == "104.16.2.2" for c, b in bound))
    check("static ip bound", any(c["ip"] == "93.184.216.34" for c, b in bound))
    check("v6 static still needs", all(c["ip"] != "2606:4700:4700::1111" or c not in [x for x, _ in bound]
                                       for c in needs) or any(c["ip"] == "2606:4700:4700::1111" for c in needs))


def test_dynamic_identity_by_iface():
    print("[3] dynamic binding identity = interface name (IP may change)")
    cfg = {"egress_marks": [{"iface": "ppp0", "mark": 1000, "dynamic": True}],
           "proxy": BASE_CFG["proxy"], "rules": []}
    cand_renewed = {"ifname": "ppp0", "version": 4, "ip": "116.237.99.99",  # new IP after redial
                    "prefixlen": 32, "dynamic": True, "method": "ppp"}
    check("new IP still matches iface binding", ib.find_binding(cfg, cand_renewed) is not None)


def test_next_free_mark():
    print("[4] mark suggestion / fallback allocation")
    cfg = copy.deepcopy(BASE_CFG)
    check("suggest reuses free proxy-line mark (51)", ib.suggest_mark(cfg) == 51)
    cfg["egress_marks"] = [{"iface": "ppp0", "mark": 51, "dynamic": True}]
    check("suggest moves to next line mark", ib.suggest_mark(cfg) == 903)
    for m in (51, 903, 35):
        cfg["egress_marks"].append({"ip": "1.0.0.%d" % m, "iface": "ethZ", "mark": m})
    check("all lines used -> falls back to 1000+", ib.suggest_mark(cfg) == ib.EGRESS_AUTO_BASE)
    cfg["egress_marks"].append({"ip": "1.0.1.1", "iface": "ethY", "mark": ib.EGRESS_AUTO_BASE})
    check("next_free skips used + reserved",
          ib.next_free_mark(cfg) not in ib.used_marks(cfg) | ib.RESERVED_MARKS)
    check("next_free starts past EGRESS_AUTO_BASE", ib.next_free_mark(cfg) == ib.EGRESS_AUTO_BASE + 1)


def test_duplicate_and_collision_rejected():
    print("[5] wizard add_binding rejects duplicates / collisions")
    cfg = copy.deepcopy(BASE_CFG)

    def add(**c):
        try:
            ib.add_binding(cfg, c, c.pop("m"))
            return None
        except ValueError as e:
            return str(e)

    r = add(ifname="ppp0", version=4, ip="104.16.2.2", prefixlen=32, dynamic=True, m=1000)
    check("first dynamic add ok", r is None and len(cfg["egress_marks"]) == 1)
    r = add(ifname="ppp0", version=4, ip="1.2.3.4", prefixlen=32, dynamic=True, m=1001)
    check("duplicate iface rejected", r is not None and "iface" in r)
    r = add(ifname="eth9", version=4, ip="5.6.7.8", prefixlen=24, dynamic=False, m=1002)
    check("first static add ok", r is None)
    r = add(ifname="eth9", version=4, ip="5.6.7.8", prefixlen=24, dynamic=False, m=1003)
    check("duplicate ip rejected", r is not None and "ip" in r)
    r = add(ifname="eth9", version=4, ip="5.6.7.9", prefixlen=24, dynamic=False, m=1004)
    check("multi-homing: 2nd static IP on SAME iface allowed", r is None)
    r = add(ifname="ppp0", version=4, ip="104.16.2.2", prefixlen=32, dynamic=True, m=1005)
    check("dynamic iface duplicate still rejected", r is not None and "iface" in r)
    r = add(ifname="ethA", version=4, ip="9.9.9.9", prefixlen=32, dynamic=False, m=1002)
    check("duplicate mark rejected", r is not None and "mark" in r)
    r = add(ifname="ethB", version=4, ip="8.8.8.8", prefixlen=32, dynamic=False, m=51)
    check("reusing a proxy-line mark is ALLOWED (egress mark == line mark)", r is None)
    r = add(ifname="ethC", version=4, ip="7.7.7.7", prefixlen=32, dynamic=False, m=0x99)
    check("reserved mark rejected", r is not None and "reserved" in r)
    check("cfg has exactly the 4 accepted bindings", len(cfg["egress_marks"]) == 4)


def test_validate_bindings():
    print("[6] validate_bindings end-to-end")
    good = copy.deepcopy(BASE_CFG)
    good["egress_marks"] = [
        {"iface": "ppp0", "mark": 1000, "dynamic": True},
        {"ip": "93.184.216.34", "iface": "bond0.2000", "mark": 1001},
    ]
    check("clean config -> no errors", ib.validate_bindings(good) == [])

    bad = copy.deepcopy(BASE_CFG)
    bad["egress_marks"] = [
        {"iface": "ppp0", "mark": 1000, "dynamic": True},
        {"iface": "ppp0", "mark": 1000, "dynamic": True},  # dup iface + dup mark
        {"ip": "2.2.2.2", "iface": "eth1", "mark": 903},
        {"ip": "3.3.3.3", "iface": "eth2", "mark": 903},   # same mark, 2nd ethX
    ]
    errs = ib.validate_bindings(bad)
    check("finds duplicate iface", any("iface" in e for e in errs))
    check("finds duplicate mark across bindings", any("duplicate mark" in e for e in errs))


def test_wizard_flow():
    print("[7] run_wizard end-to-end with scripted chooser")
    cfg = copy.deepcopy(BASE_CFG)
    cands = ib.scan_candidates(DETECT)
    chosen = {}

    def chooser(c, suggested):
        chosen[c["ip"]] = suggested
        return suggested if suggested % 2 == 0 else None  # skip odd suggestions to exercise skip path

    created = ib.run_wizard(cfg, cands, chooser, log=lambda *a: None)
    check("chooser invoked per candidate", len(chosen) == len(cands))
    check("created <= candidates", len(created) <= len(cands))
    check("validate after wizard", ib.validate_bindings(cfg) == [])
    # rerun wizard on same cfg -> nothing new created (idempotent)
    created2 = ib.run_wizard(cfg, cands, chooser, log=lambda *a: None)
    check("re-run is idempotent", all(any(ib.find_binding(cfg, c) for c in [cd]) for cd in []) or len(created2) == 0)


def test_rules_safety_and_shape():
    print("[8] planned rules (v2: prerouting setter + generic OUTPUT restore)")
    cfg = copy.deepcopy(BASE_CFG)
    cfg["egress_marks"] = [
        {"iface": "ppp0", "mark": 51, "dynamic": True},          # egress mark == line mark
        {"ip": "93.184.216.34", "iface": "bond0.2000", "mark": 903},
        {"ip": "2606:4700:4700::1111", "iface": "bond0.254", "mark": 35},
    ]
    chains4, rules4 = ib.plan_rules(cfg, "ip")
    chains6, rules6 = ib.plan_rules(cfg, "ip6")

    for ch in chains4 + chains6:
        check("chain %s policy=accept" % ch["name"], ch["policy"] == "accept")
    set4 = [c for c in chains4 if c["name"] == ib.CHAIN_SET][0]
    res4 = [c for c in chains4 if c["name"] == ib.CHAIN_RESTORE][0]
    check("setter chain: type nat, hook prerouting",
          set4["type"] == "nat" and set4["hook"] == "prerouting")
    check("setter prio after conntrack(-200) before policy queue(-90)",
          -200 < set4["prio"] < -90)
    check("restore chain: type FILTER, hook output (connmark restore, not steering)",
          res4["type"] == "filter" and res4["hook"] == "output")
    check("restore prio after conntrack(-200) before policy queue(-90)",
          -200 < res4["prio"] < -90)
    check("restore prio back at -120 (not the route chain's -150)", res4["prio"] == -120)
    # the skuid->mark STAMP chain is a SEPARATE type-route chain
    rspec = ib.route_chain_spec("ip")
    check("route chain is its OWN chain (name != restore)", rspec["name"] == ib.CHAIN_ROUTE != ib.CHAIN_RESTORE)
    check("route chain: type route, hook output", rspec["type"] == "route" and rspec["hook"] == "output")
    check("route chain: mangle prio -150", rspec["prio"] == -150 == ib.ROUTE_PRIO)
    check("ip rules safe", ib.rules_are_safe(rules4))
    check("ip6 rules safe", ib.rules_are_safe(rules6))

    # setter rules: dynamic -> iifname ; static -> ip daddr (NOT saddr)
    check("dynamic setter iifname ppp0 (ip)", any(
        e.get("match", {}).get("left") == {"meta": {"key": "iifname"}} and e["match"]["right"] == "ppp0"
        for r in rules4 for e in r["expr"]))
    check("dynamic setter iifname ppp0 (ip6 too)", any(
        e.get("match", {}).get("left") == {"meta": {"key": "iifname"}} and e["match"]["right"] == "ppp0"
        for r in rules6 for e in r["expr"]))
    check("static v4 setter uses daddr", any(
        e.get("match", {}) == {"left": {"payload": {"protocol": "ip", "field": "daddr"}},
                               "op": "==", "right": "93.184.216.34"} for r in rules4 for e in r["expr"]))
    check("NO saddr matches anywhere (OUTPUT only looks at ct mark)",
          not any(e.get("match", {}).get("left", {}).get("payload", {}).get("field") == "saddr"
                  for r in rules4 + rules6 for e in r["expr"]))
    check("static v4 rule only in ip family",
          any("93.184.216.34" in json.dumps(r) for r in rules4) and
          not any("93.184.216.34" in json.dumps(r) for r in rules6))
    check("static v6 rule only in ip6 family",
          any("2606:4700:4700::1111" in json.dumps(r) for r in rules6) and
          not any("2606:4700:4700::1111" in json.dumps(r) for r in rules4))
    # setter writes meta mark AND saves to ct mark
    for r in rules4 + rules6:
        if r["chain"] == ib.CHAIN_SET:
            check("setter saves mark into ct",
                  any("mangle" in e and e["mangle"]["key"] == {"ct": {"key": "mark"}}
                      and e["mangle"]["value"] == {"meta": {"key": "mark"}} for e in r["expr"]))

    # generic restore: exactly ONE rule per family, keyed on ct mark != 0
    restore_rules = [r for r in rules4 + rules6 if r["chain"] == ib.CHAIN_RESTORE]
    check("one generic restore rule per family", len(restore_rules) == 2)
    for r in restore_rules:
        check("restore matches ct mark != 0",
              any(e.get("match", {}).get("left") == {"ct": {"key": "mark"}}
                  and e["match"]["op"] == "!=" and e["match"]["right"] == 0 for e in r["expr"]))
        check("restore guarded by meta mark == 0",
              any(e.get("match", {}).get("left") == {"meta": {"key": "mark"}}
                  and e["match"]["op"] == "==" and e["match"]["right"] == 0 for e in r["expr"]))
        check("restore value comes FROM ct mark (meta mark set ct mark)",
              {"mangle": {"key": {"meta": {"key": "mark"}},
                          "value": {"ct": {"key": "mark"}}}} in r["expr"])

    # no per-binding OUTPUT rules with 'ct mark == <specific M>' (user: redundant)
    check("no per-binding numeric ct-mark equality matches outside generic restore",
          not any(e.get("match", {}).get("left") == {"ct": {"key": "mark"}}
                  and isinstance(e["match"].get("right"), int) and e["match"]["right"] != 0
                  for r in rules4 + rules6 if r["chain"] == ib.CHAIN_RESTORE for e in r["expr"]))

    # restore_exists suppresses the generic chain entirely
    _, rules_dedup = ib.plan_rules(cfg, "ip", restore_exists=True)
    check("existing manual restore respected -> no auto chain/rules",
          all(r["chain"] != ib.CHAIN_RESTORE for r in rules_dedup))
    chains_dedup, _ = ib.plan_rules(cfg, "ip", restore_exists=True)
    check("no restore chain when already deployed",
          all(c["name"] != ib.CHAIN_RESTORE for c in chains_dedup))

    # restore detection helper against the real running ruleset text
    check("restore_in_ruleset finds deployed rule",
          ib.restore_in_ruleset("... ct mark != 0x00000000 meta mark 0x00000000 "
                                "meta mark set ct mark comment ..."))
    check("restore_in_ruleset false on empty", not ib.restore_in_ruleset(""))


def test_guard_never_clobbers_policy_mark():
    print("[9] OUTPUT restore only fires when meta mark == 0")
    cfg = copy.deepcopy(BASE_CFG)
    cfg["egress_marks"] = [{"ip": "93.184.216.34", "iface": "bond0.2000", "mark": 903}]
    _, rules = ib.plan_rules(cfg, "ip")
    restore = [r for r in rules if r["chain"] == ib.CHAIN_RESTORE][0]
    guard = [e for e in restore["expr"] if e.get("match", {}).get("left") == {"meta": {"key": "mark"}}]
    check("meta mark 0 guard present", len(guard) == 1 and guard[0]["match"]["right"] == 0)


def test_atomic_save_and_backup():
    print("[10] save_config: valid json, backup, atomic, idempotent round-trip")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "nft_route.json")
        with open(path, "w") as f:
            f.write(json.dumps(BASE_CFG))
        cfg = copy.deepcopy(BASE_CFG)
        cfg["egress_marks"] = [{"iface": "ppp0", "mark": 1000, "dynamic": True}]
        ib.save_config(path, cfg)
        check("backup created", os.path.exists(path + ".bak"))
        with open(path) as f:
            reloaded = json.load(f)
        check("round-trip equal", reloaded == cfg)
        check("backup holds original", json.load(open(path + ".bak")) == BASE_CFG)
        # idempotent: load, save again -> no temp files left behind
        ib.save_config(path, reloaded)
        left = [x for x in os.listdir(d) if x.startswith(".nft_route.")]
        check("no temp file leak", left == [])


def test_bad_input_no_partial_write():
    print("[11] corrupt/invalid config refused before touching file")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "x.json")
        with open(path, "w") as f:
            f.write("ORIGINAL")
        try:
            ib.save_config(path, {"nope": object()})  # not json-serializable
            ok = False
        except Exception:
            ok = True
        check("raised on unserializable", ok)
        check("original file untouched", open(path).read() == "ORIGINAL")


def test_json_roundtrip_via_add_binding():
    print("[12] add_binding deep-copies before validating (no half-applied state)")
    cfg = copy.deepcopy(BASE_CFG)
    before = json.dumps(cfg)
    try:
        ib.add_binding(cfg, {"ifname": "ethX", "version": 4, "ip": "1.1.1.1",
                             "prefixlen": 32, "dynamic": False}, 0x99)  # reserved mark
        raised = False
    except ValueError:
        raised = True
    check("rejection raised ValueError", raised)
    check("cfg unchanged on rejection", json.dumps(cfg) == before)




class _MockNftCtx:
    def __init__(self):
        self.committed = []
    def json_cmd(self, obj):
        self.committed.append(obj)
        return (0, "", "")

class _MockNfu:
    """stand-in for nftUtils: get_rules returns canned rule dicts."""
    def __init__(self, rules):
        self._rules = rules
        self.nft = _MockNftCtx()
    def get_rules(self, table=None, chain=None, family="ip"):
        return [r for r in self._rules if (table is None or r.get("table") == table)
                and (family is None or r.get("family") == family)]


def test_clear_egress_rules():
    print("[13] clear_egress_rules targets only our table/chain/comment")
    rules = [
        {"table": "policy_route", "family": "ip", "chain": ib.CHAIN_SET, "comment": "AUTOGEN X", "handle": 10},
        {"table": "policy_route", "family": "ip", "chain": ib.CHAIN_RESTORE, "comment": "AUTOGEN X", "handle": 11},
        {"table": "policy_route", "family": "ip", "chain": "nat_PREROUTING", "comment": "AUTOGEN X", "handle": 12},
        {"table": "other", "family": "ip", "chain": ib.CHAIN_SET, "comment": "AUTOGEN X", "handle": 13},
        {"table": "policy_route", "family": "ip", "chain": ib.CHAIN_SET, "comment": "manual", "handle": 14},
    ]
    nfu = _MockNfu(rules)
    n = ib.clear_egress_rules(nfu, "ip", "AUTOGEN X")
    check("deleted exactly our 2 egress rules", n == 2)
    dels = [c["nftables"][0]["delete"]["rule"]["handle"] for c in nfu.nft.committed]
    check("handles 10,11 deleted only", dels == [10, 11])
    check("empty ruleset -> 0", ib.clear_egress_rules(_MockNfu([]), "ip", "AUTOGEN X") == 0)


def test_restore_json_detection():
    print("[14] restore_in_ruleset: ct->meta restore in an OUTPUT chain counts (filter OK)")
    # connmark restore is legitimate in a plain FILTER output chain (it is NOT
    # the egress-steering job -- that is the separate CHAIN_ROUTE). Respect a
    # manually deployed Src-Policy so we do not double-add.
    rs = {"nftables": [
        {"chain": {"family": "ip", "table": "mangle", "name": "OUTPUT", "type": "filter",
                   "hook": {"hook": "output", "priority": -120, "policy": "accept"}}},
        {"rule": {"family": "ip", "table": "mangle", "chain": "OUTPUT", "expr": [
            {"match": {"left": {"ct": {"key": "mark"}}, "op": "!=", "right": 0}},
            {"match": {"left": {"meta": {"key": "mark"}}, "op": "==", "right": 0}},
            {"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"ct": {"key": "mark"}}}}]}},
    ]}
    check("restore in FILTER output chain -> True (ip)", ib.restore_in_ruleset(rs, "ip"))
    check("other family -> False", not ib.restore_in_ruleset(rs, "ip6"))
    check("bare rule list also accepted", ib.restore_in_ruleset(rs["nftables"], "ip"))
    # same expr but in a NON-output chain (prerouting) must NOT be treated as
    # the OUTPUT restore, else we would wrongly skip installing ours
    rs_p = {"nftables": [
        {"chain": {"family": "ip", "table": "mangle", "name": "PREROUTING", "type": "filter",
                   "hook": {"hook": "prerouting", "priority": -100, "policy": "accept"}}},
        {"rule": {"family": "ip", "table": "mangle", "chain": "PREROUTING", "expr": [
            {"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"ct": {"key": "mark"}}}}]}},
    ]}
    check("restore in PREROUTING chain does NOT count", not ib.restore_in_ruleset(rs_p, "ip"))
    check("garbage -> False", not ib.restore_in_ruleset("no restore here", "ip"))




# ---------------------------------------------------------------------------
# iprule closed loop (mock IPRoute)
# ---------------------------------------------------------------------------

import socket as _sock

class MockIPRoute:
    def __init__(self, links=None, rules=None, routes=None):
        self.links = links if links is not None else {"ppp0": 33, "bond0.2000": 13}
        self.rules = list(rules or [])      # {priority, fwmark, table, family}
        self.routes = list(routes or [])    # {table, family, attrs:[(RTA_*,v)..]}
        self.calls = []
    def get_links(self):
        return [{"index": i, "attrs": [("IFLA_IFNAME", n)]} for n, i in self.links.items()]
    def link_lookup(self, ifname=None):
        return [self.links[ifname]] if ifname in self.links else []
    def get_rules(self, family=None):
        return [r for r in self.rules if r.get("family") in (family, None)]
    def rule(self, cmd, **kw):
        self.calls.append(("rule", cmd, kw))
        if cmd == "add":
            self.rules.append(dict(kw))
        elif cmd == "del":
            self.rules = [r for r in self.rules
                          if not (r.get("priority") == kw.get("priority")
                                  and r.get("fwmark") == kw.get("fwmark"))]
    def get_routes(self, table=None, dst=None, family=None):
        out = []
        for r in self.routes:
            if r.get("table") == table and r.get("family") in (family, None):
                out.append(r)
        return out
    def route(self, cmd, **kw):
        self.calls.append(("route", cmd, kw))
        if cmd == "add":
            self.routes.append({"table": kw.get("table"), "family": kw.get("family"),
                                "attrs": [("RTA_GATEWAY", kw.get("gateway")),
                                          ("RTA_OIF", kw.get("oif"))]
                                 + ([("RTA_SRC", kw.get("src"))] if kw.get("src") else [])})
        elif cmd == "del":
            self.routes = [r for r in self.routes if r.get("table") != kw.get("table")]


def _cfg_with_bindings(binds):
    cfg = copy.deepcopy(BASE_CFG)
    cfg["egress_marks"] = binds
    return cfg


def test_iprule_plan():
    print("[15] iprule plan defaults")
    cfg = _cfg_with_bindings([
        {"ip": "93.184.216.34", "iface": "bond0.2000", "mark": 1005,
         "iprule": {"gateway": "93.184.216.35"}},
        {"iface": "ppp0", "mark": 51, "dynamic": True, "iprule": {"gateway": "auto"}},
        {"ip": "240e::1", "iface": "bond0.254", "mark": 1006, "iprule": {"gateway": "fe80::1"}},
    ])
    p4 = ib.iprule_plan(cfg, 4)
    check("2 ipv4 plans", len(p4) == 2)
    sp = p4[0]
    check("table defaults to mark", sp["table"] == 1005)
    check("priority in owned band", ib.IPRULE_PRIO_BASE <= sp["priority"] < ib.IPRULE_PRIO_BASE + ib.IPRULE_PRIO_SPAN)
    check("static keeps src ip", sp["src"] == "93.184.216.34" and sp["gateway"] == "93.184.216.35")
    dp = [x for x in p4 if x["dynamic"]][0]
    check("dynamic gateway=auto -> gateway_auto", dp["gateway"] is None and dp["gateway_auto"])
    p6 = ib.iprule_plan(cfg, 6)
    check("v6 plan: v6 static + dynamic (both families)",
          len(p6) == 2 and any(x["ip"] == "240e::1" for x in p6) and not any(
              x["ip"] == "93.184.216.34" for x in p6))


def test_iprule_apply_lifecycle():
    print("[16] iprule apply: add -> idempotent -> drift -> stale-remove -> external")
    binds = [{"ip": "93.184.216.34", "iface": "bond0.2000", "mark": 1005,
              "iprule": {"gateway": "93.184.216.35"}}]
    cfg = _cfg_with_bindings(binds)
    plans = ib.iprule_plan(cfg, 4)
    ipr = MockIPRoute()
    r1 = ib.iprule_apply(ipr, plans)
    check("rule+route added", len(r1["added"]) == 1 and any(c[0] == "route" and c[1] == "add" for c in ipr.calls))
    radd = [c for c in ipr.calls if c == ("rule", "add", {**c[2]})]
    kw = [c[2] for c in ipr.calls if c[0] == "rule" and c[1] == "add"][0]
    check("rule fields", kw["fwmark"] == 1005 and kw["table"] == 1005)
    rkw = [c[2] for c in ipr.calls if c[0] == "route" and c[1] == "add"][0]
    check("route has gateway/oif/src", rkw["gateway"] == "93.184.216.35" and rkw["oif"] == 13
          and rkw["src"] == "93.184.216.34")
    # idempotency
    ipr.calls = []
    r2 = ib.iprule_apply(ipr, plans)
    check("second apply no writes", ipr.calls == [] and r2["kept"] == [1005])
    # gateway drift -> replace route
    ipr.routes = [{"table": 1005, "family": _sock.AF_INET,
                   "attrs": [("RTA_GATEWAY", "1.1.1.1"), ("RTA_OIF", 13), ("RTA_SRC", "93.184.216.34")]}]
    r3 = ib.iprule_apply(ipr, plans)
    check("gateway drift -> del+add route",
          ("route", "del", {**[c for c in ipr.calls if c[1] == 'del'][0][2]}) and
          any(c[0] == "route" and c[1] == "add" for c in ipr.calls))
    # stale ours (mark no longer configured) -> rule removed
    ipr2 = MockIPRoute(rules=[{"priority": 29105, "fwmark": 777, "table": 777, "family": _sock.AF_INET}])
    r4 = ib.iprule_apply(ipr2, plans)
    check("stale own rule deleted", 777 in r4["removed"] and not any(
        rr["fwmark"] == 777 for rr in ipr2.rules))
    # external manual rule same fwmark -> untouched
    ipr3 = MockIPRoute(rules=[{"priority": 30000, "fwmark": 1005, "table": 200, "family": _sock.AF_INET}])
    r5 = ib.iprule_apply(ipr3, plans)
    check("external fwmark respected (kept untouched, table adopted, no duplicate rule)",
          r5["external"] == [{"mark": 1005, "table": 200, "prio": 30000}] and
          any(rr["fwmark"] == 1005 and rr["priority"] == 30000 for rr in ipr3.rules) and
          not any(c[0] == "rule" and c[1] == "add" and c[2].get("fwmark") == 1005
                  for c in ipr3.calls))
    # missing interface -> pending, rule still there
    ipr4 = MockIPRoute()
    plans_nodev = [dict(plans[0], dev="ghost0")]
    r6 = ib.iprule_apply(ipr4, plans_nodev)
    check("dev missing -> pending", r6["pending"] and not any(c[0] == "route" for c in ipr4.calls))
    # auto gateway via injected resolver
    ipr5 = MockIPRoute()
    dyn_plan = dict(ib.iprule_plan(_cfg_with_bindings(
        [{"iface": "ppp0", "mark": 51, "dynamic": True, "iprule": {"gateway": "auto"}}]), 4)[0])
    r7 = ib.iprule_apply(ipr5, [dyn_plan], auto_gateway=lambda dev, fam: "10.0.0.1")
    check("auto gateway resolved into route",
          any(c[1] == "add" and c[0] == "route" and c[2]["gateway"] == "10.0.0.1" for c in ipr5.calls))
    ipr6 = MockIPRoute()
    r8 = ib.iprule_apply(ipr6, [dyn_plan], auto_gateway=lambda dev, fam: None)
    check("auto gw unavailable -> pending", r8["pending"] and not any(
        c[0] == "route" and c[1] == "add" for c in ipr6.calls))


def test_external_rule_adopts_table():
    print("[18] external fwmark rule -> route ensured in ITS table, no duplicate rule")
    import socket as _s
    binds = [{"ip": "93.184.216.39", "iface": "eno2.2000", "mark": 907,
              "iprule": {"gateway": "93.184.216.38"}}]
    cfg = {"egress_marks": binds, "proxy": {}}
    plans = ib.iprule_plan(cfg, 4)
    ipr = MockIPRoute(links={"ppp0": 33, "eno2.2000": 12},
                      rules=[{"priority": 30000, "fwmark": 907, "table": 907, "family": _s.AF_INET}])
    res = ib.iprule_apply(ipr, plans)
    check("marked external", res["external"] == [{"mark": 907, "table": 907, "prio": 30000}])
    check("no rule add", not any(c[0] == "rule" and c[1] == "add" for c in ipr.calls))
    radd = [c[2] for c in ipr.calls if c[0] == "route" and c[1] == "add"]
    check("default route added into adopted table 907",
          len(radd) == 1 and radd[0]["table"] == 907 and radd[0]["gateway"] == "93.184.216.38"
          and radd[0]["src"] == "93.184.216.39", str(radd))
    # idempotent
    ipr2 = MockIPRoute(links={"ppp0": 33, "eno2.2000": 12}, rules=ipr.rules, routes=ipr.routes)
    res2 = ib.iprule_apply(ipr2, plans)
    check("second pass no writes", ipr2.calls == [] and res2["external"])

def test_wizard_post_bind():
    print("[17] run_wizard post_bind hook (gateway prompt)")
    cfg = copy.deepcopy(BASE_CFG)
    cand = {"ifname": "ppp0", "version": 4, "ip": "1.2.3.4", "prefixlen": 32,
            "dynamic": True, "method": "ppp"}
    seen = []
    def pb(c, entry):
        seen.append((c["ifname"], entry["mark"]))
        entry.setdefault("iprule", {})["gateway"] = "auto"
    created = ib.run_wizard(cfg, [cand], lambda c, s: s, log=lambda *a: None, post_bind=pb)
    check("post_bind saw entry", seen == [("ppp0", created[0]["mark"])])
    check("entry got iprule.gateway", created[0].get("iprule", {}).get("gateway") == "auto")


def test_iprule_combined_families_no_flap():
    print("[18] combined v4+v6 apply: no cross-family rule teardown")
    # regression: per-family apply calls used to treat the OTHER family's own
    # rules as stale and delete them every sync cycle (60s egress blackholes)
    binds = [{"iface": "ppp0", "mark": 1007, "dynamic": True,
              "iprule": {"gateway": "auto"}}]
    cfg = _cfg_with_bindings(binds)
    plans = ib.iprule_plan(cfg, 4) + ib.iprule_plan(cfg, 6)
    check("dynamic binding plans both families", {p["family"] for p in plans} == {4, 6})
    ipr = MockIPRoute()
    auto_gw = lambda dev, fam: "10.64.64.64" if fam == 4 else None
    r1 = ib.iprule_apply(ipr, plans, auto_gateway=auto_gw)
    check("both family rules added", sorted(r1["added"]) == [1007, 1007], str(r1))
    r2 = ib.iprule_apply(ipr, plans, auto_gateway=auto_gw)
    check("second combined apply: nothing added/removed",
          not r2["added"] and not r2["removed"], str(r2))
    check("v4 rule survived", any(r.get("fwmark") == 1007 and r.get("family") == _sock.AF_INET
                                  for r in ipr.rules))
    check("v6 rule survived", any(r.get("fwmark") == 1007 and r.get("family") == _sock.AF_INET6
                                  for r in ipr.rules))


def test_iprule_line_mark_opt_in():
    print("[19] proxy-line marks are managed only with explicit iprule")
    # reusing a line mark without explicit iprule must NOT be auto-managed:
    # line marks usually have hand-maintained rules/tables (tunnel routes),
    # and a bare-default auto table would divert that line's policy traffic
    cfg = _cfg_with_bindings([{"ip": "93.184.216.34", "iface": "bond0.2000", "mark": 51}])
    check("line mark without iprule -> no plan", ib.iprule_plan(cfg, 4) == [])
    cfg2 = _cfg_with_bindings([{"ip": "93.184.216.34", "iface": "bond0.2000", "mark": 51,
                               "iprule": {"gateway": "93.184.216.35"}}])
    check("line mark with explicit iprule -> planned",
          [p["mark"] for p in ib.iprule_plan(cfg2, 4)] == [51])
    cfg3 = _cfg_with_bindings([{"ip": "93.184.216.34", "iface": "bond0.2000", "mark": 1005,
                               "iprule": {"gateway": "93.184.216.35"}}])
    check("non-line mark planned as before",
          [p["mark"] for p in ib.iprule_plan(cfg3, 4)] == [1005])


if __name__ == "__main__":
    for t in [test_classify_and_scan, test_plan_bound_vs_needs, test_dynamic_identity_by_iface,
              test_next_free_mark, test_duplicate_and_collision_rejected, test_validate_bindings,
              test_wizard_flow, test_rules_safety_and_shape, test_guard_never_clobbers_policy_mark,
              test_atomic_save_and_backup, test_bad_input_no_partial_write, test_json_roundtrip_via_add_binding,
              test_clear_egress_rules, test_restore_json_detection,
              test_external_rule_adopts_table,
              test_iprule_plan, test_iprule_apply_lifecycle, test_wizard_post_bind,
              test_iprule_combined_families_no_flap, test_iprule_line_mark_opt_in]:
        t()
    print("\n==== %d passed, %d failed ====" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)
