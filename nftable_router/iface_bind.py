#!/usr/bin/env python3
"""
Egress interface / source-IP -> fwmark binding (wizard + config writer + rule plan).

Startup flow (used by router main, unit-tested offline in test_iface_bind.py):

 1. scan every local interface (netinfo.detect, read-only)
 2. skip loopback / link-local / private addresses
 3. for each remaining public egress address:
      - dynamic (ppp/dhcp): identity is the INTERFACE NAME (address may change)
      - static:             identity is the IP ADDRESS
    if not already bound in nft_route.json ("egress_marks" section), run the
    wizard to assign a fwmark, and write the binding back to the config file
    (atomic, with .bak backup, duplicates rejected).
 4. plan nftables rules (two-step connmark, mirroring the deployed manual
    "Src-Route Policy", kernel-5.10 compatible) so that a connection arriving
    on WAN interface B (dynamic binding) or addressed to bound local IP X
    (static binding) has its mark stored in conntrack at PREROUTING, and the
    generic OUTPUT rule `ct mark != 0 meta mark 0 meta mark set ct mark`
    restores it for reply routing via `ip rule fwmark M table M` -> SAME
    interface / same source IP return.

SAFETY / anti-stall invariants (checked by the test suite):
  * planned rules may ONLY contain: match guards, counter, mangle meta/ct mark.
    NEVER a verdict (accept/drop/queue/redirect/tproxy/reject) -- that is
    what would kill egress.
  * setter matches are iifname / daddr-of-local-IP only: daddr of a local
    address can never be transit, so forwarded traffic is not re-routed.
  * per-binding OUTPUT rules do NOT exist: the single generic ct->meta
    restore (already deployed manually, else auto-added once per family)
    handles reply marking; it only fires when meta mark == 0, so existing
    policy (proxy-line) marks are never overwritten.
  * mark values must not collide with reserved 0x99 / 0x100.
  * set-chain prio -95: after conntrack confirm, before the policy queue
    rules (-90) so inbound-marked return traffic skips re-policy evaluation.
"""

import copy
import ipaddress
import json
import os
import socket
import tempfile

RESERVED_MARKS = {0, 0x99, 0x100}
EGRESS_AUTO_BASE = 1000
EGRESS_MARKS_KEY = "egress_marks"
# Two-step connmark scheme, mirroring the deployed "Src-Route Policy":
#   SETTER   prerouting (type nat, prio -95: after conntrack confirm -200,
#            BEFORE policy_route nat chains at -90/-89 so mark/ctmark is set
#            before the policy queue and before fullcone DNAT):
#              static  : ip(daddr X) -> meta mark set M; ct mark set meta mark
#              dynamic : iifname B   -> meta mark set M; ct mark set meta mark
#            (daddr of a local IP can never be transit traffic; iifname B on a
#            WAN is the deployed production semantics.)
#   RESTORE  output (type filter, prio -120, AFTER conntrack -200, BEFORE
#            nat_OUTPUT policy queue -90 so return traffic skips re-policy):
#              ct mark != 0 ; meta mark 0 ; meta mark set ct mark
#            generic, ONE rule per family -- skipped if the running ruleset
#            already contains an equivalent (manually maintained ones survive
#            clearRules because of a different comment tag).
#            This is CONNMARK restore for already-tracked flows -- its natural
#            home is a FILTER output chain.
#   ROUTE    output (type ROUTE, prio -150 mangle class, flat form, policy
#            OMITTED): hosts ONLY the skuid->fwmark identity stamps built by
#            proxy_mgr. Only a route-type OUTPUT chain re-triggers the FIB
#            lookup after a mark change -- the production bug this split fixes.
#            VERIFIED SAFE on this box's nftables v0.9.8 by tools/type_route_probe.py
#            (all route flat/no-policy/stamp cases pass, zero crashes).
CHAIN_SET = "nat_EGRESS_SET"
CHAIN_RESTORE = "mangle_EGRESS_RESTORE"
CHAIN_ROUTE = "mangle_EGRESS_ROUTE"
SET_PRIO = -95
RESTORE_PRIO = -120
ROUTE_PRIO = -150
DANGEROUS_VERDICTS = {"accept", "drop", "queue", "redirect", "tproxy", "reject"}
RESTORE_SIGNATURE = "meta mark set ct mark"


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------

def classify_addr(addr_info, iface_loopback=False):
    """loopback | link-local | private | public"""
    if iface_loopback:
        return "loopback"
    ip = ipaddress.ip_address(addr_info["addr"])
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    if addr_info["scope"] in ("host", "link"):
        return "link-local"
    return "public"


def scan_candidates(detect_result):
    """From netinfo.detect() output -> list of candidate egress bindings to check.

    candidate = {ifname, version, ip, prefixlen, dynamic, method}
    """
    out = []
    for name, r in detect_result.items():
        if r.get("master"):          # slave ports of a bond -> ignore
            continue
        dynamic = ("ppp" in r["methods"] or r["dhcp"])
        for a in r["addrs"]:
            kind = classify_addr(a, iface_loopback=r.get("loopback", False))
            if kind != "public":
                continue
            out.append({
                "ifname": name,
                "version": a["version"],
                "ip": a["addr"],
                "prefixlen": a["prefixlen"],
                "dynamic": dynamic,
                "method": ",".join(r["methods"]),
            })
    return out


# ---------------------------------------------------------------------------
# config load / save
# ---------------------------------------------------------------------------

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(path, cfg, backup=True):
    """Atomic rewrite; keeps a .bak. Raises ValueError on non-dict/jsonable
    data. IMPORTANT: writes through to realpath (deployed configs are often
    symlinks -- os.replace on the link path would silently DETACH the link
    and orphan the real file), and preserves the original file mode."""
    text = json.dumps(cfg, ensure_ascii=False, indent=3)
    # round-trip validation before touching the real file
    json.loads(text)
    real = os.path.realpath(path)
    try:
        mode = os.stat(real).st_mode & 0o777
    except OSError:
        mode = 0o644
    if backup and os.path.exists(real):
        try:
            with open(real, "r", encoding="utf-8") as f:
                old = f.read()
            with open(real + ".bak", "w", encoding="utf-8") as f:
                f.write(old)
        except OSError:
            pass
    d = os.path.dirname(os.path.abspath(real)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".nft_route.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, real)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# ---------------------------------------------------------------------------
# bindings & validation
# ---------------------------------------------------------------------------

def get_bindings(cfg):
    return cfg.get(EGRESS_MARKS_KEY, [])


def find_binding(cfg, cand):
    """Return existing binding entry for a candidate, or None."""
    for b in get_bindings(cfg):
        if cand["dynamic"]:
            if b.get("iface") == cand["ifname"]:
                return b
        else:
            if b.get("ip") == cand["ip"]:
                return b
    return None


def proxy_marks(cfg):
    marks = set()
    for line in cfg.get("proxy", {}).values():
        if "mark" in line:
            marks.add(int(line["mark"]))
    return marks


def used_marks(cfg):
    return {int(b["mark"]) for b in get_bindings(cfg) if "mark" in b}


def next_free_mark(cfg):
    """Fallback mark (needs its own ip rule fwmark/table when outside line marks)."""
    used = used_marks(cfg) | RESERVED_MARKS
    m = EGRESS_AUTO_BASE
    while m in used:
        m += 1
    return m


def suggest_mark(cfg):
    """Preferred: reuse an existing proxy-line mark (ip rule/table already
    exists for it) -- the deployed 'Src-Route Policy' binds ppp0 -> 0x33
    (TEL-FIB), daddr 93.184.216.36 -> 0x387 etc. Falls back to a fresh number."""
    used = used_marks(cfg) | RESERVED_MARKS
    for line in cfg.get("proxy", {}).values():
        m = int(line.get("mark", 0))
        if m and m not in used:
            return m
    return next_free_mark(cfg)


def validate_bindings(cfg):
    """Return list of human-readable problems (empty == OK)."""
    errors = []
    seen_if, seen_ip, seen_mark = set(), set(), {}
    for b in get_bindings(cfg):
        ident = b.get("iface") or b.get("ip")
        if ident is None:
            errors.append("binding without iface/ip: %r" % (b,))
            continue
        if b.get("iface") is not None and b.get("dynamic"):
            # only DYNAMIC entries are identified by interface name; a static
            # entry's iface field is an annotation and may repeat (multi-homing)
            if b["iface"] in seen_if:
                errors.append("duplicate iface binding: %s" % b["iface"])
            seen_if.add(b["iface"])
        if b.get("ip") is not None:
            if b["ip"] in seen_ip:
                errors.append("duplicate ip binding: %s" % b["ip"])
            seen_ip.add(b["ip"])
        try:
            mark = int(b["mark"])
        except (KeyError, TypeError, ValueError):
            errors.append("binding %s has invalid mark: %r" % (ident, b.get("mark")))
            continue
        if mark in RESERVED_MARKS:
            errors.append("binding %s uses reserved mark %d" % (ident, mark))
        # NOTE: reusing a proxy-line mark is the DESIGNED behaviour (egress mark
        # == line mark, matching ip rule fwmark->table), so no proxy-collision
        # error here; only duplicate marks ACROSS bindings are rejected.
        if mark in seen_mark:
            errors.append("duplicate mark %d on %s and %s" % (mark, seen_mark[mark], ident))
        else:
            seen_mark[mark] = ident
    return errors


def add_binding(cfg, cand, mark):
    """Append a binding derived from a candidate. Raises ValueError on duplicates."""
    mark = int(mark)
    errors_before = []
    trial = copy.deepcopy(cfg)
    entry = {"mark": mark}
    if cand["dynamic"]:
        entry = {"iface": cand["ifname"], "mark": mark, "dynamic": True,
                 "note": "%s/%d" % (cand["ip"], cand["prefixlen"])}
    else:
        entry = {"ip": cand["ip"], "iface": cand["ifname"], "mark": mark}
    trial.setdefault(EGRESS_MARKS_KEY, []).append(entry)
    for err in validate_bindings(trial):
        errors_before.append(err)
    if errors_before:
        raise ValueError("refused: %s" % "; ".join(errors_before))
    cfg.setdefault(EGRESS_MARKS_KEY, []).append(entry)
    return entry


# ---------------------------------------------------------------------------
# wizard
# ---------------------------------------------------------------------------

def run_wizard(cfg, needs, chooser, log=print, post_bind=None):
    """For each unbound candidate ask `chooser(cand, suggested_mark)` for a mark.

    chooser returns int mark or None to skip. post_bind(cand, entry) runs right
    after a successful add (interactive gateways etc.). Entries added in-memory;
    caller decides when to save_config(). Returns list of created entries.
    """
    created = []
    for cand in needs:
        suggested = suggest_mark(cfg)
        mark = chooser(cand, suggested)
        if mark is None:
            log("[wizard] skipped %s (%s)" % (cand["ifname"], cand["ip"]))
            continue
        try:
            entry = add_binding(cfg, cand, mark)
        except ValueError as e:
            log("[wizard] %s" % e)
            continue
        log("[wizard] bound %s %s -> mark %d" % (
            "iface" if cand["dynamic"] else "ip", cand["ifname"] + "/" + cand["ip"], mark))
        if post_bind is not None:
            try:
                post_bind(cand, entry)
            except Exception as e:
                log("[wizard] post-bind prompt aborted for %s: %s" % (cand.get("ifname", "?"), e))
        created.append(entry)
    return created


def interactive_chooser(cand, suggested):
    kind = "dynamic iface" if cand["dynamic"] else "static ip"
    ans = input("[%s %s] bind to fwmark [%d]: " % (kind, cand["ifname"] + "/" + cand["ip"], suggested)).strip()
    if ans == "":
        return suggested
    try:
        return int(ans, 0)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# nftables rule planning (pure dicts, JSON nft format; no kernel access)
# ---------------------------------------------------------------------------

def _match(left, op, right):
    return {"match": {"left": left, "op": op, "right": right}}


def plan_rules(cfg, family="ip", restore_exists=None):
    """Return ([chain defs], [rule dicts]) -- setter + generic restore.

    Per binding (mark M):
      dynamic iface B : prerouting rule  iifname B -> meta mark set M, ct save
      static ip X     : prerouting rule  ip daddr X -> meta mark set M, ct save
    Generic OUTPUT restore (added once, only if restore_exists is falsy):
      ct mark != 0 ; meta mark 0 ; meta mark set ct mark
    No per-binding OUTPUT rules: the deployed generic restore covers reply
    marking (same scheme as the manual "Src-Route Policy").
    family: 'ip' or 'ip6'.
    """
    if family not in ("ip", "ip6"):
        raise ValueError("family must be ip|ip6")
    chains = [
        {"family": family, "table": "policy_route", "name": CHAIN_SET,
         "type": "nat", "hook": "prerouting", "prio": SET_PRIO, "policy": "accept"},
    ]
    rules = []
    for b in get_bindings(cfg):
        mark = int(b["mark"])
        if b.get("dynamic") and b.get("iface"):
            match = _match({"meta": {"key": "iifname"}}, "==", b["iface"])
        elif b.get("ip") is not None:
            ver = ipaddress.ip_address(b["ip"]).version
            if (ver == 4 and family != "ip") or (ver == 6 and family != "ip6"):
                continue
            match = _match({"payload": {"protocol": family, "field": "daddr"}}, "==", b["ip"])
        else:
            continue
        rules.append({"family": family, "table": "policy_route", "chain": CHAIN_SET, "expr": [
            match,
            {"counter": {"bytes": 0, "packets": 0}},
            {"mangle": {"key": {"meta": {"key": "mark"}}, "value": mark}},
            {"mangle": {"key": {"ct": {"key": "mark"}}, "value": {"meta": {"key": "mark"}}}},
        ]})
    if not restore_exists:
        chains.append({"family": family, "table": "policy_route", "name": CHAIN_RESTORE,
                       "type": "filter", "hook": "output", "prio": RESTORE_PRIO, "policy": "accept"})
        rules.append({"family": family, "table": "policy_route", "chain": CHAIN_RESTORE, "expr": [
            _match({"ct": {"key": "mark"}}, "!=", 0),
            _match({"meta": {"key": "mark"}}, "==", 0),
            {"counter": {"bytes": 0, "packets": 0}},
            {"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"ct": {"key": "mark"}}}},
        ]})
    return chains, rules


RESTORE_EXPR = {"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"ct": {"key": "mark"}}}}


def clear_egress_rules(nfu, family, comment):
    """Delete previously installed egress rules by AUTOGEN comment tag so
    reload can re-apply without duplicating. Never touches foreign rules:
    matches on table/chain/comment only."""
    deleted = 0
    try:
        items = nfu.get_rules(table="policy_route", family=family)
    except Exception:
        return 0
    for r in items:
        if r.get("chain") in (CHAIN_SET, CHAIN_RESTORE) and r.get("comment") == comment:
            nfu.nft.json_cmd({"nftables": [{"delete": {
                "rule": {"family": family, "table": "policy_route",
                         "chain": r["chain"], "handle": r["handle"]}}}]})
            deleted += 1
    return deleted


def restore_in_ruleset(ruleset, family="ip"):
    """Detect a generic `ct mark -> meta mark` OUTPUT restore already deployed
    (e.g. the manual 'Src-Route Policy'), so we do not add a duplicate. The
    RESTORE lives in an OUTPUT chain of ANY type (it is connmark restore for
    tracked flows -- egress steering is NOT its job; see route_chain_spec CHAIN_ROUTE
    so match on the expression regardless of filter/route. Accepts the nft JSON
    ruleset dict/list or raw text (substring fallback)."""
    if isinstance(ruleset, str):
        try:
            ruleset = json.loads(ruleset)
        except ValueError:
            return RESTORE_SIGNATURE in ruleset
    if isinstance(ruleset, dict):
        items = ruleset.get("nftables", [])
    elif isinstance(ruleset, (list, tuple)):
        items = list(ruleset)
    else:
        items = []
    output_chains = set()
    has_chain_objs = False
    for item in items:
        ch = item.get("chain") if isinstance(item, dict) else None
        if not isinstance(ch, dict):
            continue
        has_chain_objs = True
        hook = ch.get("hook")
        hook = hook.get("hook") if isinstance(hook, dict) else hook
        if hook not in (None, "output") or ch.get("family") not in (family, "inet"):
            continue
        output_chains.add((ch.get("family"), ch.get("table"), ch.get("name")))
    for item in items:
        rule = item.get("rule") if isinstance(item, dict) else None
        # an inet-family table covers both ip and ip6 hooks
        if not rule or rule.get("family") not in (family, "inet"):
            continue
        fam, tab, cname = rule.get("family"), rule.get("table"), rule.get("chain")
        known = (fam, tab, cname) in output_chains
        # strict when chain objects were provided (a prerouting-only chain then
        # must NOT count); lenient only for ruleset exports with no chain meta
        if known or not has_chain_objs:
            for e in rule.get("expr", []):
                m = e.get("mangle", {}) if isinstance(e, dict) else {}
                if m.get("key") == {"meta": {"key": "mark"}} and m.get("value") == {"ct": {"key": "mark"}}:
                    return True
    return False


def route_chain_spec(family):
    """Chain definition for the skuid->fwmark identity-stamp chain. FLAT form
    WITHOUT a policy field -- both variants verified crash-free on the target's
    nftables v0.9.8 by tools/type_route_probe.py (route_flat_no_policy /
    stamp_in_route_flat_nopolicy). A separate chain is mandatory: the connmark
    RESTORE chain is 'type filter' and a chain cannot be two types at once;
    only 'type route' re-runs the FIB lookup after a mark change."""
    return {"family": family, "table": "policy_route", "name": CHAIN_ROUTE,
            "type": "route", "hook": "output", "prio": ROUTE_PRIO}


def rules_are_safe(rules):
    """Hard check: no verdict statements anywhere in the planned rules."""
    for r in rules:
        for e in r["expr"]:
            if set(e.keys()) & DANGEROUS_VERDICTS:
                return False
    return True


# ---------------------------------------------------------------------------
# top level
# ---------------------------------------------------------------------------

def plan_bindings(cfg, candidates):
    bound, needs = [], []
    for cand in candidates:
        b = find_binding(cfg, cand)
        if b is None:
            needs.append(cand)
        else:
            bound.append((cand, b))
    return bound, needs


# ===========================================================================
# ip rule / route table closed loop (auto management)
# ===========================================================================
# Owned namespace: every rule we create lives in priority band
# [IPRULE_PRIO_BASE, IPRULE_PRIO_BASE+IPRULE_PRIO_SPAN). Anything with the same
# fwmark OUTSIDE that band (or pointing to a foreign table) is treated as an
# external/manual rule: reported, never modified or deleted.
#
# Binding entries gain an optional "iprule" object:
#   {"gateway": "93.184.216.35" | "auto" | "", "table": 1005?, "priority": 29005?,
#    "dev": "bond0.2000"?}
# Defaults: table = mark, priority = IPRULE_PRIO_BASE + table % SPAN,
# dev = binding iface; static bindings also emit 'src <ip>' on the route.
# dynamic bindings accept gateway "auto" => follow the interface's current
# default route (refreshed by the caller's periodic sync).

IPRULE_PRIO_BASE = 29000
IPRULE_PRIO_SPAN = 900


def iprule_plan(cfg, family=4):
    """Normalize config into desired ip-rule state (list of plans).

    Bindings that reuse a proxy-LINE mark are only auto-managed when the
    binding carries an explicit "iprule" object: line marks normally already
    have hand-maintained ip rules/tables (tunnel routes etc.), and silently
    shadowing them with a bare-default table would divert that line's policy
    traffic. Invalid entries are skipped (validate_bindings reports them)."""
    plans = []
    line_marks = proxy_marks(cfg)
    for b in get_bindings(cfg):
        try:
            mark = int(b["mark"])
        except (KeyError, TypeError, ValueError):
            continue
        if mark in line_marks and not b.get("iprule"):
            continue
        ip = b.get("ip")
        dynamic = bool(b.get("dynamic"))
        if ip is not None:
            ver = ipaddress.ip_address(ip).version
            if ver != family:
                continue
        elif not dynamic:
            continue
        ir = dict(b.get("iprule") or {})
        table = int(ir.get("table", mark))
        priority = int(ir.get("priority", IPRULE_PRIO_BASE + table % IPRULE_PRIO_SPAN))
        gw = ir.get("gateway")
        gw = None if gw in (None, "", "auto") else str(gw)
        plans.append({
            "mark": mark,
            "table": table,
            "priority": priority,
            "family": family,
            "dev": ir.get("dev") or b.get("iface"),
            "gateway": gw,
            "gateway_auto": (ir.get("gateway") in ("auto", "", None)) and dynamic,
            "src": None if dynamic else ip,
            "ip": ip,
            "dynamic": dynamic,
        })
    return plans


def _our_priority(prio):
    return IPRULE_PRIO_BASE <= prio < IPRULE_PRIO_BASE + IPRULE_PRIO_SPAN


def iprule_apply(ipr, plans, log=None, auto_gateway=None):
    """Idempotent reconcile of ip rules + route tables using a pyroute2
    IPRoute-like object.

    IMPORTANT: `plans` must contain the plans of EVERY family managed in the
    config (v4 + v6 together). The stale sweep below removes any owned-band
    rule whose (fwmark, family) is absent from the plans -- passing a single
    family's plans would tear down the other family's live rules.

    Returns summary dict of lists:
      added / kept / external / removed / pending (waiting gateway) / errors.
    auto_gateway(dev, family) -> gw|None resolver is injectable for tests."""
    res = {"added": [], "kept": [], "external": [], "removed": [], "pending": [], "errors": []}
    logf = log or (lambda m: None)
    af = {4: socket.AF_INET, 6: socket.AF_INET6}
    want_marks = {(p["mark"], p["family"]) for p in plans}
    active_tables = {(p["table"], p["family"]) for p in plans}

    def norm_fwmark(r):
        fw = r.get("fwmark", 0)
        if isinstance(fw, str):
            fw = int(fw, 0)
        return fw & 0xffffffff

    def del_rule_and_flush(r, m, fam, why):
        ipr.rule("del", priority=r.get("priority"), fwmark=m,
                 table=r.get("table"), family=af[fam])
        logf("ip rule del fwmark %d (%s)" % (m, why))
        tbl = r.get("table") or m
        if (tbl, fam) not in active_tables:
            try:      # flush the default route we owned in that table
                ipr.route("del", dst="default", table=tbl, family=af[fam])
                logf("route table %d flushed (%s)" % (tbl, why))
            except Exception:
                pass  # table already empty / no default -> nothing to do

    # current rules, both families
    cur = {}
    for fam in (4, 6):
        try:
            rules = ipr.get_rules(family=af[fam])
        except Exception as e:
            res["errors"].append("get_rules(%d): %s" % (fam, e))
            rules = []
        for r in rules:
            m = norm_fwmark(r)
            if m:
                cur.setdefault((m, fam), []).append(r)

    # ---- remove stale (ours, no longer in config). Ownership is the priority
    # band alone: a custom "iprule.table" rule is still ours to clean up.
    for (m, fam), rl in cur.items():
        if (m, fam) in want_marks:
            continue
        for r in rl:
            if _our_priority(r.get("priority", 0)):
                try:
                    del_rule_and_flush(r, m, fam, "stale binding")
                    res["removed"].append(m)
                except Exception as e:
                    res["errors"].append("rule del fwmark %d: %s" % (m, e))

    def link_index(dev):
        try:
            idx = ipr.link_lookup(ifname=dev)
            return idx[0] if idx else None
        except Exception:
            return None

    def current_default(ipr_obj, table, fam):
        """existing default-route attrs dict for a table, or None"""
        try:
            for rt in ipr_obj.get_routes(table=table, dst="default", family=af[fam]):
                attrs = {"gateway": None, "src": None, "oif": None}
                for a, v in (rt.get("attrs") or []):
                    if a in ("RTA_GATEWAY", "RTA_SRC", "RTA_OIF"):
                        attrs[{"RTA_GATEWAY": "gateway", "RTA_SRC": "src",
                                "RTA_OIF": "oif"}[a]] = v
                o = rt.get("_object", rt)
                attrs["gateway"] = o.get("gateway", attrs["gateway"])
                return attrs
            return None
        except Exception:
            return None

    # ---- ensure desired
    for p in plans:
        fam = p["family"]
        key = (p["mark"], fam)
        tag = "fwmark %d -> table %s via %s dev %s" % (
            p["mark"], p["table"], p["gateway"] or "auto", p["dev"])
        ours = [r for r in cur.get(key, []) if _our_priority(r.get("priority", 0))]
        foreign = [r for r in cur.get(key, []) if r not in ours]
        exact = [r for r in ours if (r.get("table") or 0) == p["table"]
                 and r.get("priority") == p["priority"]]
        adopted = False
        if foreign and not ours:
            # The RULE is externally managed (e.g. manual prio-30000 policy
            # rules): never duplicate or touch it -- but ADOPT the table it
            # points at so the binding still guarantees its default route.
            # (Previously this branch `continue`d entirely: bound entries that
            #  reused a line mark got an empty routing table = the 907 case.)
            ft = foreign[0].get("table")
            if isinstance(ft, str) and ft.strip().isdigit():
                ft = int(ft.strip())
            if isinstance(ft, int) and ft not in (0, 252, 253, 254, 255):
                p = dict(p, table=ft)
            res["external"].append({"mark": p["mark"], "table": p["table"],
                                    "prio": foreign[0].get("priority")})
            logf("ip rule %s: external rule (prio %s -> table %s) respected; adopting table for default route"
                 % (tag, foreign[0].get("priority"), p["table"]))
            adopted = True
        # migrate: owned-band rules whose table/priority no longer match the
        # plan (config changed) are replaced instead of reported external
        for r in ours:
            if r in exact:
                continue
            try:
                del_rule_and_flush(r, p["mark"], fam, "table/priority changed")
            except Exception as e:
                res["errors"].append("rule migrate fwmark %d: %s" % (p["mark"], e))
        # 1) rule (skipped when adopted from an external rule)
        if not exact and not adopted:
            try:
                ipr.rule("add", priority=p["priority"], fwmark=p["mark"],
                         table=p["table"], family=af[fam])
                logf("ip rule add prio %d fwmark %d lookup %d" % (
                    p["priority"], p["mark"], p["table"]))
                res["added"].append(p["mark"])
            except Exception as e:
                res["errors"].append("rule add %s: %s" % (tag, e))
                continue
        else:
            res["kept"].append(p["mark"])
        # 2) route inside the table
        dev = p["dev"]
        idx = link_index(dev) if dev else None
        if dev and idx is None:
            res["pending"].append((p["mark"], "interface %s missing" % dev))
            continue
        gw = p["gateway"]
        if p["gateway_auto"]:
            resolver = auto_gateway or _main_default_gateway
            gw = resolver(dev, fam)
            if gw is None:
                # PPPoE-style links carry NO gateway anywhere: pppd itself
                # installs plain 'default dev ppp0' (point-to-point, gateway-
                # less), so the main-table gateway probe can never resolve --
                # waiting for one keeps the table empty forever. Fall back to
                # the dev-only table default, but ONLY for point-to-point
                # devices: on a broadcast net (e.g. the 5G CPE VLANs) a
                # gateway-less route is broken and would clobber a good
                # statically-declared default.
                if p.get("dynamic") and _link_is_pointopoint(ipr, dev):
                    gw = None  # dev-only
                else:
                    res["pending"].append((p["mark"], "auto gateway: no default on %s yet" % dev))
                    continue
        elif gw is None and not p.get("dynamic"):
            res["pending"].append((p["mark"], "gateway not set"))
            continue
        try:
            existing = current_default(ipr, p["table"], fam)
            want = {"dst": "default", "table": p["table"], "family": af[fam]}
            if gw is not None:
                want["gateway"] = gw
            if idx is not None:
                want["oif"] = idx
            if p["src"]:
                want["src"] = p["src"]
            if gw is None and idx is not None:
                # dev-only binding: the table default must point at THIS device
                same = (existing is not None and existing.get("gateway") is None
                        and existing.get("oif") == idx)
            else:
                same = (existing is not None
                        and existing.get("gateway") == gw
                        and (p["src"] is None or existing.get("src") == p["src"])
                        and (idx is None or existing.get("oif") in (idx, None)))
            if same:
                continue
            if existing is not None:
                try:
                    ipr.route("del", dst="default", table=p["table"], family=af[fam])
                except Exception:
                    pass
            ipr.route("add", **want)
            logf("route table %d: default via %s dev %s%s" % (
                p["table"], gw, dev or "?", (" src " + p["src"]) if p["src"] else ""))
        except Exception as e:
            res["errors"].append("route table %d: %s" % (p["table"], e))
    return res


IFF_POINTOPOINT = 0x8000
IFF_NOARP = 0x80


def _link_is_pointopoint(ipr, dev):
    """True when <dev> is a point-to-point link (ppp/pppoe/sit/wireguard...):
    IFF_POINTOPOINT or IFF_NOARP. Only such devices may safely carry a
    gateway-less 'default dev X' route; on broadcast media that route is
    broken (per-dst ARP) and would clobber a good declared default."""
    try:
        for l in ipr.get_links():
            if hasattr(l, "get_attr"):
                name = l.get_attr("IFLA_IFNAME")
            else:
                name = next((v for a, v in (l.get("attrs") or [])
                             if a == "IFLA_IFNAME"), None)
            if name == dev:
                return bool(int(l.get("flags") or 0) & (IFF_POINTOPOINT | IFF_NOARP))
    except Exception:
        pass
    return False


def _main_default_gateway(dev, family=4):
    """gateway of the current default route on <dev> (main table); None if absent."""
    try:
        from pyroute2 import IPRoute
    except ImportError:
        return None
    af = socket.AF_INET if family == 4 else socket.AF_INET6
    ipr = IPRoute()
    try:
        want_idx = None
        for l in ipr.get_links():
            if l.get_attr("IFLA_IFNAME") == dev:
                want_idx = l["index"]
                break
        if want_idx is None:
            return None
        for rt in ipr.get_routes(family=af):
            o = rt.get("_object", rt)
            if o.get("dst_len", 0) != 0 or o.get("table", 254) != 254:
                continue
            gw = None
            oif = None
            for a, v in (rt.get("attrs") or []):
                if a == "RTA_GATEWAY":
                    gw = v
                elif a == "RTA_OIF":
                    oif = v
            if gw and oif == want_idx:
                return gw
    except Exception:
        return None
    finally:
        ipr.close()
    return None
