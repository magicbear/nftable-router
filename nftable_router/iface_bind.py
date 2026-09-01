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
CHAIN_SET = "nat_EGRESS_SET"
CHAIN_RESTORE = "mangle_EGRESS_RESTORE"
SET_PRIO = -95
RESTORE_PRIO = -120
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
    """Atomic rewrite; keeps a .bak. Raises ValueError on non-dict/jsonable data."""
    text = json.dumps(cfg, ensure_ascii=False, indent=3)
    # round-trip validation before touching the real file
    json.loads(text)
    if backup and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                old = f.read()
            with open(path + ".bak", "w", encoding="utf-8") as f:
                f.write(old)
        except OSError:
            pass
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".nft_route.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
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

def run_wizard(cfg, needs, chooser, log=print):
    """For each unbound candidate ask `chooser(cand, suggested_mark)` for a mark.

    chooser returns int mark or None to skip. Entries added in-memory; caller
    decides when to save_config(). Returns list of created entries.
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
    """Detect an equivalent generic ct->meta restore already deployed
    (e.g. the manual 'Src-Route Policy' in table mangle). Accepts either the
    nft JSON ruleset dict / list or raw text (substring fallback)."""
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
    for item in items:
        rule = item.get("rule") if isinstance(item, dict) else None
        if not rule or rule.get("family") != family:
            continue
        for e in rule.get("expr", []):
            m = e.get("mangle", {}) if isinstance(e, dict) else {}
            if m.get("key") == {"meta": {"key": "mark"}} and m.get("value") == {"ct": {"key": "mark"}}:
                return True
    return False


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
