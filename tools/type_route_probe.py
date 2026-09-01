#!/usr/bin/env python3
"""Standalone probe: find a `type route` nftables-chain creation + stamp-rule
JSON that does NOT crash on THIS host's libnftables.

Background: the main router tried to build a `type route` OUTPUT chain for skuid
-> fwmark identity stamps. On this box that SIGSEGV'd libnftables 0.9.8 inside
nft_run_cmd_from_buffer (NULL cmd->obj deref, "segfault at 48"), killing the
router AT BOOT. This tool reproduces the operation in ISOLATION so we can find a
working command form before any re-merge.

SAFETY
  * touches ONLY a throwaway table  tr_probe  (never policy_route / the live set)
  * EVERY case runs in its OWN child process: a segfault kills only the child;
    the parent reads returncode<0 and reports SIGSEGV instead of dying
  * cleans up tr_probe before + after + on any crash

RUN (as root -- needs CAP_NET_ADMIN):
  sudo python3 tools/type_route_probe.py
  sudo python3 tools/type_route_probe.py --only route_flat,stamp_in_route   # subset

Exit 0 iff a usable route-chain form + stamp-rule form both pass.
"""
import argparse
import json
import os
import subprocess
import sys

FAMILY = "ip"
TABLE = "tr_probe"
CHAIN = "route_probe"
MARK = 0x7e          # arbitrary test fwmark
UID = 65534          # nobody (arbitrary test skuid)

CASES = []


def case(fn):
    CASES.append(fn.__name__)
    return fn


def jc(n, cmd):
    """Run one nftables json_cmd; return (rc:int, out, err:str)."""
    rc, out, err = n.json_cmd(cmd)
    if isinstance(out, (bytes, bytearray)):
        out = out.decode("utf-8", "replace")
    if isinstance(out, str):
        try:
            out = json.loads(out)
        except ValueError:
            pass
    rc0 = rc[0] if isinstance(rc, (list, tuple)) else rc
    if isinstance(err, (bytes, bytearray)):
        err = err.decode("utf-8", "replace")
    return rc0, out, (err or "")


def wipe(n):
    """Idempotently remove any prior tr_probe (never touches other tables)."""
    for fam in (FAMILY, "ip6"):
        jc(n, {"nftables": [{"delete": {"table": {"family": fam, "name": TABLE}}}]})


def mktable(n):
    rc, _, err = jc(n, {"nftables": [{"add": {"table": {"family": FAMILY, "name": TABLE}}}]})
    if rc != 0:
        raise RuntimeError("add table failed: %s" % err)


def add_chain(n, chain_obj):
    return jc(n, {"nftables": [{"add": {"chain": chain_obj}}]})


def base(fam=FAMILY, **over):
    d = {"family": fam, "table": TABLE, "name": CHAIN}
    d.update(over)
    return d


def dump_chain(n, fam=FAMILY, name=CHAIN):
    """Return {'type':..,'prio':..,'hook':..} for the listed chain, or None."""
    rc, out, _ = jc(n, {"nftables": [{"list": {"chain": {"family": fam, "table": TABLE, "name": name}}}]})
    if rc != 0 or not isinstance(out, dict):
        return None
    for it in out.get("nftables", []):
        ch = it.get("chain") if isinstance(it, dict) else None
        if isinstance(ch, dict):
            hk = ch.get("hook")
            pri = hk.get("priority") if isinstance(hk, dict) else ch.get("prio")
            return {"type": ch.get("type"), "prio": pri,
                    "hook": (hk.get("hook") if isinstance(hk, dict) else ch.get("hook"))}
    return None


def ok_rule_expr(mark=MARK):
    """The stamp body: skuid -> fwmark, tcp only (NOT a verdict; verdicts stay
    in nat chains). ct mark save lets it steer egress for already-routed pkts."""
    return {"family": FAMILY, "table": TABLE, "chain": CHAIN, "comment": "AUTOGEN probe",
            "expr": [
                {"match": {"left": {"meta": {"key": "skuid"}}, "op": "==", "right": UID}},
                {"match": {"left": {"meta": {"key": "l4proto"}}, "op": "==", "right": "tcp"}},
                {"counter": {"bytes": 0, "packets": 0}},
                {"mangle": {"key": {"meta": {"key": "mark"}}, "value": mark}},
                {"mangle": {"key": {"ct": {"key": "mark"}}, "value": {"meta": {"key": "mark"}}}},
            ]}


def add_rule(n, rule=None):
    return jc(n, {"nftables": [{"add": {"rule": rule or ok_rule_expr()}}]})


# --------------------------------------------------------------------------- #
# chain-CREATION forms (each self-contained: wipe, mktable, add chain, list)
# --------------------------------------------------------------------------- #
@case
def ctrl_filter(n):
    """SANITY baseline: a plain type-filter OUTPUT chain must create without
    crashing. If THIS crashes, the environment is the problem, not route."""
    mktable(n)
    rc, _, err = add_chain(n, base(type="filter", hook="output", prio=-120, policy="accept"))
    assert rc == 0, "baseline filter create failed: %s" % err
    info = dump_chain(n)
    print("    created:", info)
    assert info and info.get("type") == "filter", info


@case
def route_flat_int(n):
    """EXACT form the router used: flat hook/prio/policy + type route."""
    mktable(n)
    rc, _, err = add_chain(n, base(type="route", hook="output", prio=-150, policy="accept"))
    assert rc == 0, "flat route (int prio) create failed: %s" % err
    print("    created:", dump_chain(n))


@case
def route_flat_strprio(n):
    """Flat but priority as the nft keyword 'mangle' instead of -150."""
    mktable(n)
    rc, _, err = add_chain(n, base(type="route", hook="output", prio="mangle", policy="accept"))
    assert rc == 0, "flat route (prio 'mangle') create failed: %s" % err
    print("    created:", dump_chain(n))


@case
def route_nested(n):
    """Canonical nested hook object: {hook:{hook,priority,policy}}."""
    mktable(n)
    rc, _, err = add_chain(n, base(type="route",
                                   hook={"hook": "output", "priority": -150, "policy": "accept"}))
    assert rc == 0, "nested route create failed: %s" % err
    print("    created:", dump_chain(n))


@case
def route_nested_strprio(n):
    mktable(n)
    rc, _, err = add_chain(n, base(type="route",
                                   hook={"hook": "output", "priority": "mangle", "policy": "accept"}))
    assert rc == 0, "nested route (prio mangle) create failed: %s" % err
    print("    created:", dump_chain(n))


@case
def mangle_type(n):
    """Legacy chain type 'mangle' at output hook (some builds accept it as a
    filter alias and never reroute; listed so we can SEE if it differs)."""
    mktable(n)
    rc, _, err = add_chain(n, base(type="mangle", hook="output", prio=-150, policy="accept"))
    if rc != 0:
        raise RuntimeError("mangle-type create failed: %s" % err)
    print("    created:", dump_chain(n))


@case
def ctrl_filter_prio_mangle(n):
    """CONTROL: a FILTER chain at prio -150 (same number route uses) with
    policy accept. If this PASSES but route@-150 crashes, the priority value is
    innocent and the crash is specific to the ROUTE type / its policy field."""
    mktable(n)
    rc, _, err = add_chain(n, base(type="filter", hook="output", prio=-150, policy="accept"))
    assert rc == 0, "filter@-150 control failed: %s" % err
    print("    created:", dump_chain(n))


@case
def route_flat_no_policy(n):
    """PRIME HYPOTHESIS: the crash is the `policy` key on a ROUTE chain (a route
    chain has no accept/drop verdict semantics; the parser may NULL-deref while
    resolving it). Create route WITHOUT the policy field, everything else
    identical to the crashing form. If THIS passes, the fix is: drop policy=accept."""
    mktable(n)
    rc, _, err = add_chain(n, {"family": FAMILY, "table": TABLE, "name": CHAIN,
                               "type": "route", "hook": "output", "prio": -150})
    assert rc == 0, "route flat NO-policy failed: %s" % err
    print("    created:", dump_chain(n))


@case
def route_nested_no_policy(n):
    mktable(n)
    rc, _, err = add_chain(n, {"family": FAMILY, "table": TABLE, "name": CHAIN,
                               "type": "route",
                               "hook": {"hook": "output", "priority": -150}})
    assert rc == 0, "route nested NO-policy failed: %s" % err
    print("    created:", dump_chain(n))


# --------------------------------------------------------------------------- #
# stamp-RULE forms, each first creating a route chain via whichever form works
# --------------------------------------------------------------------------- #
def _make_route_chain(n, which="nested"):
    mktable(n)
    if which == "flat":
        rc, _, err = add_chain(n, base(type="route", hook="output", prio=-150, policy="accept"))
    elif which == "flat_nopolicy":
        rc, _, err = add_chain(n, {"family": FAMILY, "table": TABLE, "name": CHAIN,
                                   "type": "route", "hook": "output", "prio": -150})
    else:
        rc, _, err = add_chain(n, base(type="route",
                                       hook={"hook": "output", "priority": -150, "policy": "accept"}))
    if rc != 0:
        raise RuntimeError("route chain (%s) create failed: %s" % (which, err))
    return n


@case
def stamp_in_route_flat_nopolicy(n):
    """END-TO-END of the fix hypothesis: create route chain WITHOUT policy, then
    insert the real stamp body. PASS here == ready to merge back."""
    _make_route_chain(n, "flat_nopolicy")
    rc, _, err = add_rule(n)
    assert rc == 0, "stamp into route (flat, no-policy) failed: %s" % err
    print("    created:", dump_chain(n))


@case
def stamp_in_route_flat(n):
    """skuid->mark stamp inserted into a FLAT-created route chain."""
    _make_route_chain(n, "flat")
    rc, _, err = add_rule(n)
    assert rc == 0, "stamp rule into route (flat chain) failed: %s" % err
    print("    rules:", dump_chain(n))


@case
def stamp_in_route_nested(n):
    _make_route_chain(n, "nested")
    rc, _, err = add_rule(n)
    assert rc == 0, "stamp rule into route (nested chain) failed: %s" % err


@case
def stamp_no_ct(n):
    """meta mark only (no `ct mark set meta mark` second statement)."""
    _make_route_chain(n, "flat")
    e = ok_rule_expr()
    e["expr"] = [x for x in e["expr"] if "ct" not in json.dumps(x)]
    rc, _, err = add_rule(n, e)
    assert rc == 0, "meta-only stamp failed: %s" % err


@case
def stamp_no_counter(n):
    _make_route_chain(n, "flat")
    e = ok_rule_expr()
    e["expr"] = [x for x in e["expr"] if "counter" not in x]
    rc, _, err = add_rule(n, e)
    assert rc == 0, "no-counter stamp failed: %s" % err


@case
def stamp_mark_inet(n):
    """mark set as hex STRING '0x7e' rather than int (some parsers picky)."""
    _make_route_chain(n, "flat")
    e = ok_rule_expr()
    for x in e["expr"]:
        if x.get("mangle", {}).get("key", {}).get("meta") == {"key": "mark"}:
            x["mangle"]["value"] = "0x7e"
    rc, _, err = add_rule(n, e)
    assert rc == 0, "hex-string mark stamp failed: %s" % err


@case
def stamp_in_filter(n):
    """Control: identical stamp body in a type-FILTER chain (known-good). If
    route crashes but this passes, the issue is specifically the route chain."""
    mktable(n)
    rc, _, err = add_chain(n, base(type="filter", hook="output", prio=-150, policy="accept"))
    assert rc == 0, "filter chain create failed: %s" % err
    rc, _, err = add_rule(n)
    assert rc == 0, "stamp in filter failed: %s" % err


# --------------------------------------------------------------------------- #
# runner
# --------------------------------------------------------------------------- #
DISPATCH = {c.__name__: c for c in [globals()[n] for n in CASES]}


def _child_run(name):
    """executed in a FRESH process: import nftables here so a segfault during
    the actual command is captured by the parent as a signal death."""
    try:
        import nftables
    except ImportError:
        sys.stderr.write("python-nftables NOT importable in this interpreter\n")
        return 3
    n = nftables.Nftables()
    n.set_json_output(True)
    wipe(n)          # clean slate inside the child too
    try:
        DISPATCH[name](n)
    except AssertionError as e:
        sys.stderr.write("ASSERT: %s\n" % e)
        return 2
    except Exception as e:
        sys.stderr.write("ERR: %r\n" % e)
        return 1
    finally:
        try:
            wipe(n)
        except Exception:
            pass
    return 0


def _parent_cli_wipe():
    for fam in (FAMILY, "ip6"):
        subprocess.call(["nft", "delete", "table", fam, TABLE],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser(description="type-route json probe (root required)")
    ap.add_argument("--only", help="comma list of case names to run")
    ap.add_argument("--case", help=argparse.SUPPRESS)
    ap.add_argument("--repeat", type=int, default=1, help="re-run all cases N times (stability)")
    args = ap.parse_args()

    if args.case:
        sys.exit(_child_run(args.case))

    if os.geteuid() != 0:
        print("must run as root (CAP_NET_ADMIN to create tables)")
        return 4
    try:
        import nftables  # noqa: F401  (parent import = environment check only)
    except ImportError:
        print("python-nftables not installed -- cannot probe")
        return 4
    ver = subprocess.check_output(["nft", "--version"]).decode().strip()
    print("host: %s\nnft : %s\n" % (os.uname().nodename, ver))

    names = args.only.split(",") if args.only else list(CASES)
    for r in range(args.repeat):
        if args.repeat > 1:
            print("\n===== pass %d/%d =====" % (r + 1, args.repeat))
        results = {}
        for name in names:
            _parent_cli_wipe()
            p = subprocess.run([sys.executable, os.path.abspath(__file__), "--case", name],
                               capture_output=True, text=True, timeout=30)
            if p.returncode < 0:
                status = "CRASH SIG%s" % (-p.returncode)
            elif p.returncode == 0:
                status = "PASS"
            else:
                status = "FAIL(%d)" % p.returncode
            detail = (p.stdout + p.stderr).strip().replace("\n", " | ")
            print("  %-22s %s   %s" % (name, status, detail[:140]))
            results[name] = (p.returncode, detail)
            _parent_cli_wipe()
        bad = [k for k, (rc, _) in results.items() if rc != 0]
        crashed = [k for k, (rc, _) in results.items() if rc < 0]
        print("\nsummary: %d/%d pass; crashes: %s; fails: %s"
              % (len(names) - len(bad), len(names),
                 crashed or "none",
                 [k for k in bad if k not in crashed] or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
