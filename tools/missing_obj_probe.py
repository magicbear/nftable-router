#!/usr/bin/env python3
"""Standalone probe: which name-addressed JSON ops NULL-deref THIS host's
libnftables 0.9.8 when the target object is MISSING?

Background: two production segfaults are already documented (see
nftable_router/nft_utils.py):

  * JSON `delete chain` by NAME of a missing chain  -> "segfault at 48"
  * JSON `list chain`  by NAME of a missing chain   -> "segfault at 48"
    (found the hard way: the delete_chain fix itself crashed at boot via
     get_chain_info because the stale chains it looks for do not exist yet)

This tool sweeps the whole name-addressed surface so every remaining landmine
is mapped before touching nft_utils again. Same safety model as
type_route_probe.py:

  * touches ONLY a throwaway table  mo_probe  (never policy_route / live set)
  * EVERY case runs in its OWN child process: a segfault kills only the child;
    the parent reads returncode<0 and reports SIGSEGV instead of dying
  * cleans up mo_probe before + after + on any crash

RUN (as root -- needs CAP_NET_ADMIN):
  sudo python3 tools/missing_obj_probe.py

Exit 0 always (it is a measurement tool; read the matrix it prints).
"""
import argparse
import json
import os
import subprocess
import sys

FAMILY = "ip"
TABLE = "mo_probe"
CHAIN = "chain_probe"
SET = "set_probe"
MARK = 0x7d


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
    """Idempotently remove any prior mo_probe (never touches other tables)."""
    for fam in (FAMILY, "ip6"):
        jc(n, {"nftables": [{"delete": {"table": {"family": fam, "name": TABLE}}}]})


def mktable(n):
    rc, _, err = jc(n, {"nftables": [{"add": {"table": {"family": FAMILY, "name": TABLE}}}]})
    if rc != 0:
        raise RuntimeError("add table failed: %s" % err)


def mkchain(n):
    rc, _, err = jc(n, {"nftables": [{"add": {"chain": {
        "family": FAMILY, "table": TABLE, "name": CHAIN, "type": "filter",
        "hook": "output", "prio": -120, "policy": "accept"}}}]})
    if rc != 0:
        raise RuntimeError("add chain failed: %s" % err)


def mkset(n):
    rc, _, err = jc(n, {"nftables": [{"add": {"set": {
        "family": FAMILY, "table": TABLE, "name": SET, "type": "mark",
        "flags": ["interval"]}}}]})
    if rc != 0:
        raise RuntimeError("add set failed: %s" % err)


# --------------------------------------------------------------------------- #
# cases: (setup, op-under-test) pairs; each case = own child process
# --------------------------------------------------------------------------- #
CASES = []


def case(fn):
    CASES.append(fn.__name__)
    return fn


@case
def list_chain_exists(n):
    """CONTROL: name-addressed LIST of an EXISTING chain (known-good)."""
    mktable(n)
    mkchain(n)
    rc, out, err = jc(n, {"nftables": [{"list": {"chain": {
        "family": FAMILY, "table": TABLE, "name": CHAIN}}}]})
    assert rc == 0, "list existing chain failed: %s" % err


@case
def list_chain_missing(n):
    """SUSPECT: name-addressed LIST of a MISSING chain (the heal-path crash)."""
    mktable(n)
    rc, out, err = jc(n, {"nftables": [{"list": {"chain": {
        "family": FAMILY, "table": TABLE, "name": "no_such_chain"}}}]})
    print("    list missing chain rc=%s err=%r" % (rc, (err or "")[:80]))


@case
def delete_chain_missing_name(n):
    """CONTROL (documented crasher): name-addressed DELETE of a missing chain."""
    mktable(n)
    rc, _, err = jc(n, {"nftables": [{"delete": {"chain": {
        "family": FAMILY, "table": TABLE, "name": "no_such_chain"}}}]})
    print("    delete missing chain rc=%s err=%r" % (rc, (err or "")[:80]))


@case
def add_chain_twice(n):
    """RELOAD HAZARD: `add chain` for a chain that ALREADY exists (boot -> hot
    reload path does exactly this unless chains are dropped first)."""
    mktable(n)
    mkchain(n)
    rc, _, err = jc(n, {"nftables": [{"add": {"chain": {
        "family": FAMILY, "table": TABLE, "name": CHAIN, "type": "filter",
        "hook": "output", "prio": -120, "policy": "accept"}}}]})
    print("    re-add existing chain rc=%s err=%r" % (rc, (err or "")[:80]))


@case
def delete_set_missing(n):
    """Name-addressed DELETE of a MISSING set."""
    mktable(n)
    rc, _, err = jc(n, {"nftables": [{"delete": {"set": {
        "family": FAMILY, "table": TABLE, "name": "no_such_set"}}}]})
    print("    delete missing set rc=%s err=%r" % (rc, (err or "")[:80]))


@case
def delete_set_exists(n):
    """CONTROL: name-addressed DELETE of an EXISTING set."""
    mktable(n)
    mkset(n)
    rc, _, err = jc(n, {"nftables": [{"delete": {"set": {
        "family": FAMILY, "table": TABLE, "name": SET}}}]})
    assert rc == 0, "delete existing set failed: %s" % err


@case
def delete_elem_missing_set(n):
    """Element delete when the SET itself is missing."""
    mktable(n)
    rc, _, err = jc(n, {"nftables": [{"delete": {"element": {
        "family": FAMILY, "table": TABLE, "name": "no_such_set",
        "elem": {"val": 1}}}}]})
    print("    delete elem in missing set rc=%s err=%r" % (rc, (err or "")[:80]))


@case
def delete_elem_missing_elem(n):
    """Element delete when the SET exists but the ELEMENT does not."""
    mktable(n)
    mkset(n)
    rc, _, err = jc(n, {"nftables": [{"delete": {"element": {
        "family": FAMILY, "table": TABLE, "name": SET,
        "elem": {"val": 12345678}}}}]})
    print("    delete missing elem rc=%s err=%r" % (rc, (err or "")[:80]))


@case
def delete_rule_missing_handle(n):
    """Handle-addressed DELETE with a bogus handle (missing object, but the
    addressing is by handle -- should be a plain error, no crash)."""
    mktable(n)
    mkchain(n)
    rc, _, err = jc(n, {"nftables": [{"delete": {"rule": {
        "family": FAMILY, "table": TABLE, "chain": CHAIN, "handle": 999999}}}]})
    print("    delete rule bogus handle rc=%s err=%r" % (rc, (err or "")[:80]))


@case
def add_rule_missing_chain(n):
    """Rule ADD into a chain that does not exist (error path)."""
    mktable(n)
    rc, _, err = jc(n, {"nftables": [{"add": {"rule": {
        "family": FAMILY, "table": TABLE, "chain": "no_such_chain",
        "expr": [{"counter": {"bytes": 0, "packets": 0}}]}}}]})
    print("    add rule missing chain rc=%s err=%r" % (rc, (err or "")[:80]))


@case
def add_elem_missing_set(n):
    """Element ADD into a set that does not exist (error path)."""
    mktable(n)
    rc, _, err = jc(n, {"nftables": [{"add": {"element": {
        "family": FAMILY, "table": TABLE, "name": "no_such_set",
        "elem": {"val": 1}}}}]})
    print("    add elem missing set rc=%s err=%r" % (rc, (err or "")[:80]))


@case
def flush_chain_missing(n):
    """FLUSH of a chain that does not exist (cleanup paths use flush)."""
    mktable(n)
    rc, _, err = jc(n, {"nftables": [{"flush": {"chain": {
        "family": FAMILY, "table": TABLE, "name": "no_such_chain"}}}]})
    print("    flush missing chain rc=%s err=%r" % (rc, (err or "")[:80]))


# --------------------------------------------------------------------------- #
# runner (mirrors type_route_probe.py)
# --------------------------------------------------------------------------- #
DISPATCH = {c: globals()[c] for c in CASES}


def _child_run(name):
    try:
        import nftables
    except ImportError:
        sys.stderr.write("python-nftables NOT importable in this interpreter\n")
        return 3
    n = nftables.Nftables()
    n.set_json_output(True)
    wipe(n)
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
    ap = argparse.ArgumentParser(description="missing-object json probe (root required)")
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
            print("  %-26s %s   %s" % (name, status, detail[:120]))
            results[name] = (p.returncode, detail)
            _parent_cli_wipe()
        crashed = [k for k, (rc, _) in results.items() if rc < 0]
        failed = [k for k, (rc, _) in results.items() if 0 < rc < 0 or 0 < rc]
        print("\nsummary: crashes: %s; fails: %s"
              % (crashed or "none",
                 [k for k, (rc, _) in results.items() if rc not in (0, 1) or (0 < rc and rc != 1)] or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
