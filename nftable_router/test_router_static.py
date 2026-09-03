#!/usr/bin/env python3
"""Static guard for router.py: module-scope / __main__-scope loop state names
(t_*, g_webadmin, queue_stdin ... the non-prefixed ones are hard to scope)
must be ASSIGNED before their first LOAD in source-line order.
Catches edits that silently drop an initializer (production incident:
`t_print = 0` replaced instead of added -> NameError loop every 0.25s)."""
import ast
import os
import sys

CHECK_PREFIXES = ("t_",)


def check_file(path):
    tree = ast.parse(open(path).read(), filename=path)
    # names that module-level statements (before __main__) bind at import time
    preassigned = set()
    mainblk = None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            preassigned.add(node.name)
        if isinstance(node, ast.Assign):
            for t in node.targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        preassigned.add(n.id)
        elif isinstance(node, ast.AugAssign):
            for n in ast.walk(node.target):
                if isinstance(n, ast.Name):
                    preassigned.add(n.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                preassigned.add((a.asname or a.name).split(".")[0])
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and \
                isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__":
            mainblk = node
    if mainblk is None:
        return ["no __main__ block found"]
    defined = set(preassigned)
    # any Store line counts as a *late* binding; error iff first Load line < first Store line
    first_load, first_store = {}, {}
    for n in ast.walk(mainblk):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id.startswith(CHECK_PREFIXES):
            first_load.setdefault(n.id, n.lineno)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id.startswith(CHECK_PREFIXES):
            first_store.setdefault(n.id, n.lineno)
        if isinstance(n, ast.arg) and n.arg.startswith(CHECK_PREFIXES):
            first_store.setdefault(n.arg, 0)
    errors = []
    for name, ln in sorted(first_load.items()):
        st = first_store.get(name)
        if name not in defined and (st is None or st > ln):
            errors.append("'%s' first READ at line %d but first assignment at %s" % (
                name, ln, st))

    # structure guard: install_proxy_chain_rules must itself build+start the
    # supervisor and must not END on a nested def. A module-level block once
    # got pasted INTO the middle of this function, silently absorbing its tail
    # into the new def -> supervisor never started, proxies never spawned.
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "install_proxy_chain_rules":
            if isinstance(node.body[-1], ast.FunctionDef):
                errors.append("install_proxy_chain_rules ends on nested def '%s' (dead tail?)"
                              % node.body[-1].name)
            code = ast.dump(node)
            if "ProxySupervisor" not in code:
                errors.append("install_proxy_chain_rules no longer references ProxySupervisor")
            if "attr='start'" not in code:
                errors.append("install_proxy_chain_rules never calls supervisor .start()")

    # libnftables 0.9.8 landmine (production segfaults, 'segfault at 48'
    # inside nft_run_cmd_from_buffer): ANY name-addressed JSON op that targets
    # a MISSING object NULL-derefs -- measured matrix (2026-09-02,
    # tools/missing_obj_probe.py):
    #   CRASH: delete/list/flush chain BY NAME (missing), delete set BY NAME
    #          (missing), delete rule by BOGUS HANDLE
    #   SAFE : bulk list ruleset/tables, add chain twice (rc=0 no-op),
    #          add/delete element, add rule, delete rule by VALID handle
    # Only nft_utils may touch chains/sets at all, and it must resolve
    # existence/handles from the bulk ruleset dump (_ruleset_scan) first.
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    import glob as _glob
    landmines = ('"delete": {"chain"', '"list": {"chain"', '"flush": {"chain"',
                 '"delete": {"set"')
    for path in _glob.glob(os.path.join(pkg_dir, "*.py")):
        if os.path.basename(path).startswith("test_"):
            continue
        src = open(path).read()
        if os.path.basename(path) == "nft_utils.py":
            # each sanctioned site must be preceded by existence/handle
            # resolution from the bulk dump (handle/_ruleset_scan/get_rules)
            for frag in ('"delete": {"chain"', '"delete": {"set"'):
                i = src.find(frag)
                if i >= 0:
                    ctx = src[max(0, i - 1500): i + 500]
                    if not any(k in ctx for k in ("handle", "_ruleset_scan", "get_rules")):
                        errors.append("nft_utils: %s without bulk-dump existence "
                                      "resolution" % frag)
        else:
            for frag in landmines:
                if frag in src:
                    errors.append("%s: %s (0.9.8 SIGSEGV on missing object) "
                                  "-- go through nft_utils"
                                  % (os.path.basename(path), frag))
    # methods MUST live INSIDE their class: an indented def after a module
    # level function silently nests into that function's body (valid syntax,
    # AttributeError at runtime -- real incident 2026-09-04 with
    # resolve_src_iface landing outside PrintResultThread)
    pt = next((n for n in tree.body if isinstance(n, ast.ClassDef)
               and n.name == "PrintResultThread"), None)
    if pt is None:
        errors.append("class PrintResultThread missing at module level")
    else:
        members = {m.name for m in pt.body if isinstance(m, ast.FunctionDef)}
        for need in ("__init__", "run", "resolve_src_iface"):
            if need not in members:
                errors.append("PrintResultThread.%s missing (misplaced def?)" % need)

    # HOOK INVARIANT (5.10.84 kernel oops class: nf_tables_commit ->
    # __nf_unregister_net_hook -> nfqnl_flush -> nf_reinject WARN, seen live
    # with Comm=python3): base chains/hooks must be created ONLY at boot
    # before the NFQUEUE is bound -- no runtime path may ever churn them.
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

    def _chain_calls(fn):
        return [n.func.attr for n in ast.walk(fn)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("add_chain", "delete_chain")]

    for fname in ("apply_egress_rules", "install_proxy_chain_rules"):
        fn = funcs.get(fname)
        if fn is not None:
            bad_calls = _chain_calls(fn)
            if bad_calls:
                errors.append("%s churns chains at runtime (%s) -- hooks are boot-only "
                              "(nf_reinject oops class)" % (fname, sorted(set(bad_calls))))
    if "ensure_hook_chains" not in funcs:
        errors.append("ensure_hook_chains missing (boot hook creation site)")

    # quit() must NOT clearRules itself (workers/queue still live -> flush race);
    # it must delegate to the main-loop KeyboardInterrupt teardown.
    q = funcs.get("quit")
    if q is not None and any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                             and n.func.id == "clearRules" for n in ast.walk(q)):
        errors.append("quit() clears rules directly -- teardown must go through the "
                      "main loop (stop workers -> unbind -> clearRules)")
    # second Ctrl+C must force-kill children and os._exit -- never nest a
    # KeyboardInterrupt that aborts teardown and leaves queue 4 held.
    if "force_kill_all_children" not in funcs:
        errors.append("force_kill_all_children missing (second Ctrl+C path)")
    if q is not None:
        has_exit = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                       and n.func.attr == "_exit" for n in ast.walk(q))
        if not has_exit:
            errors.append("quit() second Ctrl+C must os._exit after force-killing children")
        has_force = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                        and n.func.id == "force_kill_all_children" for n in ast.walk(q))
        if not has_force:
            errors.append("quit() second Ctrl+C must call force_kill_all_children")

    # KeyboardInterrupt teardown must stop NFQUEUE workers BEFORE arp/webadmin
    # joins (those used to stall 3-5s each and eat the second Ctrl+C).
    def _ki_call_order():
        for n in ast.walk(mainblk):
            if isinstance(n, ast.ExceptHandler) and n.type is not None:
                names = [a.id for a in ast.walk(n.type) if isinstance(a, ast.Name)]
                if "KeyboardInterrupt" in names:
                    ordered = []
                    for c in ast.walk(n):
                        if isinstance(c, ast.Call):
                            if isinstance(c.func, ast.Name):
                                ordered.append(c.func.id)
                            elif isinstance(c.func, ast.Attribute):
                                ordered.append(c.func.attr)
                    return ordered
        return []
    ki_calls = _ki_call_order()
    if ki_calls:
        def _idx(name):
            return ki_calls.index(name) if name in ki_calls else None
        se, unbind, arp = _idx("stop_all_executors"), _idx("unbind"), _idx("stop_all")
        if se is None:
            errors.append("KeyboardInterrupt teardown must call stop_all_executors")
        if se is not None and arp is not None and se > arp:
            errors.append("KeyboardInterrupt must stop NFQUEUE workers before "
                          "arp/proxy stop_all (queue 4 release first)")
        if se is not None and unbind is not None and se > unbind:
            errors.append("KeyboardInterrupt must stop_all_executors before nfqueue.unbind")

    # in __main__: the boot pre-flight queue probe must precede the FIRST
    # table deletion (a crashed master's orphan worker may still hold packets;
    # deleting/rebuilding with a live queue = the flush race), AND the hook
    # chains must be created before the REAL nfqueue bind (ip_mark callback)
    # so the reload path never has to churn a chain later.
    def _first(pred):
        lines = [n.lineno for n in ast.walk(mainblk) if pred(n)]
        return min(lines) if lines else None
    ln_delete_table = _first(lambda n: isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                             and n.func.attr == "delete_table")
    ln_probe_bind = _first(lambda n: isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                           and n.func.attr == "bind" and n.args
                           and isinstance(n.args[0], ast.Constant) and n.args[0].value == 4
                           and len(n.args) > 1 and not (isinstance(n.args[1], ast.Name) and n.args[1].id == "ip_mark"))
    ln_real_bind = _first(lambda n: isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                          and n.func.attr == "bind" and len(n.args) > 1
                          and isinstance(n.args[1], ast.Name) and n.args[1].id == "ip_mark")
    ln_hooks = _first(lambda n: isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                      and n.func.id == "ensure_hook_chains")
    if ln_delete_table is not None and (ln_probe_bind is None or ln_probe_bind > ln_delete_table):
        errors.append("boot: queue-4 pre-flight probe must run before the first delete_table")
    if ln_real_bind is not None and (ln_hooks is None or ln_hooks > ln_real_bind):
        errors.append("boot: ensure_hook_chains must create hooks before the real nfqueue bind")
    return errors


if __name__ == "__main__":
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "router.py")
    errs = check_file(p)
    for e in errs:
        print("FAIL:", e)
    print("router static check: %s" % ("OK" if not errs else "FAILED (%d)" % len(errs)))
    sys.exit(1 if errs else 0)
