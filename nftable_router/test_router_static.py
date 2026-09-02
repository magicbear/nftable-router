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

    # libnftables 0.9.8 landmine (3 production segfaults, 'segfault at 48'
    # inside nft_run_cmd_from_buffer): a JSON delete of a CHAIN addressed by
    # NAME NULL-derefs. Only nft_utils.delete_chain may delete chains at all,
    # and it resolves the HANDLE first -- forbid raw name-based deletes and
    # require 'handle' inside that one sanctioned call site.
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    import glob as _glob
    for path in _glob.glob(os.path.join(pkg_dir, "*.py")):
        if os.path.basename(path).startswith("test_"):
            continue
        src = open(path).read()
        n = src.count('"delete": {"chain"')
        if path.endswith("nft_utils.py"):
            if n and "handle" not in src[src.index('"delete": {"chain"') - 900:
                                       src.index('"delete": {"chain"') + 400]:
                errors.append("nft_utils: JSON chain delete without handle resolution")
        elif n:
            errors.append("%s: JSON delete-chain BY NAME (0.9.8 SIGSEGV) -- use nfu.delete_chain"
                          % os.path.basename(path))
    return errors


if __name__ == "__main__":
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "router.py")
    errs = check_file(p)
    for e in errs:
        print("FAIL:", e)
    print("router static check: %s" % ("OK" if not errs else "FAILED (%d)" % len(errs)))
    sys.exit(1 if errs else 0)
