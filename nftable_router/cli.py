#!/usr/bin/env python3
"""
Console-script entry points (see [project.scripts] in pyproject.toml).

router.py's startup is a ~700-line `if __name__ == "__main__":` block that
relies on module-level globals being bound in the __main__ namespace (the
NFQUEUE workers fork out of exactly that state). Wrapping it in a function
would change that binding, so the launcher re-runs the module under
run_name="__main__" instead -- identical semantics to `python -m
nftable_router.router`, just reachable as a console script.

webadmin/arp_snmp already expose a real main(); those are called directly.
"""

import runpy
import sys


def _check_nftables_binding():
    """The libnftables Python binding ships with nftables itself (Debian:
    python3-nftables), NOT PyPI -- pip cannot pull it in, so fail with an
    actionable message instead of a bare ImportError traceback."""
    try:
        import nftables  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "错误: 缺少 nftables Python 绑定 (import nftables 失败)。\n"
            "它由 nftables 项目自身提供，PyPI 上没有，pip 装不了。\n"
            "  Debian/Ubuntu:  apt install python3-nftables\n"
            "若使用 venv (include-system-site-packages=false)，还需把它链进 venv:\n"
            "  ln -s /usr/lib/python3/dist-packages/nftables "
            "<venv>/lib/python3.*/site-packages/\n")
        return False
    return True


def router_main():
    if not _check_nftables_binding():
        return 2
    runpy.run_module("nftable_router.router", run_name="__main__", alter_sys=True)
    return 0


def webadmin_main():
    from nftable_router import webadmin
    return webadmin.main()


def arp_collector_main():
    from nftable_router import arp_snmp
    return arp_snmp.main()
