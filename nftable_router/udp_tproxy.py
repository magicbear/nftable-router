#!/usr/bin/env python3
"""
Local (router-self-generated) UDP OUTPUT -> TPROXY closed loop.

TPROXY can only attach to `mangle`/PREROUTING (kernel hard limit -- see
iptables-extensions(8): "This target is only valid in the mangle table, in
the PREROUTING chain"); there is no such thing as "TPROXY in OUTPUT". ss-redir's
UDP relay is itself hard-wired to TPROXY semantics (IP_TRANSPARENT +
recvmsg(IP_ORIGDSTADDR)), so a plain `nat OUTPUT` DNAT/REDIRECT -- which
works fine for TCP (see router.create_tproxy) -- does not give it what it
needs for UDP.

The standard workaround: once a locally-generated UDP packet has been
classified (fwmark == a udp-tproxy-enabled proxy line's mark, same
GeoIP/domain classification pipeline as everything else), a policy route
sends it out via a `default dev lo` (unicast) route instead of a real
interface. A `local`-type route makes the kernel redeliver the packet
through the local-input path instead of actually transmitting it, which
re-enters PREROUTING (this time with iif=lo) -- where an ordinary mangle
PREROUTING TPROXY rule (matching iif lo + the same mark) can catch it,
exactly like it already does for LAN-forwarded UDP.

This module owns:
  * /etc/iproute2/rt_tables: ensures a named "tproxy" table exists (cosmetic
    for `ip rule`/`ip route show table tproxy` -- the actual rule/route
    installation always uses the resolved numeric id via pyroute2, so this
    works correctly even if the file can't be written).
  * that table's content: `default dev lo scope link` (unicast), once per
    family, idempotent.
  * one `ip rule add fwmark <mark> ipproto udp lookup tproxy` per
    udp-tproxy-enabled proxy mark, idempotent.

The corresponding `iif lo` mangle PREROUTING TPROXY rule (nft side) is
installed by router.py (needs nftables JSON, not pyroute2). Self-loop
safety (excluding the proxy daemon's own outbound UDP to its real
upstream server) is inherited from the existing skuid accept-guard chain
rule installed for every managed direct proxy in
proxy_mgr.plan_proxy_chain_rules -- a packet from that uid never reaches
the classification queue in the first place, so it never gets this mark
and never enters this loop. Only proxies WITH a resolvable managed uid are
therefore safe to enable this for; router.py enforces that.
"""

import os
import socket

TPROXY_TABLE_NAME = "tproxy"
TPROXY_TABLE_PREFERRED = 100
TPROXY_RULE_PRIO_BASE = 28000
TPROXY_RULE_PRIO_SPAN = 900
RT_TABLES_PATH = "/etc/iproute2/rt_tables"
# 0=unspec, 253=default, 254=main, 255=local: always reserved by the kernel
# regardless of what /etc/iproute2/rt_tables says.
RESERVED_RT_TABLE_NUMBERS = {0, 253, 254, 255}


def ensure_rt_table_name(name=TPROXY_TABLE_NAME, preferred=TPROXY_TABLE_PREFERRED,
                         path=RT_TABLES_PATH, log=None):
    """Ensure /etc/iproute2/rt_tables maps `name` -> some numeric table id;
    return that id. Best-effort: if the file can't be read/written the
    numeric id is still returned and still fully usable via pyroute2 --
    this file only makes `ip rule`/`ip route show table <name>` output
    readable for humans, nothing here depends on it functionally."""
    logf = log or (lambda m: None)
    used, by_name = set(RESERVED_RT_TABLE_NUMBERS), {}
    lines = []
    try:
        with open(path, "r") as f:
            lines = f.readlines()
    except OSError:
        pass
    for line in lines:
        parts = line.split("#", 1)[0].split()
        if len(parts) == 2 and parts[0].isdigit():
            num = int(parts[0])
            used.add(num)
            by_name[parts[1]] = num
    if name in by_name:
        return by_name[name]
    num = preferred
    while num in used:
        num += 1
        if num >= 253:
            raise ValueError("no free rt_tables id for %r (1-252 all used)" % name)
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "a") as f:
            if lines and not lines[-1].endswith("\n"):
                f.write("\n")
            f.write("%d\t%s\n" % (num, name))
        logf("rt_tables: added '%d %s' to %s" % (num, name, path))
    except OSError as e:
        logf("rt_tables: could not persist '%d %s' to %s (%s) -- table is "
             "still fully usable by numeric id, just unnamed in `ip` CLI output" % (
                 num, name, path, e))
    return num


def _af(family):
    return {4: socket.AF_INET, 6: socket.AF_INET6}[family]


def ensure_local_lo_route(ipr, table_id, family, log=None):
    """Ensure table `table_id` has `default dev lo` (unicast, scope link) for
    `family`. Idempotent. Returns True if a route was added.

    0.9.x/5.10 pitfall (production 2026-09-02): a `local`-TYPE default route
    here makes connect() fail with ENETUNREACH for every marked socket, while
    sendto() works -- use a plain unicast route instead: the packet is still
    emitted on lo and re-enters PREROUTING (iif lo), which is all the tproxy
    capture needs."""
    logf = log or (lambda m: None)
    af = _af(family)
    lo_idx = ipr.link_lookup(ifname="lo")
    if not lo_idx:
        raise ValueError("lo interface not found")
    lo_idx = lo_idx[0]
    if list(ipr.get_routes(table=table_id, dst="default", family=af)):
        return False
    ipr.route("add", dst="default", scope="link",
              oif=lo_idx, table=table_id, family=af)
    logf("route table %d: default dev lo scope link (family %d)" % (
        table_id, family))
    return True


def _existing_rule_marks(ipr, family, table_id):
    af = _af(family)
    have = set()
    for r in ipr.get_rules(family=af):
        fw = r.get("fwmark")
        proto = r.get("ip_proto")
        tbl = r.get("table")
        if fw and proto == socket.IPPROTO_UDP and tbl == table_id:
            have.add(int(fw) & 0xffffffff)
    return have


def ensure_mark_rule(ipr, mark, family, table_id, priority, log=None):
    """`ip rule add fwmark <mark> ipproto udp lookup <table_id>`, idempotent.
    Returns True if a rule was added."""
    logf = log or (lambda m: None)
    af = _af(family)
    if mark in _existing_rule_marks(ipr, family, table_id):
        return False
    ipr.rule("add", fwmark=mark, ip_proto=socket.IPPROTO_UDP,
             table=table_id, priority=priority, family=af)
    logf("ip rule add fwmark %d ipproto udp lookup %d (prio %d, family %d)" % (
        mark, table_id, priority, family))
    return True


def sweep_stale_rules(ipr, keep_marks, family, table_id, log=None):
    """Remove owned-band (our priority range) rules pointing at `table_id`
    whose mark is no longer in `keep_marks` (proxy line removed/udp
    disabled/reload). Returns list of removed marks."""
    logf = log or (lambda m: None)
    af = _af(family)
    removed = []
    for r in ipr.get_rules(family=af):
        fw = r.get("fwmark")
        proto = r.get("ip_proto")
        tbl = r.get("table")
        prio = r.get("priority") or 0
        if (fw and proto == socket.IPPROTO_UDP and tbl == table_id
                and TPROXY_RULE_PRIO_BASE <= prio < TPROXY_RULE_PRIO_BASE + TPROXY_RULE_PRIO_SPAN
                and int(fw) & 0xffffffff not in keep_marks):
            mark = int(fw) & 0xffffffff
            ipr.rule("del", fwmark=mark, ip_proto=socket.IPPROTO_UDP,
                     table=table_id, priority=prio, family=af)
            logf("ip rule del fwmark %d ipproto udp (stale, no longer configured)" % mark)
            removed.append(mark)
    return removed


def sync(ipr, marks, family, table_name=TPROXY_TABLE_NAME,
         preferred_table=TPROXY_TABLE_PREFERRED, priority_base=TPROXY_RULE_PRIO_BASE,
         rt_tables_path=RT_TABLES_PATH, log=None):
    """Idempotent reconcile for one family: ensure the named table exists,
    ensure its `default dev lo` (unicast) content, ensure one ip rule per mark,
    remove ip rules for marks no longer present. Safe to call every reload.
    `marks`: iterable of proxy fwmarks needing local-UDP-output tproxy."""
    marks = sorted(set(int(m) for m in marks))
    table_id = ensure_rt_table_name(table_name, preferred=preferred_table,
                                    path=rt_tables_path, log=log)
    route_added = ensure_local_lo_route(ipr, table_id, family, log=log)
    added = [m for m in marks
             if ensure_mark_rule(ipr, m, family, table_id,
                                 priority_base + (m % TPROXY_RULE_PRIO_SPAN), log=log)]
    removed = sweep_stale_rules(ipr, set(marks), family, table_id, log=log)
    return {"table_id": table_id, "route_added": route_added,
            "rules_added": added, "rules_removed": removed}
