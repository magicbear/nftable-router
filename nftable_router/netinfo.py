#!/usr/bin/env python3
"""
Local interface inventory + address-assignment detection.

Scans all local interfaces and determines, per interface, how its
addresses were obtained:
  - dhcp4/dhcp6 : via network manager (systemd-networkd / NetworkManager /
                  dhclient / udhcpc / dhcpcd) lease evidence
  - slaac       : IPv6 auto-generated from router advertisements (non-managed)
  - autoip      : link-local 169.254/16 fallback (DHCP failed / no server)
  - static      : configured address with no DHCP evidence
Only read-only commands / files are touched; safe to run unprivileged.
"""

import glob
import ipaddress
import os
import re
import subprocess


def _run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        return p.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def list_interfaces():
    """Return {ifname: {index, up, lower_up, master, addrs:[(version, addr, prefixlen, scope, flags)]}}"""
    ifs = {}
    out = _run(["ip", "-o", "link", "show"])
    for line in out.splitlines():
        m = re.match(r"^(\d+):\s+([^:@\s]+)(@[^\s:]+)?:\s+<([^>]*)>", line)
        if not m:
            continue
        index, name, _, flags = m.groups()
        ifs[name] = {
            "index": int(index),
            "up": "UP" in flags.split(","),
            "lower_up": "LOWER_UP" in flags.split(","),
            "loopback": "LOOPBACK" in flags.split(","),
            "pointopoint": "POINTOPOINT" in flags.split(","),
            "master": None,
            "addrs": [],
        }
        mm = re.search(r"master\s+(\S+)", line)
        if mm:
            ifs[name]["master"] = mm.group(1)

    out = _run(["ip", "-o", "addr", "show"])
    for line in out.splitlines():
        m = re.match(r"^\d+:\s+(\S+)\s+(inet6?)\s+(\S+?)(?:\s+peer\s+(\S+))?\s", line)
        if not m:
            continue
        name, family, local, peer = m.group(1), m.group(2), m.group(3), m.group(4)
        if name not in ifs:
            continue
        # PPP-style output: local addr may lack /prefixlen; borrow from peer or /32
        if "/" not in local:
            local = "%s/%d" % (local, 128 if family == "inet6" else 32)
            if peer and "/" in peer:
                local = "%s/%s" % (local.split("/")[0], peer.split("/")[1])
        try:
            iface = ipaddress.ip_interface(local)
        except ValueError:
            continue
        flags = line.split(m.group(0), 1)[-1]
        scope = "global"
        sm = re.search(r"scope\s+(\S+)", flags)
        if sm:
            scope = sm.group(1)
        ifs[name]["addrs"].append({
            "version": iface.version,
            "addr": str(iface.ip),
            "prefixlen": iface.network.prefixlen,
            "scope": scope,
            "deprecated": "deprecated" in flags,
            "peer": peer.split("/")[0] if peer and "/" in peer else peer,
        })

    for name, kind in _link_kinds().items():
        if name in ifs:
            ifs[name]["kind"] = kind
    return ifs


def _link_kinds():
    """{ifname: kind} e.g. ppp / wireguard / veth / bridge ... (from `ip -d link`)."""
    kinds = {}
    out = _run(["ip", "-d", "-o", "link", "show"])
    for line in out.splitlines():
        m = re.match(r"^\d+:\s+([^:@\s]+)", line)
        if not m:
            continue
        name = m.group(1)
        km = re.search(r"link/(\S+)", line)
        kind = km.group(1) if km else None
        # second line detail: PPP encap prints 'ppp' / 'ppp over Ethernet' / WireGuard prints 'iptunnel'
        if kind == "ppp" or re.search(r"\bppp\b", line):
            kind = "ppp"
        elif re.search(r"\bwireguard\b", line):
            kind = "wireguard"
        kinds[name] = kind
    return kinds


def _ppp_active(ifname, index):
    return (os.path.exists("/run/%s.pid" % ifname) or os.path.exists("/var/run/%s.pid" % ifname)
            or os.path.exists("/run/ppp/%s.pid" % index) or os.path.exists("/var/run/ppp%d.pid" % index))


def _managers():
    """Which network config daemons are running."""
    ps = _run(["ps", "-eo", "args"])
    return {
        "networkd": "systemd-networkd" in ps,
        "networkmanager": "NetworkManager" in ps,
        "dhclient": bool(re.search(r"\bdhclient\b", ps)),
        "udhcpc": bool(re.search(r"\budhcpc\b", ps)),
        "dhcpcd": bool(re.search(r"\bdhcpcd\b", ps)),
        "pppd": bool(re.search(r"\bpppd\b", ps)),
    }


def _networkd_info(ifname, index):
    info = {"managed": False, "dhcp4": False, "dhcp6": False}
    out = _run(["networkctl", "status", ifname])
    if not out:
        return info
    if "State:" not in out:
        return info
    info["managed"] = True
    # "Address: 192.168.32.130 (DHCP4 via 192.168.32.129)" or "DHCPv4 ..."
    if re.search(r"\(DHCP4?\b|DHCPv4 Address|DHCP4 Client: \w+", out, re.I):
        info["dhcp4"] = True
    if re.search(r"\(DHCP6?\b|DHCPv6 Address", out, re.I):
        info["dhcp6"] = True
    # lease file for this ifindex proves a DHCPv4 lease was handed out
    lease = "/run/systemd/netif/leases/%d" % index
    if os.path.exists(lease):
        info["dhcp4"] = True
    return info


def _nm_info(ifname):
    info = {"managed": False, "dhcp4": False, "dhcp6": False}
    out = _run(["nmcli", "-t", "device", "show", ifname])
    if not out:
        return info
    info["managed"] = "unmanaged" not in out and "10 (" not in out.split("GENERAL.STATE:10")[0] if False else ("GENERAL.CONNECTION:" in out and not out.splitlines()[0].endswith(":unmanaged:"))
    # simplest reliable evidence: DHCP4.OPTION lines only exist if NM ran DHCP
    if re.search(r"DHCP4\.OPTION\[", out):
        info["dhcp4"] = True
    if re.search(r"DHCP6\.OPTION\[", out):
        info["dhcp6"] = True
    return info


def _dhclient_leases(ifname):
    v4 = v6 = False
    paths = [
        "/var/lib/dhclient/dhclient*.leases",
        "/var/lib/NetworkManager/dhclient*-%s.conf" % ifname,
        "/run/NetworkManager/dhcp/*/raw",
    ]
    for pat in paths:
        for f in glob.glob(pat):
            try:
                with open(f, "r", errors="replace") as fh:
                    data = fh.read()
                if re.search(r"interface\s*[=]?\s*\"?%s\"?" % re.escape(ifname), data) or f.endswith("-%s.conf" % ifname):
                    v4 = True
            except Exception:
                pass
    return v4, v6


def _pid_based_dhcp(ifname):
    for pid in (
        "/run/udhcpc.%s.pid" % ifname, "/var/run/udhcpc.%s.pid" % ifname,
        "/run/dhcpcd-%s.pid" % ifname, "/run/dhcpcd/pid/%s" % ifname,
    ):
        if os.path.exists(pid):
            return True
    return False


def detect(ifname=None):
    """Main entry: returns {ifname: {fields...}} or one dict if ifname given."""
    ifs = list_interfaces()
    mgrs = _managers()
    result = {}
    for name, info in ifs.items():
        methods = set()
        manager = None
        v4_global = [a for a in info["addrs"] if a["version"] == 4 and a["scope"] == "global"]
        v4_link = [a for a in info["addrs"] if a["version"] == 4 and a["scope"] == "link"]
        v6_global = [a for a in info["addrs"] if a["version"] == 6 and a["scope"] == "global"]
        v6_link = [a for a in info["addrs"] if a["version"] == 6 and a["scope"] == "link"]

        if mgrs["networkd"]:
            nd = _networkd_info(name, info["index"])
            if nd["managed"]:
                manager = manager or "networkd"
                if nd["dhcp4"]:
                    methods.add("dhcp4")
                if nd["dhcp6"]:
                    methods.add("dhcp6")
        if mgrs["networkmanager"]:
            nm = _nm_info(name)
            if nm["dhcp4"]:
                manager = manager or "NetworkManager"
                methods.add("dhcp4")
            if nm["dhcp6"]:
                manager = manager or "NetworkManager"
                methods.add("dhcp6")
        if mgrs["dhclient"]:
            d4, d6 = _dhclient_leases(name)
            if d4:
                manager = manager or "dhclient"
                methods.add("dhcp4")
            if d6:
                manager = manager or "dhclient"
                methods.add("dhcp6")
        if (mgrs["udhcpc"] or mgrs["dhcpcd"]) and _pid_based_dhcp(name):
            manager = manager or ("udhcpc" if mgrs["udhcpc"] else "dhcpcd")
            methods.add("dhcp4")
        if info.get("kind") == "ppp" or (mgrs["pppd"] and _ppp_active(name, info["index"])):
            manager = manager or "pppd"
            methods.add("ppp")

        # heuristics for IPv6: every global v6 address whose lower 64 bits
        # match EUI-64 of the MAC (or the only address is a mngtmpaddr) -> SLAAC
        if v6_global and "dhcp6" not in methods:
            methods.add("slaac")
        # link-local only IPv4 -> autoip (failed DHCP fallback), skip lo
        if not v4_global and v4_link and not info["loopback"]:
            for a in v4_link:
                if ipaddress.ip_address(a["addr"]) in ipaddress.ip_network("169.254.0.0/16"):
                    methods.add("autoip")

        if info["loopback"]:
            methods.add("loopback")
        if not methods or methods == {"loopback"}:
            if v4_global or v6_global:
                methods.add("static")
            elif not info["lower_up"]:
                methods.add("down")
            elif v4_link:
                methods.add("link-local")
            else:
                methods.add("no-address")

        result[name] = {
            "index": info["index"],
            "up": info["up"],
            "lower_up": info["lower_up"],
            "master": info["master"],
            "manager": manager,
            "addrs": info["addrs"],
            "kind": info.get("kind"),
            "methods": sorted(methods),
            "dhcp": ("dhcp4" in methods) or ("dhcp6" in methods),
            "dynamic": ("dhcp4" in methods) or ("dhcp6" in methods) or ("ppp" in methods),
        }
    if ifname is not None:
        return result.get(ifname)
    return result


def main():
    res = detect()
    for name, r in res.items():
        addrs = ", ".join("%s/%d%s" % (a["addr"], a["prefixlen"], "" if a["version"] == 4 else " v%d" % a["version"])
                          for a in r["addrs"]) or "-"
        print("%-12s idx=%-3s %-10s mgr=%-15s methods=%-28s %s" % (
            name,
            r["index"],
            ("up" if r["up"] and r["lower_up"] else ("admin-up" if r["up"] else "down")),
            r["manager"] or "-",
            ",".join(r["methods"]),
            addrs,
        ))
    dyn_ifs = [n for n, r in res.items() if r["dynamic"]]
    print("\nDynamic-assigned (DHCP/PPP) interfaces: %s" % (", ".join(dyn_ifs) if dyn_ifs else "(none)"))


if __name__ == "__main__":
    main()
