#!/usr/bin/env python3
"""Offline tests for arp_snmp.py + arp_svc.py: SNMP varBind parsing (fake
walker, no switch), redis key layout (fake redis), and the collector
supervisor's spawn/diff/restart semantics (fake processes).
Run: python3 test_arp_snmp.py"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arp_snmp as asn
import arp_svc as asvc

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


class FakeOctets:
    """stands in for pysnmp OctetString/MacAddress"""
    def __init__(self, raw):
        self.raw = raw if isinstance(raw, bytes) else str(raw).encode()
    def asNumbers(self):
        return tuple(self.raw)
    def asOctets(self):
        return self.raw
    def __str__(self):
        return self.raw.decode("utf-8", "replace")


class FakeIp:
    """stands in for pysnmp IpAddress"""
    def __init__(self, dotted):
        self.dotted = dotted
        self.raw = bytes(int(x) for x in dotted.split("."))
    def prettyOut(self, _=None):
        return self.dotted
    def asOctets(self):
        return self.raw
    def __str__(self):
        return self.dotted


class FakeRedis:
    def __init__(self):
        self.h = {}
    def hset(self, key, field, value):
        self.h.setdefault(key, {})[str(field)] = value
    def hgetall(self, key):
        return self.h.get(key, {})
    def hlen(self, key):
        return len(self.h.get(key, {}))


def walker_from(table):
    """table: {oid_prefix: [(oid, value), ...]} -> a walk(oid, cb) callable
    that feeds only the varBinds under the requested prefix, like a real
    SNMP subtree walk."""
    def walk(oid, cb):
        for prefix, binds in table.items():
            if str(prefix) == str(oid):
                for b in binds:
                    cb(b)
    return walk


def test_mac_format():
    print("[1] mac formatting matches the on-disk redis format")
    check("6 octets -> aa-bb-... lowercase hex",
          asn.mac_str((0x00, 0x1a, 0x2b, 0xff, 0x0e, 0x5c)) == "00-1a-2b-ff-0e-5c")


def test_arp_std_parse():
    print("[2] ARP-MIB (CE/VRP8) varBind parsing")
    base = asn.OID_ARP_STD
    binds = [
        ("%s.1.9.1.4.192.168.1.10" % base, 9),                       # ifIndex
        ("%s.4.9.1.4.192.168.1.10" % base, FakeOctets(bytes([0, 26, 43, 1, 2, 3]))),  # mac
        ("%s.7.9.1.4.192.168.1.10" % base, 1),                       # state
        ("%s.4.9.1.6.32.1.13.184" % base, FakeOctets(b"xxxxxx")),    # IPv6 -> ignored
    ]
    p = asn.SwitchPoller("sw1", walker_from({base: binds}))
    p.walk(base, p.arpCallback)
    check("one IPv4 entry parsed (v6 row skipped)", list(p.arpList) == ["192.168.1.10"], str(p.arpList))
    e = p.arpList["192.168.1.10"]
    check("mac decoded", e["mac"] == "00-1a-2b-01-02-03")
    check("ifIndex captured", e["ifIndex"] == 9)
    check("state captured", e["State"] == 1)
    check("interface index from OID", e["interface"] == 9)


def test_hw_arp_parse():
    print("[3] HUAWEI-ETHARP-MIB (S5720/VRP5) varBind parsing")
    b = "1.3.6.1.4.1.2011.5.25.123.1.17.1"
    binds = [
        ("%s.11.4.10.0.0.7.0.0" % b, FakeOctets(bytes([0xaa, 0xbb, 0xcc, 0, 1, 2]))),
        ("%s.12.4.10.0.0.7.0.0" % b, 100),
        ("%s.14.4.10.0.0.7.0.0" % b, 42),
    ]
    p = asn.SwitchPoller("sw2", walker_from({b: binds}))
    p.walk(b, p.hwArpTableDataCallback)
    check("ip assembled from oid", "10.0.0.7" in p.arpList, str(list(p.arpList)))
    e = p.arpList["10.0.0.7"]
    check("mac decoded", e["mac"] == "aa-bb-cc-00-01-02")
    check("vlan captured", e["vlan"] == "100")
    check("ifIndex captured", e["ifIndex"] == "42")


def test_hw_arp_l3_ifindex_regression():
    print("[3b] regression: HW ARP index[0] is the L3 ifIndex, NOT index[1]")
    # Index layout captured from a live S5720 (VRP5):
    #   ...17.1.<col>.<L3 ifIndex>.<a.b.c.d>.<addrType>.<prefixLen>
    #   ...17.1.14.58.192.168.28.2.1.32   -> ifIndex 58 = Vlanif14
    #                                        col14 = 51 = GigabitEthernet0/0/46
    # tools/arp.py used index[1] here (copied from the standard-MIB parser,
    # whose prefix stops before the column), so `interface` became 192 --
    # the first octet of the IP -- and ifName_L3 was empty on every VRP5 box.
    b = "1.3.6.1.4.1.2011.5.25.123.1.17.1"
    binds = [
        ("%s.11.58.192.168.28.2.1.32" % b, FakeOctets(bytes([0, 15, 206, 1, 48, 16]))),
        ("%s.12.58.192.168.28.2.1.32" % b, 14),      # vlan
        ("%s.14.58.192.168.28.2.1.32" % b, 51),      # L2 access port ifIndex
    ]
    r = FakeRedis()
    p = asn.SwitchPoller("s5720", walker_from({b: binds}), redis_client=r)
    p.interfaces = {58: {"ifName": "Vlanif14"}, 51: {"ifName": "GigabitEthernet0/0/46"}}
    p.walk(b, p.hwArpTableDataCallback)
    e = p.arpList["192.168.28.2"]
    check("interface = L3 ifIndex from index[0]", e["interface"] == 58, str(e))
    check("NOT the first IP octet (the old bug)", e["interface"] != 192)
    p.poll_arp()
    stored = json.loads(r.h["ARP::MAPPING"]["192.168.28.2"])
    check("ifName_L3 now resolves to the Vlanif", stored["ifName_L3"] == "Vlanif14")
    check("L2 access port resolved from column 14",
          stored.get("ifName_L2") == "GigabitEthernet0/0/46", str(stored))
    check("vlan preserved", stored["vlan"] == "14")

    # the standard ARP-MIB parser keeps its own (different) offset: there the
    # prefix stops before the column, so the L3 ifIndex is element [1]
    p2 = asn.SwitchPoller("ce6881", walker_from({}))
    p2.arpCallback(("%s.4.59.1.4.192.168.11.1" % asn.OID_ARP_STD,
                    FakeOctets(bytes([0, 1, 2, 3, 4, 5]))))
    check("std-MIB parser still reads ifIndex from index[1]",
          p2.arpList["192.168.11.1"]["interface"] == 59)


def test_interface_and_mac_table():
    print("[4] interface table + MAC table -> redis rows")
    ifb = [("1.3.6.1.2.1.2.2.1.2.9", FakeOctets(b"GigabitEthernet0/0/9"))]
    ifn = [("1.3.6.1.2.1.31.1.1.1.1.9", FakeOctets(b"GE0/0/9"))]
    portidx = [("1.3.6.1.2.1.17.1.4.1.2.3", 9)]           # bridge port 3 -> ifIndex 9
    mac = [("1.3.6.1.2.1.17.4.3.1.1.0.26.43.1.2.3", FakeOctets(bytes([0, 26, 43, 1, 2, 3]))),
           ("1.3.6.1.2.1.17.4.3.1.2.0.26.43.1.2.3", 3)]   # -> bridge port 3
    r = FakeRedis()
    p = asn.SwitchPoller("sw3", walker_from({
        asn.OID_IF_DESCR: ifb, asn.OID_IF_NAME: ifn,
        asn.OID_MAC_PORT_IFINDEX: portidx, asn.OID_MAC_TABLE: mac}), redis_client=r)
    p.walk(asn.OID_IF_DESCR, p.interfaceDataCallback)
    p.walk(asn.OID_IF_NAME, p.interfaceDataCallback)
    check("interface parsed with both name and descr",
          p.interfaces[9]["ifName"] == "GE0/0/9" and p.interfaces[9]["ifDescr"] == "GigabitEthernet0/0/9")
    p.sysname = "CORE-SW"
    stored = p.poll_mac_table()
    check("one mac row stored", stored == 1)
    row = json.loads(r.h["MAC::TABLE::CORE-SW"]["00-1a-2b-01-02-03"])
    check("mac row resolves bridge port -> ifIndex", row["ifIndex"] == 9)
    check("mac row carries ifName/ifDescr for the UI",
          row["ifName"] == "GE0/0/9" and row["ifDescr"] == "GigabitEthernet0/0/9")


def test_redis_key_layout_and_sysname_fallback():
    print("[5] redis key layout, and the empty-sysname fallback (old bug)")
    r = FakeRedis()
    p = asn.SwitchPoller("sw-ce6881", walker_from({}), redis_client=r)
    p.isVRP = True
    p.interfaces = {5: {"ifName": "Vlanif100"}}
    p.arpList = {"192.168.1.5": {"interface": 5, "mac": "00-11-22-33-44-55"}}
    # sysname empty -> must fall back to the configured device name, NOT
    # write the bare "ARP::MAPPING::" key the original script produced
    n = p.poll_arp()
    check("arp count returned", n == 1)
    check("per-switch key uses device name when sysName missing",
          "ARP::MAPPING::sw-ce6881" in r.h, str(list(r.h)))
    check("no bare empty-suffix key written", "ARP::MAPPING::" not in r.h)
    check("merged global key also written", "ARP::MAPPING" in r.h)
    e = json.loads(r.h["ARP::MAPPING"]["192.168.1.5"])
    check("entry carries sysname + L3 interface name",
          e["sysname"] == "sw-ce6881" and e["ifName_L3"] == "Vlanif100")

    p.sysname = "REAL-SYSNAME"
    p.poll_arp()
    check("real sysName preferred once known", "ARP::MAPPING::REAL-SYSNAME" in r.h)


def test_dhcp_callback_missing_mac():
    print("[6] regression: DHCP lease join must not KeyError on mac-less ARP rows")
    p = asn.SwitchPoller("sw4", walker_from({}))
    # an ARP row created by the ifIndex varBind arriving first -- no 'mac' yet.
    # The original indexed self.arpList[ip]['mac'] directly and raised into
    # the swallow-all handler, silently aborting the whole DHCP pass.
    p.arpList = {"10.0.0.1": {"interface": 3}}
    p.dhcpsCallback(("1.3.6.1.4.1.2011.5.7.2.1.9.1.5.0.26.43.1.2.3", FakeOctets(b"pool-a")))
    check("no exception, unrelated entry untouched", p.arpList["10.0.0.1"] == {"interface": 3})


def test_status_heartbeat():
    print("[7] SW::STATUS heartbeat for the webadmin health view")
    r = FakeRedis()
    p = asn.SwitchPoller("sw5", walker_from({}), redis_client=r)
    p.sysname = "SW5"
    p.last_poll = 1234.5
    p.publish_status("running", macs=10, arps=20)
    st = json.loads(r.h["SW::STATUS"]["sw5"])
    check("status keyed by device name", st["name"] == "sw5")
    check("carries counts + last_poll", st["macs"] == 10 and st["arps"] == 20 and st["last_poll"] == 1234.5)
    check("carries pid for cross-checking with the supervisor", st["pid"] == os.getpid())
    p.publish_status("error", error="timeout")
    check("error state recorded", json.loads(r.h["SW::STATUS"]["sw5"])["error"] == "timeout")


def test_wlan_sta_parse_and_merge():
    print("[7b] Huawei WLAN STA table -> ARP::MAPPING + MAC::TABLE; switch ARP does not clobber")
    mac_oid = "0.29.99.42.177.15"
    mac = "00-1d-63-2a-b1-0f"
    ap_name = "1F-AP02 西门"
    r = FakeRedis()
    p = asn.SwitchPoller("ac1", walker_from({
        asn.OID_WLAN_STA_IP: [("%s.%s" % (asn.OID_WLAN_STA_IP, mac_oid), FakeIp("192.168.23.222"))],
        asn.OID_WLAN_STA_APNAME: [("%s.%s" % (asn.OID_WLAN_STA_APNAME, mac_oid),
                                  FakeOctets(ap_name.encode("utf-8")))],
        asn.OID_WLAN_STA_SSID: [("%s.%s" % (asn.OID_WLAN_STA_SSID, mac_oid), FakeOctets(b"HomeIOT"))],
        asn.OID_WLAN_STA_VLAN: [("%s.%s" % (asn.OID_WLAN_STA_VLAN, mac_oid), 12)],
        asn.OID_WLAN_STA_APMAC: [("%s.%s" % (asn.OID_WLAN_STA_APMAC, mac_oid),
                                 FakeOctets(bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])))],
    }), redis_client=r)
    p.sysname = "AC1"
    n = p.poll_wlan()
    check("one STA stored", n == 1)
    e = json.loads(r.h["ARP::MAPPING"]["192.168.23.222"])
    check("mac decoded from OID index", e["mac"] == mac)
    check("sysname is the AC", e["sysname"] == "AC1")
    check("AP name as ifName_L3", e["ifName_L3"] == ap_name)
    check("source=wlan", e["source"] == "wlan")
    check("ssid + vlan", e["ssid"] == "HomeIOT" and e["vlan"] == 12)
    check("per-AC mapping key", "ARP::MAPPING::AC1" in r.h)
    macrow = json.loads(r.h["MAC::TABLE::AC1"][mac])
    check("MAC::TABLE ifName is AP name (源设备 skips Eth-Trunk)",
          macrow["ifName"] == ap_name and macrow["ifDescr"] == ap_name)

    sw = asn.SwitchPoller("sw-core", walker_from({}), redis_client=r)
    sw.isVRP = True
    sw.sysname = "HSDJ-47-CORE-CE6881"
    sw.interfaces = {59: {"ifName": "Vlanif1"}}
    sw.arpList = {"192.168.23.222": {"interface": 59, "mac": mac}}
    sw.poll_arp()
    e2 = json.loads(r.h["ARP::MAPPING"]["192.168.23.222"])
    check("switch ARP does not clobber wlan-owned IP in merged view",
          e2["source"] == "wlan" and e2["sysname"] == "AC1")
    e3 = json.loads(r.h["ARP::MAPPING::HSDJ-47-CORE-CE6881"]["192.168.23.222"])
    check("per-switch key still written for the core",
          e3["sysname"] == "HSDJ-47-CORE-CE6881")


def test_oid_mac_and_skip_zero_ip():
    print("[7c] oid_mac helper + STA with 0.0.0.0 is not stored")
    check("6-octet index -> aa-bb-..",
          asn.oid_mac("0.29.99.42.177.15") == "00-1d-63-2a-b1-0f")
    check("short suffix rejected", asn.oid_mac("1.2.3") is None)
    p = asn.SwitchPoller("ac1", walker_from({
        asn.OID_WLAN_STA_IP: [("%s.1.2.3.4.5.6" % asn.OID_WLAN_STA_IP, FakeIp("0.0.0.0"))],
    }))
    check("zero IP skipped", p.poll_wlan() == 0)


def test_poll_once_survives_mac_table_oid_not_increasing():
    print("[7d] poll_once must set last_poll even when BRIDGE-MIB raises OID not increasing")
    def walk(oid, cb):
        if str(oid) in (asn.OID_MAC_TABLE, asn.OID_MAC_PORT_IFINDEX):
            raise RuntimeError("SNMP 192.168.11.11: OID not increasing")
    p = asn.SwitchPoller("AC", walk, log=lambda m: None)
    p.sysname = "AC1"
    macs, arps, stas = p.poll_once()
    check("returns zeros, does not raise", (macs, arps, stas) == (0, 0, 0))
    check("last_poll set so the UI is not stuck on 从未", p.last_poll is not None)


def test_poll_once_wlan_skips_bridge():
    print("[7e] AC with STAs skips the BRIDGE-MIB walk")
    called = []
    def walk(oid, cb):
        called.append(str(oid))
        if str(oid) == asn.OID_WLAN_STA_IP:
            cb(("%s.0.29.99.42.177.15" % asn.OID_WLAN_STA_IP, FakeIp("10.0.0.1")))
        elif str(oid) in (asn.OID_MAC_TABLE, asn.OID_MAC_PORT_IFINDEX):
            raise AssertionError("bridge MIB must be skipped when STAs exist")
    p = asn.SwitchPoller("AC", walk, log=lambda m: None)
    p.sysname = "AC1"
    macs, arps, stas = p.poll_once()
    check("one STA", stas == 1 and macs == 0)
    check("bridge OIDs not walked",
          asn.OID_MAC_TABLE not in called and asn.OID_MAC_PORT_IFINDEX not in called)


def test_pick_mac_port_prefers_named_edge_over_vlanif():
    print("[7f] 192.168.11.14-style: named edge trunk beats Vlanif1 / inter-switch uplinks")
    check("access port ranks highest",
          asn.rank_mac_port("10GE1/0/20", "To-2F-20 Workshop") == 3)
    check("To NAS is a named edge trunk",
          asn.rank_mac_port("Eth-Trunk3", "To NAS") == 2)
    check("uplink to CE is inter-switch",
          asn.rank_mac_port("Eth-Trunk2", "To UpLink - CE6881") == 1)
    check("bare trunk",
          asn.rank_mac_port("Eth-Trunk0", "") == 1)
    check("Vlanif is not a location",
          asn.rank_mac_port("Vlanif1", "") == 0)
    picked = asn.pick_mac_port([
        ("HSDJ-47-ACC-S5720", {"ifName": "Eth-Trunk0", "ifDescr": ""}),
        ("HSDJ-47-ACC-S5732", {"ifName": "Eth-Trunk0", "ifDescr": "To SW1-CE6881"}),
        ("HSDJ-47-CONV-FM6857", {"ifName": "Eth-Trunk2", "ifDescr": "To UpLink - CE6881"}),
        ("HSDJ-47-CORE-CE6881", {"ifName": "Eth-Trunk3", "ifDescr": "To NAS"}),
        ("AC1", {"ifName": "Eth-Trunk0", "ifDescr": "To CE6881-Eth-Trunk 10"}),
    ])
    check("picks CE6881 Eth-Trunk3 To NAS",
          picked == ("HSDJ-47-CORE-CE6881", "Eth-Trunk3", "To NAS"), str(picked))
    access = asn.pick_mac_port([
        ("HSDJ-47-CORE-CE6881", {"ifName": "Eth-Trunk3", "ifDescr": "To NAS"}),
        ("HSDJ-47-CORE-CE6881", {"ifName": "10GE1/0/20", "ifDescr": "To-2F-20 Workshop"}),
    ])
    check("real access port still beats named trunk",
          access[1] == "10GE1/0/20")
    wifi = asn.pick_mac_port([
        ("HSDJ-47-CORE-CE6881", {"ifName": "Eth-Trunk10", "ifDescr": "To AC-1 Eth-Trunk-0"}),
        ("AC1", {"ifName": "B1F-AP05 车库", "ifDescr": "B1F-AP05 车库"}),
    ])
    check("WLAN AP name beats AC-facing trunk",
          wifi[1] == "B1F-AP05 车库")


# ---------------------------------------------------------------------------
# supervisor (arp_svc.py)
# ---------------------------------------------------------------------------

CFG = {"switches": {"enabled": True, "python": "python3.9", "devices": [
    {"name": "sw-a", "ip": "192.168.11.1", "user": "monitor", "auth_key": "AK", "priv_key": "PK"},
    {"name": "sw-b", "ip": "192.168.11.2", "community": "public"},
]}}


class FakeProc:
    _next = 1000
    def __init__(self, argv):
        self.argv = argv
        FakeProc._next += 1
        self.pid = FakeProc._next
        self._rc = None
        self.terminated = False
    def poll(self):
        return self._rc
    def wait(self, timeout=None):
        return self._rc
    def terminate(self):
        self.terminated = True
        self._rc = -15
    def kill(self):
        self._rc = -9


def make_svc():
    spawned = []
    def spawn(argv, outfile):
        p = FakeProc(argv)
        spawned.append(p)
        return p
    svc = asvc.ArpCollectorService(spawn=spawn, now=lambda: make_svc.now, log=lambda m: None,
                                   script="/x/arp_snmp.py")
    return svc, spawned
make_svc.now = 0.0


def test_spec_parsing():
    print("[8] arp_svc.parse_spec: filtering, defaults, dedup")
    spec = asvc.parse_spec(CFG)
    check("two devices parsed", [d["name"] for d in spec["devices"]] == ["sw-a", "sw-b"])
    check("configured python honored (pysnmp lives in a different interpreter)",
          spec["python"] == "python3.9")
    check("defaults filled", spec["poll_interval"] == 300 and spec["redis_db"] == 1)
    check("absent section -> None", asvc.parse_spec({}) is None)
    check("enabled:false -> None", asvc.parse_spec({"switches": {"enabled": False, "devices": [
        {"ip": "1.2.3.4", "community": "x"}]}}) is None)
    check("no devices -> None", asvc.parse_spec({"switches": {"enabled": True, "devices": []}}) is None)
    dis = asvc.parse_spec({"switches": {"devices": [
        {"name": "on", "ip": "1.1.1.1", "community": "c"},
        {"name": "off", "ip": "2.2.2.2", "community": "c", "enabled": False}]}})
    check("per-device enabled:false dropped", [d["name"] for d in dis["devices"]] == ["on"])
    dup = asvc.parse_spec({"switches": {"devices": [
        {"name": "same", "ip": "1.1.1.1", "community": "c"},
        {"name": "same", "ip": "2.2.2.2", "community": "c"}]}})
    check("duplicate names collapsed (would collide on SW::STATUS/logfile)",
          len(dup["devices"]) == 1)
    noip = asvc.parse_spec({"switches": {"devices": [{"name": "x", "community": "c"}]}})
    check("device without ip dropped -> None", noip is None)
    alias = asvc.parse_spec({"switches": {"devices": [
        {"ip": "3.3.3.3", "user": "u", "authKey": "A", "privKey": "P"}]}})
    check("legacy authKey/privKey spelling accepted",
          alias["devices"][0]["auth_key"] == "A" and alias["devices"][0]["priv_key"] == "P")
    check("name defaults to ip", alias["devices"][0]["name"] == "3.3.3.3")


def test_argv_and_redaction():
    print("[9] device_argv: flags match the legacy supervisor command line; creds redacted")
    spec = asvc.parse_spec(CFG)
    argv = asvc.device_argv(spec, spec["devices"][0], script="/x/arp_snmp.py")
    check("uses configured interpreter", argv[0] == "python3.9")
    check("passes --ip", "--ip" in argv and argv[argv.index("--ip") + 1] == "192.168.11.1")
    check("v3 creds passed with legacy flag spelling",
          "--user" in argv and "--authKey" in argv and "--privKey" in argv)
    check("carries the poll intervals", "--poll-interval" in argv and "--redis-db" in argv)
    v2 = asvc.device_argv(spec, spec["devices"][1], script="/x/arp_snmp.py")
    check("v2c passes --community, no v3 flags", "--community" in v2 and "--user" not in v2)
    red = " ".join(asvc.redact_argv(argv))
    check("authKey/privKey masked for logs+UI", "AK" not in red and "PK" not in red and "****" in red)
    check("non-secret args survive redaction", "192.168.11.1" in red)


def test_supervisor_lifecycle():
    print("[10] supervisor: start / diff-reconcile / crash-restart / rate-limit")
    svc, spawned = make_svc()
    svc.reconcile(CFG)
    check("one child per device", len(spawned) == 2 and len(svc.children) == 2)
    first_a = svc.children["sw-a"].proc

    svc.reconcile(CFG)
    check("unchanged config -> no respawn (collectors keep polling across reloads)",
          len(spawned) == 2 and svc.children["sw-a"].proc is first_a)

    changed = json.loads(json.dumps(CFG))
    changed["switches"]["devices"][0]["ip"] = "192.168.11.9"
    svc.reconcile(changed)
    check("changed device respawned", len(spawned) == 3)
    check("old process terminated", first_a.terminated is True)
    check("untouched device kept running", svc.children["sw-b"].proc is spawned[1])

    removed = json.loads(json.dumps(changed))
    removed["switches"]["devices"] = [removed["switches"]["devices"][0]]
    svc.reconcile(removed)
    check("removed device stopped and dropped", "sw-b" not in svc.children and spawned[1].terminated)

    # crash -> restart, with the rate limit kicking in
    make_svc.now = 100.0
    n_before = len(spawned)
    svc.children["sw-a"].proc._rc = 1
    svc.tick()
    check("dead child restarted (back to running, new process object)",
          len(spawned) == n_before + 1 and svc.children["sw-a"].state == "running"
          and svc.children["sw-a"].proc is spawned[-1])
    for i in range(6):
        make_svc.now += 1
        if svc.children["sw-a"].proc is None:
            break                      # already gave up: nothing left to kill
        svc.children["sw-a"].proc._rc = 1
        svc.tick()
    check("rate limit reached -> gaveup (unreachable switch cannot spin forever)",
          svc.children["sw-a"].state == "gaveup")
    n_gaveup = len(spawned)
    svc.tick()
    check("gaveup child is not retried until reload", len(spawned) == n_gaveup)

    st = svc.status()
    check("status reports gaveup + redacted cmd",
          st[0]["state"] == "gaveup" and "AK" not in st[0]["cmd"])

    svc.reconcile(removed)
    check("reload clears gaveup and starts fresh", svc.children["sw-a"].state == "running")

    svc.stop_all()
    check("stop_all stops everything", svc.children == {})


def test_disable_stops_children():
    print("[11] flipping switches.enabled off stops every collector")
    svc, spawned = make_svc()
    svc.reconcile(CFG)
    procs = list(spawned)
    svc.reconcile({"switches": {"enabled": False, "devices": CFG["switches"]["devices"]}})
    check("all children terminated", all(p.terminated for p in procs))
    check("child registry emptied", svc.children == {})
    check("spec cleared", svc.spec is None)
    svc.tick()
    check("tick after disable is a no-op (no resurrection)", len(spawned) == len(procs))


if __name__ == "__main__":
    for t in (test_mac_format, test_arp_std_parse, test_hw_arp_parse,
              test_hw_arp_l3_ifindex_regression, test_interface_and_mac_table, test_redis_key_layout_and_sysname_fallback,
              test_dhcp_callback_missing_mac, test_status_heartbeat,
              test_wlan_sta_parse_and_merge, test_oid_mac_and_skip_zero_ip,
              test_poll_once_survives_mac_table_oid_not_increasing,
              test_poll_once_wlan_skips_bridge,
              test_pick_mac_port_prefers_named_edge_over_vlanif,
              test_spec_parsing, test_argv_and_redaction, test_supervisor_lifecycle,
              test_disable_stops_children):
        t()
    print("\n==== %d passed, %d failed ====" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)
