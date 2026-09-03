#!/usr/bin/env python3
"""
Per-switch SNMP collector: ARP table / MAC table / interface names -> redis.

Refactored out of tools/arp.py (which was deployed by hand as
/etc/network/arp.py under supervisor, one [program:] block per switch).
Behaviour and every redis key it writes are unchanged, so the router's
PrintResultThread / webadmin "源设备" lookups keep working as-is:

  SW::INT::<sysname>        hash ifIndex -> {ifName, ifDescr, ifMtu, ...}
  MAC::TABLE::<sysname>     hash mac     -> {ifIndex, ifName, ifDescr}
  ARP::MAPPING::<sysname>   hash ip      -> {mac, ifIndex, sysname, ifName_L3, ...}
  ARP::MAPPING              hash ip      -> same (merged view across switches)

Huawei WLAN AC (HUAWEI-WLAN-STATION-MIB hwWlanStationTable) is the same
collector: STA IP/MAC/AP name/SSID/VLAN are merged into ARP::MAPPING with
source=wlan, and MAC::TABLE::<ac> so the flow view's 源设备 shows
`AC1:<AP name>` instead of the upstream switch's Eth-Trunk. Switch ARP
polls skip overwriting a wlan-owned IP.

Added on top of the original script:
  * SW::STATUS::<name> heartbeat (last poll ts / entry counts / last error)
    so webadmin can show whether a collector is actually healthy rather
    than merely "process is alive".
  * clean SIGTERM shutdown (the supervisor/parent stops it between polls
    instead of killing mid-walk).
  * redis socket timeouts + reconnect (the original blocked forever if
    redis went away).
  * sysname fallback: the original wrote to the literal keys
    "ARP::MAPPING::" / "MAC::TABLE::" when the sysName walk came back empty
    (visible in production redis as empty-suffix keys). Now falls back to
    the configured device name.

Run standalone exactly like the old script (flags are compatible):
  python3 -m nftable_router.arp_snmp --ip 192.168.11.1 --community X \\
      --user monitor --authKey X --privKey Y
"""

import argparse
import json
import os
import signal
import sys
import time
import traceback

# ARP-MIB (RFC4293 ipNetToPhysical) -- CloudEngine / VRP8
OID_ARP_STD = "1.3.6.1.2.1.4.35.1"
# HUAWEI-ETHARP-MIB -- S5720 and friends (VRP5)
OID_ARP_HW = "1.3.6.1.4.1.2011.5.25.123.1.17.1"
OID_VRP_PROBE = "1.3.6.1.4.1.2011.5.25.188.1.2"
OID_SYSNAME = "1.3.6.1.2.1.1.5"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
OID_IF_MTU = "1.3.6.1.2.1.2.2.1.4"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER = "1.3.6.1.2.1.2.2.1.8"
OID_MAC_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
OID_MAC_TABLE = "1.3.6.1.2.1.17.4.3.1"
OID_DHCPS_POOL_NAME = "1.3.6.1.4.1.2011.5.7.2.1.1.1."
OID_DHCPS_POOL_CFG = "1.3.6.1.4.1.2011.5.7.2.1.2.1."
OID_DHCPS_INUSE_IP = "1.3.6.1.4.1.2011.5.7.2.1.9.1.2."
OID_DHCPS_INUSE_POOL = "1.3.6.1.4.1.2011.5.7.2.1.9.1.5."
# HUAWEI-WLAN-STATION-MIB hwWlanStationTable (index = STA MAC)
OID_WLAN_STA_APMAC = "1.3.6.1.4.1.2011.6.139.18.1.2.1.3"
OID_WLAN_STA_APNAME = "1.3.6.1.4.1.2011.6.139.18.1.2.1.4"
OID_WLAN_STA_SSID = "1.3.6.1.4.1.2011.6.139.18.1.2.1.18"
OID_WLAN_STA_VLAN = "1.3.6.1.4.1.2011.6.139.18.1.2.1.24"
OID_WLAN_STA_IP = "1.3.6.1.4.1.2011.6.139.18.1.2.1.25"

INTERFACE_KEYS = {
    "1.3.6.1.2.1.2.2.1.2.": "ifDescr",
    "1.3.6.1.2.1.31.1.1.1.1.": "ifName",
    "1.3.6.1.2.1.31.1.1.1.18.": "ifDescr",
    "1.3.6.1.2.1.2.2.1.4.": "ifMtu",
    "1.3.6.1.2.1.2.2.1.5.": "ifSpeed",
    "1.3.6.1.2.1.2.2.1.7.": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8.": "ifOperStatus",
}
MAC_KEYS = {
    "1.3.6.1.2.1.17.4.3.1.1.": "mac",
    "1.3.6.1.2.1.17.4.3.1.2.": "macPort",
    "1.3.6.1.2.1.17.1.4.1.2.": "macPortIndex",
}
HW_ARP_KEYS = {
    "1.3.6.1.4.1.2011.5.25.123.1.17.1.11.": "mac",
    "1.3.6.1.4.1.2011.5.25.123.1.17.1.12.": "vlan",
    "1.3.6.1.4.1.2011.5.25.123.1.17.1.13.": "inner-vlan",
    "1.3.6.1.4.1.2011.5.25.123.1.17.1.14.": "ifIndex",
    "1.3.6.1.4.1.2011.5.25.123.1.17.1.15.": "LastUpdated",
}
DHCPS_KEYS = {
    "1.3.6.1.4.1.2011.5.7.2.1.1.1.1.": "hwDHCPSGlobalPoolName",
    "1.3.6.1.4.1.2011.5.7.2.1.1.1.2.": "hwDHCPSGlobalPoolRowStatus",
    "1.3.6.1.4.1.2011.5.7.2.1.2.1.1.": "hwDHCPSGlobalPoolType",
    "1.3.6.1.4.1.2011.5.7.2.1.2.1.2.": "hwDHCPSGlobalPoolNetwork",
    "1.3.6.1.4.1.2011.5.7.2.1.2.1.3.": "hwDHCPSGlobalPoolNetworkMask",
    "1.3.6.1.4.1.2011.5.7.2.1.2.1.5.": "hwDHCPSGlobalPoolHostMask",
    "1.3.6.1.4.1.2011.5.7.2.1.2.1.7.": "hwDHCPSGlobalPoolConfigUndoFlag",
    "1.3.6.1.4.1.2011.5.7.2.1.9.1.2.": "hwDHCPSIPInUseIP",
    "1.3.6.1.4.1.2011.5.7.2.1.9.1.3.": "hwDHCPSIPInUseEndLease",
    "1.3.6.1.4.1.2011.5.7.2.1.9.1.4.": "hwDHCPSIPInUseType",
    "1.3.6.1.4.1.2011.5.7.2.1.9.1.5.": "hwDHCPSIPInUsePoolName",
}
WLAN_STA_KEYS = {
    OID_WLAN_STA_APMAC + ".": "ap_mac",
    OID_WLAN_STA_APNAME + ".": "ap_name",
    OID_WLAN_STA_SSID + ".": "ssid",
    OID_WLAN_STA_VLAN + ".": "vlan",
    OID_WLAN_STA_IP + ".": "ip",
}

STATUS_KEY = "SW::STATUS"          # hash: device name -> status json
STATUS_TTL_HINT = 900              # webadmin flags a collector stale past this


def mac_str(octets):
    """SNMP OctetString -> 'aa-bb-cc-dd-ee-ff' (the format already stored in
    redis and matched by router.py's MAC::TABLE lookups)."""
    return "-".join(["%02x" % x for x in octets])


def oid_mac(suffix):
    """STA-table index '0.29.99.42.177.15' -> '00-1d-63-2a-b1-0f'."""
    parts = suffix.split(".")
    if len(parts) != 6:
        return None
    try:
        nums = [int(x) for x in parts]
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in nums):
        return None
    return mac_str(nums)


def octet_str(val):
    """UTF-8 OctetString (AP names have CJK); fall back to str()."""
    if hasattr(val, "asOctets"):
        try:
            return val.asOctets().decode("utf-8")
        except UnicodeDecodeError:
            return val.asOctets().decode("utf-8", "replace")
    return str(val)


def ip_str(val):
    """pysnmp IpAddress / 4-byte OctetString / already-dotted str -> dotted."""
    if val is None:
        return ""
    if hasattr(val, "prettyOut"):
        try:
            out = val.prettyOut(val)
            if out and out != "0.0.0.0":
                return out
        except Exception:
            pass
    if hasattr(val, "asOctets"):
        raw = val.asOctets()
        if len(raw) == 4:
            return "%d.%d.%d.%d" % tuple(raw)
    return str(val)


# Inter-switch uplinks: skip these when a more specific port exists.
# Named edge trunks ("To NAS", "To AC-1") still beat a Vlanif SVI.
_UPLINK_HINTS = ("uplink", "to sw", "to ce", "to acc-", "to conv", "to hsdj")


def rank_mac_port(ifName, ifDescr=""):
    """How specific a MAC-table location is. Higher wins.

    3  access port (GE/10GE/...)
    2  named edge trunk (Eth-Trunk + descr like "To NAS")
    1  inter-switch trunk / bare trunk
    0  SVI / empty -- not a physical location
    """
    name = (ifName or "").strip()
    descr = (ifDescr or "").strip()
    nlow, dlow = name.lower(), descr.lower()
    if not name:
        return 0
    if nlow.startswith("vlanif") or nlow.startswith("vlan") \
            or nlow.startswith("nve") or nlow.startswith("loop") \
            or nlow.startswith("inloop"):
        return 0
    if nlow.startswith("eth-trunk"):
        if any(h in dlow for h in _UPLINK_HINTS):
            return 1
        return 2 if descr else 1
    return 3


def pick_mac_port(hits):
    """hits: iterable of (sysname, {ifName, ifDescr}).
    Returns (sysname, ifName, ifDescr) of the most specific location, or None."""
    best = None  # (rank, sysname, ifName, ifDescr)
    for sw, row in hits:
        if not row:
            continue
        ifName = row.get("ifName") or ""
        ifDescr = row.get("ifDescr") or ""
        rank = rank_mac_port(ifName, ifDescr)
        if rank <= 0:
            continue
        if best is None or rank > best[0]:
            best = (rank, sw, ifName, ifDescr)
    if best is None:
        return None
    return best[1], best[2], best[3]


class SwitchPoller:
    """One switch. `walk(oid, callback)` is injected so the whole parsing
    layer is testable without a live switch (see test_arp_snmp.py)."""

    def __init__(self, name, walk, redis_client=None, poll_interval=300,
                 iface_interval=1800, log=print):
        self.name = name
        self.walk = walk
        self.r = redis_client
        self.poll_interval = poll_interval
        self.iface_interval = iface_interval
        self.log = log
        self.arpList = {}
        self.macPortIndex = {}
        self.macTable = {}
        self.interfaces = {}
        self.ipPools = {}
        self.staList = {}
        self.isVRP = False
        self.sysname = ""
        self.stopping = False
        self.last_error = None
        self.last_poll = None
        self.last_counts = {}   # macs/arps/stas kept across status writes

    # -- key naming ---------------------------------------------------------
    def key_suffix(self):
        """sysname when the device gave us one, else the configured name.
        The original wrote bare 'ARP::MAPPING::' on an empty sysName walk,
        which produced junk keys indistinguishable between switches."""
        return self.sysname or self.name

    # -- varBind callbacks (kept semantically identical to tools/arp.py) ----
    def arpCallback(self, varBind):
        arpItem = str(varBind[0])[len(OID_ARP_STD) + 1:].split(".")
        itemType = arpItem[0]
        interfaceIndex = arpItem[1]
        if ".".join(arpItem[2:4]) == "1.4":          # IPv4
            itemIP = ".".join(arpItem[4:])
            if itemIP not in self.arpList:
                self.arpList[itemIP] = {"interface": int(interfaceIndex)}
            entry = self.arpList[itemIP]
            if itemType == "1":
                entry["ifIndex"] = int(varBind[1])
            elif itemType == "4":
                entry["mac"] = mac_str(varBind[1].asNumbers())
            elif itemType == "5":
                entry["LastUpdated"] = int(varBind[1])
            elif itemType == "6":
                entry["Type"] = int(varBind[1])
            elif itemType == "7":
                entry["State"] = int(varBind[1])
            elif itemType == "8":
                entry["RowStatus"] = int(varBind[1])

    def interfaceDataCallback(self, varBind):
        oid = str(varBind[0])
        for key, field in INTERFACE_KEYS.items():
            if oid[0:len(key)] == key:
                try:
                    intIndex = int(oid[len(key):])
                except ValueError:
                    return
                slot = self.interfaces.setdefault(intIndex, {})
                val = varBind[1]
                if hasattr(val, "asOctets"):
                    try:
                        slot[field] = val.asOctets().decode("utf-8")
                    except UnicodeDecodeError:
                        slot[field] = val.asOctets().decode("utf-8", "replace")
                else:
                    slot[field] = str(val)
                return

    def macTableDataCallback(self, varBind):
        oid = str(varBind[0])
        for key, field in MAC_KEYS.items():
            if oid[0:len(key)] == key:
                intIndex = oid[len(key):]
                if field == "macPortIndex":
                    try:
                        self.macPortIndex[int(intIndex)] = int(varBind[1])
                    except ValueError:
                        pass
                    return
                slot = self.macTable.setdefault(intIndex, {})
                slot[field] = str(varBind[1])
                if field == "macPort":
                    try:
                        port = int(varBind[1])
                    except ValueError:
                        return
                    if port in self.macPortIndex:
                        slot["ifIndex"] = self.macPortIndex[port]
                elif field == "mac":
                    slot[field] = mac_str(varBind[1].asNumbers())
                return

    def dhcpsCallback(self, varBind):
        oid = str(varBind[0])
        for key, field in DHCPS_KEYS.items():
            if oid[0:len(key)] != key:
                continue
            poolIndex = oid[len(key):]
            value = varBind[1]
            strValue = str(value)
            if type(value).__name__ == "IpAddress":
                strValue = value.prettyOut(value)

            if "hwDHCPSGlobalPool" in field:
                poolIndex = "".join([chr(int(x)) for x in poolIndex.split(".")[1:]])
                self.ipPools.setdefault(poolIndex, {})[field] = strValue
            elif "hwDHCPSIPInUseIP" in field:
                mac = "-".join(["%02x" % int(x) for x in poolIndex.split(".")])
                if strValue not in self.arpList:
                    self.arpList[strValue] = {"interface": -1, "mac": mac}
            elif "hwDHCPSIPInUse" in field:
                macIndex = "-".join(["%02x" % int(x) for x in poolIndex.split(".")])
                for ip in self.arpList:
                    # .get(): ARP entries created by arpCallback may not have
                    # a mac yet (walk order) -- the original indexed directly
                    # and raised KeyError into the swallow-all handler
                    if self.arpList[ip].get("mac") == macIndex:
                        self.arpList[ip][field[14:]] = strValue
                        break
            return

    def hwArpTableDataCallback(self, varBind):
        """HUAWEI-private ARP table (VRP5 boxes: S5720 etc). Index layout
        verified against live switches -- the OID after the column is
            <L3 ifIndex>.<a>.<b>.<c>.<d>.<addrType>.<prefixLen>
        e.g. ...17.1.14.58.192.168.28.2.1.32  ->  ifIndex 58 = Vlanif14.

        NOTE the index offset differs from the standard ARP-MIB parser: the
        HW_ARP_KEYS prefixes already include the column number, so the L3
        ifIndex is element [0] here, whereas in arpCallback (whose prefix
        stops before the column) it is element [1]. tools/arp.py used [1]
        in both, so on every VRP5 switch `interface` was silently set to the
        FIRST OCTET OF THE IP (192, 10, ...) -- never a real ifIndex, which
        is why ifName_L3 came out empty for those devices."""
        oid = str(varBind[0])
        for key, field in HW_ARP_KEYS.items():
            if oid[0:len(key)] == key:
                arpIndex = oid[len(key):].split(".")
                if len(arpIndex) < 5:
                    return
                itemIP = ".".join(arpIndex[1:5])
                entry = self.arpList.setdefault(itemIP, {})
                try:
                    entry["interface"] = int(arpIndex[0])
                except ValueError:
                    pass
                if field == "mac":
                    entry[field] = mac_str(varBind[1].asNumbers())
                else:
                    entry[field] = str(varBind[1])
                return

    def assignSysName(self, varBind):
        self.sysname = str(varBind[1])

    def checkVRP(self, varBind):
        self.isVRP = str(varBind[1]) == "VRP"

    def wlanStaCallback(self, varBind):
        oid = str(varBind[0])
        for key, field in WLAN_STA_KEYS.items():
            if oid[0:len(key)] != key:
                continue
            mac = oid_mac(oid[len(key):])
            if not mac:
                return
            slot = self.staList.setdefault(mac, {"mac": mac})
            val = varBind[1]
            if field == "ap_mac":
                if hasattr(val, "asNumbers"):
                    slot[field] = mac_str(val.asNumbers())
                else:
                    slot[field] = str(val)
            elif field == "ip":
                ip = ip_str(val)
                if ip and ip != "0.0.0.0":
                    slot[field] = ip
            elif field in ("ap_name", "ssid"):
                slot[field] = octet_str(val).strip()
            elif field == "vlan":
                try:
                    slot[field] = int(val)
                except (TypeError, ValueError):
                    slot[field] = str(val)
            return

    # -- polling ------------------------------------------------------------
    def probe_identity(self):
        """sysName + VRP flavour + interface list. Determines which ARP MIB
        to walk and what the redis key suffix will be."""
        self.isVRP = False
        self.walk(OID_VRP_PROBE, self.checkVRP)
        self.walk(OID_SYSNAME, self.assignSysName)
        self.walk(OID_IF_DESCR, self.interfaceDataCallback)
        self.walk(OID_IF_NAME, self.interfaceDataCallback)

    def refresh_interfaces(self):
        for oid in (OID_IF_MTU, OID_IF_SPEED, OID_IF_ADMIN, OID_IF_OPER,
                    OID_IF_NAME, OID_IF_ALIAS):
            self.walk(oid, self.interfaceDataCallback)

    def store_interfaces(self):
        if self.r is None:
            return
        for intIndex, data in self.interfaces.items():
            self.r.hset("SW::INT::%s" % self.key_suffix(), intIndex, json.dumps(data))

    def poll_mac_table(self):
        self.macTable = {}
        self.macPortIndex = {}
        self.walk(OID_MAC_PORT_IFINDEX, self.macTableDataCallback)
        self.walk(OID_MAC_TABLE, self.macTableDataCallback)
        stored = 0
        for index, row in self.macTable.items():
            if "ifIndex" not in row or "mac" not in row:
                continue
            ifIndex = row["ifIndex"]
            iface = self.interfaces.get(ifIndex, {})
            if self.r is not None:
                self.r.hset("MAC::TABLE::%s" % self.key_suffix(), row["mac"], json.dumps({
                    "ifIndex": ifIndex,
                    "ifName": iface.get("ifName", ""),
                    "ifDescr": iface.get("ifDescr", ""),
                }))
            stored += 1
        return stored

    def poll_dhcp(self):
        if self.isVRP:
            return
        for oid in (OID_DHCPS_POOL_NAME, OID_DHCPS_POOL_CFG,
                    OID_DHCPS_INUSE_IP, OID_DHCPS_INUSE_POOL):
            self.walk(oid, self.dhcpsCallback)

    def poll_arp(self):
        if self.isVRP:
            self.walk(OID_ARP_STD, self.arpCallback)
        else:
            self.walk(OID_ARP_HW, self.hwArpTableDataCallback)
        count = 0
        wlan_owned = self._wlan_owned_ips()
        for ip, entry in self.arpList.items():
            count += 1
            entry["sysname"] = self.key_suffix()
            iface = self.interfaces.get(entry.get("interface"), {})
            entry["ifName_L3"] = iface.get("ifName", "")
            # The HUAWEI-private table also hands us the L2 access port
            # (column 14) outright; the standard ARP-MIB does not, so there
            # this stays empty and the MAC-table join is the only answer.
            l2 = entry.get("ifIndex")
            if l2 is not None:
                try:
                    entry["ifName_L2"] = self.interfaces.get(int(l2), {}).get("ifName", "")
                except (TypeError, ValueError):
                    pass
            if self.r is not None:
                blob = json.dumps(entry)
                self.r.hset("ARP::MAPPING::%s" % self.key_suffix(), ip, blob)
                if ip not in wlan_owned:
                    self.r.hset("ARP::MAPPING", ip, blob)
        return count

    def _wlan_owned_ips(self):
        """IPs already claimed by a WLAN STA poll. Switch ARP must not clobber
        them in the merged ARP::MAPPING view (core CE learns the same hosts
        on the AC-facing Eth-Trunk)."""
        if self.r is None:
            return set()
        try:
            raw = self.r.hgetall("ARP::MAPPING") or {}
        except Exception:
            return set()
        owned = set()
        for ip, blob in raw.items():
            ip_s = ip.decode("utf-8", "replace") if isinstance(ip, bytes) else str(ip)
            try:
                text = blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
                if json.loads(text).get("source") == "wlan":
                    owned.add(ip_s)
            except (ValueError, TypeError, AttributeError):
                pass
        return owned

    def poll_wlan(self):
        """HUAWEI-WLAN-STATION-MIB: STA IP -> MAC + AP name. No-op on a
        switch (OID missing / empty). Walks IP first so an empty table
        skips the other columns."""
        self.staList = {}
        try:
            self.walk(OID_WLAN_STA_IP, self.wlanStaCallback)
        except Exception:
            return 0
        if not self.staList:
            return 0
        for oid in (OID_WLAN_STA_APNAME, OID_WLAN_STA_SSID,
                    OID_WLAN_STA_VLAN, OID_WLAN_STA_APMAC):
            try:
                self.walk(oid, self.wlanStaCallback)
            except Exception:
                pass
        count = 0
        suffix = self.key_suffix()
        for mac, sta in self.staList.items():
            ip = sta.get("ip")
            if not ip:
                continue
            ap = sta.get("ap_name") or suffix
            entry = {
                "interface": -1,
                "mac": mac,
                "sysname": suffix,
                "ifName_L3": ap,
                "vlan": sta.get("vlan"),
                "ssid": sta.get("ssid") or "",
                "ap_name": sta.get("ap_name") or "",
                "ap_mac": sta.get("ap_mac") or "",
                "source": "wlan",
            }
            count += 1
            if self.r is not None:
                blob = json.dumps(entry)
                self.r.hset("ARP::MAPPING::%s" % suffix, ip, blob)
                self.r.hset("ARP::MAPPING", ip, blob)
                self.r.hset("MAC::TABLE::%s" % suffix, mac, json.dumps({
                    "ifIndex": -1,
                    "ifName": ap,
                    "ifDescr": ap,
                }))
        return count

    def poll_once(self):
        """One full ARP/MAC/DHCP/WLAN cycle. Returns (macs, arps, stas).

        Each MIB walk is isolated: a Huawei AC's BRIDGE-MIB commonly
        reports 'OID not increasing' and must not leave last_poll unset
        (the UI then shows 从未 + 错误). WLAN STAs are walked first; if
        any are found this is an AC and the useless bridge/DHCP walks
        are skipped."""
        self.arpList = {}
        macs = arps = stas = 0
        try:
            stas = self.poll_wlan()
        except Exception as e:
            self.log("[%s] wlan: %s" % (self.name, e))
        if stas == 0:
            try:
                macs = self.poll_mac_table()
            except Exception as e:
                self.log("[%s] mac table: %s" % (self.name, e))
            try:
                self.poll_dhcp()
            except Exception as e:
                self.log("[%s] dhcp: %s" % (self.name, e))
        try:
            arps = self.poll_arp()
        except Exception as e:
            self.log("[%s] arp: %s" % (self.name, e))
        self.last_poll = time.time()
        return macs, arps, stas

    def publish_status(self, state, macs=None, arps=None, stas=None, error=None):
        if self.r is None:
            return
        # remember the last real counts so a later "stopped"/"error" write
        # does not blank out what the UI knows about this switch
        if macs is not None:
            self.last_counts["macs"] = macs
        if arps is not None:
            self.last_counts["arps"] = arps
        if stas is not None:
            self.last_counts["stas"] = stas
        macs = self.last_counts.get("macs") if macs is None else macs
        arps = self.last_counts.get("arps") if arps is None else arps
        stas = self.last_counts.get("stas") if stas is None else stas
        try:
            self.r.hset(STATUS_KEY, self.name, json.dumps({
                "name": self.name,
                "sysname": self.sysname,
                "state": state,
                "vrp": self.isVRP,
                "wlan": bool(stas),
                "interfaces": len(self.interfaces),
                "macs": macs,
                "arps": arps,
                "stas": stas,
                "last_poll": self.last_poll,
                "error": error,
                "pid": os.getpid(),
                "ts": time.time(),
            }))
        except Exception:
            pass          # status is diagnostics only; never break polling

    def run_forever(self, sleeper=time.sleep):
        last_iface = 0
        try:
            self.probe_identity()
            self.store_interfaces()
            self.publish_status("running")
            self.log("[%s] sysname=%s vrp=%s interfaces=%d" % (
                self.name, self.sysname, self.isVRP, len(self.interfaces)))
        except Exception as e:
            self.last_error = "%s: %s" % (type(e).__name__, e)
            self.publish_status("error", error=self.last_error)
            self.log("[%s] identity probe failed: %s" % (self.name, self.last_error))

        last_poll = 0
        while not self.stopping:
            now = time.time()
            if now - last_iface >= self.iface_interval:
                last_iface = now
                try:
                    self.refresh_interfaces()
                    self.store_interfaces()
                except Exception as e:
                    self.last_error = "%s: %s" % (type(e).__name__, e)
                    self.log("[%s] interface refresh error: %s" % (self.name, self.last_error))
                    self.log(traceback.format_exc())

            if now - last_poll >= self.poll_interval:
                last_poll = now
                try:
                    macs, arps, stas = self.poll_once()
                    self.last_error = None
                    self.publish_status("running", macs=macs, arps=arps, stas=stas)
                    self.log("[%s] mac=%d arp=%d sta=%d" % (self.name, macs, arps, stas))
                except Exception as e:
                    self.last_error = "%s: %s" % (type(e).__name__, e)
                    self.publish_status("error", error=self.last_error)
                    self.log("[%s] poll error: %s" % (self.name, self.last_error))
                    self.log(traceback.format_exc())
            else:
                sleeper(1)
        self.publish_status("stopped")


# ---------------------------------------------------------------------------
# pysnmp binding (imported lazily so the parsing layer stays unit-testable
# on boxes without pysnmp -- note the production router only has pysnmp
# under python3.9, hence the configurable interpreter in arp_svc.py)
# ---------------------------------------------------------------------------

def _pysnmp_generation():
    """'modern' = pysnmp 6/7.x (lextudio, asyncio API, the maintained line),
    'legacy' = pysnmp 4.4.x (2019, sync nextCmd). 4.4.x cannot run on
    Python >= 3.12 at all -- it imports the removed `asyncore` module -- so
    both are supported here: the deployed router still has 4.4.12 under
    python3.9 while new installs get 7.x."""
    try:
        import pysnmp.hlapi.v3arch.asyncio  # noqa: F401
        return "modern"
    except Exception:
        pass
    try:
        from pysnmp.hlapi import nextCmd  # noqa: F401
        return "legacy"
    except Exception as e:
        raise ImportError(
            "需要 pysnmp。新环境请装 pysnmp>=7 (pip install 'pysnmp>=7')；"
            "Python<3.12 上的旧环境可继续用 pysnmp 4.4.x。原始错误: %s" % e)


def _make_walker_modern(host, community, user, auth_key, priv_key, port, timeout, retries):
    """pysnmp 6/7.x: the hlapi is asyncio-only, so each walk is driven to
    completion inside its own event loop and handed to the same sync
    callback contract the rest of this module (and its tests) expect."""
    import asyncio
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UsmUserData, ContextData,
        UdpTransportTarget, ObjectType, ObjectIdentity, walk_cmd,
        usmHMAC192SHA256AuthProtocol, usmAesCfb128Protocol)

    if user and auth_key:
        login = UsmUserData(user, authProtocol=usmHMAC192SHA256AuthProtocol,
                            authKey=auth_key, privKey=priv_key,
                            privProtocol=usmAesCfb128Protocol)
    elif community:
        login = CommunityData(community)
    else:
        raise ValueError("需要 community (v2c) 或 user+authKey (v3) 之一")

    def walk(oid, callback):
        base = str(oid)

        async def _run():
            engine = SnmpEngine()
            target = await UdpTransportTarget.create((host, port), timeout=timeout,
                                                     retries=retries)
            try:
                async for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd(
                        engine, login, target, ContextData(),
                        ObjectType(ObjectIdentity(base)),
                        lexicographicMode=False, ignoreNonIncreasingOid=True):
                    if errorIndication:
                        raise RuntimeError("SNMP %s: %s" % (host, errorIndication))
                    if errorStatus:
                        raise RuntimeError("SNMP %s: %s" % (host, errorStatus.prettyPrint()))
                    for varBind in varBinds:
                        # walk_cmd already stops at the subtree end, but a
                        # buggy agent can still hand back a sibling OID
                        if not str(varBind[0]).startswith(base):
                            return
                        callback(varBind)
            finally:
                try:
                    engine.close_dispatcher()
                except Exception:
                    pass

        asyncio.run(_run())

    return walk


def make_snmp_walker(host, community=None, user=None, auth_key=None, priv_key=None,
                     port=161, timeout=5, retries=2, log=print):
    if _pysnmp_generation() == "modern":
        return _make_walker_modern(host, community, user, auth_key, priv_key,
                                   port, timeout, retries)
    from pysnmp.hlapi import (SnmpEngine, CommunityData, UsmUserData, ContextData,
                              UdpTransportTarget, ObjectType, ObjectIdentity, nextCmd)
    from pysnmp.entity import config as snmp_config

    if user and auth_key:
        login = UsmUserData(user, authProtocol=snmp_config.usmHMAC192SHA256AuthProtocol,
                            authKey=auth_key, privKey=priv_key,
                            privProtocol=snmp_config.usmAesCfb128Protocol)
    elif community:
        login = CommunityData(community)
    else:
        raise ValueError("需要 community (v2c) 或 user+authKey (v3) 之一")

    engine = SnmpEngine()
    target = UdpTransportTarget((host, port), timeout=timeout, retries=retries)

    def walk(oid, callback):
        # lexicographicMode=False: stop at end of subtree (Huawei agents
        # otherwise keep walking into unrelated MIBs).
        # ignoreNonIncreasingOid=True: Huawei WLAN/BRIDGE tables commonly
        # return a non-monotonic OID (MAC indexes) and pysnmp would abort
        # with 'OID not increasing'. Combined with the subtree check and
        # a same-OID repeat cap this cannot loop forever.
        base = oid if not isinstance(oid, str) else ObjectIdentity(oid)
        last_name = None
        repeats = 0
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                engine, login, target, ContextData(), ObjectType(base),
                lexicographicMode=False, ignoreNonIncreasingOid=True):
            if errorIndication:
                raise RuntimeError("SNMP %s: %s" % (host, errorIndication))
            if errorStatus:
                raise RuntimeError("SNMP %s: %s at %s" % (
                    host, errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?"))
            out_of_subtree = False
            for varBind in varBinds:
                name = varBind[0]
                name_s = str(name)
                if name_s == last_name:
                    repeats += 1
                    if repeats >= 3:
                        return
                else:
                    repeats = 0
                    last_name = name_s
                if hasattr(name, "__getitem__") and not isinstance(name, str):
                    try:
                        if name[0:len(base)] != base:
                            out_of_subtree = True
                            break
                    except (TypeError, ValueError):
                        pass
                callback(varBind)
            if out_of_subtree:
                break

    return walk


def build_parser():
    p = argparse.ArgumentParser(description="switch ARP/MAC SNMP collector -> redis")
    # long flags match the legacy supervisor command lines verbatim
    p.add_argument("--ip", required=True, help="switch management IP")
    p.add_argument("--community", default=None, help="SNMP v2c community")
    p.add_argument("--user", default=None, help="SNMP v3 user")
    p.add_argument("--authKey", dest="auth_key", default=None, help="SNMP v3 auth key")
    p.add_argument("--privKey", dest="priv_key", default=None, help="SNMP v3 priv key")
    p.add_argument("--name", default=None, help="display name (default: the IP)")
    p.add_argument("--snmp-port", type=int, default=161)
    p.add_argument("--poll-interval", type=int, default=300)
    p.add_argument("--iface-interval", type=int, default=1800)
    p.add_argument("--redis-host", default="127.0.0.1")
    p.add_argument("--redis-port", type=int, default=6379)
    p.add_argument("--redis-db", type=int, default=1)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    import redis

    name = args.name or args.ip
    r = redis.Redis(host=args.redis_host, port=args.redis_port, db=args.redis_db,
                    socket_timeout=5, socket_connect_timeout=5)

    def log(msg):
        print(msg, flush=True)

    walk = make_snmp_walker(args.ip, community=args.community, user=args.user,
                            auth_key=args.auth_key, priv_key=args.priv_key,
                            port=args.snmp_port, log=log)
    poller = SwitchPoller(name, walk, redis_client=r,
                          poll_interval=args.poll_interval,
                          iface_interval=args.iface_interval, log=log)

    def bye(sig, frm):
        poller.stopping = True
    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)

    log("[%s] collector start (%s, redis %s:%d/%d)" % (
        name, args.ip, args.redis_host, args.redis_port, args.redis_db))
    poller.run_forever()
    log("[%s] collector stopped" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
