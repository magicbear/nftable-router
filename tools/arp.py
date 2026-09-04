import pysnmp.proto.rfc1902
from pysnmp.hlapi import *
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.rfc1902 import *
import logging
import time
import json
import sys
import io
import getopt
import pathlib
import threading
import redis
import traceback

# logging.basicConfig(filename="/data/log/huawei-sw.log", filemode='w', format='%(asctime)s - %(message)s', level=logging.INFO)
log_handler = logging.StreamHandler(sys.stderr)
log_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler.setFormatter(formatter)
logging.getLogger().addHandler(log_handler)
logging.getLogger().setLevel(logging.INFO)

class ioThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.arpList = {}
        self.macPortIndex = {}
        self.macTable = {}
        self.interfaces = {}
        self.ipPools = {}
        self.isVRP = False
        self.sysname = ""
        self.r = redis.Redis(host='127.0.0.1', port=6379, db=1)

    def arpCallback(self, varBind):
        arpItem = str(varBind[0])[len("1.3.6.1.2.1.4.35.1")+1:].split(".")
        itemType = arpItem[0]
        interfaceIndex = arpItem[1]
        if ".".join(arpItem[2:4]) == "1.4": # IPv4
            itemIP = ".".join(arpItem[4:])
            if itemIP not in self.arpList:
                self.arpList[itemIP] = {
                    "interface": int(interfaceIndex)
                }

            if itemType == "1":
                self.arpList[itemIP]['ifIndex'] = int(varBind[1])
            elif itemType == "4":
                self.arpList[itemIP]['mac'] = '-'.join(["%02x" % (x) for x in varBind[1].asNumbers()])
            elif itemType == "5":
                self.arpList[itemIP]['LastUpdated'] = int(varBind[1])
            elif itemType == "6":
                self.arpList[itemIP]['Type'] = int(varBind[1])
            elif itemType == "7":
                self.arpList[itemIP]['State'] = int(varBind[1])
            elif itemType == "8":
                self.arpList[itemIP]['RowStatus'] = int(varBind[1])
            # print("ARP CALLBACK -> ", arpItem, itemIndex, itemIP, itemType)

    def interfaceDataCallback(self, varBind):
        interfaceKey = {
            "1.3.6.1.2.1.2.2.1.2.": "ifDescr",
            "1.3.6.1.2.1.31.1.1.1.1.": "ifName",
            "1.3.6.1.2.1.31.1.1.1.18.": "ifDescr",
            "1.3.6.1.2.1.2.2.1.4.": "ifMtu",
            "1.3.6.1.2.1.2.2.1.5.": "ifSpeed",
            "1.3.6.1.2.1.2.2.1.7.": "ifAdminStatus",
            "1.3.6.1.2.1.2.2.1.8.": "ifOperStatus"
        }
        for key in interfaceKey:
            if str(varBind[0])[0:len(key)] == key:
                intIndex = int(str(varBind[0])[len(key):])
                if intIndex not in self.interfaces:
                    self.interfaces[intIndex] = {}
                if isinstance(varBind[1], OctetString):
                    self.interfaces[intIndex][interfaceKey[key]] = varBind[1].asOctets().decode('utf-8')
                else:
                    self.interfaces[intIndex][interfaceKey[key]] = str(varBind[1])

    def macTableDataCallback(self, varBind):
        interfaceKey = {
            "1.3.6.1.2.1.17.4.3.1.1.": "mac",
            "1.3.6.1.2.1.17.4.3.1.2.": "macPort",
            "1.3.6.1.2.1.17.1.4.1.2.": "macPortIndex",
        }
        for key in interfaceKey:
            if str(varBind[0])[0:len(key)] == key:
                intIndex = str(varBind[0])[len(key):]
                if interfaceKey[key] == "macPortIndex":
                    self.macPortIndex[int(intIndex)] = int(varBind[1])
                else:
                    if intIndex not in self.macTable:
                        self.macTable[intIndex] = {}
                    self.macTable[intIndex][interfaceKey[key]] = str(varBind[1])
                    if interfaceKey[key] == "macPort" and int(varBind[1]) in self.macPortIndex:
                        self.macTable[intIndex]["ifIndex"] = self.macPortIndex[int(varBind[1])]
                    elif interfaceKey[key] == "mac":
                        self.macTable[intIndex][interfaceKey[key]] = '-'.join(["%02x" % (x) for x in varBind[1].asNumbers()])

    def dhcpsCallback(self, varBind):
        interfaceKey = {
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

        for key in interfaceKey:
            if str(varBind[0])[0:len(key)] == key:
                poolIndex = str(varBind[0])[len(key):]
                strValue = str(varBind[1])
                if isinstance(varBind[1], IpAddress):
                    strValue = varBind[1].prettyOut(varBind[1])

                if "hwDHCPSGlobalPool" in interfaceKey[key]:
                    poolIndex = "".join([chr(int(x)) for x in poolIndex.split(".")[1:]])
                    if poolIndex not in self.ipPools:
                        self.ipPools[poolIndex] = {}
                    self.ipPools[poolIndex][interfaceKey[key]] = strValue
                elif "hwDHCPSIPInUseIP" in interfaceKey[key]:
                    poolIndex = "-".join(["%02x" % int(x) for x in poolIndex.split(".")])
                    if strValue not in self.arpList:
                        self.arpList[strValue] = {
                            "interface": -1,
                            "mac": poolIndex
                        }
                elif "hwDHCPSIPInUse" in interfaceKey[key]:
                    macIndex = "-".join(["%02x" % int(x) for x in poolIndex.split(".")])
                    for ip in self.arpList:
                        if self.arpList[ip]['mac'] == macIndex:
                            self.arpList[ip][interfaceKey[key][14:]] = strValue
                            break
                    # print("%s -> %s = %s: %s" % (macIndex, interfaceKey[key], varBind[1].__class__.__name__, strValue))

                # print("%s = %s: %s" % (interfaceKey[key], varBind[1].__class__.__name__, strValue))

    def hwArpTableDataCallback(self, varBind):
        interfaceKey = {
            "1.3.6.1.4.1.2011.5.25.123.1.17.1.11.": "mac",
            "1.3.6.1.4.1.2011.5.25.123.1.17.1.12.": "vlan",
            "1.3.6.1.4.1.2011.5.25.123.1.17.1.13.": "inner-vlan",
            "1.3.6.1.4.1.2011.5.25.123.1.17.1.14.": "ifIndex",
            "1.3.6.1.4.1.2011.5.25.123.1.17.1.15.": "LastUpdated"
        }
        for key in interfaceKey:
            if str(varBind[0])[0:len(key)] == key:
                arpIndex = str(varBind[0])[len(key):].split(".")
                itemIP = ".".join(arpIndex[1:5])
                if itemIP not in self.arpList:
                    self.arpList[itemIP] = {
                        "interface": int(arpIndex[1])
                    }
                self.arpList[itemIP][interfaceKey[key]] = str(varBind[1])
                if interfaceKey[key] == "mac":
                    self.arpList[itemIP][interfaceKey[key]] = '-'.join(["%02x" % (x) for x in varBind[1].asNumbers()])

    def assignSysName(self, varBind):
        self.sysname = str(varBind[1])

    def checkVRP(self, varBind):
        if str(varBind[1]) == "VRP":
            self.isVRP = True
        else:
            self.isVRP = False

    def run(self):
        lastCheck = 0
        lastCheckInterface = 0
        self.isVRP = False
        snmpWalk(ObjectIdentity("1.3.6.1.4.1.2011.5.25.188.1.2"), lambda x: self.checkVRP(x))

        snmpWalk(ObjectIdentity("1.3.6.1.2.1.1.5"), lambda x: self.assignSysName(x))
        snmpWalk(ObjectIdentity("1.3.6.1.2.1.2.1"), lambda x: print("ifNumber = ",x[1]))
        snmpWalk(ObjectIdentity("1.3.6.1.2.1.2.2.1.2"), lambda x: self.interfaceDataCallback(x))

        for intIndex in self.interfaces:
            self.r.hset("SW::INT::%s" % self.sysname, intIndex, json.dumps(self.interfaces[intIndex]))

        while True:
            if time.time() - lastCheckInterface >= 1800:
                try:
                    snmpWalk(ObjectIdentity("1.3.6.1.2.1.2.2.1.4"), lambda x: self.interfaceDataCallback(x))
                    snmpWalk(ObjectIdentity("1.3.6.1.2.1.2.2.1.5"), lambda x: self.interfaceDataCallback(x))
                    snmpWalk(ObjectIdentity("1.3.6.1.2.1.2.2.1.7"), lambda x: self.interfaceDataCallback(x))
                    snmpWalk(ObjectIdentity("1.3.6.1.2.1.2.2.1.8"), lambda x: self.interfaceDataCallback(x))
                    snmpWalk(ObjectIdentity("1.3.6.1.2.1.31.1.1.1.1"), lambda x: self.interfaceDataCallback(x))
                    snmpWalk(ObjectIdentity("1.3.6.1.2.1.31.1.1.1.18"), lambda x: self.interfaceDataCallback(x))
                    lastCheckInterface = time.time()
                except Exception as e:
                    print("Error: ", e)
                    print(''.join(traceback.format_tb(e.__traceback__)))
                    pass

            if time.time() - lastCheck >= 300:
                lastCheck = time.time()
                try:
                    self.arpList = {}
                    self.macTable = {}
                    macTableIfIndex = {}
                    print("Updating Mac Table...", end="", flush=True)
                    snmpWalk(ObjectIdentity("1.3.6.1.2.1.17.1.4.1.2"), lambda x: self.macTableDataCallback(x))
                    snmpWalk(ObjectIdentity("1.3.6.1.2.1.17.4.3.1"), lambda x: self.macTableDataCallback(x))
                    print("Done, received %d" % len(self.macTable))
                    for index in self.macTable:
                        if 'ifIndex' in self.macTable[index]:
                            macTableIfIndex[self.macTable[index]['mac']] = self.macTable[index]['ifIndex']
                            ifIndex = self.macTable[index]['ifIndex']
                            self.r.hset("MAC::TABLE::%s" % self.sysname, self.macTable[index]['mac'], json.dumps({
                                'ifIndex': self.macTable[index]['ifIndex'],
                                'ifName': self.interfaces[ifIndex]['ifName'] if ifIndex in self.interfaces and 'ifName' in self.interfaces[ifIndex] else "",
                                'ifDescr': self.interfaces[ifIndex]['ifDescr'] if ifIndex in self.interfaces and 'ifDescr' in self.interfaces[ifIndex] else ""
                            }))

                    if self.isVRP:
                        print("Ignore DHCP Allocated Table...")
                    else:
                        print("Updating DHCP Allocated Table...")
                        snmpWalk(ObjectIdentity("1.3.6.1.4.1.2011.5.7.2.1.1.1."), lambda x: self.dhcpsCallback(x)) # HUAWEI-DHCPS-MIB
                        snmpWalk(ObjectIdentity("1.3.6.1.4.1.2011.5.7.2.1.2.1."), lambda x: self.dhcpsCallback(x)) # HUAWEI-DHCPS-MIB
                        snmpWalk(ObjectIdentity("1.3.6.1.4.1.2011.5.7.2.1.9.1.2."), lambda x: self.dhcpsCallback(x)) # HUAWEI-DHCPS-MIB -> hwDHCPSIPInUseTable.hwDHCPSIPInUseIP
                        snmpWalk(ObjectIdentity("1.3.6.1.4.1.2011.5.7.2.1.9.1.5."), lambda x: self.dhcpsCallback(x)) # HUAWEI-DHCPS-MIB -> hwDHCPSIPInUseTable.hwDHCPSIPInUsePoolName

                    # print(self.ipPools)

                    print("Updating ARP Table...")
                    if self.isVRP:
                        snmpWalk(ObjectIdentity("1.3.6.1.2.1.4.35.1"), lambda x: self.arpCallback(x)) # ARP-MIB     For CE
                    else:
                        snmpWalk(ObjectIdentity("1.3.6.1.4.1.2011.5.25.123.1.17.1"), lambda x: self.hwArpTableDataCallback(x))  # HUAWEI-ETHARP-MIB  for S5720

                    arpCount = 0
                    for ip in self.arpList:
                        arpCount += 1
                        self.arpList[ip]['sysname'] = self.sysname
                        if 'interface' in self.arpList[ip]:
                            self.arpList[ip]['ifName_L3'] = self.interfaces[self.arpList[ip]['interface']]['ifName'] if self.arpList[ip]['interface'] in self.interfaces and 'ifName' in self.interfaces[self.arpList[ip]['interface']] else ""
                        self.r.hset("ARP::MAPPING::%s" % (self.sysname), ip, json.dumps(self.arpList[ip]))
                        self.r.hset("ARP::MAPPING", ip, json.dumps(self.arpList[ip]))

                    print("Done, received %d" % arpCount)
                except Exception as e:
                    print("Error: ", e)
                    print(''.join(traceback.format_tb(e.__traceback__)))
                    pass
            else:
                time.sleep(1)

def snmpWalk(identity, callback):
    base_identity = identity if isinstance(identity, ObjectIdentity) else ObjectIdentity(identity)
    isNotSubClass = False
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(), loginData, UdpTransportTarget((snmpHost, 161)), ContextData(),
                              ObjectType(base_identity)):
        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'),
                  file=sys.stderr)
            break
        else:
            for varBind in varBinds:
                if isinstance(varBind[0], ObjectIdentity):
                    if varBind[0][0:len(base_identity)] != base_identity:
                        isNotSubClass = True
                        break

                if callback:
                    callback(varBind)
                else:
                    print(' = '.join([x.prettyPrint() for x in varBind]))

        if isNotSubClass:
            break


snmpEngine = SnmpEngine()

config.addTargetParams(snmpEngine, 'my-creds', 'monitor', 'noAuthNoPriv', 1)

snmpHost = None
snmpV3User = None
snmpV3AuthKey = None
snmpV3PrivKey = None

try:
    opts, _ = getopt.getopt(sys.argv[1:], "i:c:u:A:X:", ["ip=", "community=", "user=", "authKey=", "privKey="])
except getopt.GetoptError:
    sys.exit(2)
address_filters = None
isRouting = False
for opt, arg in opts:
    if opt in ["-i", "--ip"]:
        snmpHost = arg
    if opt in ["-c", "--community"]:
        config.addV1System(snmpEngine, 'monitor', arg)
        loginData = CommunityData(arg)
    if opt in ["-u", "--user"]:
        snmpV3User = arg
    if opt in ["-A", "--authKey"]:
        snmpV3AuthKey = arg
    if opt in ["-X", "--privKey"]:
        snmpV3PrivKey = arg

if snmpV3User is not None and snmpV3AuthKey is not None:
    config.addV3User(snmpEngine, userName=snmpV3User, authProtocol=config.usmHMAC192SHA256AuthProtocol,
                     authKey=snmpV3AuthKey, privKey=snmpV3PrivKey, privProtocol=config.usmAesCfb128Protocol)
    loginData = UsmUserData(snmpV3User, authProtocol=config.usmHMAC192SHA256AuthProtocol, authKey=snmpV3AuthKey,
                            privKey=snmpV3PrivKey, privProtocol=config.usmAesCfb128Protocol)

cmdThread = ioThread()
cmdThread.start()
cmdThread.join()
