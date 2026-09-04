import libvirt
from xml.dom import minidom
import redis
import json
import csv
import threading, time

def get_arp_table():
    with open('/proc/net/arp') as arp_table:
        #'IP address', 'HW type', 'Flags', 'HW address', 'Mask', 'Device'
        reader = csv.reader(arp_table, skipinitialspace=True, delimiter=' ')

        arp_list = [a for a in reader]
        return {a[0]: {'mac': a[3], 'ifName_L3': a[5]} for a in filter(lambda x: x[3] != '00:00:00:00:00:00', arp_list[1:])}

class ioThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        lastCheck = 0
        while True:
            if time.time() - lastCheck >= 300:
                lastCheck = time.time()
                try:
                    self.r = redis.Redis(host='127.0.0.1', port=6379, db=1)

                    conn = libvirt.open('qemu:///system')

                    hostname = conn.getHostname()
                    arp_list = get_arp_table()
                    for ip in arp_list:
                        arp_list[ip]['sysname'] = hostname
                        self.r.hset("ARP::MAPPING::%s" % hostname, ip, json.dumps(arp_list[ip]))
                        self.r.hset("ARP::MAPPING", ip, json.dumps(arp_list[ip]))

                    domainIDs = conn.listDomainsID()
                    for domain in domainIDs:
                        dom = conn.lookupByID(domain)

                        raw_xml = dom.XMLDesc(0)
                        xml = minidom.parseString(raw_xml)
                        interfaceTypes = xml.getElementsByTagName('interface')
                        for interfaceType in interfaceTypes:
                            print('interface: type=' + interfaceType.getAttribute('type'))
                            interfaceNodes = interfaceType.childNodes
                            int_meta = {}
                            for interfaceNode in interfaceNodes:
                                if interfaceNode.nodeName[0:1] != '#':
                                    print('  ' + interfaceNode.nodeName)
                                    for attr in interfaceNode.attributes.keys():
                                        int_meta[interfaceNode.nodeName] = interfaceNode.attributes[attr].value
                                        print('    ' + interfaceNode.attributes[attr].name + ' = ' +
                                              interfaceNode.attributes[attr].value)
                            self.r.hset("MAC::TABLE::%s" % hostname, int_meta['mac'], json.dumps({
                                'ifName': "%s->%s:%s" % (int_meta['source'], dom.name(), int_meta['target'])
                            }))

                    self.r.close()
                    conn.close()
                except Exception as e:
                    pass
            else:
                time.sleep(1)

cmdThread = ioThread()
cmdThread.start()
cmdThread.join()
