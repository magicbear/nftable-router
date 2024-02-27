import ctypes
import threading
import multiprocessing
from multiprocessing import shared_memory
import time
import traceback
import netfilterqueue
from datetime import datetime
import os
from scapy.all import *
import scapy.layers.inet
from scapy.layers.dns import DNSRR, DNS, DNSQR
from pytput import TputFormatter
import prctl
import signal
import json

tf = TputFormatter()

class MMDNSProperty(ctypes.Structure):
    _fields_ = [("current", ctypes.c_ulong),
                ("version", ctypes.c_ulong)]

class MPDNSItem(ctypes.Structure):
    _fields_ = [("ip_family", ctypes.c_byte),
                ("ip_addr", ctypes.c_wchar * 40),
                ("expire", ctypes.c_double),
                ("qname", ctypes.c_wchar * 253)]

    def __repr__(self):
        return f"MPDNSItem({self.ip_family}, {self.qname} -> {self.ip_addr} Expire: {self.expire})"

class MPDNSList(list):
    DNS_MAX_LENGTH = 65536

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.closed = False
        size = ctypes.sizeof(MMDNSProperty) + ctypes.sizeof(MPDNSItem) * MPDNSList.DNS_MAX_LENGTH
        self.shm = shared_memory.SharedMemory(create=True, size=size)
        self.lock = threading.Lock()
        self.memaddr = ctypes.addressof(ctypes.c_void_p.from_buffer(self.shm.buf.obj))
        ctypes.memset(self.memaddr, 0, size)
        self.prop = MMDNSProperty.from_address(self.memaddr)
        self.offset = ctypes.sizeof(MMDNSProperty)
        self.extend((MPDNSItem * MPDNSList.DNS_MAX_LENGTH).from_address(self.memaddr + self.offset))
        self.MapCache = {
            'version': None,
            "full_version": None,
            'map': {

            }
        }

    def __len__(self):
        return self.prop.current

    def close(self):
        if self.closed:
            return
        self.closed = True
        del self.prop
        self.shm.buf.release()
        self.shm.close()

    def release(self):
        self.shm.unlink()

    def append(self, obj):
        if self.closed:
            raise ValueError("Share Memory closed")
        if self.prop.current >= MPDNSList.DNS_MAX_LENGTH:
            raise MemoryError("Out of memory")
        self.lock.acquire()
        if not self.closed and self.prop.current < MPDNSList.DNS_MAX_LENGTH:
            ctypes.memmove(ctypes.byref(self[self.prop.current]), ctypes.byref(obj), ctypes.sizeof(MPDNSItem))
            self.prop.current += 1
        self.lock.release()

    def __iter__(self):
        x = self
        for i in range(len(self)):
            if i >= self.prop.current:
                return None
            yield x[i]

    def __delitem__(self, item):
        self.lock.acquire()
        self.prop.current -= 1
        if self.prop.current - item > 0:
            ctypes.memmove(self.memaddr + self.offset + ctypes.sizeof(MPDNSItem) * item,
                           self.memaddr + self.offset + ctypes.sizeof(MPDNSItem) * (item + 1),
                           ctypes.sizeof(MPDNSItem) * (self.prop.current - item))
        self.prop.version += 1
        self.lock.release()

    def pop(self, item=None):
        if item is None:
            raise KeyError("pop key error")
        c = self[item]
        self.__delitem__(item)
        return c

    def __getitem__(self, item):
        if isinstance(item, int):
            return super().__getitem__(item)
        if self.MapCache['version'] != self.prop.version:
            self.lock.acquire()
            self.MapCache['version'] = self.prop.version
            self.MapCache['count'] = len(self)
            self.MapCache['map'] = {}
            for x in self:
                if x.ip_addr not in self.MapCache['map']:
                    self.MapCache['map'][x.ip_addr] = []
                self.MapCache['map'][x.ip_addr].append(x)
            self.lock.release()
        elif self.MapCache['count'] != self.prop.current:
            for n in range(self.MapCache['count'], self.prop.current):
                if self[n].ip_addr not in self.MapCache['map']:
                    self.MapCache['map'][self[n].ip_addr] = []
                self.MapCache['map'][self[n].ip_addr].append(self[n])
            self.MapCache['count'] = len(self)
        return self.MapCache['map'][item]

    def clean(self, force=False):
        now = time.time()
        for k, v in enumerate(self):
            if v.expire < now or (force and v.expire < now + 1500):
                del self[k]

class DNSProcess(multiprocessing.Process):
    def __init__(self, dns_list: list[MPDNSItem], term):
        super().__init__()
        self.dns_list = dns_list
        self.term = term

    def update_dns_item(self, ver, dns, dnsrr):
        ttl = dnsrr.ttl
        if ttl < 1800:
            ttl = 1800
        rrname = dnsrr.rrname.decode("utf-8")
        qname = dns[DNS].qd.qname.decode("utf-8")
        foundQname = False
        foundRRName = False
        try:
            list = self.dns_list[dnsrr.rdata]
            for item in list:
                if item.ip_family == dns.version and item.qname == qname:
                    item.expire = time.time() + ttl
                    foundQname = True
                if item.ip_family == dns.version and item.qname == rrname:
                    item.expire = time.time() + ttl
                    foundRRName = True
        except KeyError:
            pass
        if not foundQname or not foundRRName:
            rc = MPDNSItem()
            rc.expire = time.time() + ttl
            rc.ip_family = ver
            rc.qname = qname
            rc.ip_addr = dnsrr.rdata
        if not foundQname:
            try:
                self.dns_list.append(rc)
            except MemoryError:
                self.dns_list.clean(True)
                self.dns_list.append(rc)
        if dnsrr.rrname != dns[DNS].qd.qname and not foundRRName:
            rc.qname = dnsrr.rrname.decode("utf-8")
            try:
                self.dns_list.append(rc)
            except MemoryError:
                self.dns_list.clean(True)
                self.dns_list.append(rc)

    def dnsSpoof(self, packet):
        try:
            dns = scapy.layers.inet.IP(packet.get_payload())
            if dns.haslayer(DNSQR):
                # print("[*] query name: %s" % (dns[DNS].qd.qname))
                dns_results = []
                for i in range(dns.ancount):
                    dnsrr = dns.an[i]
                    # print("[*] response:  %s - %s - %s" % (
                    #     dnsrr.rrname, dnsrr.type, dnsrr.rdata))
                    if dnsrr.type == 1:
                        # A Record
                        self.update_dns_item(4, dns, dnsrr)
                    elif dnsrr.type == 5:
                        # CName
                        pass
                    elif dnsrr.type == 28:
                        # AAAA Record
                        self.update_dns_item(6, dns, dnsrr)
        except Exception as e:
            print(tf.format("{msg:s,bg_red,black}", msg="[-] DNS Thread Error: %s" % e))
            with open("nft_route.log", "a+") as f:
                f.write("%s: DNS Worker Process Error: %s\n  %s\n" % (
                    datetime.now().isoformat(), str(e), '  '.join(traceback.format_tb(e.__traceback__))))
        packet.accept()

    def dump_dns(self, signum, sigframe):
        print(tf.format("{msg:s,bg_cyan,black}", msg="[+] DNS Thread Dumping"))
        with open("/dev/shm/dns_list.json", "w", encoding="utf-8") as f:
            dns_lists = []
            for dns in self.dns_list:
                dns_lists.append({
                    "ip_family": dns.ip_family,
                    "ip_addr": dns.ip_addr,
                    "expire": dns.expire,
                    "qname": dns.qname
                })
            json.dump(dns_lists, f, indent=4)

    def load_dns(self):
        if os.path.exists("/dev/shm/dns_list.json"):
            with open("/dev/shm/dns_list.json", "r", encoding="utf-8") as f:
                dns_lists = json.load(f)
                for dns in dns_lists:
                    item = MPDNSItem()
                    item.ip_family = dns['ip_family']
                    item.ip_addr = dns['ip_addr']
                    item.expire = dns['expire']
                    item.qname = dns['qname']
                    self.dns_list.append(item)
            print(tf.format("{msg:s,bg_cyan,black}", msg="[+] DNS Thread Load %d" % len(self.dns_list)))

    def quit(self, signum, sigframe):
        self.dump_dns(signum, sigframe)
        os._exit(0)

    def run(self):
        signal.signal(signal.SIGUSR1, self.dump_dns)
        signal.signal(signal.SIGTERM, self.quit)
        signal.signal(signal.SIGHUP, self.quit)
        nfqueue = netfilterqueue.NetfilterQueue()
        nfqueue.bind(53, self.dnsSpoof, mode=netfilterqueue.COPY_PACKET)
        prctl.set_proctitle("Policy Route - DNS")
        try:
            self.load_dns()
        except Exception as e:
            print("[-] Error: %s" % e)
            with open("nft_route.log", "a+") as f:
                f.write("%s: DNS Worker Process Load Error: %s\n  %s\n" % (
                    datetime.now().isoformat(), str(e), '  '.join(traceback.format_tb(e.__traceback__))))

        while not self.term.value:
            try:
                print("[*] waiting for data (DNS Process, PID: %d)" % (os.getpid()), flush=True)
                nfqueue.run()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print("[-] Error: %s" % e)
                with open("nft_route.log", "a+") as f:
                    f.write("%s: DNS Worker Process Error: %s\n  %s\n" % (
                        datetime.now().isoformat(), str(e), '  '.join(traceback.format_tb(e.__traceback__))))

        self.dump_dns(0, 0)
        print("[-] DNS process exit")