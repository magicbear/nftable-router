import multiprocessing
import posix
import threading
from multiprocessing import Queue as ProcessQueue
from multiprocessing import Process, Value, Array, Lock
from datetime import datetime
import syslog

import ipdb
import scapy.layers.inet

from scapy.all import *
import netfilterqueue
import ipaddress
import sys
import os

module_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, module_dir)
sys.path.insert(0, os.path.join(module_dir, "../"))

import redis
from scapy.layers.dns import DNSRR, DNS, DNSQR
from pyroute2 import IPSet
from pyroute2.netlink import NetlinkError
from pyroute2 import IPRoute
import time
import signal
import flag
import json
import ctypes
from nftable_router.nft_utils import nftUtils
from nftable_router.icmp_builder import *
from nftable_router.dns import *
from nftable_router.fullcone_nat import *
from nftable_router import netinfo
from nftable_router import iface_bind as ib
from nftable_router import proxy_mgr as pmm
from pytput import TputFormatter
import subprocess, urllib, psutil
from queue import Queue, Empty
from contextlib import contextmanager
import traceback
import itertools
import prctl, tty, termios
import netifaces

tf = TputFormatter()

nfu = nftUtils()

"""

"""

term = Value('b', False)
g_parallel_process = int(os.cpu_count() / 2)
if g_parallel_process <= 16:
    g_parallel_process = 16
g_lock = Lock()
g_io_lock = Lock()


@contextmanager
def timed_lock(lock, timeout=2.0):
    got = lock.acquire(timeout=timeout)
    try:
        yield got
    finally:
        # Only release if we actually acquired it; releasing a lock we do not
        # own would corrupt the semaphore and break mutual exclusion for every
        # other process/thread waiting on it.
        if got:
            lock.release()


def run_cmd_capture(args, timeout):
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, shell=False)
    try:
        out = proc.communicate(timeout=timeout)[0]
    except subprocess.TimeoutExpired:
        proc.kill()
        out = proc.communicate()[0]
    return out.decode('utf-8')

g_test_ip = Array(ctypes.c_wchar, 40)
g_test_proxy_id = Value('i', -1)
g_running_process = Value('i', 0)
g_cps = Value('i', 0)
g_cps_dup = Value('i', 0)
g_cps_reset = Value('d', 0)
g_overload_flag = Value('b', False)
g_working_flag = [Value('b', False) for x in range(g_parallel_process)]
g_worker_last_active = [Value('d', time.time()) for x in range(g_parallel_process)]
g_worker_process_connections = [Value(ctypes.c_ulong, 0) for x in range(g_parallel_process)]
g_proxy_index = []
g_dead_proxy_ipv4 = {}
g_dead_proxy_ipv6 = {}
g_runner = []
g_proxy_sup = None            # ProxySupervisor instance (master only)
g_proxy_pending = Value('b', False)   # SIGUSR1 -> incremental reconfigure in main loop
g_proxy_restart_all = Value('b', False)  # SIGUSR2 -> restart ALL managed proxies
is_master = True
worker_id = 0  # Modified by Process
process_term = False  # Modified by Process
queue = ProcessQueue()

cmt_class = '**AUTOGEN BY PolicyRoute**'
protos = {1: "ICMP", 2: "IGMP", 6: {"color": "green", "name": "TCP"}, 17: {"color": "blue", "name": "UDP"}, 47: "GRE",
          58: "ICMP6"}

raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
syslog.openlog(ident="PolicyRoute[%d]" % os.getpid())

class TestThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.test_ip = None
        self.test_mark = None
        self.test_proxy_id = None
        self.last_check = None
        self.r = redis.Redis(host='127.0.0.1', port=6379, db=1, socket_timeout=3, socket_connect_timeout=3)

    def run(self):
        global config, g_test_ip, g_test_proxy_id, g_dead_proxy_ipv4, g_dead_proxy_ipv6
        prctl.set_name("PR - %s" % self.__class__.__name__)
        time.sleep(3)
        while not term.value:
            # 获取当前连接数
            with open("/proc/sys/net/netfilter/nf_conntrack_max") as f:
                MAX_CONNTRACK = int(f.read().strip())
            with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
                count = int(f.read().strip())
            # 超过80%容量时告警
            if count > 0.8 * MAX_CONNTRACK:
                syslog.syslog(syslog.LOG_ALERT, f"Conntrack table 80% full: {count}/{MAX_CONNTRACK}")
            flog = open("/var/log/nft_route.log", "a+")
            test_result = []
            for proxy_id in config['proxy']:
                proxy = config['proxy'][proxy_id]
                if 'test_url' not in proxy:
                    with timed_lock(g_lock):
                        g_dead_proxy_ipv4[proxy_id].value = 0
                        g_dead_proxy_ipv6[proxy_id].value = 0
                    continue

                parse_path = urllib.parse.urlparse(proxy['test_url'])

                for ip_version in [4, 6]:
                    dig_result = None
                    tested_ip = []
                    if 'ipv%d' % ip_version not in proxy or not proxy['ipv%d' % ip_version]:
                        continue
                    for i in range(0, 3):
                        if dig_result is None:
                            # , "+dscp=32"
                            digParams = ["dig", "+time=2", "+tries=1", "+short", parse_path.netloc]
                            if 'test_dns' in proxy:
                                pxy_ip = proxy['test_dns'] if isinstance(proxy['test_dns'], str) else proxy['test_dns'][
                                    i % len(proxy['test_dns'])]
                                digParams.append("+tcp")
                                digParams.append("@%s" % pxy_ip)
                                self.test_proxy_id = proxy_id
                                self.test_mark = proxy['mark']
                                self.test_ip = pxy_ip
                                with timed_lock(g_lock):
                                    g_test_ip[0:len(pxy_ip) + 1] = pxy_ip + "\0"
                                    g_test_proxy_id.value = g_proxy_index.index(proxy_id)

                            # if "bind" in proxy:
                            #     digParams.append("-b")
                            #     digParams.append(proxy['bind'].replace(":","#"))
                            digParams.append('AAAA' if ip_version == 6 else 'A')

                            # print(proxy_id, i, " ".join(digParams))
                            # time.sleep(0.1)
                            dig_result = run_cmd_capture(digParams, 10).split("\n")
                            dig_index = 0
                            while dig_index < len(dig_result):
                                try:
                                    test_ip = ipaddress.ip_address(dig_result[dig_index])
                                    if test_ip.version != ip_version:
                                        dig_result.remove(dig_result[dig_index])
                                        continue
                                    dig_index += 1
                                except ValueError:
                                    dig_result.remove(dig_result[dig_index])

                        # print(ip_version, proxy_id, dig_result)
                        if len(dig_result) > 0:
                            self.test_proxy_id = proxy_id
                            self.test_mark = proxy['mark']
                            self.test_ip = dig_result[i % len(dig_result)].strip()
                            with timed_lock(g_lock):
                                g_test_ip[0:len(self.test_ip) + 1] = self.test_ip + "\0"
                                g_test_proxy_id.value = g_proxy_index.index(proxy_id)

                            curl_args = ["curl", "-%d" % ip_version, "-s", "-k", "-m", "1",
                                         "-o", "/dev/null",
                                         "-x", "%s:%d" % (self.test_ip if ip_version == 4 else "[%s]" % self.test_ip,
                                                          80 if parse_path.scheme == 'http' else 443),
                                         proxy['test_url'], '-w', '%{time_total} %{http_code}']
                            # print(" ".join(curl_args))

                            # time.sleep(0.1)
                            tquery = run_cmd_capture(curl_args, 5).split(" ")
                            while len(tquery) < 2:
                                tquery.append("000")
                            # print(tquery)
                            if tquery[1] == '200' or tquery[1] == '204' or tquery[1] == '301' or tquery[1] == '302':
                                # print("[+] \033[38;5;157mProxy Check IPv%d %s OK\033[0m, time %s" % (
                                # ip_version, proxy_id, tquery[0]))
                                test_result.append([proxy_id, ip_version, "%s %s" % (tquery[0], self.test_ip)])
                                flog.write("%s: %s OK %s\n" % (datetime.now().isoformat(), proxy_id, tquery[0]))
                                self.test_ip = None
                                with timed_lock(g_lock):
                                    if ip_version == 4:
                                        g_dead_proxy_ipv4[proxy_id].value = float(tquery[0])
                                    else:
                                        g_dead_proxy_ipv6[proxy_id].value = float(tquery[0])
                                    g_test_ip[0] = "\0"
                                    g_test_proxy_id.value = -1
                                break
                            else:
                                tested_ip.append(self.test_ip)
                                # print("[-] \033[41mProxy Check IPv%d %s Failed\033[0m" % (ip_version, proxy_id))
                                self.test_ip = None
                                with timed_lock(g_lock):
                                    if ip_version == 4:
                                        g_dead_proxy_ipv4[proxy_id].value = -1
                                    else:
                                        g_dead_proxy_ipv6[proxy_id].value = -1
                                    g_test_ip[0] = "\0"
                                    g_test_proxy_id.value = -1
                        else:
                            dig_result = None
                            # print("[-] \033[41mProxy Check IPv%d %s Failed, DNS Resolve Failed\033[0m" % (ip_version, proxy_id))
                            self.test_ip = None
                            with timed_lock(g_lock):
                                if ip_version == 4:
                                    g_dead_proxy_ipv4[proxy_id].value = -1
                                else:
                                    g_dead_proxy_ipv6[proxy_id].value = -1
                                g_test_ip[0] = "\0"
                                g_test_proxy_id.value = -1

                    if dig_result is None:
                        test_result.append([proxy_id, ip_version, "-1 DNS"])
                        print("[-] \033[41mProxy Check IPv%d %s Failed, DNS Resolve Failed, mark dead\033[0m%s" % (
                            ip_version, proxy_id, " " * 30))
                        flog.write("%s: %s Failed, IPv%d Resolve failed\n" % (
                            datetime.now().isoformat(), proxy_id, ip_version))
                    elif len(tested_ip) > 0:
                        test_result.append([proxy_id, ip_version, "-1 %s" % ",".join(tested_ip)])
                        print("[-] \033[41mProxy Check IPv%d %s Failed, ip: %s, mark dead\033[0m%s" % (
                            ip_version, proxy_id, ",".join(tested_ip), " " * 30))
                        flog.write("%s: %s IPv%d Failed, ip: %s\n" % (
                            datetime.now().isoformat(), proxy_id, ip_version, ",".join(tested_ip)))

            flog.close()
            self.r.delete("test_v4", "test_v6")
            for proxy_id, ip_version, rc in test_result:
                self.r.hset("test_v%d" % ip_version, proxy_id, rc)

            self.last_check = time.time()
            while not term.value and time.time() - self.last_check < 60:
                time.sleep(1)


class ECMPCacheItem:
    def __init__(self, ip, tun_id=None, mark=None, now=None):
        if tun_id is None:
            self.ip, self.tun_id, self.mark, self.last_active = struct.unpack("=40s20sLd", ip)
            self.ip = self.ip.decode('utf-8').rstrip("\x00")
            self.tun_id = self.tun_id.decode('utf-8').rstrip("\x00")
        else:
            self.ip = ip
            self.tun_id = tun_id
            self.mark = mark
            self.last_active = now

    def dump(self):
        return struct.pack("=40s20sLd", self.ip.encode("utf-8"), self.tun_id.encode("utf-8"), int(self.mark),
                           float(self.last_active))


class PolicyRouteItem:
    def __init__(self, tun_id, mark, weight, start_r, end_r, is_proxy):
        self.tun_id = tun_id
        self.mark = mark
        self.weight = weight
        self.start_r = start_r
        self.end_r = end_r
        self.is_proxy = is_proxy


class ResultData:
    def __init__(self, pkt_version, proto, src, dst, sport, port, out_interface, mark, geodata, matched_priority,
                 test_session, t_total, t_init, payload, process_fullcone):
        self.pkt_version = pkt_version
        self.proto = proto
        self.src = src
        self.dst = dst
        self.sport = sport
        self.port = port
        self.out_interface = out_interface
        self.mark = mark
        self.geodata = geodata
        self.matched_priority = matched_priority
        self.test_session = test_session
        self.t_total = t_total
        self.t_init = t_init
        self.process_fullcone = process_fullcone
        self.payload = payload

    def dump(self):
        return struct.pack("=q40s40s40sBbbHHdd",
                           len(self.payloda),
                           self.src.encode("utf-8"),
                           self.dst.encode("utf-8"),
                           self.out_interface.encode("utf-8"),
                           int(self.proto),
                           int(self.matched_priority),
                           int(self.test_session),
                           int(self.sport),
                           int(self.port),
                           float(self.t_total),
                           float(self.t_init)
                           ) + self.payload


class ECMPThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.lock = threading.Lock()
        self.ip_list = {}
        self.now = 0
        self.queue = Queue()
        self.fdr, self.fdw = os.pipe()
        self.fdr_cb, self.fdw_cb = os.pipe()

    def run(self):
        prctl.set_name("PR - %s" % self.__class__.__name__)
        self.r = None
        last_check = 0
        while term.value == False:
            try:
                if self.r is None:
                    self.r = redis.Redis(host='127.0.0.1', port=6379, db=1, socket_timeout=3, socket_connect_timeout=3)
                    sub = self.r.pubsub()

                sub.subscribe('ecmp_list')
                try:
                    queue_item = self.queue.get(True, 0.05)
                    self.r.publish('ecmp_list', queue_item.dump())
                except Empty:
                    pass

                self.now = datetime.now().timestamp()

                # cmd, payload = struct.unpack("=B72s", os.read(self.fdr, 73))
                # ip = payload[0:40].rstrip(b"\x00").decode("utf-8")
                # if cmd == 0:    # Request Item
                #     if ip in self.ip_list:
                #         os.write(self.fdw_cb, struct.pack("=B72s", 1, self.ip_list[ip].dump()))
                #         self.ip_list[ip].last_active = self.now
                #     else:
                #         os.write(self.fdw_cb, struct.pack("=B72s", 0, b""))
                # elif cmd == 1:  # Append Item
                #     self.ip_list[ip] = ECMPCacheItem(payload)

                while True:
                    message = sub.get_message()
                    if message is not None and isinstance(message.get('data'), bytes):
                        data = ECMPCacheItem(message.get('data'))
                        data.last_active = self.now
                        self.ip_list[data.ip] = data
                    else:
                        break

                if self.now - last_check >= 1:
                    delete_ip_list = []
                    for ip in self.ip_list:
                        if self.ip_list[ip].last_active < self.now - 5:
                            delete_ip_list.append(ip)

                    if len(delete_ip_list) > 0:
                        self.lock.acquire()
                        for ip in delete_ip_list:
                            del self.ip_list[ip]
                        self.lock.release()

                    last_check = self.now
            except Exception as e:
                print(tf.format("{msg:s,bg_red,black}", msg="[-] ECMP Thread Error: %s" % e))
                print(''.join(traceback.format_tb(e.__traceback__)))
                self.r = None
                time.sleep(1)


def load_config():
    global config, test_mapping, g_dead_proxy_ipv4, g_dead_proxy_ipv6, g_proxy_index

    ptr_records = []
    with open('nft_route.json', 'rb') as f:
        try:
            new_config = json.load(f)
            test_mapping = {}
            for priority in range(0, len(new_config["rules"])):
                for tun_id, rule_cfg in new_config["rules"][priority].items():
                    for geo_k, geo_list in rule_cfg.items():
                        if geo_k == "cidr" or geo_k == "from":
                            for cidr_id in range(len(geo_list)):
                                geo_list[cidr_id] = ipaddress.ip_network(geo_list[cidr_id])

            proxy_index = []
            for pxy_id in new_config["proxy"]:
                proxy_index.append(pxy_id)
                g_dead_proxy_ipv4[pxy_id] = Value('d', 0)
                g_dead_proxy_ipv6[pxy_id] = Value('d', 0)
                pxy = new_config["proxy"][pxy_id]
                ptr_records.append("ptr-record=%d.%d.254.169.in-addr.arpa.,\"%s.nft-route.\"" % (
                    pxy['mark'] & 0xff, pxy['mark'] >> 8, pxy_id))
                if "proxy_ip" in pxy:
                    ip_ptr = pxy['proxy_ip'].split(".")
                    ip_ptr.reverse()
                    ptr_records.append(
                        "ptr-record=%s.in-addr.arpa.,\"%s.proxy.nft-route.\"" % (".".join(ip_ptr), pxy_id))
                if "bind" in pxy:
                    pxy['proxy_id'] = pxy_id
                    test_mapping[pxy['bind']] = pxy

            if os.path.exists("/etc/dnsmasq.d"):
                fptr = open("/etc/dnsmasq.d/nft_route.conf", "w")
                fptr.write("\n".join(ptr_records) + "\n")
                fptr.close()

            config = new_config
            g_proxy_index = proxy_index
        except Exception as e:
            print("[-] \033[41mLoad Config Error: %s\033[0m" % (e))
            syslog.syslog(syslog.LOG_CRIT, "Load Config Error: %s\n  %s" % (
                    str(e), '  '.join(traceback.format_tb(e.__traceback__))))


def create_tproxy(mark, port, ip_family, udp=False):
    # hkfdc ss-redir
    nfu.add_rule({'family': ip_family, 'chain': ['nat_PREROUTING'], 'table': 'policy_route', 'comment': cmt_class,
                  'expr': [{'match': nfu.match_mark(mark)},
                           {'match': nfu.match_l4proto('tcp')},
                           {'match': nfu.match_iif("@nat_interfaces")},
                           {'counter': {'bytes': 0, 'packets': 0}},
                           {'redirect': {'port': port}}]
                  })

    nfu.add_rule({'family': ip_family, 'chain': ['nat_OUTPUT'], 'table': 'policy_route', 'comment': cmt_class,
                  'expr': [{'match': nfu.match_mark(mark)},
                           {'match': nfu.match_l4proto('tcp')},
                           {'counter': {'bytes': 0, 'packets': 0}},
                           {'redirect': {'port': port}}]
                  })
    if udp:
        nfu.add_rule(
            {'family': ip_family, 'chain': ['mangle_TPROXY_PREROUTING'], 'table': 'policy_route', 'comment': cmt_class,
             'expr': [{'match': nfu.match_mark(mark)},
                      {'match': nfu.match_l4proto(17)},
                      {'match': nfu.match_iif("@nat_interfaces")},
                      {'counter': {'bytes': 0, 'packets': 0}},
                      {'mangle': {'key': {'meta': {'key': 'mark'}}, 'value': 0x100}},  # Force Traffic to Local
                      # {'log': {'prefix': 'AUTOGEN SAVE MARK '}},
                      {'tproxy': {
                          'addr': '127.0.0.1',
                          'port': port}}
                      # {'accept': None}
                      ]
             })


PRINT_FULL_MIN_WIDTH = 220
PRINT_COMPACT_MIN_WIDTH = 130

g_term_width = -1
g_term_width_check = 0.0


def egress_wizard_boot():
    """Startup egress binding: scan interfaces, prompt wizard for unbound
    public egress IP/interface -> fwmark, write nft_route.json (atomic+bak).
    Must run in master BEFORE worker fork and BEFORE tty cbreak mode."""
    global config
    config_path = os.environ.get("NFT_ROUTE_CONFIG", "nft_route.json")
    try:
        detect = netinfo.detect()
    except Exception as e:
        syslog.syslog(syslog.LOG_WARNING, "egress scan failed: %s" % e)
        print(tf.format("{msg:s,bg_yellow,black}", msg="[-] egress: interface scan failed: %s" % e))
        return
    candidates = ib.scan_candidates(detect)
    for err in ib.validate_bindings(config):
        print(tf.format("{msg:s,bg_yellow,black}", msg="[-] egress_marks config invalid: %s" % err))
        syslog.syslog(syslog.LOG_WARNING, "egress_marks config invalid: %s" % err)
    bound, needs = ib.plan_bindings(config, candidates)
    for cand, b in bound:
        print("[*] egress: %s %s -> mark %s (bound)" % (
            "iface" if cand["dynamic"] else "ip  ",
            cand["ifname"] + (" / " + cand["ip"] if not cand["dynamic"] else ""), b["mark"]))
    missing_gw = [b for b in ib.get_bindings(config)
                  if not (b.get("iprule") or {}).get("gateway")]
    if not needs and not missing_gw:
        return
    interactive = sys.stdin.isatty() and is_master
    if not interactive:
        for cand in needs:
            msg = "unbound public egress: %s %s (%s)" % (
                cand["ifname"], cand["ip"], "dynamic" if cand["dynamic"] else "static")
            print(tf.format("{msg:s,bg_yellow,black}", msg="[-] egress: %s" % msg))
            syslog.syslog(syslog.LOG_WARNING, msg)
        for b in missing_gw:
            msg = "egress binding %s (mark %s) has no iprule gateway" % (
                b.get("iface") or b.get("ip"), b["mark"])
            print(tf.format("{msg:s,bg_yellow,black}", msg="[-] egress: %s" % msg))
            syslog.syslog(syslog.LOG_WARNING, msg)
        return

    def chooser(cand, suggested):
        lines = [k for k, v in config.get("proxy", {}).items() if int(v.get("mark", -1)) == int(suggested)]
        kind = "dynamic iface %s" % cand["ifname"] if cand["dynamic"] else "static ip %s" % cand["ip"]
        print()
        ans = input("[*] egress wizard: %s (%s) -> bind fwmark [%s%s]:\n    "
                    "(Enter=use default, 0x.. / decimal=custom, s=skip) " % (
                        kind, cand["method"], suggested,
                        (" / line %s" % ",".join(lines)) if lines else "")).strip().lower()
        if ans in ("", "y", "yes"):
            return suggested
        if ans in ("s", "n", "no", "skip"):
            return None
        try:
            return int(ans, 0)
        except ValueError:
            line_names = {k.lower(): int(v.get("mark", 0)) for k, v in config.get("proxy", {}).items()}
            if ans in line_names and line_names[ans]:
                return line_names[ans]
            print("    [-] invalid input, skipped")
            return None

    def gateway_prompt(cand, entry):
        dyn = bool(cand.get("dynamic"))
        hint = "回车=auto(跟随接口默认路由)" if dyn else "回车=稍后在配置里手填"
        ans = input("    gateway for %s (mark %s)  [%s]: " % (
            cand["ifname"], entry["mark"], hint)).strip()
        entry.setdefault("iprule", {})["gateway"] = ans if ans else ("auto" if dyn else "")

    changed = []
    created = ib.run_wizard(config, needs, chooser, post_bind=gateway_prompt if interactive else None)
    # existing bindings still missing a gateway -> ask interactively as well
    if interactive:
        for b in ib.get_bindings(config):
            if not (b.get("iprule") or {}).get("gateway"):
                dyn = bool(b.get("dynamic"))
                hint = "回车=auto(跟随接口默认路由)" if dyn else "回车=稍后在配置里手填"
                ans = input("    gateway for %s (mark %s, already bound) [%s]: " % (
                    b.get("iface") or b.get("ip"), b["mark"], hint)).strip()
                b.setdefault("iprule", {})["gateway"] = ans if ans else ("auto" if dyn else "")
                changed.append(b)
    if created or changed:
        try:
            ib.save_config(config_path, config)
            print("[+] egress_marks updated in %s (%d new, %d gateway-filled, backup: %s.bak)" % (
                config_path, len(created), len(changed), config_path))
            syslog.syslog(syslog.LOG_NOTICE, "egress_marks updated: %s" % json.dumps(created))
        except Exception as e:
            print(tf.format("{msg:s,bg_red,black}", msg="[-] egress_marks save FAILED (rules will use in-memory cfg): %s" % e))
            syslog.syslog(syslog.LOG_CRIT, "egress_marks save failed: %s" % e)


def apply_egress_rules(nfu, ip_family):
    """Install prerouting setter rules (+ generic OUTPUT restore only when the
    running ruleset has none). Pure 'meta mark/ct mark set' -- no verdicts,
    no drop of transit traffic."""
    bindings = ib.get_bindings(config)
    if not bindings:
        return
    removed = ib.clear_egress_rules(nfu, ip_family, cmt_class)
    if removed:
        print("[*] egress marks (%s): cleared %d old rules" % (ip_family, removed))
    try:
        ruleset_rc, ruleset_json, _ = nfu.nft.json_cmd({"nftables": [{"list": {"ruleset": None}}]})
        restore_exists = ib.restore_in_ruleset(ruleset_json if ruleset_rc == 0 else "", ip_family)
    except Exception as e:
        syslog.syslog(syslog.LOG_WARNING, "egress ruleset inspect failed: %s" % e)
        restore_exists = False
    chains, rules = ib.plan_rules(config, ip_family, restore_exists=restore_exists)
    for ch in chains:
        nfu.add_chain(ch)
    n_ok = 0
    for r in rules:
        params = dict(r)
        params["comment"] = cmt_class
        rc = nfu.add_rule(params)
        try:
            ok = not any(x[0] for x in rc if isinstance(x, (list, tuple))) if isinstance(rc, list) else rc[0] == 0
        except Exception:
            ok = True
        n_ok += 1 if ok else 0
        if not ok:
            print(tf.format("{msg:s,bg_red,black}", msg="[-] add egress rule failed (%s): %s" % (ip_family, rc)))
            syslog.syslog(syslog.LOG_CRIT, "add egress rule failed %s: %s" % (ip_family, rc))
    print("[+] egress marks (%s): %d/%d rules, restore %s" % (
        ip_family, n_ok, len(rules), "already deployed" if restore_exists else "auto-added"))


_g_iprule_last_pending = None


def sync_iprules(reason=""):
    """Idempotent reconcile of 'ip rule fwmark -> route table' for every
    egress_marks binding (closed loop). Owns ONLY priority band 29000+;
    manual rules with the same fwmark are respected and reported."""
    global _g_iprule_last_pending
    try:
        from pyroute2 import IPRoute
    except ImportError:
        return
    dirty = False
    pending_note = []
    try:
        ipr = IPRoute()
    except Exception as e:
        syslog.syslog(syslog.LOG_WARNING, "sync_iprules: IPRoute open failed: %s" % e)
        return
    try:
        for fam in (4, 6):
            plans = ib.iprule_plan(config, fam)
            if not plans:
                continue
            res = ib.iprule_apply(ipr, plans,
                                  log=lambda m: syslog.syslog(syslog.LOG_NOTICE, "iprule: %s" % m))
            for p, why in res["pending"]:
                pending_note.append("%d:%s" % (p, why))
            if res["added"] or res["removed"] or res["errors"] or res["external"]:
                dirty = True
                msg = ("iprules(%s%s): +%s -%s ext=%s err=%s" % (
                    ("v%d" % fam), ("/" + reason) if reason else "",
                    res["added"] or "-", res["removed"] or "-",
                    res["external"] or "-", res["errors"] or "-"))
                print("[*] %s" % msg)
                syslog.syslog(syslog.LOG_NOTICE, msg)
    finally:
        ipr.close()
    note = ",".join(sorted(pending_note))
    if note != (_g_iprule_last_pending or ""):
        _g_iprule_last_pending = note
        if note:
            print(tf.format("{msg:s,bg_yellow,black}", msg="[-] iprule waiting: %s" % note))
            syslog.syslog(syslog.LOG_WARNING, "iprule waiting: %s" % note)
    return dirty


def install_proxy_chain_rules():
    """(Re)build proxy-chain nft rules and the process supervisor from the
    current config. Master process only; safe to call on boot and reload.
    On chain config errors: logs CRIT and DISABLES management (existing
    manual proxy processes and traffic keep working untouched)."""
    global g_proxy_sup
    managed = {k: v for k, v in config["proxy"].items() if pmm.is_managed(v)}
    try:
        nfu.delete_rules(comment=pmm.CHAIN_CMT, family=None)
    except Exception as e:
        syslog.syslog(syslog.LOG_WARNING, "clear proxy-chain rules failed: %s" % e)
    if not managed:
        if g_proxy_sup:
            g_proxy_sup.stop_all()
            g_proxy_sup = None
        return
    try:
        order = pmm.validate_chain(config["proxy"])
    except ValueError as e:
        print(tf.format("{msg:s,bg_red,black}", msg="[-] proxy chain config error, management DISABLED: %s" % e))
        syslog.syslog(syslog.LOG_CRIT, "proxy chain config error, management disabled: %s" % e)
        return
    uid_cache = {}
    for name in list(managed):
        try:
            uid_cache[name] = pmm.get_uid(managed[name], name)
        except ValueError as e:
            if pmm.upstream_of(managed[name]) or any(
                    pmm.upstream_of(c) == name for n, c in managed.items()):
                # uid is mandatory for chained proxies (skuid rules)
                print(tf.format("{msg:s,bg_red,black}", msg="[-] %s" % e))
                syslog.syslog(syslog.LOG_CRIT, "proxy chain disabled for %s: %s" % (name, e))
                managed.pop(name)
            else:
                uid_cache[name] = None
    print("[*] managed proxies, start order (deepest dependency first):")
    for n, cfg in config["proxy"].items():
        if n not in managed:
            continue
        up = pmm.upstream_of(cfg)
        try:
            argv = pmm.build_cmd(n, cfg)
        except ValueError as e:
            print("      [%s] BUILD ERROR: %s" % (n, e))
            continue
        where = ("via -> %s" % up) if up else ("direct: %s:%s" % (cfg.get("server") or cfg.get("proxy_ip"),
                                                                  cfg.get("server_port", "-")))
        print("      [%-12s] %-8s :%-6s %s  uid=%s  cmd=%s" % (
            n, cfg.get("daemon"), cfg.get("port"), where,
            uid_cache.get(n), " ".join(pmm.redact(argv))))
        if cfg.get("password"):
            print("      [!] %s: inline password visible in /proc cmdline; prefer 'password_file'" % n)
    n_ok = 0
    for ip_family in ("ip", "ip6"):
        for r in pmm.plan_proxy_chain_rules(config["proxy"], uid_cache, ip_family):
            rc = nfu.add_rule(dict(r))
            if rc[0] != 0:
                print(tf.format("{msg:s,bg_red,black}", msg="[-] add proxy-chain rule failed (%s): %s" % (ip_family, rc)))
                syslog.syslog(syslog.LOG_CRIT, "add proxy-chain rule failed %s: %s" % (ip_family, rc))
            else:
                n_ok += 1
    print("[+] proxy-chain skuid rules: %d installed" % n_ok)

    def on_status(name, state, pid):
        msg = "proxy %s: %s%s" % (name, state, (" pid=%s" % pid) if pid else "")
        print("    " + msg)
        syslog.syslog(syslog.LOG_NOTICE, msg)

    if g_proxy_sup is not None:
        # SIGUSR1 reload path: diff start/stop only (unchanged processes stay up)
        try:
            g_proxy_sup.reconfigure(config["proxy"])
            print("[*] proxy supervisor reconfigured (incremental)")
        except ValueError as e:
            print(tf.format("{msg:s,bg_red,black}", msg="[-] proxy reconfigure failed, running set kept: %s" % e))
            syslog.syslog(syslog.LOG_CRIT, "proxy reconfigure failed, running set kept: %s" % e)
        return
    try:
        g_proxy_sup = pmm.ProxySupervisor(config["proxy"], on_status=on_status,
                                          log=lambda m: syslog.syslog(syslog.LOG_NOTICE, "proxyd: %s" % m))
        g_proxy_sup.start()
    except ValueError as e:
        g_proxy_sup = None
        print(tf.format("{msg:s,bg_red,black}", msg="[-] proxy supervisor config error: %s" % e))
        syslog.syslog(syslog.LOG_CRIT, "proxy supervisor config error: %s" % e)


def get_term_width():
    global g_term_width, g_term_width_check
    if time.time() - g_term_width_check >= 1:
        g_term_width_check = time.time()
        try:
            g_term_width = os.get_terminal_size(sys.stdout.fileno()).columns
        except Exception:
            g_term_width = -1
    return g_term_width


class PrintResultThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.device_list = None
        self.lock = threading.Lock()
        self.filter_ip = None

    def run(self) -> None:
        global queue, term

        prctl.set_name("PR - %s" % self.__class__.__name__)

        self.r = None
        while not term.value:
            try:
                rc = queue.get(True, 1)
            except Empty:
                continue

            #
            # if g_overload_flag.value:
            #     continue

            if g_cps_dup.value >= 20 and rc is not None and rc.test_session == 2:
                # g_io_lock.acquire()
                # print(tf.format("{msg:s,cyan} Working: {working:d,yellow,bold} ",msg="Info: Print Cached Result overloaded", working=g_running_process.value), end="\r")
                # g_io_lock.release()
                continue

            if g_cps.value >= 50:
                # g_io_lock.acquire()
                # print(tf.format("{msg:s,bg_cyan,red} Working: {working:d,yellow,bold} ",
                #                 msg="Info: Print Result overloaded", working=g_running_process.value), end="\r")
                # g_io_lock.release()
                continue

            self.lock.acquire()
            try:
                if rc is not None:
                    try:
                        if self.r is None:
                            self.r = redis.Redis(host='127.0.0.1', port=6379, db=1, socket_timeout=3, socket_connect_timeout=3)

                        if self.device_list is None:
                            self.device_list = self.r.keys("MAC::TABLE::*")

                        if rc.process_fullcone:
                            self.r.publish("fullcone_nat", json.dumps({
                                "ver": rc.pkt_version,
                                "proto": rc.proto,
                                "src": rc.src,
                                "sport": rc.sport
                            }))
                        # webadmin live stream (independent subscriber; failures
                        # here must never affect the router itself)
                        try:
                            self.r.publish("pr_stream", json.dumps({
                                "ts": round(time.time(), 3),
                                "ver": rc.pkt_version, "proto": rc.proto,
                                "src": rc.src, "dst": rc.dst,
                                "sport": rc.sport, "dport": rc.port,
                                "line": rc.out_interface, "mark": rc.mark,
                                "pri": rc.matched_priority, "sess": rc.test_session,
                                "ms": round(rc.t_total, 2), "fc": 1 if rc.process_fullcone else 0}))
                        except Exception as e:
                            syslog.syslog(syslog.LOG_WARNING, "pr_stream publish failed: %s" % e)
                    except Exception as e:
                        print(tf.format("{msg:s,bg_red,black}", msg="[-] PrintResult Thread Error: %s" % e))
                        self.r = None

                    if isinstance(self.filter_ip, ipaddress.IPv4Network) or isinstance(self.filter_ip, ipaddress.IPv6Network):
                        if (ipaddress.ip_address(rc.src) not in self.filter_ip and
                                ipaddress.ip_address(rc.dst) not in self.filter_ip):
                            continue

                    geodata = rc.geodata
                    if geodata is None:
                        try:
                            geodata = db_v6.find_map(rc.dst, "CN")
                        except Exception:
                            geodata = None

                    if geodata is None:
                        with timed_lock(g_io_lock):
                            print("[*] Connect to IP: %s => %15s FROM %s  Resolve: %.06f" % (
                                rc.dst, rc.out_interface, rc.src, rc.t_total))
                    else:
                        proto_info = protos.get(rc.proto)
                        if type(proto_info) is dict:
                            proto_str = tf.format("{proto:6s,%s,bold}" % (proto_info['color']),
                                                  proto=proto_info['name'])
                        else:
                            proto_str = proto_info if proto_info is not None else "%d" % rc.proto

                        try:
                            if geodata['anycast'] == "ANYCAST":
                                flag_str = flag.flag('UN') + " "
                            elif geodata['country_name'] == "局域网":
                                flag_str = "💻"
                            else:
                                flag_str = flag.flag(geodata["country_code"]) + " "
                        except Exception as e:
                            flag_str = "❌"
                            pass

                        if rc.test_session == 1:
                            out_interface_color = tf.format("{out_interface:12s,purple,bold,dim}",
                                                            out_interface=rc.out_interface)
                        elif rc.test_session == 2:
                            out_interface_color = tf.format("{out_interface:12s,green,bold,dim}",
                                                            out_interface=rc.out_interface)
                        elif rc.test_session == 3:
                            out_interface_color = tf.format("{out_interface:12s,cyan,bold}",
                                                            out_interface=rc.out_interface)
                        else:
                            out_interface_color = tf.format("{out_interface:12s}", out_interface=rc.out_interface)

                        isp_string = tf.format("{country:3s,%s,bold}{region:s,cyan}{isp:12s,green}" % (
                            "blue" if geodata["anycast"] == "ANYCAST" else "yellow"),
                                               country=geodata['country_name'],
                                               region=geodata["region_name"] if geodata["region_name"] != geodata[
                                                   "country_name"] else "",
                                               isp=geodata["isp_domain"])

                        try:
                            resolve = dns_list[rc.dst]
                        except KeyError:
                            resolve = None

                        ignorePrint = False
                        if resolve is not None and 'ignore_print_domain' in config:
                            for dns_item in resolve:
                                if dns_item.qname in config['ignore_print_domain']:
                                    ignorePrint = True
                                    break

                        if isinstance(self.filter_ip, str) and self.filter_ip != "":
                            ignorePrint = True
                            if resolve is not None:
                                for dns_item in resolve:
                                    if self.filter_ip in dns_item.qname:
                                        ignorePrint = False

                        if ignorePrint:
                            continue

                        # extra_string = "%02d:%02d:%02d %.2f ms (%.2f ms) Resolve: %s" % (
                        #     datetime.now().hour, datetime.now().minute, datetime.now().second, rc.t_total, rc.t_init,
                        #     ",".join({res.qname for res in resolve}) if resolve is not None else "")
                        extra_string = "%.2f ms (%.2f ms) Resolve: %s" % (
                            rc.t_total, rc.t_init,
                            ",".join({res.qname for res in resolve}) if resolve is not None else "")
                        try:
                            if (rc.proto == 6 or rc.proto == 17) and rc.port == 53:
                                pktObject = IP(rc.payload)
                                if pktObject.haslayer(DNSQR):
                                    dns = pktObject[DNSQR]
                                    extra_string = "%02d:%02d:%02d %.2f ms (%.2f ms) Query Request: %s %d" % (
                                        datetime.now().hour, datetime.now().minute, datetime.now().second,
                                        rc.t_total, rc.t_init,
                                        dns.qname.decode("utf-8"), dns.qtype)
                        except Exception as e:
                            pass
                        src_interfaces = ""
                        try:
                            arp_record = self.r.hget("ARP::MAPPING", rc.src)
                        except Exception as e:
                            arp_record = None
                            src_interfaces = tf.format("{error:30s,red,bold}", error="ERROR " + str(e))

                        try:
                            if arp_record is not None and self.device_list is not None:
                                arp_record = json.loads(arp_record)
                                for dev in self.device_list:
                                    mac_record = self.r.hget(dev, arp_record['mac'])
                                    if mac_record is not None:
                                        mac_record = json.loads(mac_record)
                                        if mac_record['ifName'][0:9] != "Eth-Trunk":
                                            dev = dev[12:]  # len("MAC::TABLE::")
                                            if re.match(r"^[A-Z]{4}\-[0-9]{2}", dev.decode('utf-8')):
                                                dev = dev[8:]
                                            if 'ifDescr' in mac_record and mac_record['ifDescr'] != "":
                                                if mac_record['ifDescr'][0:3] == "To ":
                                                    mac_record['ifDescr'] = mac_record['ifDescr'][3:]
                                                desc_len = 29 - len(dev) - int((len(
                                                    mac_record['ifDescr'].encode('utf-8')) - len(
                                                    mac_record['ifDescr'])) / 2)
                                                if desc_len < 0:
                                                    desc_len = 0
                                                src_interfaces = tf.format(
                                                    "{dev:s,cyan}:{interface:%ds,green,bold}" % desc_len,
                                                    dev=dev.decode("utf-8"),
                                                    interface=mac_record['ifDescr'][0:29 - len(dev.decode("utf-8"))])
                                            else:
                                                mac_record['ifName'] = mac_record['ifName'].replace("GigabitEthernet", "GE")
                                                src_interfaces = tf.format(
                                                    "{dev:s,cyan}:{interface:%ds,green}" % (29 - len(dev)),
                                                    dev=dev.decode("utf-8"), interface=mac_record['ifName'])
                            if src_interfaces == "":
                                if arp_record is not None and 'ifName_L3' in arp_record:
                                    src_interfaces = tf.format("> {interface:28s,purple,bold}",
                                                               interface=arp_record['ifName_L3'])
                                else:
                                    src_interfaces = " " * 30
                        except Exception as e:
                            src_interfaces = tf.format("{error:30s,red,bold}", error="ERROR " + str(e))

                        if rc.test_session == 1:
                            src_interfaces = tf.format("{dev:30s,yellow}", dev=" >> Check Alive Connection << ")
                        if rc.test_session == 2:
                            with g_cps_dup.get_lock():
                                g_cps_dup.value += 1
                        elif rc.test_session == 4:
                            src_interfaces = tf.format("{dev:30s,cyan}", dev=" >> QoS Test Connection << ")
                        else:
                            with g_cps.get_lock():
                                g_cps.value += 1

                        dst_str = rc.dst + (":%d" % rc.port if (rc.proto == 6 or rc.proto == 17) else "")
                        if rc.process_fullcone:
                            dst_str = tf.format("{dst:21s,cyan}", dst=dst_str)

                        term_width = get_term_width()
                        g_io_lock.acquire()
                        try:
                            if 0 < term_width < PRINT_COMPACT_MIN_WIDTH:
                                print("[*] %-6s: %s %15s -> %21s => %s\033[0m %1s %3d %2d" % (
                                          proto_str, flag_str,
                                          rc.src if rc.test_session != 1 else "",
                                          dst_str,
                                          out_interface_color,
                                          "" if rc.matched_priority == -1 else rc.matched_priority, rc.mark,
                                          worker_id))
                                print("    %s %s" % (extra_string, isp_string))
                            elif 0 < term_width < PRINT_FULL_MIN_WIDTH:
                                print("[*] %-6s: %s %15s -> %21s => %s\033[0m %1s %3d [%-50s] %2d %s%s" % (
                                          proto_str, flag_str,
                                          rc.src if rc.test_session != 1 else "",
                                          dst_str,
                                          out_interface_color,
                                          "" if rc.matched_priority == -1 else rc.matched_priority, rc.mark,
                                          "", worker_id, extra_string + "\b" * (len(extra_string) + 52 + 3),
                                          isp_string))
                            else:
                                print("[*] %-6s: %s %15s [%s] -> %21s => %s\033[0m %1s %3d [%-50s] %2d %s%s" % (
                                          proto_str, flag_str,
                                          rc.src if rc.test_session != 1 else "",
                                          src_interfaces,
                                          dst_str,
                                          out_interface_color,
                                          "" if rc.matched_priority == -1 else rc.matched_priority, rc.mark,
                                          "", worker_id, extra_string + "\b" * (len(extra_string) + 52 + 3),
                                          isp_string))
                        finally:
                            g_io_lock.release()

                else:
                    time.sleep(0.01)
            except Exception as e:
                # Never let an unexpected error kill this thread while it holds
                # self.lock; log and keep draining the queue.
                syslog.syslog(syslog.LOG_CRIT, "PrintResult Thread Error: %s\n  %s" % (
                    str(e), '  '.join(traceback.format_tb(e.__traceback__))))
            finally:
                self.lock.release()

    def get_id(self):
        # returns id of the respective thread
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def raise_exception(self):
        thread_id = self.get_id()
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id,
                                                         ctypes.py_object(SystemExit))
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            print('Exception raise failure')


def ip_mark(packet):
    global ecmp_thread, config, test_mapping, worker_id

    t1 = time.time()

    try:
        test_session = 0
        geodata = None
        proto = 0

        packet_payload = packet.get_payload()
        pkt_version = packet_payload[0] >> 4
        qos_flag = packet_payload[1] >> 2
        if pkt_version == 4:
            proto = packet_payload[9]
            src = str(socket.inet_ntoa(packet_payload[12:16]))
            dst = str(socket.inet_ntoa(packet_payload[16:20]))
            dst_int = struct.unpack("!L", packet_payload[16:20])[0]
            sport = struct.unpack("!H", packet_payload[20:22])[0]
            port = struct.unpack("!H", packet_payload[22:24])[0]
            ttl = packet_payload[8]
        elif pkt_version == 6:
            proto = packet_payload[6]
            src = str(socket.inet_ntop(socket.AF_INET6, packet_payload[8:24]))
            dst = str(socket.inet_ntop(socket.AF_INET6, packet_payload[24:40]))
            sport = struct.unpack("!H", packet_payload[40:42])[0]
            port = struct.unpack("!H", packet_payload[42:44])[0]
            ttl = packet_payload[7]

        pkt_version_str = "ipv%d" % pkt_version

        g_worker_last_active[worker_id].value = t1
        g_worker_process_connections[worker_id].value += 1

        allow_ecmp = proto in [6, 17] and 'allow_ecmp_port' in config and port in config['allow_ecmp_port']

        if pkt_version == 4 or pkt_version == 6:
            mark = 0
            t_init = time.time() - t1
            out_interface = ""
            matched_priority = -1

            test_ip = None
            test_proxy_id = None
            if g_test_proxy_id.value != -1:
                with timed_lock(g_lock, 0.5) as got:
                    if got and g_test_proxy_id.value != -1:
                        test_proxy_id = g_proxy_index[g_test_proxy_id.value]
                        test_ip = str(g_test_ip[:])
                        test_ip = test_ip[0:test_ip.index("\0")]
            # elif not allow_ecmp:
            #     g_lock.acquire()
            #     os.write(ecmp_thread.fdw, struct.pack("=B72s", 0, dst.encode("utf-8")))
            #     ecmp_result = os.read(ecmp_thread.fdr_cb, 73)
            #     g_lock.release()
            #     if len(ecmp_result) == 73:
            #         result, ecmp_item = struct.unpack("=B72s", ecmp_result)
            #         if result == 1:
            #             cache_ecmp = ECMPCacheItem(ecmp_item)
            #     else:
            #         print("ERROR ", len(ecmp_result), ecmp_result)

            process_fullcone = (proto == 17 and port in [3478, 3479]) or (proto == 6 and port in [3478, 3479, 3480])

            src_mtx = "%s:%d" % (src, sport)
            if src_mtx in test_mapping:
                test_info = test_mapping[src_mtx]
                mark = test_info['mark']
                packet.set_mark(mark)
                packet.repeat()
                test_session = 1
                out_interface = test_info['proxy_id']
            elif test_ip is not None and test_ip == dst:
                proxy = config['proxy'][test_proxy_id]
                mark = proxy['mark']
                packet.set_mark(mark)
                packet.repeat()
                test_session = 1
                out_interface = test_proxy_id
                # print("[*] Connect to Test IP: %s  Mark: %d" % (dst, mark))
            elif not allow_ecmp and dst in ecmp_thread.ip_list:
                # Use Cached ECMP
                cache_ecmp = ecmp_thread.ip_list[dst]
                if ecmp_thread.now - cache_ecmp.last_active >= 1:
                    ecmp_thread.queue.put(cache_ecmp)
                    # ecmp_thread.lock.acquire()
                    # ecmp_thread.ip_list[dst].last_active = ecmp_thread.now
                    # ecmp_thread.lock.release()
                mark = cache_ecmp.mark
                packet.set_mark(mark)
                packet.repeat()
                out_interface = cache_ecmp.tun_id
                geodata = None
                test_session = 2
            elif qos_flag != 0 and (proto == 1 or (proto == 6 and port == 53)) and qos_flag <= len(config['proxy']):
                proxy = list(config['proxy'].values())[qos_flag - 1]
                mark = proxy['mark']
                packet.set_mark(mark)
                packet.repeat()
                test_session = 4
                out_interface = g_proxy_index[qos_flag - 1]
            else:
                if g_parallel_process - g_running_process.value <= 2:
                    packet.set_mark(0x99)
                    packet.repeat()
                    if not g_overload_flag.value:
                        g_overload_flag.value = True
                        with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
                            conntrack_count = int(f.read().strip())
                        with open("/proc/net/netfilter/nfnetlink_queue") as f:
                            queue_info = f.read()
                        syslog.syslog(syslog.LOG_NOTICE, f"[*] running process overload, running: {g_running_process.value}, conntrack: {conntrack_count}, queue_info: {queue_info}")
                    return

                try:
                    with g_running_process.get_lock():
                        g_running_process.value += 1

                    g_working_flag[worker_id].value = True

                    if pkt_version == 4:
                        geodata = db.find_map(dst_int, "CN")
                    elif pkt_version == 6:
                        geodata = db_v6.find_map(dst, "CN")

                    if geodata is None:
                        packet.set_mark(0x99)
                        packet.repeat()
                        return

                    src_addr = ipaddress.ip_address(src)
                    dst_addr = ipaddress.ip_address(dst)
                    try:
                        resolve = set([dns_item.qname for dns_item in dns_list[dst]])
                    except KeyError:
                        resolve = None

                    t_init = time.time() - t1

                    for priority in range(0, len(config["rules"])):
                        policy_route_list = []
                        sum_weight = 0
                        for tun_id, rule_cfg in config["rules"][priority].items():
                            if pkt_version == 4 and tun_id in g_dead_proxy_ipv4 and \
                                    g_dead_proxy_ipv4[tun_id].value < 0:
                                continue
                            if pkt_version == 6 and tun_id in g_dead_proxy_ipv6 and \
                                    g_dead_proxy_ipv6[tun_id].value < 0:
                                continue
                            if not config["proxy"][tun_id][pkt_version_str]:
                                continue
                            if config["proxy"][tun_id].get('weight', -1) < 0:
                                continue
                            if proto == 17 and not config["proxy"][tun_id].get("udp_v%d" % pkt_version, False):
                                continue
                            if process_fullcone and not config["proxy"][tun_id].get("fullcone", False):
                                continue

                            ignore_apps = config["proxy"][tun_id].get("ignore_apps", None)
                            if ignore_apps is not None:
                                ignore_by_app = False
                                for app in ignore_apps:
                                    if app[0] != proto:
                                        continue
                                    if len(app) == 2:
                                        if app[1] == port:
                                            ignore_by_app = True
                                    elif len(app) == 3:
                                        if app[1] <= port <= app[2]:
                                            ignore_by_app = True

                                if ignore_by_app:
                                    continue

                            if "from" in rule_cfg:
                                net_pass = False
                                for from_net in rule_cfg["from"]:
                                    if src_addr in from_net:
                                        net_pass = True
                                        break
                                if not net_pass:
                                    continue

                            for geo_k, geo_list in rule_cfg.items():
                                if geo_k == "from":
                                    pass
                                elif geo_k == "cidr":
                                    for dst_net in geo_list:
                                        if dst_addr in dst_net:
                                            weight = config["proxy"][tun_id]['weight'] if 'weight' in config["proxy"][
                                                tun_id] else 0
                                            policy_route_list.append(
                                                PolicyRouteItem(tun_id, config["proxy"][tun_id]["mark"], weight,
                                                                sum_weight, sum_weight + weight,
                                                                "port" in config["proxy"][tun_id]))
                                            sum_weight += weight
                                            break
                                elif geo_k == "resolve":
                                    if resolve is None:
                                        continue
                                    for domain in geo_list:
                                        for resolve_name in resolve:
                                            if domain == resolve_name or (
                                                    domain[0] == '.' and resolve_name[-len(domain):] == domain):
                                                weight = config["proxy"][tun_id]['weight'] if 'weight' in \
                                                                                              config["proxy"][
                                                                                                  tun_id] else 0
                                                policy_route_list.append(
                                                    PolicyRouteItem(tun_id, config["proxy"][tun_id]["mark"], weight,
                                                                    sum_weight, sum_weight + weight,
                                                                    "port" in config["proxy"][tun_id]))
                                                sum_weight += weight
                                elif geo_k == "any" or (geo_k in geodata and geodata[geo_k] in geo_list):
                                    weight = config["proxy"][tun_id]['weight'] if 'weight' in config["proxy"][
                                        tun_id] else 0
                                    policy_route_list.append(
                                        PolicyRouteItem(tun_id, config["proxy"][tun_id]["mark"], weight, sum_weight,
                                                        sum_weight + weight, "port" in config["proxy"][tun_id]))
                                    sum_weight += weight
                            if out_interface != "":
                                break

                        if len(policy_route_list) > 0:
                            policy_route_list.sort(key=lambda x: x.weight, reverse=True)
                            for match_policy in policy_route_list:
                                if match_policy.weight == 0 or (
                                        packet.id % sum_weight >= match_policy.start_r and packet.id % sum_weight < match_policy.end_r):
                                    if not allow_ecmp:
                                        ecmp_thread.queue.put(
                                            ECMPCacheItem(dst, match_policy.tun_id, match_policy.mark, ecmp_thread.now))
                                    # g_lock.acquire()
                                    # os.write(ecmp_thread.fdw, struct.pack("=B72s", 1, ECMPCacheItem(dst, match_policy.tun_id, match_policy.mark, ecmp_thread.now).dump()))
                                    # g_lock.release()

                                    if ttl <= 6 and proto == 1 and match_policy.is_proxy:
                                        # Return ICMP Proxy by IP
                                        if ttl == 1:
                                            raw_socket.sendto(ICMP_TTL_TIMEOUT_Builder.packet(
                                                socket.inet_ntoa(struct.pack("!L", 0xA9FE0000 + match_policy.mark)),
                                                src, packet_payload), (src, 80))
                                        elif ttl == 2 and "proxy_ip" in config["proxy"][match_policy.tun_id]:
                                            raw_socket.sendto(ICMP_TTL_TIMEOUT_Builder.packet(
                                                config["proxy"][match_policy.tun_id]["proxy_ip"], src, packet_payload),
                                                (src, 80))
                                        elif (ttl == 2 and "proxy_ip" not in config["proxy"][match_policy.tun_id]) or (
                                                ttl == 3 and "proxy_ip" in config["proxy"][match_policy.tun_id]):
                                            raw_socket.sendto(ICMP_TTL_TIMEOUT_Builder.packet(dst, src, packet_payload),
                                                              (src, 80))
                                        packet.drop()
                                        test_session = 3
                                    else:
                                        packet.set_mark(match_policy.mark)
                                        packet.repeat()
                                    mark = match_policy.mark
                                    out_interface = match_policy.tun_id
                                    break

                        if out_interface != "":
                            matched_priority = priority
                            break

                    if out_interface == "":
                        process_fullcone = False
                        packet.set_mark(0x99)
                        packet.repeat()
                except Exception as e:
                    syslog.syslog(syslog.LOG_CRIT,
                          "IP Mark Process Error: %s\n  %s\n" % (str(e), '  '.join(traceback.format_tb(e.__traceback__))))
                    print("ERROR: ", e)
                    print(''.join(traceback.format_tb(e.__traceback__)))
                    print(packet)
                    packet.set_mark(0x99)
                    packet.repeat()
                finally:
                    with g_running_process.get_lock():
                        g_running_process.value -= 1
                    g_working_flag[worker_id].value = False

            if queue.qsize() <= 10:
                queue.put(ResultData(pkt_version, proto, src, dst, sport, port, out_interface, mark, geodata,
                                     matched_priority, test_session,
                                     1000 * (time.time() - t1), 1000 * t_init, packet_payload, process_fullcone))
        else:
            packet.set_mark(0x99)
            packet.repeat()
    except Exception as e:
        print("ERROR: ", e)
        print(''.join(traceback.format_tb(e.__traceback__)))
        print(packet)
        syslog.syslog(syslog.LOG_CRIT,
            "IP Mark Process Error: %s\n  %s\n" % (str(e), '  '.join(traceback.format_tb(e.__traceback__))))
        packet.set_mark(0x99)
        packet.repeat()


def clearRules():
    print("[*] clear rules -> delete_table")

    for i in range(0, 5):
        print("[*] \033[32mTrying to delete rules\033[0m")
        try:
            nfu = nftUtils()
            nfu.delete_table(family="ip", name="policy_route")
            nfu.delete_table(family="ip6", name="policy_route")

            print("[*] clear rules -> delete_rules")
            nfu.delete_rules(comment=cmt_class, family=None)
            break
        except Exception as e:
            print("[*] \033[31mDelete rules failed: %s, retry: %d\033[0m" % (e, i))

    # print("[*] clear rules -> delete_set")
    # ALL SET are defined at policy_route table, so they are deleted
    # nfu.delete_set(family=ip_family, table="nat", name="local")
    # nfu.delete_set(family=ip_family, table="nat", name="policy_mark")
    # nfu.delete_set(family=ip_family, table="nat", name="ignore_list")
    # nfu.delete_set(family=ip_family, table="mangle", name="policy_mark")
    print("[*] clear rules finished")


def quit(signum, sigframe):
    if is_master:
        print("[*] clear rules by received signal %d" % (signum))
        clearRules()
        print("[*] clear rules by received signal %d finished" % (signum))
        raise KeyboardInterrupt


def restart_all_proxies(signum, sigframe):
    """SIGUSR2: restart every managed proxy process (config unchanged,
    rate-limit/gaveup state cleared). Handled in the main loop."""
    if is_master:
        g_proxy_restart_all.value = True


def load_executor():
    global g_runner

    for run_p in g_runner:
        try:
            run_p.release_process()
        except Exception as e:
            pass

    g_runner = []

    for i in range(g_parallel_process):
        nq = NFQUEUE_Executeor(i)
        nq.start()
        g_runner.append(nq)


def reload_queue(signum, sigframe):
    global ecmp_thread, test_thread, g_runner

    if not is_master:
        sys.exit(0)

    print("[*] loading configure")

    # nfqueue.unbind()
    load_config()
    test_thread.last_check = 0
    # SIGUSR1: reconcile chain rules + managed proxies INCREMENTALLY from the
    # MAIN loop (new->start, removed->stop, changed->restart, same->keep alive;
    # spawn/fork must not happen inside signal handler context)
    g_proxy_pending.value = True

    # re-apply egress mark rules on reload (non-interactive; new unbound
    # public egress IPs/interfaces are logged, wizard runs only at boot)
    try:
        for ip_family in ("ip", "ip6"):
            apply_egress_rules(nfu, ip_family)
    except Exception as e:
        syslog.syslog(syslog.LOG_CRIT, "egress rules reload error: %s\n  %s" % (
            str(e), '  '.join(traceback.format_tb(e.__traceback__))))
    # tp.lock.acquire()
    # tp.device_list = None
    # tp.lock.release()

    # nfqueue.bind(4, ip_mark, mode=netfilterqueue.COPY_PACKET)

    for np_id in range(len(g_runner)):
        try:
            print("[*] %s" % tf.format("{msg:s,yellow,bold}", msg="rebooting executer %d  " % np_id))
            run_p = g_runner[np_id]
            run_p.release_process()
            nq = NFQUEUE_Executeor(np_id)
            nq.start()
            g_runner[np_id] = nq
        except Exception as e:
            print(tf.format("{msg:s,bg_red,black}", msg="[-] Reload Error: %s" % e))
            print(''.join(traceback.format_tb(e.__traceback__)))

            syslog.syslog(syslog.LOG_CRIT, "Reload Process Error: %s\n  %s" % (
                 str(e), '  '.join(traceback.format_tb(e.__traceback__))))
    print("[+] %s" % tf.format("{msg:s,green,bold}", msg="reboot executer done"))


class NFQUEUE_Executeor(Process):
    def __init__(self, worker_id):
        # threading.Thread.__init__(self)
        super().__init__()
        self.worker_id = worker_id

    def release_process(self) -> None:
        # Ask the worker to exit its own loop first (checked in
        # NFQUEUE_Executeor.run() after nfqueue.run() returns/raises).
        self.terminate()

        # Only release locks we actually acquired -- acquire() can time out
        # if a worker was killed mid critical-section in a previous call,
        # and blindly releasing here would corrupt state for every other
        # process still waiting on the lock.
        got_lock = g_lock.acquire(timeout=2.0)
        got_io_lock = g_io_lock.acquire(timeout=2.0)
        try:
            deadline = time.time() + 2.0
            while self.is_alive() and time.time() < deadline:
                time.sleep(0.05)
        finally:
            if got_io_lock:
                g_io_lock.release()
            if got_lock:
                g_lock.release()

        if self.is_alive():
            print("[-] force kill %d" % self.worker_id)
            if not got_lock:
                print("[-] %d did not release g_lock in time before kill, state may be inconsistent" % self.worker_id)
            self.kill()

    @staticmethod
    def quit(signum, sigframe):
        global process_term
        process_term = True

    def run(self):
        global ecmp_thread, is_master, worker_id, process_term, nfu

        syslog.openlog(ident="PolicyRoute[%d]::W%02d" % (os.getpid(), self.worker_id))

        worker_id = self.worker_id

        signal.signal(signal.SIGTERM, self.quit)
        signal.signal(signal.SIGQUIT, self.quit)

        is_master = False

        ecmp_thread = ECMPThread()
        ecmp_thread.start()

        prctl.set_proctitle("Policy Route - W%02d" % (self.worker_id))

        while not term.value and not process_term:
            try:
                syslog.syslog(syslog.LOG_INFO,
                              "[*] waiting for data (Process %2d, PID: %d)" % (self.worker_id, os.getpid()))
                print("[*] waiting for data (Process %2d, PID: %d)" % (self.worker_id, os.getpid()), flush=True)
                nfqueue.run()
            except KeyboardInterrupt:
                term.value = True
                pass
            except Exception as e:
                print("[-] Error: %s" % e)
                syslog.syslog(syslog.LOG_ERR, "%s: Worker %d Process Error: %s\n  %s\n" % (
                    datetime.now().isoformat(), worker_id, str(e), '  '.join(traceback.format_tb(e.__traceback__))))

        # tp.raise_exception()
        os.kill(os.getpid(), signal.SIGKILL)


def time_to_level(t, proxy_id):
    # tf.format("{off:2d,green,bold}",off=x)
    global config
    if 'weight' in config['proxy'][proxy_id] and config['proxy'][proxy_id]['weight'] < 0:
        return "🈲"  # "⭕"

    if t == 0:
        return "⚫" if "port" not in config['proxy'][proxy_id] else "⬛"
    if t < 0:
        return "🔴" if "port" not in config['proxy'][proxy_id] else "🟥"
    if t <= 0.1:
        return "🟢" if "port" not in config['proxy'][proxy_id] else "🟩"
    elif t <= 0.2:
        return "🔵" if "port" not in config['proxy'][proxy_id] else "🟦"
    elif t <= 0.4:
        return "🟣" if "port" not in config['proxy'][proxy_id] else "🟪"
    elif t <= 0.6:
        return "🟡" if "port" not in config['proxy'][proxy_id] else "🟨"
    elif t <= 0.8:
        return "🟠" if "port" not in config['proxy'][proxy_id] else "🟧"
    else:
        return "🟤" if "port" not in config['proxy'][proxy_id] else "🟫"


MASTER_PID_FILE = "/run/nft_route.pid"


def write_master_pid():
    try:
        with open(MASTER_PID_FILE, "w") as f:
            f.write(str(os.getpid()))
    except OSError as e:
        syslog.syslog(syslog.LOG_WARNING, "cannot write master pidfile: %s" % e)


if __name__ == "__main__":
    write_master_pid()
    print("[+] create nftables mangle checking rules")
    nfu.delete_rules(comment=cmt_class, family=None)

    print("[*] initalize dns memory")
    dns_list = MPDNSList()
    dns_proc = None

    load_config()

    print("[*] load ipdb")
    db = ipdb.City(config['ipdb_v4'])
    db_v6 = None
    if config.get('ipdb_v6', None) and config['ipdb_v6'] != config['ipdb_v4']:
        db_v6 = ipdb.City(config['ipdb_v6'])
    elif db.is_ipv6():
        db_v6 = db

    test_thread = TestThread()
    test_thread.start()

    # Internal Interface
    nat_interfaces = config['nat_interfaces']
    for n, _interface in enumerate(nat_interfaces):
        if _interface not in netifaces.interfaces():
            syslog.syslog(syslog.LOG_WARNING, f"Interface {_interface} not exists")
            nat_interfaces.pop(n)

    # scan interfaces -> wizard-bind public egress IP/interface to fwmark -> save config
    egress_wizard_boot()
    # closed-loop ip rule / route table reconcile (gateways from config)
    sync_iprules("boot")

    for ip_version, ip_family in [(4, "ip"), (6, "ip6")]:
        # nfu.delete_set(family=ip_family, table="nat", name="local")
        # nfu.delete_set(family=ip_family, table="nat", name="ignore_list")
        # nfu.delete_set(family=ip_family, table="nat", name="policy_mark")

        nfu.delete_table(family=ip_family, name="policy_route")

        nfu.add_table(family=ip_family, name="policy_route")

        nfu.add_set(family=ip_family, table="policy_route", name="local", set_type="ipv%d_addr" % (ip_version))
        nfu.add_set(family=ip_family, table="policy_route", name="tunnel_ip", set_type="ipv%d_addr" % (ip_version))
        nfu.add_set(family=ip_family, table="policy_route", name="ignore_list", set_type="ipv%d_addr" % (ip_version))
        nfu.add_set(family=ip_family, table="policy_route", name="policy_mark", set_type="mark")
        nfu.add_set(family=ip_family, table="policy_route", name="nat_interfaces", set_type="iface_index")
        nfu.add_set(family=ip_family, table="policy_route", name="redir_ports", set_type="inet_service")
        nfu.add_set_element(family=ip_family, table="policy_route", name="nat_interfaces", element=nat_interfaces)

        nfu.add_chain(
            {"family": ip_family, "table": "policy_route", "name": "nat_PREROUTING", "type": "nat",
             "hook": "prerouting",
             "prio": -90, "policy": 'accept'})
        nfu.add_chain(
            {"family": ip_family, "table": "policy_route", "name": "nat_FULLCONE", "type": "nat", "hook": "prerouting",
             "prio": -89, "policy": 'accept'})
        nfu.add_chain(
            {"family": ip_family, "table": "policy_route", "name": "nat_OUTPUT", "type": "nat", "hook": "output",
             "prio": -90, "policy": 'accept'})
        nfu.add_chain(
            {"family": ip_family, "table": "policy_route", "name": "nat_POSTROUTING", "type": "nat",
             "hook": "postrouting",
             "prio": 110, "policy": 'accept'})
        # Add Rules to marking for TProxy tables
        # Priority = mangle + 5
        nfu.add_chain({"family": ip_family, "table": "policy_route", "name": "mangle_PREROUTING", "type": "filter",
                       "hook": "prerouting", "prio": -145, "policy": 'accept'})
        # Priority = mangle + 10
        nfu.add_chain(
            {"family": ip_family, "table": "policy_route", "name": "mangle_TPROXY_PREROUTING", "type": "filter",
             "hook": "prerouting", "prio": -140, "policy": 'accept'})

        nfu.add_chain({"family": ip_family, "table": "policy_route", "name": "INPUT", "type": "filter", "hook": "input",
                       "prio": 0, "policy": 'accept'})

        nfu.add_chain({"family": ip_family, "table": "policy_route", "name": "FORWARD", "type": "filter",
                       "hook": "forward", "prio": 0, "policy": 'accept'})

        nfu.add_rule({'family': ip_family, 'chain': 'INPUT', 'table': 'policy_route', 'comment': cmt_class,
                      'expr': [{'match': nfu.match_payload('sport', 53, protocol='udp')},
                               {'counter': {'bytes': 0, 'packets': 0}},
                               {'queue': {'num': 53, 'flags': ['bypass']}}]
                      })

        nfu.add_rule(
            {'family': ip_family, 'chain': ['nat_PREROUTING'], 'table': 'policy_route', 'comment': cmt_class,
             'expr': [
                 {'match': nfu.match_iifname('lo')},
                 {'counter': {'bytes': 0, 'packets': 0}},
                 {'accept': None}
             ]})

        if ip_version == 4:
            nfu.add_set_element(family=ip_family, table="policy_route", name="local",
                                element=[nfu.cidr('127.0.0.0', 8), nfu.cidr('10.0.0.0', 8), nfu.cidr('172.16.0.0', 12),
                                         nfu.cidr('192.168.0.0', 16), nfu.cidr('169.254.0.0', 16),
                                         nfu.cidr('224.0.0.0', 8),
                                         nfu.cidr('239.0.0.0', 8),
                                         nfu.cidr('255.0.0.0', 8)])
            # Add Tunnel IP
        else:
            nfu.add_set_element(family=ip_family, table="policy_route", name="local",
                                element=[nfu.cidr('fc00::', 6), nfu.cidr('fe80::', 10), nfu.cidr('ff00::', 8), "::1"])
        nfu.add_set_element(family=ip_family, table="policy_route", name="tunnel_ip",
                            element=config["tunnel_ip"]["ipv%d" % (ip_version)])
        nfu.add_set_element(family=ip_family, table="policy_route", name="ignore_list",
                            element=config["ignore_list"]["ipv%d" % (ip_version)])

        nfu.add_rule({'family': ip_family, 'chain': ['FORWARD'], 'table': 'policy_route',
                      'comment': "Fix TCP MSS for tunnel/ppp",
                      'expr': [
                          {'match': nfu.match_mark('@policy_mark')},
                          {"match": nfu.match_syn()},
                          {'counter': {'bytes': 0, 'packets': 0}},
                          {"mangle": {"key": {"tcp option": {"name": "maxseg", "field": "size"}},
                                      "value": {"rt": {"key": "mtu"}}}}
                      ]})
        # Return CIDR Process by Queue
        for priority in range(0, len(config["rules"])):
            for tun_id, rule_cfg in config["rules"][priority].items():
                for geo_k, geo_list in rule_cfg.items():
                    if geo_k == "cidr" and config["proxy"][tun_id]["ipv%d" % (ip_version)]:
                        for cidr in geo_list:
                            if cidr.version == ip_version and cidr.is_private:
                                nfu.add_rule({'family': ip_family, 'chain': ['nat_PREROUTING'], 'table': 'policy_route',
                                              'comment': cmt_class,
                                              'expr': [{'match': nfu.match_payload(field='saddr', protocol=ip_family,
                                                                                   right='@ignore_list',
                                                                                   op='!=')},
                                                       {'match': nfu.match_payload(field='daddr', protocol=ip_family,
                                                                                   right={"prefix": {
                                                                                       'addr': str(
                                                                                           cidr.network_address),
                                                                                       'len': cidr.prefixlen}})},
                                                       # {'match': nfu.match_iifname({'set': nat_interfaces})},
                                                       {'match': nfu.match_iif("@nat_interfaces")},
                                                       {'match': nfu.match_mark(0)},
                                                       {'counter': {'bytes': 0, 'packets': 0}},
                                                       {'queue': {'num': 4, 'flags': ['bypass']}}]
                                              })

                                nfu.add_rule({'family': ip_family, 'chain': ['nat_OUTPUT'], 'table': 'policy_route',
                                              'comment': cmt_class,
                                              'expr': [{'match': nfu.match_payload(field='daddr', protocol=ip_family,
                                                                                   right={"prefix": {
                                                                                       'addr': str(
                                                                                           cidr.network_address),
                                                                                       'len': cidr.prefixlen}})},
                                                       {'match': nfu.match_payload(field='saddr', protocol=ip_family,
                                                                                   right='@ignore_list',
                                                                                   op='!=')},
                                                       {'match': nfu.match_mark(0)},
                                                       {'counter': {'bytes': 0, 'packets': 0}},
                                                       {'queue': {'num': 4, 'flags': ['bypass']}}]
                                              })

                                # nfu.add_rule(
                                #     dict(family=ip_family, chain=['nat_PREROUTING', 'nat_OUTPUT'], table='policy_route',
                                #          comment=cmt_class, expr=[
                                #             {'match': nfu.match_payload(field='saddr', protocol=ip_family, right='@ignore_list',
                                #                                         op='!=')},
                                #             {'match': nfu.match_payload(field='daddr', protocol=ip_family, right={
                                #                 "prefix": {'addr': str(cidr.network_address), 'len': cidr.prefixlen}})},
                                #             {'match': nfu.match_l4proto('udp', op='!=')},
                                #             {'match': nfu.match_mark(0)},
                                #             # {'queue': {'num': 4}}]
                                #             {'mangle': {'key': {'meta': {'key': 'mark'}},
                                #                         'value': config["proxy"][tun_id]["mark"]}},
                                #             {'mangle': {'key': {'ct': {'key': 'mark'}}, 'value': {'meta': {'key': 'mark'}}}},
                                #             {'counter': {'bytes': 0, 'packets': 0}}]
                                #         ))

                                if config["proxy"][tun_id]["udp_v%d" % (ip_version)]:
                                    nfu.add_rule(
                                        dict(family=ip_family, chain=['mangle_PREROUTING'], table='policy_route',
                                             comment=cmt_class, expr=[
                                                {'match': nfu.match_payload(field='saddr', protocol=ip_family,
                                                                            right='@ignore_list',
                                                                            op='!=')},
                                                {'match': nfu.match_payload(field='daddr', protocol=ip_family, right={
                                                    "prefix": {'addr': str(cidr.network_address),
                                                               'len': cidr.prefixlen}})},
                                                {'match': nfu.match_mark(0)},
                                                {'match': nfu.match_ct('new', key='state')},
                                                {'match': nfu.match_l4proto('udp')},
                                                {'match': nfu.match_iif("@nat_interfaces")},
                                                {'counter': {'bytes': 0, 'packets': 0}},
                                                {'queue': {'num': 4, 'flags': ['bypass']}}]
                                             # {'mangle': {'key': {'meta': {'key': 'mark'}},
                                             #             'value': config["proxy"][tun_id]["mark"]}},
                                             # {'mangle': {'key': {'ct': {'key': 'mark'}},
                                             #             'value': {'meta': {'key': 'mark'}}}},
                                             # {'counter': {'bytes': 0, 'packets': 0}}]
                                             ))

        nrc = nfu.add_rule(
            {'family': ip_family, 'chain': ['nat_PREROUTING'], 'table': 'policy_route', 'comment': cmt_class,
             'expr': [
                 {'match': nfu.match_payload(field='daddr', protocol=ip_family, right='@local', op='!=')},
                 {'match': nfu.match_payload(field='saddr', protocol=ip_family, right='@ignore_list',
                                             op='!=')},
                 {'match': nfu.match_iif("@nat_interfaces")},
                 {'match': nfu.match_mark(0)},
                 {'counter': {'bytes': 0, 'packets': 0}},
                 {'queue': {'num': 4, 'flags': ['bypass']}}]
             })
        if functools.reduce(lambda a, b: a | b, [add_rule_rc[0] for add_rule_rc in nrc]):
            print("[-] %s" % tf.format("{msg:s,bg_red,white,bold}",
                                       msg="add rule %s nat_PREROUTING NFQUEUE failed: %s" % (ip_family, nrc)))

        nrc = nfu.add_rule({'family': ip_family, 'chain': ['nat_OUTPUT'], 'table': 'policy_route', 'comment': cmt_class,
                            'expr': [
                                {'match': nfu.match_payload(field='daddr', protocol=ip_family, right='@local',
                                                            op='!=')},
                                {'match': nfu.match_payload(field='daddr', protocol=ip_family, right='@tunnel_ip',
                                                            op='!=')},
                                {'match': nfu.match_payload(field='saddr', protocol=ip_family, right='@ignore_list',
                                                            op='!=')},
                                {'match': nfu.match_mark(0)},
                                {'counter': {'bytes': 0, 'packets': 0}},
                                {'queue': {'num': 4, 'flags': ['bypass']}}]
                            })
        if functools.reduce(lambda a, b: a | b, [add_rule_rc[0] for add_rule_rc in nrc]):
            print("[-] %s" % tf.format("{msg:s,bg_red,white,bold}",
                                       msg="add rule %s nat_OUTPUT NFQUEUE failed: %s" % (ip_family, nrc)))

        # For Marking UDP First Packet
        nrc = nfu.add_rule(
            {'family': ip_family, 'chain': ['mangle_PREROUTING'], 'table': 'policy_route', 'comment': cmt_class,
             'expr': [{'match': nfu.match_payload(field='daddr', protocol=ip_family, right='@local', op='!=')},
                      {'match': nfu.match_payload(field='saddr', protocol=ip_family, right='@ignore_list',
                                                  op='!=')},
                      {'match': nfu.match_mark(0)},
                      {'match': nfu.match_ct('new', key='state')},
                      {'match': nfu.match_l4proto('udp')},
                      {'match': nfu.match_iif("@nat_interfaces")},
                      {'counter': {'bytes': 0, 'packets': 0}},
                      {'queue': {'num': 4, 'flags': ['bypass']}}]
             })
        if functools.reduce(lambda a, b: a | b, [add_rule_rc[0] for add_rule_rc in nrc]):
            print("[-] %s" % tf.format("{msg:s,bg_red,white,bold}",
                                       msg="add rule %s mangle_PREROUTING NFQUEUE failed: %s" % (ip_family, nrc)))
        # end For Marking UDP First Packet

        proxy_marks = [0x99]
        redir_ports = []
        for k, proxy_cfg in config["proxy"].items():
            # tap0 ss-redir
            if proxy_cfg["ipv%d" % (ip_version)]:
                if "port" in proxy_cfg:
                    if proxy_cfg["port"] not in redir_ports:
                        redir_ports.append(proxy_cfg["port"])
                    create_tproxy(mark=proxy_cfg["mark"], port=proxy_cfg["port"], ip_family=ip_family,
                                  udp=proxy_cfg["udp_v%d" % (ip_version)])
                if proxy_cfg["mark"] not in proxy_marks:
                    proxy_marks.append(proxy_cfg["mark"])
                # [0x1, 0x2, 0x5, 0x6, 0x7, 0x8, 0x99]

        nfu.add_set_element(family=ip_family, table="policy_route", name="policy_mark", element=proxy_marks)

        # Transparent proxy listeners must be reachable from trusted ingress
        # interfaces, but never directly from WAN interfaces. Direct WAN
        # access can make ss-redir proxy its own listening address and create
        # a recursive connection loop.
        if redir_ports:
            nfu.add_set_element(family=ip_family, table="policy_route", name="redir_ports",
                                element=sorted(redir_ports))
            for protocol in ["tcp", "udp"]:
                nfu.add_rule(
                    {'family': ip_family, 'chain': 'INPUT', 'table': 'policy_route', 'comment': cmt_class,
                     'expr': [
                         {'match': nfu.match_iifname('lo')},
                         {'match': nfu.match_l4proto(protocol)},
                         {'match': nfu.match_payload('dport', '@redir_ports', protocol=protocol)},
                         {'counter': {'bytes': 0, 'packets': 0}},
                         {'accept': None}]
                     })
                nfu.add_rule(
                    {'family': ip_family, 'chain': 'INPUT', 'table': 'policy_route', 'comment': cmt_class,
                     'expr': [
                         {'match': nfu.match_iif('@nat_interfaces')},
                         {'match': nfu.match_l4proto(protocol)},
                         {'match': nfu.match_payload('dport', '@redir_ports', protocol=protocol)},
                         {'counter': {'bytes': 0, 'packets': 0}},
                         {'accept': None}]
                     })
                nfu.add_rule(
                    {'family': ip_family, 'chain': 'INPUT', 'table': 'policy_route', 'comment': cmt_class,
                     'expr': [
                         {'match': nfu.match_l4proto(protocol)},
                         {'match': nfu.match_payload('dport', '@redir_ports', protocol=protocol)},
                         {'counter': {'bytes': 0, 'packets': 0}},
                         {'drop': None}]
                     })

        nfu.add_rule(
            {'family': ip_family, 'chain': ['nat_PREROUTING', 'nat_OUTPUT', 'mangle_PREROUTING'],
             'table': 'policy_route',
             'comment': cmt_class,
             'expr': [
                 {'match': nfu.match_mark('@policy_mark')},
                 {'match': nfu.match_ct_mark(0)},
                 {'counter': {'bytes': 0, 'packets': 0}},
                 # {'log': {'prefix': 'AUTOGEN SAVE MARK '}},
                 {'mangle': {'key': {'ct': {'key': 'mark'}}, 'value': {'meta': {'key': 'mark'}}}}]
             })

        if ip_version == 4:
            nfu.add_rule(
                {'family': ip_family, 'chain': 'nat_POSTROUTING', 'table': 'policy_route', 'comment': cmt_class,
                 'expr': [
                     {'match': nfu.match_oif("@nat_interfaces", op='!=')},
                     {'match': nfu.match_mark('@policy_mark')},
                     {'counter': {'bytes': 0, 'packets': 0}},
                     {'masquerade': None}]
                 })
        elif ip_version == 6:
            nfu.add_rule(
                {'family': ip_family, 'chain': 'nat_POSTROUTING', 'table': 'policy_route', 'comment': cmt_class,
                 'expr': [
                     {'match': nfu.match_oif("@nat_interfaces", op='!=')},
                     {'match': nfu.match_mark('@policy_mark')},
                     {'counter': {'bytes': 0, 'packets': 0}},
                     {'masquerade': None}]
                 })

        # egress return-path marking (prerouting setter + generic ct->meta restore)
        apply_egress_rules(nfu, ip_family)

    # managed proxy processes + skuid anti-loop/chain rules (after all families installed)
    install_proxy_chain_rules()
    nfqueue = netfilterqueue.NetfilterQueue()
    nfqueue.bind(4, ip_mark, mode=netfilterqueue.COPY_PACKET)

    signal.signal(signal.SIGTERM, quit)
    signal.signal(signal.SIGQUIT, quit)
    signal.signal(signal.SIGHUP, quit)
    signal.signal(signal.SIGUSR1, reload_queue)
    signal.signal(signal.SIGUSR2, restart_all_proxies)

    load_executor()

    fcnat_listner = None
    fcnat_cleaner = None

    t_dns_clean = 0
    t_iprule = 0
    queue_stdin = []
    mouse_offset = 0
    old_settings = termios.tcgetattr(sys.stdin.fileno())
    tty.setcbreak(sys.stdin.fileno())
    unbuffered_stdin = os.fdopen(sys.stdin.fileno(), 'rb', buffering=0)

    selected_proxy = None
    cps = 0

    tp = PrintResultThread()
    tp.start()

    while not term.value:
        try:
            l_read = [unbuffered_stdin]
            s = select.select(l_read, [], [], 0.25)
            if len(s[0]) > 0:
                n = unbuffered_stdin.read(1)
                queue_stdin.append(n)

            while len(queue_stdin) > 0:
                if queue_stdin[0] == b"\x1B":
                    if len(queue_stdin) >= 3:
                        if b"".join(queue_stdin[0:3]) == b"\x1b[C":
                            mouse_offset += 1
                        queue_stdin = queue_stdin[4:]
                    else:
                        break
                elif queue_stdin[0] == b"l":
                    queue_stdin = queue_stdin[1:]
                    print()
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
                    print("Source Filter: ", end="", flush=True)
                    tp.lock.acquire()
                    tp.filter_ip = ipaddress.ip_network("0.0.0.0/32")
                    tp.lock.release()
                    filter_ip = unbuffered_stdin.readline().strip().decode("utf-8")
                    tty.setcbreak(sys.stdin.fileno())
                    try:
                        assert filter_ip != ""
                        filter = ipaddress.ip_network(filter_ip)
                        tp.lock.acquire()
                        tp.filter_ip = filter
                        tp.lock.release()
                        # assert len(filter_ip.split("/")) == 2
                        # assert isinstance(int(filter_ip.split("/")[1]), int)
                    except AssertionError:
                        tp.lock.acquire()
                        tp.filter_ip = None
                        tp.lock.release()
                        print(tf.format("{msg:s,bg_yellow,black}", msg="[-] Filter clear"), file=sys.stderr)
                    except ValueError as e:
                        tp.lock.acquire()
                        tp.filter_ip = filter_ip
                        tp.lock.release()
                        print(tf.format("{msg:s,bg_red,black}",
                            msg="[-] Filter Error: Invalid IP Address / Network: %s, domain: %s" % (e, filter_ip)),
                            file=sys.stderr)
                elif queue_stdin[0] == b"d":
                    queue_stdin = queue_stdin[1:]
                    for n in range(g_parallel_process):
                        print("[+] Process %02d process: %d" % (n, g_worker_process_connections[n].value))
                else:
                    queue_stdin = queue_stdin[1:]

            if g_proxy_pending.value:
                g_proxy_pending.value = False
                sync_iprules("reload")
                install_proxy_chain_rules()

            if time.time() - t_iprule > 60:
                t_iprule = time.time()
                sync_iprules()

            if g_proxy_restart_all.value:
                g_proxy_restart_all.value = False
                if g_proxy_sup is not None:
                    print("[*] SIGUSR2: restarting all managed proxies")
                    try:
                        g_proxy_sup.restart_all()
                    except Exception as e:
                        print(tf.format("{msg:s,bg_red,black}", msg="[-] proxy restart_all failed: %s" % e))
                        syslog.syslog(syslog.LOG_CRIT, "proxy restart_all failed: %s" % e)
                else:
                    print("[*] SIGUSR2: no managed proxies (no 'daemon' fields in config)")

            if time.time() - t_dns_clean > 15:
                t_dns_clean = time.time()
                dns_list.clean()

            if time.time() - t_print > 0.25:
                t_print = time.time()

                if dns_proc is None or not dns_proc.is_alive():
                    dns_proc = DNSProcess(dns_list, term)
                    dns_proc.start()
                # if fcnat_listner is None or not fcnat_listner.is_alive():
                #     fcnat_listner = FullConeNAT_Listener()
                #     fcnat_listner.start()
                # if fcnat_cleaner is None or not fcnat_cleaner.is_alive():
                #     fcnat_cleaner = FullConeNAT_Cleaner()
                #     fcnat_cleaner.start()

                with timed_lock(g_io_lock, 1.0):

                    base_offset = len(" ALIVE: [🟩🟩")
                    if base_offset <= mouse_offset < base_offset + len(g_runner):
                        selected_proxy = None
                        print(tf.format("{msg:s,red,bold}", msg="ALIVE Process: %d" % (mouse_offset - base_offset)),
                              "            ")

                    base_offset += len(g_runner) + len("]  IPv4: [")
                    if base_offset <= mouse_offset < base_offset + len(g_proxy_index):
                        selected_proxy = g_proxy_index[(mouse_offset - base_offset)]
                        print(tf.format("{msg:s,red,bold}",
                                        msg="IPv4 Proxy: %s" % g_proxy_index[(mouse_offset - base_offset)]),
                              "            ")

                    base_offset += len(g_proxy_index) + len("]  IPv6: [")
                    if base_offset <= mouse_offset < base_offset + len(g_proxy_index):
                        selected_proxy = g_proxy_index[(mouse_offset - base_offset)]
                        print(tf.format("{msg:s,red,bold}",
                                        msg="IPv6 Proxy: %s" % g_proxy_index[(mouse_offset - base_offset)]),
                              "            ")

                    # error_msg = " " * 40
                    error_msg = "CPS: %-35s" % cps

                    if g_overload_flag.value:
                        error_msg = tf.format("{msg:s,bg_yellow,red} ",
                                              msg="Warning: Queue overloaded, working: %d" % g_running_process.value)

                    if g_cps_dup.value >= 20:
                        error_msg = tf.format("{msg:s,cyan} ", msg="Info: Print Cached Result overloaded")

                    if g_cps.value >= 50:
                        error_msg = tf.format("{msg:s,bg_cyan,red} ",
                                              msg="Info: Print Result overloaded")

                    print(" ALIVE: [%s%s%s]  IPv4: [%s]  IPv6: [%s]%s %s" % (
                        "🟧" if g_lock.locked() else "🟩",
                        "🟧" if g_running_process._lock._semlock._count() > 0 else "🟩",
                        "".join(["🔴" if g_runner[x].join(0) is None and not g_runner[x].is_alive() else (
                            "🟡" if g_working_flag[x].value else (
                                "🟢" if t_print - g_worker_last_active[x].value <= 30 else "🟩"))
                                 for x in range(len(g_runner))]),
                        "".join([time_to_level(g_dead_proxy_ipv4[g_proxy_index[x]].value, g_proxy_index[x]) for x in
                                 range(len(g_dead_proxy_ipv4.values()))]),
                        "".join([time_to_level(g_dead_proxy_ipv6[g_proxy_index[x]].value, g_proxy_index[x]) for x in
                                 range(len(g_dead_proxy_ipv6.values()))]),
                        "" if selected_proxy is None else " Proxy: %s" % (
                            tf.format("{proxy:s,cyan}", proxy=selected_proxy)),
                        error_msg), end="\r" if not g_overload_flag.value else "\n")

                    mouse_offset = 0

            now = time.time()
            if now - g_cps_reset.value >= 1:
                cps = g_cps.value
                with g_cps_reset.get_lock():
                    g_cps_reset.value = now
                with g_cps.get_lock():
                    g_cps.value = 0
                with g_cps_dup.get_lock():
                    g_cps_dup.value = 0

                if g_overload_flag.value:
                    g_overload_flag.value = False
                    # g_io_lock.acquire()
                    # print(tf.format("{msg:s,bg_yellow,red} Working: {working:d,yellow,bold} ",msg="Warning: Queue overloaded", working=g_running_process.value))
                    # g_io_lock.release()
        except KeyboardInterrupt:
            term.value = True
            if g_proxy_sup:
                g_proxy_sup.stop_all()   # before rules are cleared & master SIGKILLs itself
            clearRules()
            for run_p in g_runner:
                run_p.release_process()
            print("[*] system exit")
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
            os.kill(os.getpid(), signal.SIGKILL)
            break
        except RuntimeError:
            pass
        except Exception as e:
            print(tf.format("{msg:s,bg_red,black}", msg="[-] System Error: %s" % e), file=sys.stderr)
            print(''.join(traceback.format_tb(e.__traceback__)), file=sys.stderr)
            syslog.syslog(syslog.LOG_CRIT, "Main Process Error: %s\n  %s" % (
                    str(e), '  '.join(traceback.format_tb(e.__traceback__))))
