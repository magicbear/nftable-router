import threading
import time
from multiprocessing import Process
import signal
import redis
from .nft_utils import nftUtils
from datetime import datetime
import traceback

def add_fullcone_nat(nfu, ip_version, proto, ip, sport):
    dnat_params = {'family': 'ip' if ip_version == 4 else 'ip6', 'chain': ['nat_FULLCONE'], 'table': 'policy_route',
                   'comment': cmt_class,
                   'expr': [{'match': nfu.match_payload('dport', sport, protocol=proto)},
                            {'match': nfu.match_iifname({'set': nat_interfaces}, op='!=')},
                            {'counter': {'bytes': 0, 'packets': 0}},
                            # {'mangle': {'key': {'meta': {'key': 'mark'}},'value': 0x241}},
                            # {'mangle': {'key': {'ct': {'key': 'mark'}}, 'value': {'meta': {'key': 'mark'}}}},
                            {'dnat': {'addr': ip}}]
                   }

    #
    # n = 0
    has_rules = False
    rules = nfu.get_rules("policy_route", "nat_FULLCONE", 'ip' if ip_version == 4 else 'ip6')
    for r in rules:
        rep_obj = None
        if {'dnat': {'addr': ip}} in r['expr']:
            for expr in r['expr']:
                if 'match' in expr and expr['match']['left'] == {'payload': {'field': 'dport', 'protocol': proto}}:
                    if not isinstance(dnat_params['expr'][0]['match']['right'], dict):
                        dnat_params['expr'][0]['match']['right'] = {'set': [sport]}
                    if isinstance(expr['match']['right'], dict):
                        if 'set' in expr['match']['right']:
                            for port in expr['match']['right']['set']:
                                dnat_params['expr'][0]['match']['right']['set'].append(port)
                    else:
                        dnat_params['expr'][0]['match']['right']['set'].append(expr['match']['right'])

                    dnat_params['handle'] = r['handle']
            nfu.replace_rule(dnat_params)
            has_rules = True

    if not has_rules:
        nrc = nfu.add_rule(dnat_params)
        if functools.reduce(lambda a, b: a | b, [add_rule_rc[0] for add_rule_rc in nrc]):
            print("[-] %s" % tf.format("{msg:s,bg_red,white,bold}", msg="add rule nat_FULLCONE failed: %s" % (nrc)))


def del_fullcone_nat(nfu, ip):
    n = 0
    rules = nfu.get_rules("policy_route", "nat_FULLCONE", "ip")
    for r in rules:
        if {'dnat': {'addr': ip}} in r['expr'] or {'match': nfu.match_payload('saddr', ip, protocol='ip')} in r['expr']:
            nfu.nft.json_cmd({"nftables": [{"delete": {
                "rule": {"family": "ip", "table": "policy_route", "chain": "nat_FULLCONE", "handle": r['handle']}}}]})

class FullConeNAT_Listener(Process):
    def __init__(self, term):
        super().__init__()
        self.process_term = False
        self.term = term
        self.r = None

    @staticmethod
    def quit(signum, sigframe):
        self.term.value = True

    def run(self):
        signal.signal(signal.SIGTERM, self.quit)
        signal.signal(signal.SIGQUIT, self.quit)

        nfu = nftUtils()
        last_check = 0
        prctl.set_proctitle("Policy Route - Full Cone NAT Actor")
        while not self.term.value:
            try:
                if self.r is None:
                    self.r = redis.Redis(host='127.0.0.1', port=6379, db=1)
                    sub = self.r.pubsub()
                sub.subscribe('fullcone_nat')
                for message in sub.listen():
                    if isinstance(message.get('data'), bytes):
                        if term.value:
                            break
                        nat_data = json.loads(message.get('data').decode('utf-8'))
                        add_fullcone_nat(nfu, nat_data['ver'], 'udp' if nat_data['proto'] == 17 else 'tcp',
                                         nat_data['src'], nat_data['sport'])
                    if time.time() - last_check >= 300:
                        last_check = time.time()
                        process = psutil.Process(os.getpid())
                        with open("nft_route.log", "a+") as f:
                            f.write("%s: FullConeNAT_Listener Process Memory Usage: %d\n" % (
                                datetime.now().isoformat(), process.memory_info().rss))
                        if process.memory_info().rss >= 1048576 * 1024:
                            raise MemoryError("Memory overload")
                            break
            except MemoryError:
                break
            except Exception as e:
                print(tf.format("{msg:s,bg_red,black}", msg="[-] FullConeNAT_Listener Thread Error: %s" % e))
                with open("nft_route.log", "a+") as f:
                    f.write("%s: FullConeNAT_Listener Process Error: %s\n  %s\n" % (
                        datetime.now().isoformat(), str(e), '  '.join(traceback.format_tb(e.__traceback__))))
                self.r = None
                time.sleep(1)


class FullConeNAT_Worker(Process):
    def __init__(self, term):
        super().__init__()
        self.process_term = False
        self.term = term
        self.r = None

    @staticmethod
    def quit(signum, sigframe):
        self.process_term = True

    # 为线程定义一个函数
    def run(self):
        signal.signal(signal.SIGTERM, self.quit)
        signal.signal(signal.SIGQUIT, self.quit)
        nfu = nftUtils()
        prctl.set_proctitle("Policy Route - Full Cone NAT Cleaner")
        self.r = redis.Redis(host='127.0.0.1', port=6379, db=1)
        nat_table = self.r.get("fullcone_nat_table")
        if nat_table is None:
            counter_cache = {}
        else:
            counter_cache = json.loads(nat_table)
        now = time.time()
        checked_ip = []
        for nfu_table in ['ip', 'ip6']:
            rules = nfu.get_rules("policy_route", "nat_FULLCONE", nfu_table)
            for r in rules:
                addr = None
                counter = None
                dport = None
                for expr in r['expr']:
                    if 'counter' in expr:
                        counter = expr['counter']
                    if 'dnat' in expr:
                        addr = expr['dnat']['addr']
                    if 'match' in expr and expr['match']['left'] == {'payload': {'field': 'dport', 'protocol': 'udp'}}:
                        if isinstance(expr['match']['right'], dict):
                            dport = ",".join([str(x) for x in expr['match']['right']['set']])
                        else:
                            dport = str(expr['match']['right'])

                if addr is not None and counter is not None:
                    checked_ip.append(addr)
                    if addr not in counter_cache:
                        counter_cache[addr] = {'counter': counter, 'last_check': now, 'dport': dport}
                    else:
                        if (counter_cache[addr]['counter']['packets'] != counter['packets'] or
                                counter_cache[addr]['dport'] != dport):
                            counter_cache[addr]['counter'] = counter
                            counter_cache[addr]['dport'] = dport
                            counter_cache[addr]['last_check'] = now
                        elif now - counter_cache[addr]['last_check'] >= 60:
                            nfu.nft.json_cmd({"nftables": [{"delete": {
                                "rule": {"family": nfu_table, "table": "policy_route", "chain": "nat_FULLCONE",
                                         "handle": r['handle']}}}]})
                            del counter_cache[addr]

        delete_list = []
        for addr in counter_cache:
            if addr not in checked_ip:
                delete_list.append(addr)

        for addr in delete_list:
            del counter_cache[addr]

        self.r.set("fullcone_nat_table", json.dumps(counter_cache))
