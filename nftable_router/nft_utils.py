import nftables


class nftUtils():
    def __init__(self):
        self.nft = nftables.Nftables()

    def get_tables(self):
        rc = self.nft.json_cmd({"nftables": [{"list": {"tables": None}}]})
        if rc[0] != 0:
            raise Exception("Cannot execute nft command")
            return {}
        tables = rc[1]['nftables']
        tbls = {}
        for i in range(0, len(tables)):
            if "table" in tables[i]:
                if tables[i]['table']['family'] not in tbls:
                    tbls[tables[i]['table']['family']] = {}
                tbls[tables[i]['table']['family']][tables[i]['table']['name']] = tables[i]['table']
        return tbls

    def get_rules(self, table=None, chain=None, family="ip"):
        rules = []
        ruleset_result = self.nft.json_cmd({"nftables": [{"list": {"ruleset": None}}]})
        if ruleset_result[0] != 0:
            return []
        ruleset = ruleset_result[1]['nftables']
        for i in range(0, len(ruleset)):
            if "rule" in ruleset[i]:
                matched = True
                if table is not None and ruleset[i]['rule']['table'] != table:
                    matched = False
                if chain is not None and ruleset[i]['rule']['chain'] != chain:
                    matched = False
                if family is not None and ruleset[i]['rule']['family'] != family:
                    matched = False

                if matched:
                    rules.append(ruleset[i]['rule'])

        return rules

    def delete_rules(self, table=None, chain=None, comment=None, match=None, family="ip"):
        # print("[-] delete rule %s:%s -> %s" % (family, table, chain))
        n = 0
        rules = self.get_rules(table, chain, family)
        for r in rules:
            matched = True
            if comment is not None and ('comment' in r and r['comment'] != comment):
                matched = False
            if comment is not None and 'comment' not in r:
                matched = False
            if match is not None and match not in r['expr']:
                matched = False
            if matched:
                self.nft.json_cmd({"nftables": [{"delete": {
                    "rule": {"family": r['family'], "table": r['table'], "chain": r['chain'],
                             "handle": r['handle']}}}]})
                n += 1

        return n

    """
    params = {
        'chain': 'OUTPUT',
        'comment': '**AUTOGEN BY Test**',
        'expr': [{'match': {'left': {'payload': {'field': 'dport', 'protocol': 'tcp'}},
                            'op': '==',
                            'right': 12678}},
                 {'queue': {'num': 2233}}],
        'family': 'ip',
        'table': 'nat'}
         }
    """

    def add_rule(self, params):
        # print("[+] add rule ", params)
        if type(params['chain']) is list:
            rc = []
            chains = params['chain']
            for i in range(0, len(chains)):
                v_params = params
                v_params['chain'] = chains[i]
                rc.append(self.nft.json_cmd({"nftables": [{"add": {"rule": v_params}}]}))

            return rc
        else:
            return self.nft.json_cmd({"nftables": [{"add": {"rule": params}}]})

    def replace_rule(self, params):
        # print("[-] replace rule")
        if type(params['chain']) is list:
            rc = []
            chains = params['chain']
            for i in range(0, len(chains)):
                v_params = params
                v_params['chain'] = chains[i]
                rc.append(self.nft.json_cmd({"nftables": [{"replace": {"rule": v_params}}]}))

            return rc
        else:
            return self.nft.json_cmd({"nftables": [{"replace": {"rule": params}}]})

    """
    type, is obligatory and determines the data type of the set elements. Supported data types currently are:
    ipv4_addr: IPv4 address
    ipv6_addr: IPv6 address.
    ether_addr: Ethernet address.
    inet_proto: Inet protocol type.
    inet_service: Internet service (read tcp port for example)
    mark: Mark type.
    ifname: Network interface name (eth0, eth1..)
    """

    def add_set(self, name, set_type, table='filter', family="ip"):
        return self.nft.json_cmd({"nftables": [{"add": {"set": {
            'name': name,
            'table': table,
            'family': family,
            'type': set_type,
            'flags': ['interval']
        }}}]})

    def delete_set(self, name, table, family="ip"):
        # print("[-] delete set %s %s %s" % (family, name, table))
        return self.nft.json_cmd({"nftables": [{"delete": {"set": {'name': name, 'table': table, 'family': family}}}]})

    def add_set_element(self, name, element, table='filter', family="ip"):
        return self.nft.json_cmd({"nftables": [{"add": {"element": {
            'name': name,
            'table': table,
            'family': family,
            'elem': element
        }}}]})

    def add_set_interface(self, name, element, table='filter', family="ip"):
        return self.nft.json_cmd({"nftables": [{"add": {"element": {
            'name': name,
            'table': table,
            'family': family,
            'elem': element
        }}}]})

    def delete_set_element(self, name, element, table='filter', family="ip"):
        # print("[-] delete set elements %s %s %s -> %s" % (family, name, table, element))
        return self.nft.json_cmd({"nftables": [{"delete": {"element": {
            'name': name,
            'table': table,
            'family': family,
            'elem': element
        }}}]})

    """
    params = {
        "family": "inet",
        "name": "c"
    }
    """

    def add_table(self, name, family="ip"):
        return self.nft.json_cmd({"nftables": [{"add": {"table": {"name": name, "family": family}}}]})

    def delete_table(self, name, handle=None, family="ip"):
        if handle is None:
            tbls = self.get_tables()
            if family not in tbls:
                return False
            if name not in tbls[family]:
                return False
            handle = tbls[family][name]['handle']
        return self.nft.json_cmd(
            {"nftables": [{"delete": {"table": {"family": family, "name": name, "handle": handle}}}]})

    """
    params = {
        "family": "inet",
        "table": "t",
        "name": "c",
        "type": "",
        "hook": "",
        "prio": 0,
        "policy": 'accept'
    }
    """

    def add_chain(self, params):
        return self.nft.json_cmd({"nftables": [{"add": {"chain": params}}]})

    """
    params = {
        "family": "inet",
        "table": "t",
        "name": "c"
    }
    """

    def delete_chain(self, params):
        return self.nft.json_cmd({"nftables": [{"delete": {"chain": params}}]})

    def cidr(self, addr, mask):
        return {'prefix': {'addr': addr, 'len': mask}}

    """
    payload => {'set': [12345, {'range': [33334,33335]}]}}
    """

    def match_payload(self, field, right, protocol='ip', op='=='):
        return {'left': {'payload': {'field': field, 'protocol': protocol}},
                'op': op,
                'right': right}

    def match_mark(self, mark, op='=='):
        return {'left': {'meta': {'key': 'mark'}},
                'op': op,
                'right': mark}

    def match_iif(self, mark, op='=='):
        return {'left': {'meta': {'key': 'iif'}},
                'op': op,
                'right': mark}

    def match_iifname(self, mark, op='=='):
        return {'left': {'meta': {'key': 'iifname'}},
                'op': op,
                'right': mark}

    def match_ct_mark(self, mark, op='=='):
        return {'left': {'ct': {'key': 'mark'}},
                'op': op,
                'right': mark}

    def match_ct(self, val, op='==', key='state'):
        return {'left': {'ct': {'key': key}},
                'op': op,
                'right': val}

    def match_l4proto(self, protocol, op='=='):
        return {'left': {'meta': {'key': 'l4proto'}},
                'op': op,
                'right': protocol}

    def match_syn(self):
        return {"op": "==",
                "left": {
                    "&": [
                        {"payload": {"protocol": "tcp", "field": "flags"}},
                        {"|": ["syn", "rst"]}
                    ]
                },
                "right": "syn"}
