#!/usr/bin/python3
import nftables
import json

nft = nftables.Nftables()
print(json.dumps(nft.json_cmd({"nftables": [{"list": {"ruleset": None}}]}), indent=4))