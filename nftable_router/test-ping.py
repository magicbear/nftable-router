#!/usr/bin/python3

import json
import os.path
import sys
import argparse
import subprocess
from pytput import TputFormatter
import ipdb
import socket

tf = TputFormatter()

parser = argparse.ArgumentParser(
    prog="test-ping",
    description="Multiple ping test",
)
parser.add_argument("ip")
parser.add_argument(
    "--file",
    "-f",
    help="Config file path",
)
args = parser.parse_args(sys.argv[1:])

file_path = ["nft_route.json", "/etc/network/nft_route.json"]
if args.file is not None:
    file_path.insert(0, args.file)

config = None
for file in file_path:
    if not os.path.exists(file):
        continue
    with open(file, "r", encoding="utf-8") as f:
        config = json.load(f)

db = ipdb.City(config['ipdb_v4'])
print("\n".join(["%30s: %s" % (tf.format("{k:s,cyan}", k=k), tf.format("{v:s,yellow}", v=v)) for k, v in
                 db.find_map(socket.gethostbyname(args.ip), "CN").items()]))

for n in range(len(config["proxy"])):
    proxy = list(config["proxy"].values())[n]
    # dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com
    dns_rc = subprocess.run(
        ["dig", "myip.opendns.com", "+short", "@resolver1.opendns.com", "+retry=1", "+timeout=1", "+dscp=%d" % (n + 1),
         "+tcp"],
        capture_output=True)
    print(tf.format("{msg:s,cyan}{line:s,yellow,bold}  Mark: {mark:d,green,bold}  IP: {ip:s,%s,bold}  Route: " % (
        "cyan" if dns_rc.returncode == 0 else "bg_red"
    ),
                    msg="[+] PING by Line : ",
                    ip=dns_rc.stdout.decode("utf-8").strip().split("\n")[
                        -1] if dns_rc.returncode == 0 else " CONNECTION ERROR ",
                    line=list(config["proxy"].keys())[n], mark=proxy['mark']),
          subprocess.run(["ip", "route", "show", "table", "%d" % proxy['mark']], capture_output=True).stdout.
          decode("utf-8").strip())
    if 'port' in proxy:
        continue
    p = subprocess.Popen(["ping", "-i", "0.3", "-c", "3", "-Q", "%d" % ((n + 1) << 2), args.ip], stdout=subprocess.PIPE)
    while p.poll() is None:
        read = p.stdout.readline()
        if read == b"":
            break
        line = read.decode("utf-8").strip()
        if line[0:5] == "PING " or line == "":
            continue
        print("  %s" % line)
    print()
