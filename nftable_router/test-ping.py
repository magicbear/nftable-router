#!/usr/bin/python3

import json
import os.path
import sys
import argparse
import subprocess
from pytput import TputFormatter

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

for n in range(len(config["proxy"])):
    proxy = list(config["proxy"].values())[n]
    if 'port' in proxy:
        continue
    print(tf.format("{msg:s,cyan}{line:s,yellow,bold}  Mark: {mark:d,green,bold,bold}  Route: ", msg="[+] PING by Line : ",
                    line=list(config["proxy"].keys())[n], mark=proxy['mark']),
          subprocess.run(["ip", "route", "show", "table", "%d" % proxy['mark']], capture_output=True).stdout.
          decode("utf-8").strip())
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
