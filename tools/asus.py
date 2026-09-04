import logging
import time
import json
import sys
import io
import getopt
import pathlib
import threading
# import redis
import traceback
import requests
import base64, urllib
import redis

log_handler = logging.StreamHandler(sys.stderr)
log_handler.setLevel(logging.DEBUG)
logging.getLogger().addHandler(log_handler)

try:
    opts, _ = getopt.getopt(sys.argv[1:], "i:u:p:", ["ip=", "user=", "password="])
except getopt.GetoptError:
    sys.exit(2)
for opt, arg in opts:
    if opt in ["-i", "--ip"]:
        asusIP = arg
    if opt in ["-u", "--user"]:
        asusUser = arg
    if opt in ["-p", "--password"]:
        asusPasswd = arg

authURL = 'http://{}/login.cgi'.format(asusIP)
onboardURL = 'http://{}/ajax_onboarding.asp'.format(asusIP)
tempURL = 'http://{}/ajax_coretmp.asp'.format(asusIP)
statusURL = 'http://{}/cpu_ram_status.xml'.format(asusIP)
# http://192.168.10.1/ajax_onboarding.asp

asusAuth = base64.b64encode('{}:{}'.format(asusUser, asusPasswd).encode())
asusAuthEncode = urllib.parse.quote(asusAuth)

sessions = requests.Session()

authPayload = 'group_id=&action_mode=&action_script=&action_wait=5&current_page=Main_Login.asp&next_page=ajax_onboarding.asp&login_authorization={}&login_captcha='.format(asusAuthEncode)
authHeaders = {
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36',
  'Content-Type': 'application/x-www-form-urlencoded',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
  'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7',
  'Cache-Control': 'max-age=0',
  'Connection': 'keep-alive',
  'Content-Length': '154',
  'host': '{}'.format(asusIP),
  'referer': 'http://{}/Main_Login.asp'.format(asusIP)
}

dataHeaders = {
  'Cookie': '',
  'Cache-Control': 'max-age=0',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
  'Accept-Encoding': 'gzip, deflate',
  'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7,zh-TW;q=0.6',
  'Upgrade-Insecure-Requests': '1',
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36'
}

# 获取 token
def getAuth():
    global token
    # ignore tls warning
    requests.packages.urllib3.disable_warnings()

    login_session = sessions.post(authURL, headers=authHeaders, data=authPayload, verify=False)
    token = sessions.cookies.get_dict()['asus_token']
    # print(token)
    logging.info('New Token: {}'.format(token))
    return token

# 获取数据
def getData(token):
    # ignore tls warning
    # requests.packages.urllib3.disable_warnings()

    # cookie
    dataHeaders['Cookie'] = 'clickedItem_tab=0; asus_token=' + token
    speedResponse1 = sessions.get(onboardURL, headers=dataHeaders, verify=False)
    in_list = False
    list_data = ""
    # print(speedResponse1.text)
    # print()

    r = redis.Redis(host='192.168.9.1', port=6379, db=1)

    device_mapping = {}
    for line in speedResponse1.text.split("\n"):
        if line[0:20] == "get_allclientlist = ":
            in_list = "get_allclientlist"
            line = line[20:]
        if line[0:21] == "get_cfg_clientlist = ":
            in_list = "get_cfg_clientlist"
            line = line[21:]

        if in_list and line[-5:] == "][0];":
            list_data += line[:-4]
            list = json.loads(list_data)[0]
            if in_list == "get_cfg_clientlist":
                for ele in list:
                    if ele['alias'] == ele['mac']:
                        ele['alias'] = ele['model_name']
                    device_mapping[ele['mac']] = ele
            elif in_list == "get_allclientlist":
                for mac in list:
                    for wlan_channel in list[mac]:
                        for ele_mac in list[mac][wlan_channel]:
                            ele = list[mac][wlan_channel][ele_mac]
                            map_data = json.dumps({
                                'ip': ele['ip'],
                                'mac': ele_mac,
                                'sysname': device_mapping[mac]['alias'],
                                "ifName_L3": device_mapping[mac]['alias']
                            })
                            mac_record = json.dumps({
                                "ifName": device_mapping[mac]['alias'],
                                "ifDescr": wlan_channel
                            })
                            r.hset("MAC::TABLE::"+device_mapping[mac]['alias'], ele_mac, mac_record)
                            r.hset("ARP::MAPPING::"+device_mapping[mac]['alias'], ele['ip'], map_data)
                            r.hset("ARP::MAPPING", ele['ip'], map_data)
            in_list = False
            list_data = ""

            # print(json.dumps(device_mapping, indent=2))
        elif in_list:
            list_data += line

# token = "w1ATWszq7DK3gkENAlbuBDtSbN8wFCg"

class ioThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.r = redis.Redis(host='127.0.0.1', port=6379, db=1)

    def run(self):
        lastCheck = 0
        while True:
            if time.time() - lastCheck >= 300:
                lastCheck = time.time()
                try:
                    token = getAuth()
                    print(token)
                    print(getData(token))
                except Exception as e:
                    pass
            else:
                time.sleep(1)

cmdThread = ioThread()
cmdThread.start()
cmdThread.join()
