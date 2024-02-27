import socket
from struct import *
import time

class ICMP_TTL_TIMEOUT_Builder:
    @staticmethod
    def checksum(source_string):
        # I'm not too confident that this is right but testing seems to
        # suggest that it gives the same answers as in_cksum in ping.c.
        sum = 0
        count_to = (len(source_string) / 2) * 2
        count = 0
        while count < count_to:
            if count + 1 < len(source_string):
                this_val = source_string[count + 1] * 256 + source_string[count]
            else:
                this_val = source_string[count]
            sum = sum + this_val
            sum = sum & 0xffffffff  # Necessary?
            count = count + 2

        if count_to < len(source_string):
            sum = sum + source_string[len(source_string) - 1]
            sum = sum & 0xffffffff  # Necessary?
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        # Swap bytes. Bugger me if I know why.
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer


    @staticmethod
    def icmp(payload):
        global icmp_p
        type = 11
        code = 0
        cs = 0
        unuse = 0x0000
        icmp_p = pack("!BBHL", type, code, cs, unuse) + payload if payload is not None else b""
        cs = ICMP_TTL_TIMEOUT_Builder.checksum(icmp_p)
        icmp_p = pack("!BBHL", type, code, cs, unuse) + payload if payload is not None else b""
        return icmp_p

    @staticmethod
    def ip_header(src, dst, ip_tot_len):
        global ip_p
        ip_ihl = 5      # Header Length = 20 bytes
        ip_ver = 4      # IPv4
        ip_tos = 0xc0
        ip_id = 28651
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_ICMP
        ip_check = 0
        ip_saddr = socket.inet_aton(src)
        ip_daddr = socket.inet_aton(dst)
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        ip_p = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, 0,
                    ip_saddr, ip_daddr)
        ip_check = ICMP_TTL_TIMEOUT_Builder.checksum(ip_p)
        ip_p = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
                    ip_saddr, ip_daddr)
        # print(" ".join(["%02x" % x for x in ip_p]))
        return ip_p

    @staticmethod
    def packet(src, dst, payload = None):
        icmp_packet = ICMP_TTL_TIMEOUT_Builder.icmp(payload)
        return ICMP_TTL_TIMEOUT_Builder.ip_header(src, dst, len(icmp_packet)) + icmp_packet

# print(ICMP_TTL_TIMEOUT_Builder.packet())
#
# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#
# while True:
#     time.sleep(.1)
#     s.sendto(packet, ("192.168.1.3", 80))
