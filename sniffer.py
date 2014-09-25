# coding: utf8
import socket
import struct
import sys
import datetime
sys.path.append('./lib/')
import pymongo
from bson.binary import Binary
# https://docs.python.org/2/library/socket.html
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser
# 如果获取所有ip层数据包
s = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

host_name = socket.gethostname()
local_ip = socket.gethostbyname(host_name)
mongo_db = pymongo.MongoClient('mongodb://10.101.130.213/sniffer').sniffer
http_cache = {}

CONTROLL_FLAGS = ['FIN','SYN','RST','PSH','ACK','URG']
def get_cotroll_flags(flags):
    r = []
    for i in xrange(0, 6):
        if flags & 2**i != 0:
            r.append(CONTROLL_FLAGS[i])
    return ','.join(r)

while True:
    packet, address = s.recvfrom(65535)
    eth_header_len = 14
    eth_header = struct.unpack('!6s6sH', packet[:eth_header_len])
    eth_protocol = socket.ntohs(eth_header[2])
    # dest_mac = packet[:6]
    # src_mac = packet[6:12]

    # IP packets
    if eth_protocol != 8:
        continue
    # 20
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[eth_header_len:eth_header_len + 20])
    version = ip_header[0] >> 4
    ip_header_len = (ip_header[0] & 0xF) * 4
    ttl = ip_header[5]
    ip_protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])

    # TCP protocol
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |          Source Port          |       Destination Port        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Sequence Number                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Acknowledgment Number                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Data |           |U|A|P|R|S|F|                               |
    # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    # |       |           |G|K|H|T|N|N|                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |           Checksum            |         Urgent Pointer        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    if ip_protocol != 6:
        continue
    tcp_start = eth_header_len + ip_header_len
    tcp_header = struct.unpack('!HHLLBB3H', packet[tcp_start:tcp_start + 20])
    src_port = tcp_header[0]
    dest_port = tcp_header[1]
    # todo: 重组http协议
    #　对应请求的　acknowledgement
    sequence = tcp_header[2]
    # 重组使用
    acknowledgement = tcp_header[3]
    doff_reserved = tcp_header[4]
    controll_flags = tcp_header[5] & 63

    tcp_header_len = doff_reserved >> 4
    headers_size = eth_header_len + ip_header_len + tcp_header_len*4
    tcp_body = packet[headers_size:]

    # filter
    if not (src_port == 80 or dest_port == 80):
        continue
    try:
        tcp_body = str(tcp_body)
        data = {
            "raw_packet": Binary(packet),
            "tcp_packet_info": {
                "body": tcp_body,
                "sequence": sequence,
                "acknowledgement": acknowledgement,
                "doff_reserved": doff_reserved,
                "controll_flags": get_cotroll_flags(controll_flags)
            },
            "time": datetime.datetime.now(),
            "src": "%s:%s" % (src_ip, src_port),
            "dest": "%s:%s" % (dest_ip, dest_port),
            "host_ip": local_ip,
            "host_name": host_name
        }
        mongo_db.packet.save(data)
    except:
        continue
    # print 'got packet'
    # try:
    #     p.execute(packet, len(packet))
    #     print 'success'
    #     print p.recv_body()
    #     print p.get_headers()
    # except Exception as e:
    #     print e
    #     pass
