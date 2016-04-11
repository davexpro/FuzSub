#!/usr/bin/env python3
# -*- utf8 -*-
# author=dave.fang@outlook.com
# create=20160410
import re
import os
import socket

import binascii


def find_ip_from_dns(dns_server, sub_domain):
    # Core Content
    host = ''
    for i in sub_domain.split('.'):
        host += chr(len(i)) + i
    data = os.urandom(2)
    data += bytearray([0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    data += bytes(host.encode('utf-8'))
    data += bytearray([0x00, 0x00, 0x01, 0x00, 0x01])
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(10)
            s.sendto(data, (dns_server, 53))
            respond = s.recv(512)
            break
        except Exception as e:
            print('[-] Error 01: ' + str(e))
            pass
    # print(str(binascii.hexlify(respond)))
    ip_list = []
    """
    0000   6c 71 d9 82 3d 8c 00 fc 8d fe f4 42 08 00 45 00  lq..=......B..E.
    0010   00 54 6c 1e 00 00 31 11 4c b5 08 08 08 08 c0 a8  .Tl...1.L.......
    0020   00 0e 00 35 d7 6a 00 40 fa f0 c9 dc 81 80 00 01  ...5.j.@........
    0030   00 02 00 00 00 00 02 71 71 03 63 6f 6d 00 00 01  .......qq.com...
    0040   00 01 c0 0c 00 01 00 01 00 00 01 f7 00 04 7d 27  ..............}'
    0050   f0 71 c0 0c 00 01 00 01 00 00 01 f7 00 04 3d 87  .q............=.
    0060   9d 9c

    827107	3104.302029	8.8.8.8	192.168.0.14
    DNS	98	Standard query response 0xc9dc A qq.com A 125.39.240.113 A 61.135.157.156..
                                                      7d.27               3d.87.9d.9c
    """
    find = re.findall("c0[\S]{2}00010001[\S]{12}([\S]{8})", str(binascii.hexlify(respond)))
    # print(find)
    for j in find:
        ip = str(int('0x' + j[0:2], 0)) + '.'
        ip += str(int('0x' + j[2:4], 0)) + '.'
        ip += str(int('0x' + j[4:6], 0)) + '.'
        ip += str(int('0x' + j[6:8], 0))
        ip_list.append(ip)
    ip_list.sort()
    return ip_list
