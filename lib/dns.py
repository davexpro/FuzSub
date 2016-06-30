#!/usr/bin/env python
# -*- utf8 -*-
# author=dave.fang@outlook.com
# create=20160410
# update=20160630
import re
import os
import sys
import socket
import binascii


def get_analysis_from_dns(dns_server, sub_domain):
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
            s.settimeout(8)
            s.sendto(data, (dns_server, 53))
            respond = s.recv(512)
            break
        except Exception as e:
            # print('[-] Error 01: {0}'.format(e))
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
    # Query Name
    try:
        if sys.version_info >= (3, 0):
            find = re.findall("^[\S]{26}[\S]{2}([\S]+?)0000010001", str(binascii.hexlify(respond)))
        else:
            find = re.findall("^[\S]{26}([\S]+?)0000010001", str(binascii.hexlify(respond)))
        query_name = ''
        for i in range(int(len(find[0]) / 2)):
            # print(chr(int(find[0][i*2:i*2+2], 16)), int(find[0][i*2:i*2+2], 16))
            if int(find[0][i * 2:i * 2 + 2], 16) < 16:
                query_name += '.'
            else:
                query_name += chr(int(find[0][i * 2:i * 2 + 2], 16))
    except Exception as e:
        print('[-] Query Name Error: {0} \n{1}'.format(str(e), find))
        pass

    # CNAME Record
    sub_cnames = []
    try:
        find = re.findall("c0[\S]{2}00050001[\S]{8}([\S]{4})", str(binascii.hexlify(respond)))
        if len(find) > 0:
            # for one_answer in find:
            one_answer = find[0]
            length = int(one_answer, 16) * 2
            find = re.findall("c0[\S]{2}00050001[\S]{8}[\S]{4}([\S]{%d})c0" % length, str(binascii.hexlify(respond)))
            offset = re.findall('c0([\S]{2})$', find[0])
            sub_cname = ''
            for_range = int(len(find[0]) / 2) - 1
            if len(offset) > 0:
                for_range -= 1
            for i in range(for_range):
                # print(chr(int(find[0][i*2:i*2+2], 16)), find[0][i*2:i*2+2])
                if 16 <= int(find[0][i * 2:i * 2 + 2], 16) < 32:
                    pass
                elif int(find[0][i * 2:i * 2 + 2], 16) < 16:
                    sub_cname += '.'
                else:
                    sub_cname += chr(int(find[0][i * 2:i * 2 + 2], 16))
            if len(offset) > 0:
                sub_cname += query_name[int(offset[0], 16) - 13:]
            while sub_cname[0] == '.':
                sub_cname = sub_cname[1:]
            sub_cnames.append(sub_cname)
    except Exception as e:
        print('[-] CNAME Error: {0} {1} {2}'.format(str(e), sub_domain, find))
        pass

    # A Record
    find = re.findall("c0[\S]{2}00010001[\S]{12}([\S]{8})", str(binascii.hexlify(respond)))
    for j in find:
        ip = str(int('0x' + j[0:2], 0)) + '.'
        ip += str(int('0x' + j[2:4], 0)) + '.'
        ip += str(int('0x' + j[4:6], 0)) + '.'
        ip += str(int('0x' + j[6:8], 0))
        ip_list.append(ip)
    ip_list.sort()

    return [sub_cnames, ip_list]
