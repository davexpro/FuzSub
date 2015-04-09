#!/usr/bin/env python
# -*- utf8 -*-
# author=dave
# create=20150408

"""
* A Tool For Fuzzing Sub-domain.
* GitHub: https://github.com/Captain-D/FuzSub
* Version: 1.0
* SUPPORT TOP-LEVEL & SECOND-LEVEL
"""
import datetime
import sys
import socket
import threadpool as tp
import random
import re
import requests
import os
from common.output import *
TOP_LEVEL = []
THREADS_NUM = 10
DNS_LIST = []


def get_ban_ip(dns, domain):
    # In Case it's Pan analytical
    ban_ip = 'time out'
    while ban_ip == 'time out':
        try:
            ban_ip = find_ip_from_dns(dns, 'an9xm02d.' + domain)
        except Exception, e:
            ban_ip = 'time out'
    return ban_ip


def find_ip_from_dns(dns_server, sub_domain):
    # Core Content
    host = ''
    for i in sub_domain.split('.'):
        host += chr(len(i))+i
    index = os.urandom(2)
    data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (index, host)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(15)
    s.sendto(data, (dns_server, 53))
    respond = s.recv(512)
    ip_list = []
    for j in re.findall("\xC0[\s\S]\x00\x01\x00\x01[\s\S]{6}([\s\S]{4})", respond):
        ip = '.'.join(str(ord(ii)) for ii in j)
        ip_list.append(ip)
    ip_list.sort()
    return ip_list


def get_ip(sub_domain, ban_ip, category, domain):
    # Use Method find_ip_from_dns to Fetch ip
    global DNS_LIST, TOP_LEVEL
    dns_server = random.choice(DNS_LIST)
    try:
        ip = find_ip_from_dns(dns_server, sub_domain)
        if ip != ban_ip and ip != []:
            print "[+] <Found> %s" % sub_domain
            output_add(sub_domain, ip, category, domain)
            if category == "TOP-LEVEL":
                TOP_LEVEL.append(sub_domain)
            # print "[+] <Found> %s %s" % (sub_domain, ip)
            # dns_server, sub_domain, ip
    except Exception, e:
        print "[-] Error.get_ip Domain: %s Detail: %s" % (sub_domain, e)
        pass


def start_fuzz(domain):
    global TOP_LEVEL, DNS_LIST
    print "[*] Target: %s" % domain
    output_init(domain)
    file_handle = open("./dict/dns.dict")
    DNS_LIST = file_handle.read().split('\n')
    # In Case it's Pan analytical
    dns = random.choice(DNS_LIST)
    ban_ip = get_ban_ip(dns, domain)
    while not ban_ip:
        ban_ip = get_ban_ip(dns, domain)
    fuzz_top_domain(domain, ban_ip)
    fuzz_second_domain(domain, ban_ip)
    print "[*] Done!"
    output_finished(domain)


def fuzz_top_domain(domain, ban_ip):
    print "[*] TOP-LEVEL DOMAIN FUZZING..."
    file_handle = open("./dict/top-level.dict")
    content_dict = file_handle.read().split('\n')
    for i in xrange(len(content_dict)):
        sub_domain = content_dict[i] + '.' + domain
        get_ip(sub_domain, ban_ip, "TOP-LEVEL", domain)
    print "[*] TOP-LEVEL DOMAIN FINISHED..."


def fuzz_second_domain(domain, ban_ip):
    global TOP_LEVEL
    print "[*] SECOND-LEVEL DOMAIN FUZZING..."
    file_handle = open("./dict/second-level.dict")
    content_dict = file_handle.read().split('\n')
    for j in xrange(len(TOP_LEVEL)):
        for i in xrange(len(content_dict)):
            sub_domain = content_dict[i] + '.' + TOP_LEVEL[j]
            get_ip(sub_domain, ban_ip, "SECOND-LEVEL", domain)
    print "[*] SECOND-LEVEL DOMAIN FINISHED..."


def domain_verify(doamin):
    full_domain = "http://%s" % doamin
    try:
        status = requests.get(full_domain, timeout=3).status_code
        print "[+] <[%s]> %s" % (status, full_domain)
    except Exception, e:
        # Something to check whether the network problem
        pass


if __name__ == "__main__":
    start_time = datetime.datetime.now()
    print "[*] FuzSub is hot."
    if len(sys.argv) == 1:
        print "[-] Error! You should input the domain you want to Fuzz."
        print "[-] E.g. python fuzz.py foo.com"
    else:
        domain = sys.argv[1]
        # domain = "qq.com"
        start_fuzz(domain)
    end_time = datetime.datetime.now()
    print '[*] Total Time Consumption: ' + str((end_time - start_time).seconds) + 's'