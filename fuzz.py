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
import multiprocessing
import random
import re
import requests
import os
import time
from common.output import *
TOP_LEVEL = []
THREADS_NUM = 10
DNS_LIST = ['223.5.5.5', '223.6.6.6', '180.76.76.76']

# TODO
# 1. use yield to optimize the memory usage
# 2. encapsulate this code to module


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
    try_count = 0
    while True:
        try:
            ip = find_ip_from_dns(dns_server, sub_domain)
            try_count = 0
            break
        except Exception, e:
            print "[-] Get Failed ! Regetting... Domain: %s" % sub_domain
            try_count += 1
            time.sleep(3)  # sleep 3 seconds to avoid network error.
    if ip != ban_ip and ip != []:
        print "[+] <Found> %s" % sub_domain
        output_add(sub_domain, ip, category, domain)
        if category == "TOP-LEVEL":
            TOP_LEVEL.append(sub_domain)


def start_fuzz(domain):
    global TOP_LEVEL, DNS_LIST
    print "[*] Target: %s" % domain
    output_init(domain)
    # file_handle = open("./dict/dns.dict")
    # DNS_LIST = file_handle.read().split('\n')
    # In Case it's Pan analytical
    ban_ip = get_ban_ip(random.choice(DNS_LIST), domain)
    print "[*] %s" % ban_ip
    '''
    while not ban_ip:
        ban_ip = get_ban_ip(random.choice(DNS_LIST), domain)
    '''
    fuzz_top_domain(domain, ban_ip)
    fuzz_second_domain(domain, ban_ip)
    print "[*] Done!"
    output_finished(domain)


def fuzz_top_domain(domain, ban_ip):
    print "[*] TOP-LEVEL DOMAIN FUZZING..."
    file_handle = open("./dict/top-level.dict")
    content_dict = file_handle.read().split('\n')
    jobs = []
    for i in xrange(len(content_dict)):
        sub_domain = content_dict[i] + '.' + domain
        # get_ip(sub_domain, ban_ip, "TOP-LEVEL", domain)
        p = multiprocessing.Process(target=get_ip, args=(sub_domain, ban_ip, 'TOP-LEVEL', domain))
        p.start()
        jobs.append(p)
    while sum([i.is_alive() for i in jobs]) != 0:
        pass
    for i in jobs:
        i.join()
    print "[*] TOP-LEVEL DOMAIN FINISHED..."


def fuzz_second_domain(domain, ban_ip):
    global TOP_LEVEL
    print "[*] SECOND-LEVEL DOMAIN FUZZING..."
    file_handle = open("./dict/second-level.dict")
    content_dict = file_handle.read().split('\n')
    jobs = []
    for j in xrange(len(TOP_LEVEL)):
        for i in xrange(len(content_dict)):
            sub_domain = content_dict[i] + '.' + TOP_LEVEL[j]
            # get_ip(sub_domain, ban_ip, "SECOND-LEVEL", domain)
            p = multiprocessing.Process(target=get_ip, args=(sub_domain, ban_ip, 'SECOND-LEVEL', domain))
            p.start()
            jobs.append(p)
    while sum([i.is_alive() for i in jobs]) != 0:
        pass
    for i in jobs:
        i.join()
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