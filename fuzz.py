#!/usr/bin/env python
# -*- utf8 -*-
# author=dave
# creat=20150408

"""
* A Tool For Fuzzing Sub-domain.
* GitHub: https://github.com/Captain-D/FuzSub
* Version: 1.0
* SUPPORT TOP-LEVEL & SECOND-LEVEL
"""
import datetime
import sys
import socket
import os
import re
import requests
TOP_LEVEL = []


def start_fuzz(domain):
    global TOP_LEVEL
    print "[*] Target: %s" % domain
    fuzz_top_domain(domain)
    fuzz_second_domain()
    print "[*] Done!"


def fuzz_top_domain(domain):
    print "[*] TOP-LEVEL DOMAIN FUZZING..."
    file_handle = open("./dict/top-level.dict")
    content_dict = file_handle.read().split('\n')
    for i in xrange(len(content_dict)):
        sub_domain = content_dict[i] + '.' + domain
        dns_forward_query(sub_domain, True)
    print "[*] TOP-LEVEL DOMAIN FINISHED..."


def fuzz_second_domain():
    global TOP_LEVEL
    print "[*] SECOND-LEVEL DOMAIN FUZZING..."
    file_handle = open("./dict/second-level.dict")
    content_dict = file_handle.read().split('\n')
    for j in xrange(len(TOP_LEVEL)):
        for i in xrange(len(content_dict)):
            sub_domain = content_dict[i] + '.' + TOP_LEVEL[j]
            dns_forward_query(sub_domain, False)
    print "[*] SECOND-LEVEL DOMAIN FINISHED..."


def dns_forward_query(p_domain, top):
    global TOP_LEVEL
    try:
        result = socket.getaddrinfo(p_domain, None)
        print "[+] <Discovered> %s" % p_domain
        if top:
            TOP_LEVEL.append(p_domain)
        # For Debug
        '''
        counter = 0
        for item in result:
            # Print out the address tuple for each item
            print "%-2d: %s" % (counter, item[4])
            counter += 1
            '''
    except Exception, e:
        # print e
        pass


def dns_reserve_lookup(ip):
    try:
        result = socket.gethostbyaddr(ip)
        print "[+] Hostname is %s" % result[0]
    except Exception, e:
        print e


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