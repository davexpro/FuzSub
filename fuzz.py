#!/usr/bin/env python3
# -*- utf8 -*-
# author=dave.fang@outlook.com
# create=20160410

"""
* A Tool For Fuzzing Sub-domain.
* GitHub: https://github.com/DavexPro/FuzSub
* Version: 1.1
* SUPPORT TOP-LEVEL
"""
import random
import sys
import datetime
from common.dns import *
from common.evil import Evil

DNS_LIST = ['8.8.8.8']
THREAD_BRUTE = 30


def get_pan_ip(dns, domain):
    """
    :param dns: DNS服务器
    :param domain: 顶级域名
    :return: 泛解析IP
    """
    ban_ip = find_ip_from_dns(dns, '500accfde65a0c66c2415017ca8104a6.' + domain)
    return ban_ip


def start_fuzz(domain):
    print('[*] Target: %s' % domain)
    ban_ip = get_pan_ip(random.choice(DNS_LIST), domain)
    evil = Evil(DNS_LIST, domain, ban_ip, THREAD_BRUTE)
    evil.start()


if __name__ == '__main__':
    start_time = datetime.datetime.now()
    print('[*] FuzSub is hot.')
    if len(sys.argv) != 2:
        print('[-] E.g. python3 fuzz.py foo.com')
    else:
        fuzz_domain = sys.argv[1]
        print('[+] <Found> ' + fuzz_domain + ' ' + str(find_ip_from_dns('8.8.8.8', fuzz_domain)))
        start_fuzz(fuzz_domain)
    end_time = datetime.datetime.now()
    print('[*] Total Time Consumption: ' + \
          str((end_time - start_time).seconds) + 's')
