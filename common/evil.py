#!/usr/bin/env python3
# -*- utf8 -*-
# author=dave.fang@outlook.com
# create=20160410
import random

import gevent.pool
import gevent.monkey
from common.dns import *


class Evil(object):
    def __init__(self, dns, domain, ban_ip, threads):
        self.dns_list = dns
        self.ban_ip = ban_ip
        self.main_domain = domain
        self.threads = threads
        print('[*] Pan IP: %s' % ban_ip)

    def start(self):
        self.fuzz_top_level()
        print('[*] Done!')

    def fuzz_top_level(self):
        print('[*] TOP-LEVEL DOMAIN FUZZING...')
        file_handle = open("./dict/top-level.dict")
        content_dict = file_handle.read().split('\n')
        if content_dict[-1] == '':
            del content_dict[-1]
        pool = gevent.pool.Pool(self.threads)
        data = pool.map(self.get_ip, content_dict)
        pass

    def get_ip(self, sub_domain):
        if sub_domain == '' or sub_domain.startswith('.'):
            return
        sub_domain = sub_domain + '.' + self.main_domain
        dns_server = random.choice(self.dns_list)
        ip = find_ip_from_dns(dns_server, sub_domain)
        if ip != self.ban_ip and ip != []:
            print('[+] <Found> %s' % sub_domain)
