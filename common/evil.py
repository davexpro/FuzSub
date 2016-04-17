#!/usr/bin/env python3
# -*- utf8 -*-
# author=dave.fang@outlook.com
# create=20160410
import random
import dns.zone
import dns.query
import dns.resolver
import gevent.pool
import gevent.monkey
from common.dns import *


class Evil(object):
    def __init__(self, dns, domain, ban_ip, threads):
        self.dns_list = dns
        self.ban_ip = ban_ip
        self.main_domain = domain
        self.threads = threads
        self.name_servers = []
        self.zone_transfer = False
        gevent.monkey.patch_socket()
        print('[*] Pan IP: %s' % ban_ip)

    def start(self):
        self.get_ns_servers()
        self.axfr_check()
        if not self.zone_transfer:
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

    def get_ns_servers(self):
        while True:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10
                resolver.nameservers = self.dns_list
                answers = resolver.query(self.main_domain, "NS")
                if answers:
                    for answer in answers:
                        ns_one = str(answer)
                        self.name_servers.append(ns_one[0:-1])
                break
            except Exception as e:
                print(str(e))
                print("[-] %s Get NS Server ERROR" % self.main_domain)
        print('[+] Name Server: ' + str(self.name_servers))

    def axfr_check(self):
        for ns in self.name_servers:
            try:
                print('[*] Checking: ' + self.main_domain + ' NS: ' + ns)
                zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.main_domain, timeout=5, lifetime=10))
                if zone:
                    self.zone_transfer = True
                    print('[+] ' + self.main_domain + ' HAS THE ZONE TRANSFER BUG')
                    # get detail info
                    for name, node in zone.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            print("\t", name, rdataset)
                    # if there is then break
                    break
            except Exception as e:
                pass
