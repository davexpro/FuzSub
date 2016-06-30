#!/usr/bin/env python3
# -*- utf8 -*-
# author=dave.fang@outlook.com
# create=20160410
import queue
import random
import gevent.pool
import gevent.monkey

from lib.dnspython import zone
from lib.dnspython import query
from lib.dnspython import resolver
from config import DNS_LIST, IGNORE_DNS_LIST, THREAD_BRUTE, BASE_DIR, MAX_TRY_COUNT
from lib.decorator import max_try_wrapper
from lib.dns import get_analysis_from_dns


class Evil(object):
    def __init__(self, domain, depth=1):
        self.main_domain = domain
        self.current_domain = domain
        self.depth = depth
        self.name_servers = []
        self.pan_analysis = []
        self.domain_queue = queue.Queue()
        self.domain_queue.put(domain)
        self.zone_transfer = False
        self.pool = gevent.pool.Pool(THREAD_BRUTE)
        gevent.monkey.patch_socket()

    def start(self):
        file_handle = open('{0}/output/{1}.txt'.format(BASE_DIR, self.main_domain), 'w')
        file_handle.close()
        self.get_ns_servers()
        self.axfr_check()
        if not self.zone_transfer:
            while not self.domain_queue.empty():
                self.current_domain = self.domain_queue.get()
                self.fuzz_domain_level()
        print('[*] Done!')

    @max_try_wrapper
    def get_pan_analyse(self, domain):
        for i in range(MAX_TRY_COUNT):
            if self.pan_analysis != [] and self.pan_analysis != [[], []]:
                break
            self.pan_analysis = get_analysis_from_dns(random.choice(DNS_LIST), '*.{0}'.format(domain))
            file_handle = open('{0}/output/{1}.txt'.format(BASE_DIR, self.main_domain), 'a')
            file_handle.write('{0}\t{1}\t{2}\n'.
                              format('*.{0}'.format(domain), self.pan_analysis[0], self.pan_analysis[1]))
            file_handle.close()

    def fuzz_domain_level(self):
        print('[*] < {0} > FUZZING...'.format(self.current_domain))
        self.get_pan_analyse(self.current_domain)
        print('[*] Pan Analysis: {0}'.format(str(self.pan_analysis)))
        file_handle = open("./dict/all-level.dict")
        content_dict = file_handle.read().split('\n')
        if content_dict[-1] == '':
            del content_dict[-1]
        self.pool.map(self.get_analysis, content_dict)

    def get_analysis(self, sub_domain):
        if sub_domain == '' or sub_domain.startswith('.'):
            return
        sub_domain = '{0}.{1}'.format(sub_domain, self.current_domain)
        analysis = get_analysis_from_dns(random.choice(DNS_LIST), sub_domain)
        if not analysis[1] or analysis[1] == self.pan_analysis[1]:
            return
        if analysis[0] != [] and analysis[0] == self.pan_analysis[0]:
            return
        file_handle = open('{0}/output/{1}.txt'.format(BASE_DIR, self.main_domain), 'a')
        print('[+] <Found> {0}\t{1}'.format(sub_domain, str(analysis[1])))
        if self.depth < 0:
            self.domain_queue.put(sub_domain)  # Recursive Detect
        file_handle.write('{0}\t{1}\t{2}\n'.format(sub_domain, analysis[0], analysis[1]))
        file_handle.close()

    @max_try_wrapper
    def get_ns_servers(self):
        resolver_tmo = resolver.Resolver()
        resolver_tmo.timeout = 5
        resolver_tmo.lifetime = 10
        resolver_tmo.nameservers = DNS_LIST
        answers = resolver_tmo.query(self.main_domain, "NS")
        if answers:
            for answer in answers:
                ns_one = str(answer)
                self.name_servers.append(ns_one[0:-1])
        self.name_servers.sort()
        print('[+] Name Server:  {0}'.format(self.name_servers))

    def axfr_check(self):
        for ns in self.name_servers:
            print('[*] Checking: ' + self.main_domain + ' NS: ' + ns)
            if ns in IGNORE_DNS_LIST:
                continue
            self.axfr_ns_check(ns)
            if self.zone_transfer:
                break

    @max_try_wrapper
    def axfr_ns_check(self, ns):
        zone_tmp = zone.from_xfr(query.xfr(str(ns), self.main_domain, timeout=5, lifetime=10))
        if zone_tmp:
            self.zone_transfer = True
            print('[+] ' + self.main_domain + ' HAS THE ZONE TRANSFER VULNERABILITY')
            # get detail info
            file_handle = open('{0}/output/{1}.txt'.format(BASE_DIR, self.main_domain), 'a')
            for name, node in zone_tmp.nodes.items():
                rdatasets = node.rdatasets
                for rdataset in rdatasets:
                    file_handle.write('{0}\t{1}\n'.format(name, rdataset))
                    print('\t{0} {1}'.format(name, rdataset))
            file_handle.close()
