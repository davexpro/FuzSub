#!/usr/bin/env python
# -*- utf8 -*-
# author=dave.fang@outlook.com
# create=20160623
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
THREAD_BRUTE = 50
MAX_TRY_COUNT = 5
# DNS_LIST = ['8.8.8.8', '8.8.4.4']
DNS_LIST = ['114.114.114.114', '114.114.115.115']
IGNORE_DNS_LIST = ['f1g1ns2.dnspod.net', 'f1g1ns1.dnspod.net', 'ns1.dnsv2.com', 'ns2.dnsv2.com', 'ns1.dnsv3.com',
                   'ns2.dnsv3.com', 'ns1.dnsv4.com', 'ns2.dnsv4.com', 'ns1.dnsv5.com', 'ns2.dnsv5.com', 'ns3.dnsv2.com',
                   'ns4.dnsv2.com', 'ns3.dnsv3.com', 'ns4.dnsv3.com', 'ns3.dnsv4.com', 'ns4.dnsv4.com', 'ns3.dnsv5.com',
                   'ns4.dnsv5.com']
