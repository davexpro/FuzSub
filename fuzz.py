#!/usr/bin/env python
# coding=utf-8
# author=dave.fang@outlook.com
# create=20160410

"""
* A Tool For Fuzzing Sub-domain.
* GitHub: https://github.com/DavexPro/FuzSub
* Version: 2.0
* SUPPORT TOP-LEVEL & All-LEVEL
"""
import sys
import datetime

from lib.evil import Evil


def start_fuzz(domain, depth=1):
    print('[*] Target: %s' % domain)
    evil = Evil(domain, depth)
    evil.start()


if __name__ == '__main__':
    start_time = datetime.datetime.now()
    print('[*] FuzSub is hot.')
    if len(sys.argv) < 2:
        print('[-] E.g. python fuzz.py foo.com (top level) OR python fuzz.py foo.com full (full level)')
        exit()
    else:
        if len(sys.argv) == 2:
            start_fuzz(sys.argv[1], 1)
        elif sys.argv[2] == 'full':
            start_fuzz(sys.argv[1], -1)
    end_time = datetime.datetime.now()
    print('[*] Total Time Consumption: {0}s'.format((end_time - start_time).seconds))
