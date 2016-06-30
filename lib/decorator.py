#!/usr/bin/env python3
# -*- utf8 -*-
# author=dave.fang@outlook.com
# create=20160623
import time

from config import MAX_TRY_COUNT


def max_try_wrapper(func):
    def wrapper(*args, **kwargs):
        for i in range(MAX_TRY_COUNT):
            try:
                func(*args, **kwargs)
                break
            except Exception as e:
                if func.__name__ != 'axfr_ns_check' or func.__name__ == 'get_ns_servers':
                    print('[-] {0} Called Error: {1}'.format(func.__name__, e))

    return wrapper


def infinite_try_wrapper(func):
    def wrapper(*args, **kwargs):
        while True:
            try:
                func(*args, **kwargs)
                break
            except Exception as e:
                if func.__name__ != 'axfr_ns_check' or func.__name__ == 'get_ns_servers':
                    print('[-] {0} Called Error: {1}'.format(func.__name__, e))
                time.sleep(5)

    return wrapper
