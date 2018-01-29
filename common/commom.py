#! /usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Taerg"

import logging

def log_init():
    logging.basicConfig(filename='taerg_test.log', level=logging.DEBUG,  # 在这里调整输出到文件的等级
                        format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                        datefmt='%a, %d %b %Y %H:%M:%S',
                        filemode='w'
                        )
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)  # 在这里调整输出到屏幕的等级
    formatter = logging.Formatter('[line:%(lineno)d]%(levelname)s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)


black_ext_list = ["css","jpg", 'png', 'gif', 'js', 'avi', 'pdf', 'exe', 'doc', 'xls', 'woff', 'ico']