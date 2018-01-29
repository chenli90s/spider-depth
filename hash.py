#-*- coding: utf-8 -*-
#
# Create by Frank
#
# Last updated: 2015-01-13
import re, random, types
import hashlib
import time,os,sys,ast
from bs4 import BeautifulSoup
import urlparse
from urllib import unquote

def similarity(url,post):
 
    #shuzi = re.compile('/(\d+)/?')
    '''
    if '-' in url:
        url = url.replace('-','')
    '''
    tmp1 = list()
    shuzi = re.compile('[\/]?(\d+)')
    pdate = re.compile('(.*?)=')
    hash_size = 1000000000
    if post:
        try:
            tt = ast.literal_eval(post)
            a = ''.join(sorted(tt.keys()))
        except:
            t1 = post.split('&')
            for i in t1:
                st = i.split('=')[0]
                tmp1.append(st)
            a = ''.join(sorted(tmp1))
    else:
        a = ''
    #print a
    #url = urllib.unquote(url)
    url = url.lower()
    tmp = urlparse.urlparse(url)
    scheme = tmp[0]; netloc = tmp[1]; path = tmp[2][1:]; query = tmp[4]
    #print path.split('/')
    
    if len(path.split('/')[-1].split('.')) > 1:
        tail = path.split('/')[-1].split('.')[-1]
    #elif len(path.split('/')) == 1 :
    #    tail = path
    else:
        #print 'test'
        tail = '-1'
    tail = tail.lower()
    #print tail
    shuzilist = re.findall(shuzi,path)
    path1 = path
    temp = dict()
    if shuzilist:
        shuzilist.sort(key=lambda x:len(x),reverse=True)
        #print shuzilist
        for i in shuzilist:
            path = path.replace(i,'d')
            #path
    #print query,tmp.query
    #print path
    a +=''.join(sorted(urlparse.parse_qs(tmp.query).keys()))
    #print a
    if 'htm' in tail:
        urls = netloc + '/' + str(len(path))+a
    elif not a:
        urls = netloc + '/' + str(len(path))
    else:
        urls = netloc + '/' + path + a
    #print urls
    '''
    if a:
        urls = netloc + '/' + path + a
    elif 'htm' in tail:
        urls = netloc + '/' + str(len(path))
    else:
        urls = netloc + '/' + path1
    '''
    #print urls
    url_value = hash(hashlib.new("md5", urls).hexdigest())%(hash_size-1)
    return url_value
#s11 = similarity('http://mkt-activity.qas.mx.com/activity/list','{"captcha":"","mobile":"15832133632","pwd":"1234567a"}')
#print s11
#https://h5.ffan.com/newactivity/161225_tingche_main.html?uid=14102415191001665&ts=1490236763&from=&market_token=644c92bfed6cd74321a17811d5029509
#https://h5.ffan.com/newactivity/161225_tingche_main.html?uid=15000000061472688&ts=1490167684&from=&market_token=d1fc780bb8bd7eb961a741c30a5644eb