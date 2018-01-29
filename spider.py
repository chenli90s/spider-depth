#! /usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Taerg"

import json
import md5
import re
import sys
import urlparse
import datetime, time
import threading
import hash

from optparse import OptionParser 
from bs4 import BeautifulSoup
from processing import Process, Queue
from redis import client

#from common.db_config import *
from common.commom import *
from common.topdomain import *
from jsparse import MyParser
from queue import queue

import platform

reload(sys)
sys.setdefaultencoding('utf8')


class redis():
    def __init__(self,host, port, count=5, key=None):
        # self.r = client.Redis(host=host, port=port)
        self.key = key

    def llen(self):
        len = self.r.llen(self.key)
        return len

    def rpop(self):
        result = self.r.rpop(self.key)
        return result

    def rpush(self, value):
        self.r.lpush(self.key, value)

class Spider(object):
    def __init__(self, phjs, pid, url, depth, maxlink, post, cookie, host, regex, authorization):
        self.target = url
        self.rules = []
        self.domfules = []
        self.result = queue()
        self.urlhashmap = {}
        self.thirdqueue = queue()
        tmp = {}
        tmp['host'] = host
        tmp['url'] = url
        tmp['post'] = post
        tmp['src'] = ''
        tmp['referer'] = url
        tmpqueue = queue()
        tmpqueue.push(tmp)
        self.urlhashmap[0] = tmpqueue  # 把第一个url(任务队列)放进第一层[0],从这网页中爬去的放在下一层[1],依次
        self.host = urlparse.urlparse(url)[1]
        # self.maxdepth 爬虫深度
        self.maxdepth = depth
        # self.maxlink 最多爬的url树木
        self.maxlink = maxlink
        # 正则匹配内容
        self.regex = regex
        self.auth = authorization
        self.post = post
        self.urlmd5 = []
        self.depth = 0
        self.phjs = phjs
        self.pid = pid
        self.tmpqueue = queue()
        self.cookie = cookie
        self.headers =  {"Accept-Language" : "zh-CN,zh;q=0.8", 
                         "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                         "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36", 
                         "Cache-Control" : "max-age=0", 
                         "Cookie" : "Hm_lvt_a4ca63a1a1903a32ce375a3f83ed1ea8=1491900098; _ga=GA1.2.16789343.1489375761; PHPSESSID=5qgseeafq13e570d5hicbjcoj3; jsessionid|JSESSIONID=59f68366110c4900c690eddc02fa08d5; cardNo=8100100000804988; login_arr=a%3A10%3A%7Bs%3A4%3A%22name%22%3Bs%3A8%3A%22testtest%22%3Bs%3A6%3A%22CardNo%22%3Bs%3A16%3A%228100100000804988%22%3Bs%3A7%3A%22VipType%22%3Bs%3A3%3A%22IVM%22%3Bs%3A8%3A%22VipLevel%22%3Bs%3A1%3A%220%22%3Bs%3A9%3A%22FirstName%22%3Bs%3A4%3A%22test%22%3Bs%3A8%3A%22LastName%22%3Bs%3A4%3A%22test%22%3Bs%3A6%3A%22Mobile%22%3Bs%3A11%3A%2218521305769%22%3Bs%3A5%3A%22Email%22%3Bs%3A12%3A%22abc%40wanda.cn%22%3Bs%3A3%3A%22Sex%22%3Bs%3A1%3A%22M%22%3Bs%3A6%3A%22Points%22%3Bs%3A1%3A%220%22%3B%7D; form_username=18521305769; form_password=s%3A6%3A%22321073%22%3B; form_check=1; Hm_lvt_409ce23c3f2dfd3322530519dd81f558=1497858006; Hm_lpvt_409ce23c3f2dfd3322530519dd81f558=1497858129; Hm_lvt_51179d8b3807ddcb0ad60f026cd9028c=1497858006; Hm_lpvt_51179d8b3807ddcb0ad60f026cd9028c=1497858129", 
                         "Upgrade-Insecure-Requests" : "1", 
                         "Accept-Encoding" : "gzip, deflate, sdch"}
        self.headers = str(self.headers)
        #self.rules = load_site_policey(self.host)
        #self.domfules = load_site_policey_dom(self.host)
        self.rules = [1,2]
        self.domfules = [3,4]
        self.flag = 0 #漏洞标示,0为正常,1为xss
        #logging.debug("load rules:%s" % str(self.rules))
        #logging.debug("load domrules:%s" % str(self.domfules))

    ''' 
    # 计算urlMD5用作去重
    def make_md5(self, url, post):
        urlpart = urlparse.urlparse(url)
        # logging.debug("urlpart:%s" % str(urlpart))
        scheme = urlpart[0]
        netloc = urlpart[1]
        path = urlpart[2]
        params = urlpart[3]
        queryget = urlpart[4].split('&')
        queryget.sort()
        querypost = post.split('&')
        querypost.sort()
        frgment = urlpart[5]
        querygetkey = ""
        querypostkey = ""
        for var in queryget:
            querygetkey = querygetkey + var.split('=')[0]
        for var in querypost:
            querypostkey = querypostkey + var.split('=')[0]
        urlkey = netloc + path + params + frgment + querygetkey + querypostkey
        # logging.debug("getMd5-urlkey:%s" % urlkey)
        m = md5.new()
        m.update(urlkey)
        return m.hexdigest()
    '''
    
    # url后缀筛选, 静态资源过滤
    def extFilter(self, exts):
        if str(exts) in black_ext_list:
            return False

        return True

    # url去重 域名不同 会给过滤掉
    def urlFilter(self, item, referer):
        if item['referer'] == "":
            item['referer'] = referer
        try:
            urlpart = urlparse.urlparse(str(item['url']))
            # print urlpart
            urlpart_topdomain = get_domain(str(item['url']))
            # logging.debug("urlpart:%s" % str(urlpart))
        except Exception as e:
            logging.debug("urlpart:%s" % str(urlpart))
            return False

        url_infos = converturl(str(item['url']))
        #themd5 = self.make_md5(item['url'], item['post'])
        themd5 = hash.similarity(item['url'],item['post'])
        if urlpart and self.host in urlpart[1] and self.extFilter(str(url_infos['ext'])): # 不检测子域名。
        #if urlpart_topdomain and urlpart_topdomain in self.host and self.extFilter(str(url_infos['ext'])):
            if themd5 not in self.urlmd5:
#                self.xssScan(item['url'], item['post'])#对于同类型url仅作一次检测
                self.urlmd5.append(themd5)
                self.result.push(item)
                depth = self.depth + 1
                if self.urlhashmap.has_key(depth):
                    self.urlhashmap[depth].push(item)
                else:
                    tmp = queue()
                    tmp.push(item)
                    self.urlhashmap[depth] = tmp
        else:
            if themd5 not in self.urlmd5:
#                self.xssScan(item['url'], item['post'])#对于同类型url仅作一次检测
                self.thirdqueue.push(item)
                self.urlmd5.append(themd5)

    def regularMacth(self, regpattern, inputstr):
        pattern = re.compile(regpattern, re.IGNORECASE)
        try:
            m = pattern.findall(str(inputstr))
            if m:
                return m
            else:
                return False
        except Exception as e:
            return False

    def newProcExecuteCmd(self, queue, cmd):
        import os

        if cmd == "" or cmd is None:
            return False
        print cmd
        #result = (commands.getstatusoutput(cmd))
        result = [0, os.popen(cmd).read()]
        # print result

        #print result[1]
        if result[0] != 0:
            queue.put(-1)
            return
        queue.put(result[1])

        return

    def cmdrun(self, cmd):
        try:
            comScanCmd = cmd
            queue = Queue()
            scanProc = Process(
                target=self.newProcExecuteCmd, args=[queue, comScanCmd])
            scanProc.start()
            scanProc.join(5)
            try:
                scanResult = queue.get(timeout=30)
                #print scanResult
            except Exception, e:
                print e
                print "get cmd result error: %s " % str(e)
                scanResult = -1
            scanProc.terminate()
            return scanResult
        except Exception,e:
            print e

    def phantomjs_fetcher(self, pid, url, post):
        #print(pid)

        # 超过最大爬取数后退出
        if self.result.length() >= int(self.maxlink):
            return

        url = url.replace('"', '\\"')
        self.post = post.replace('"', '\\"')
        #self.cookie = self.cookie.replace('"', '\\"')
        if 'loginname=null' in self.post or 'loginname=&' in self.post:
            post = self.post.replace('loginname=null', 'loginname=admin')
            self.post = self.post.replace('loginname=null', 'loginname=admin')
            post = self.post.replace('loginname=&', 'loginname=admin&')
            self.post = self.post.replace('loginname=&', 'loginname=admin&')
        if 'actiontype=null' in self.post or 'actiontype=&' in self.post:
            post = self.post.replace('actiontype=null','actiontype=1')
            self.post = self.post.replace('actiontype=null','actiontype=1')
            post = self.post.replace('actiontype=&','actiontype=1&')
            self.post = self.post.replace('actiontype=&','actiontype=1&')
        # self.auth=self.auth.replace('"','\\"')
        if len(post) > 0:
            if 'win' in self.phjs:
                cmd = "%s .\\js\\taergtest.js  \"%s\" \"%s\" \"%s\" \"%s\" \"30\"" % (self.phjs, url, self.headers, self.auth, post)
            else:
                cmd = "./%s ./js/taergtest.js  \"%s\" \"%s\" \"%s\" \"%s\" \"30\"" % (self.phjs, url, self.headers, self.auth, post)
            method = 'POST'
        else:
            if 'win' in self.phjs:
                cmd = "%s .\\js\\wilson.js  \"%s\" \"%s\" \"%s\" \"\" \"30\"" % (self.phjs, url, self.headers, self.auth)
            else:
                cmd = "./%s ./js/wilson.js  \"%s\" \"%s\" \"%s\" \"\" \"30\"" % (self.phjs, url, self.headers, self.auth)
            method = 'GET'
        #log = open('1.log','a+')
        # print "[Info][%s][Queue:%s][Crawled:%s][%s] crawled url: %s | post_data:%s" % (method, len(self.urlhashmap[self.depth].queue), self.result.length(), datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),url, post)
        #log.write("[%s] [%s] crawled url: %s | post_data:%s" % (method, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),url, post)+'\n')
        #r = redis(host='127.0.0.1', port=6379, key='spider') # 绑定redis

        #r.rpush('["%s", "%s", "%s", "%s"]' % (method, url, post, self.cookie))
        #排除登录
        #print cmd

        if 'loginout' in url or 'logout' in url or 'javascript:' in url:
            outputstr = -1
        else:
            outputstr = self.cmdrun(cmd)
        #print 'outputstr',outputstr
        if outputstr == -1 or outputstr == None:
            #logging.debug("runcmd error:%s" % cmd)
            return
        
        url_part = self.regularMacth("hook_url:(.*)hook_url_end", outputstr)
        outputstr = outputstr.replace("\n", "")
        outputstr = outputstr.replace("\r", "")
        html_part = self.regularMacth(
            "crawl_content:(.*)content_end", outputstr)
        try:
            s = html_part[0]
        except:
            #print html_part
            s = ''
        taerg_test = self.regularMacth(
            "x624x(.*)x624x", outputstr
        )
        if taerg_test:
            self.flag = 1
            #logging.info("*!Find taerg Falg!*%s"%taerg_test)
        #insert_scan_result_to_db(self.target, url, outputstr, self.flag, time.strftime('%Y-%m-%d %H:%M:%S'))
        #import pdb;pdb.set_trace()
        #for i in re.findall(r'hook_url:(.*?)hook_url_end', outputstr):print i
        #print outputstr, self.flag, time.strftime('%Y-%m-%d %H:%M:%S')
        self.flag = 0
        # hook 到的 urls
        # url_part是一个list,[{"url":"http://...","method":""...},{}]
        # 每一个元素是一个字典,可用json解析
        if url_part:
            for var in url_part:
                var = json.loads(var)
                # logger.info(MySQLdb.escape_string("[+] hookurls:%s" % var['url']).decode('utf8').encode('utf8'))
                if var['method'] == "POST":
                    r = {'url': var['url'], 'post': var['post'], 'referer': '', 'tag': ''}
                else:
                    r = {'url': var['url'], 'post': '', 'referer': '', 'tag': ''}
                self.urlFilter(r, url)
        else:
            pass

        # 分析渲染页面的 href
        soup = BeautifulSoup(s, "lxml")
        p = MyParser(soup, url)
        p.parser()

        while p.tmpqueue.length() > 0:
            var = p.tmpqueue.pop()
            #print "[+]get href:%s" % var['url']
            # logger.info(MySQLdb.escape_string("[+]get href:%s" % var['url']).decode('utf8').encode('utf8'))
            self.urlFilter(var, url)

    def _thread(self, pool):
        thread_pools = []

        # 此处加多线程.
        try:
            for i in pool:
                urldata = i
                url = urldata['url']
                post = urldata['post']
                #
                th = threading.Thread(target=self.phantomjs_fetcher, args=(self.pid,url, post, ))
                thread_pools.append(th)

            for i in range(len(pool)):
                thread_pools[i].start()

            for i in range(len(pool)):
                thread_pools[i].join()
        except Exception,e:
            print e

    def crawl(self):
        # 初始为self.depth ＝0
        """
        while (self.depth <= self.maxdepth):
            if self.urlhashmap.has_key(self.depth) is False:  # 当前depth是否有网址\需要爬的东西,如果没有,进入if并break
                print "1-------------%s--------------1" % self.depth
                break

            # 第二层时候 会发生多个请求
            if self.urlhashmap[self.depth].length() > 0:  # 当前深度队列长度大于0
                Queue_list = self.urlhashmap[self.depth]
                print len(Queue_list.queue), Queue_list.queue

                total = len(Queue_list.queue)
                pool = []
                thread_num = 5
                if thread_num >= total:thread_num=total # 当预设线程数大于总数, 设置线程为总数
                print total
                while (total > 0):
                    print total
                    pool.append(Queue_list.pop())
                    total=len(Queue_list.queue)
                    if len(pool) >= thread_num:
                        self._thread(pool)
                        pool = []
                    elif total == 0 and len(pool) != 0 and len(pool) < thread_num:
                        self._thread(pool)
                        pool = []
        """
        while (self.depth <= self.maxdepth):
            if self.urlhashmap.has_key(self.depth) is False:  # 当前depth是否有网址\需要爬的东西,如果没有,进入if并break
                print "1-------------%s--------------1" % self.depth
                break

            # 第二层时候 会发生多个请求
            try:
                while self.urlhashmap[self.depth].length() :  # 当前深度队列长度大于0
                    Queue_list = self.urlhashmap[self.depth]
                    #print len(Queue_list.queue), Queue_list.queue
                    total = len(Queue_list.queue)
                    pool = []
                    thread_num = 10
                    if thread_num >= total:thread_num=total # 当预设线程数大于总数, 设置线程为总数
                    while (total > 0):
                        pool.append(Queue_list.pop())
                        total=len(Queue_list.queue)
                        if len(pool) >= thread_num:
                            self._thread(pool)
                            pool = []
                        elif total == 0 and len(pool) != 0 and len(pool) < thread_num:
                            self._thread(pool)
                            pool = []

                    self.depth = self.depth + 1
            except Exception,e:
                return



# def usage():
#     print "python spider.py -u url --cookie cookie -p post -d depth --maxlink maxlink --regex regex "

def start(phjs, pid, url, cookie, depth, maxlink):
    # db_init()
    target = url #唯一标示码
    post = ""
    cookie = cookie
    depth = depth
    #depth = "5"
    maxlink = maxlink
    regex = ""
    authorization = None
    # logging.debug("[+] Crawl cgi:%s post:%s depth:%s maxlin:%s regex:%s", cgi, post, depth, maxlink, regex)
    host = urlparse.urlparse(target)[1]
    try:
        depth = int(depth)
    except:
        pass
    try:
        maxlink = int(maxlink)
    except:
        pass

    spider = Spider( phjs, pid, target, depth, maxlink, post, cookie, host, regex, authorization )

    spider.crawl()
    logging.debug("[+] Done crawl!")

    while spider.result.length() > 0:
        var = spider.result.pop()
        print var
        #insert_url_to_db(target,var['url'],var['post'],var['referer'],var['tag'])
    while spider.thirdqueue.length() > 0:
        var = spider.thirdqueue.pop()
        print var
        #insert_third_url_to_db(target,var['url'],var['post'],var['referer'],var['tag'])

def main(url=None):

    log_init()

    if platform.system() == 'Darwin':
        phjs = "bin/phantomjs4mac"
    elif platform.system() == 'Linux':
        phjs = "bin/phantomjs4linux"
    elif platform.system() == 'Windows':
        phjs = "bin\\phantomjs4win.exe"
    else:
        phjs = "bin/phantomjs4linux"

    #url = 'http://vul.ossec.cn'
    url = 'http://www.iqiyi.com'
    #url = 'http://demo.aisec.cn/demo/aisec/'
    # url = "http://e.yiguo.com"
    # url = "http://demo.anshi.tech"
    
    cookie = ''

    parser = OptionParser() 
    parser.add_option("-u", "--url", dest="url",
                  help="Enter a start URL.", metavar="Url")
    
    parser.add_option("--cookie", dest="cookie", default=cookie,
                  help="Set a cookie.", metavar="cookie")

    parser.add_option("--depth", dest="depth", default=10,
                  help="Set a max depth.")  

    parser.add_option("--maxlink", dest="maxlink", default=2000,
                  help="Set a maxlink.")
    
    (options, args) = parser.parse_args()

    if url:
        if url.startswith('http'):
            pid = urlparse.urlparse(url).netloc
        else:
            print "[*] Url Don't miss http:// or https:// \n"
            sys.exit()

        cookie = options.cookie
        depth = options.depth
        maxlink = options.maxlink
        start(phjs, pid, url, cookie, depth, maxlink)
    else:
        if options.url != None:
            url = options.url
            if url.startswith('http'):
                pid = urlparse.urlparse(url).netloc
            else:
                print "[*] Url Don't miss http:// or https:// \n"

                parser.print_help()

                sys.exit()

            if options.cookie:
                cookie = options.cookie

            if options.depth:
                depth = options.depth

            if options.maxlink:
                maxlink = options.maxlink

            start(phjs, pid, url, cookie, depth, maxlink)
        else:
            parser.print_help() 


if __name__ == '__main__': main()









