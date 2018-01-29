# -*- coding: utf-8 -*-
'''
Created on 02/01/2014
'''

import MySQLdb
import _mysql_exceptions
import logging
import time

class mySQLHandler(logging.Handler):
    """
    Logging handler for MySQL.

    Based on Vinay Sajip's DBHandler class (http://www.red-dove.com/python_logging.html)
    forked from ykessler/gae_handler.py (https://gist.github.com/ykessler/2662203)
    <from ykessler/gae_handler.py>
    This version sacrifices performance for thread-safety:
    Instead of using a persistent cursor, we open/close connections for each entry.
    AFAIK this is necessary in multi-threaded applications,
    because SQLite doesn't allow access to objects across threads.
    </from>
    <from onemoretime>
    please see:
        https://github.com/onemoretime/mySQLHandler for more up-to-date version
        README.md
        LICENSE
    </from>
    @todo: create SQL table if necessary, try/except when execute sql, ...
    @author: "onemoretime"
    @copyright: "Copyright 2014, onemoretime"
    @license: "WTFPL."
    @version: "0.1"
    @contact: "onemoretime"
    @email: "onemoretime@cyber.world.universe"
    @status: "Alpha"
    """

    initial_sql = """CREATE TABLE IF NOT EXISTS log(
    Created text,
    Name text,
    LogLevel text,
    LogLevelName text,
    Message longtext,
    Args text,
    Module text,
    FuncName text,
    LineNo text,
    Exception text,
    Process text,
    Thread text,
    ThreadName text
    )"""

    insertion_fields = [
        'dbtime',
        'name',
        'leveno',
        'levelname',
        'msg',
        'args',
        'module',
        'funcName',
        'lineno',
        'exc_text',
        'process',
        'thread',
        'threadName',
    ]

    insertion_sql = """INSERT INTO log(
    Created,
    Name,
    LogLevel,
    LogLevelName,
    Message,
    Args,
    Module,
    FuncName,
    LineNo,
    Exception,
    Process,
    Thread,
    ThreadName
    )
    VALUES (%s)""" % ','.join(['%s'] * len(insertion_fields))

    def __init__(self, db):
        """
        Constructor
        @param db: ['host','port','dbuser', 'dbpassword', 'dbname']
        @return: mySQLHandler
        """

        logging.Handler.__init__(self)
        self.db = db
        print self.db
        # Try to connect to DB

        # Check if 'log' table in db already exists
        result = self.checkTablePresence()
        print result
        # If not exists, then create the table
        if not result:
            try:
                conn=MySQLdb.connect(host=self.db['host'],port=self.db['port'],user=self.db['dbuser'],passwd=self.db['dbpassword'],db=self.db['dbname'])
            except _mysql_exceptions, e:
                raise Exception(e)
                exit(-1)
            else:
                cur = conn.cursor()
                try:
                    cur.execute(self.initial_sql)
                except _mysql_exceptions as e:
                    conn.rollback()
                    cur.close()
                    conn.close()
                    raise Exception(e)
                    exit(-1)
                else:
                    conn.commit()
                finally:
                    cur.close()
                    conn.close()

    def checkTablePresence(self):
        try:
            conn=MySQLdb.connect(host=self.db['host'],port=self.db['port'],user=self.db['dbuser'],passwd=self.db['dbpassword'],db=self.db['dbname'])
        except _mysql_exceptions, e:
            raise Exception(e)
            exit(-1)
        else:
            # Check if 'log' table in db already exists
            cur = conn.cursor()
            stmt = "SHOW TABLES LIKE 'log';"
            cur.execute(stmt)
            result = cur.fetchone()
            print ("exist log: %s"%result)
            cur.close()
            conn.close()

        if not result:
            return 0
        else:
            return 1
    def createTableLog(self):
        pass

    def formatDBTime(self, record):
        """
        Time formatter
        @param record:
        @return: nothing
        """
        record.dbtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.created))

    def emit(self, record):
        """
        Connect to DB, execute SQL Request, disconnect from DB
        @param record:
        @return:
        """
        # Use default formatting:
        self.format(record)
        # Set the database time up:
        self.formatDBTime(record)
        if record.exc_info:
            record.exc_text = logging._defaultFormatter.formatException(record.exc_info)
        else:
            record.exc_text = ""
        # Insert log record:
        sql = self.insertion_sql
        try:
            conn=MySQLdb.connect(host=self.db['host'],port=self.db['port'],user=self.db['dbuser'],passwd=self.db['dbpassword'],db=self.db['dbname'])
        except _mysql_exceptions, e:
            from pprint import pprint
            print("The Exception during db.connect")
            pprint(e)
            raise Exception(e)
            exit(-1)
        cur = conn.cursor()
        try:
            cur.execute('set names utf8mb4')
            params = [record.__dict__.get(item) if record.__dict__.get(item) else ''
                            for item in self.insertion_fields]
            cur.execute(sql, tuple(params))
        except _mysql_exceptions.ProgrammingError as e:
            errno, errstr = e.args
            if not errno == 1146:
                raise
            cur.close() # close current cursor
            cur = conn.cursor() # recreate it (is it mandatory?)
            try:            # try to recreate table
                cur.execute(self.initial_sql)
            except _mysql_exceptions as e:
                # definitly can't work...
                conn.rollback()
                cur.close()
                conn.close()
                raise Exception(e)
                exit(-1)
            else:   # if recreate log table is ok
                conn.commit()
                cur.close()
                cur = conn.cursor()
                cur.execute(sql)
                conn.commit()
                # then Exception vanished

        except _mysql_exceptions, e:
            conn.rollback()
            cur.close()
            conn.close()
            raise Exception(e)
            exit(-1)
        else:
            conn.commit()
        finally:
            cur.close()
            conn.close()