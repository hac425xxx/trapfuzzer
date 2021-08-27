# /usr/bin/env python
# -*- coding: UTF-8 -*-

import pymysql
import requests
import hashlib
import random
import os
from time import sleep

requests.packages.urllib3.disable_warnings()


class Seed:
    # def __init__(self, seed_id, parent_id, seed_hash, seed_size, new_seed_count, crash_count, dos_count):
    #     self.seed_id = seed_id
    #     self.parent_id = parent_id
    #     self.seed_hash = seed_hash
    #     self.seed_size = seed_size
    #     self.new_seed_count = new_seed_count
    #     self.crash_count = crash_count
    #     self.dos_count = dos_count

    def __init__(self, data):
        self.seed_id = data[0]
        self.parent_hash = data[1]
        self.seed_hash = data[2]
        self.seed_size = data[3]
        self.new_seed_count = data[4]
        self.crash_count = data[5]
        self.dos_count = data[6]
        self.file_type = data[7]
        self.file_name = data[8]
        self.mutate_infomation = data[9]
        self.extra_info = data[10]
        self.timestamp = data[11]


class SeedDB:
    """
    CREATE TABLE fuzz_seed_table (
        seed_id INT NOT NULL AUTO_INCREMENT,
        parent_hash VARCHAR ( 32 )  DEFAULT "",
        seed_hash VARCHAR ( 32 ) NOT NULL,
        seed_size INT UNSIGNED NOT NULL,
        new_seed_count INT DEFAULT 0,
        crash_count INT DEFAULT 0,
        dos_count INT DEFAULT 0,
        file_type VARCHAR ( 40 ) DEFAULT "",
        file_name VARCHAR ( 2048 ) DEFAULT "",
        mutate_infomation MEDIUMTEXT,
        extra_info MEDIUMTEXT,
        `timestamp` TIMESTAMP  DEFAULT CURRENT_TIMESTAMP,
        UNIQUE ( seed_hash ) ,
        PRIMARY KEY ( seed_id ) ,
      INDEX `seed_hash_index`(`seed_hash`) USING BTREE,
      INDEX `parent_hash_index`(`parent_hash`) USING BTREE
    );
    """

    def __init__(self, ip, user, passwd, db_name, table_name):
        # 打开数据库连接
        self.db = pymysql.connect(ip, user, passwd, db_name)
        self.cursor = self.db.cursor()
        self.table_name = table_name

    def get_db_version(self):
        self.cursor.execute("SELECT VERSION()")
        data = self.cursor.fetchone()
        print("Database version : %s " % data)

    def insert_new_seed(self, parent_hash, seed_hash, seed_size, new_seed_count=0, crash_count=0, dos_count=0,
                        file_type="",
                        file_name="", mutate_infomation="", extra_info=""):

        sql = "INSERT INTO {} (parent_hash, seed_hash, seed_size, new_seed_count, crash_count, dos_count, file_type, file_name, mutate_infomation, extra_info ) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})".format(
            self.table_name,
            repr(parent_hash).strip('u'), repr(seed_hash).strip('u'), seed_size, new_seed_count, crash_count, dos_count,
            repr(file_type).strip('u'),
            repr(file_name).strip('u'),
            repr(mutate_infomation).strip('u'),
            repr(extra_info).strip('u')
        )

        # print sql

        try:
            self.db.begin()
            self.cursor.execute(sql)
            data = self.cursor.fetchone()
            self.db.commit()
            return True
        except Exception as e:
            print e
            self.db.rollback()
            raise Exception("insert_new_seed failed")
            return False

    def get_seed(self, i):
        data = self.get_row(i)
        if data:
            seed = Seed(data)
            return seed
        return None

    def get_row(self, i):
        ret = None
        if isinstance(i, int):
            ret = self.get_row_by_id(i)
        elif isinstance(i, str):
            ret = self.get_row_by_hash(i)
        else:
            print "get_row param invaild!"
            return None

        return ret

    def get_row_by_id(self, seed_id):
        data = None
        while True:
            try:
                self.db.begin()
                self.cursor.execute(
                    "select * from {} where seed_id={}".format(self.table_name, seed_id))
                data = self.cursor.fetchone()
                self.db.commit()
                break
            except pymysql.err.OperationalError:
                self.reconnect()
            except:
                self.db.rollback()
        return data

    def get_row_by_hash(self, seed_hash):
        data = None
        while True:
            try:
                self.db.begin()
                self.cursor.execute(
                    "select * from {} where seed_hash={}".format(self.table_name,
                                                                 repr(seed_hash)))
                data = self.cursor.fetchone()
                self.db.commit()
                break
            except pymysql.err.OperationalError:
                self.reconnect()
            except:
                self.db.rollback()

        return data

    def inc_child_seed_count(self, i):
        self.inc_column("new_seed_count", i)

    def inc_dos_count(self, i):
        self.inc_column("dos_count", i)

    def inc_crash_count(self, i):
        self.inc_column("crash_count", i)

    def inc_column(self, column_name, i):
        if isinstance(i, int):
            self.inc_column_by_id(column_name, i)
        elif isinstance(i, str):
            self.inc_column_by_hash(column_name, i)
        else:
            print "inc_column param invaild!"

    def inc_column_by_id(self, column_name, seed_id):
        while True:
            try:
                self.db.begin()
                self.cursor.execute(
                    "UPDATE {} SET {} = {} + 1 where seed_id={}".format(self.table_name, column_name, column_name,
                                                                        seed_id))
                self.cursor.fetchone()
                self.db.commit()
                break
            except pymysql.err.OperationalError:
                self.reconnect()
            except:
                self.db.rollback()

    def inc_column_by_hash(self, column_name, seed_hash):
        while True:
            try:
                self.db.begin()
                self.cursor.execute(
                    "UPDATE {} SET {} = {} + 1 where seed_hash={}".format(self.table_name,
                                                                          column_name, column_name,
                                                                          repr(seed_hash)))
                self.cursor.fetchone()
                self.db.commit()
                break
            except pymysql.err.OperationalError:
                self.reconnect()
            except:
                self.db.rollback()

    def set_file_type(self, hash, v):
        self.set_column_by_hash("file_type", hash, v)

    def set_column_by_hash(self, column_name, seed_hash, v):
        while True:
            try:
                self.db.begin()
                self.cursor.execute(
                    "UPDATE {} SET {} = {} where seed_hash={}".format(self.table_name,
                                                                      column_name, repr(v).strip('u'),
                                                                      repr(seed_hash).strip('u')))
                self.cursor.fetchone()
                self.db.commit()
                break
            except pymysql.err.OperationalError:
                self.reconnect()
            except:
                self.db.rollback()

    def reconnect(self):
        # self.cursor.close()
        self.db.ping(True)
        self.cursor = self.db.cursor()

    def debug(self):

        self.db.commit()

    def __del__(self):
        # 关闭数据库连接
        self.db.close()


if __name__ == "__main__":
    conn = SeedDB("192.168.245.1", "root", "root", "testcase", "fuzz_seed_table")
    # conn.insert_new_seed(12, "026651b30b4367d6c2eeb9f5968dcd28", 288, 2, 3, 4)

    conn.get_seed_by_id(1)
    conn.inc_child_seed_count(1)
    conn.inc_child_seed_count("026651b30b4367d6c2eeb9f5968dcd28")
    conn.inc_crash_count(1)
    conn.inc_dos_count(1)
