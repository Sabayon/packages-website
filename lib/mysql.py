# -*- coding: utf-8 -*-
import os

from www.model import config

from entropy.const import const_convert_to_unicode, etpConst
etpConst['entropygid'] = config.DEFAULT_WEB_GID
import entropy.dump
import entropy.tools

from www.lib.exceptions import ServiceConnectionError, TransactionError

class Database:

    def escape_fake(self, mystr):
        return mystr

    def __init__(self):
        import MySQLdb, _mysql_exceptions
        from MySQLdb.constants import FIELD_TYPE
        from MySQLdb.converters import conversions
        self.dbconn = None
        self.cursor = None
        self.plain_cursor = None
        self.escape_string = self.escape_fake
        self.connection_data = {}
        self.mysql = MySQLdb
        self.mysql_exceptions = _mysql_exceptions
        self.FIELD_TYPE = FIELD_TYPE
        self.conversion_dict = conversions.copy()
        self.conversion_dict[self.FIELD_TYPE.DECIMAL] = int
        self.conversion_dict[self.FIELD_TYPE.LONG] = int
        self.conversion_dict[self.FIELD_TYPE.LONGLONG] = int
        self.conversion_dict[self.FIELD_TYPE.FLOAT] = float
        self.conversion_dict[self.FIELD_TYPE.NEWDECIMAL] = float

    def check_connection(self):
        if self.dbconn is None:
            return
        try:
            self.dbconn.ping()
        except self.mysql_exceptions.OperationalError as e:
            if e[0] != 2006:
                raise
            else:
                self.connect()
                return True
        return False

    def set_connection_data(self, data):
        self.connection_data = data.copy()
        if 'converters' not in self.connection_data and self.conversion_dict:
            self.connection_data['converters'] = self.conversion_dict.copy()

    def connect(self):
        kwargs = {}
        keys = [
            ('host', "hostname"),
            ('user', "username"),
            ('passwd', "password"),
            ('db', "dbname"),
            ('port', "port"),
            ('conv', "converters"), # mysql type converter dict
        ]
        for ckey, dkey in keys:
            if dkey not in self.connection_data:
                continue
            kwargs[ckey] = self.connection_data.get(dkey)

        try:
            self.dbconn = self.mysql.connect(**kwargs)
        except self.mysql_exceptions.OperationalError as e:
            raise ServiceConnectionError(repr(e))
        self.plain_cursor = self.dbconn.cursor()
        self.cursor = self.mysql.cursors.DictCursor(self.dbconn)
        self.escape_string = self.dbconn.escape_string
        return True

    def disconnect(self):
        self.check_connection()
        self.escape_string = self.escape_fake
        if hasattr(self.cursor, 'close'):
            self.cursor.close()
        if hasattr(self.dbconn, 'close'):
            self.dbconn.close()
        self.dbconn = None
        self.cursor = None
        self.plain_cursor = None
        self.connection_data.clear()
        return True

    def commit(self):
        self.check_connection()
        return self.dbconn.commit()

    def execute_script(self, myscript):
        try:
            pty = None
            for line in myscript.split(";"):
                line = line.strip()
                if not line:
                    continue
                pty = self.cursor.execute(line)
            return pty
        except self.mysql_exceptions.OperationalError as err:
            if err[0] == 1213:
                raise TransactionError(err[0], err[1])
            raise

    def execute_query(self, *args):
        try:
            return self.cursor.execute(*args)
        except self.mysql_exceptions.OperationalError as err:
            if err[0] in (1213, 1205):
                raise TransactionError(err[0], err[1])
            raise

    def execute_many(self, query, myiter):
        try:
            return self.cursor.executemany(query, myiter)
        except self.mysql_exceptions.OperationalError as err:
            if err[0] == 1213:
                raise TransactionError(err[0], err[1])
            raise

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def fetchmany(self, *args, **kwargs):
        return self.cursor.fetchmany(*args, **kwargs)

    def lastrowid(self):
        return self.cursor.lastrowid

    def table_exists(self, table):
        self.cursor.execute("show tables like %s", (table,))
        rslt = self.cursor.fetchone()
        if rslt:
            return True
        return False

    def column_in_table_exists(self, table, column):
        t_ex = self.table_exists(table)
        if not t_ex:
            return False
        self.cursor.execute("show columns from "+table)
        data = self.cursor.fetchall()
        for row in data:
            if row['Field'] == column:
                return True
        return False

    def fetchall2set(self, item):
        mycontent = set()
        for x in item:
            mycontent |= set(x)
        return mycontent

    def fetchall2list(self, item):
        content = []
        for x in item:
            content += list(x)
        return content

    def fetchone2list(self, item):
        return list(item)

    def fetchone2set(self, item):
        return set(item)

    def _generate_sql(self, action, table, data, where = ''):
        sql = ''
        keys = sorted(data.keys())
        if action == "update":
            sql += 'UPDATE %s SET ' % (self.escape_string(table),)
            keys_data = []
            for key in keys:
                keys_data.append("%s = '%s'" % (
                        self.escape_string(key),
                        self.escape_string(
                            const_convert_to_unicode(data[key],
                                'utf-8').encode('utf-8')).decode('utf-8')
                    )
                )
            sql += ', '.join(keys_data)
            sql += ' WHERE %s' % (where,)
        elif action == "insert":
            sql = 'INSERT INTO %s (%s) VALUES (%s)' % (
                self.escape_string(table),
                ', '.join([self.escape_string(x) for x in keys]),
                ', '.join(["'" + \
                    self.escape_string(
                    const_convert_to_unicode(data[x],
                        'utf-8').encode('utf-8')).decode('utf-8') + \
                    "'" for x in keys])
            )
        return sql
