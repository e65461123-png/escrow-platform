# -*- coding: utf-8 -*-
"""Wrapper يجعل pg8000 يشبه sqlite3 مع auto-commit"""
import re
import pg8000.dbapi

class DictRow:
    def __init__(self, values, keys):
        self._values = values
        self._keys = list(keys)
        self._map = dict(zip(self._keys, values))
    def __getitem__(self, key):
        if isinstance(key, int): return self._values[key]
        return self._map[key]
    def keys(self): return self._keys
    def get(self, k, d=None): return self._map.get(k, d)
    def __contains__(self, k): return k in self._map
    def items(self): return self._map.items()
    def __iter__(self): return iter(self._keys)
    def __len__(self): return len(self._keys)


class PGCursor:
    def __init__(self, pg_conn):
        self._pconn = pg_conn
        self._cursor = pg_conn._conn.cursor()
        self.lastrowid = None
        self.rowcount = 0
    def _translate(self, sql):
        s = sql
        s = s.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
        s = s.replace('DATETIME', 'TIMESTAMP')
        s = s.replace("datetime('now', '-30 days')", "(NOW() - INTERVAL '30 days')")
        s = s.replace("DATE('now')", 'CURRENT_DATE')
        s = s.replace('PRAGMA journal_mode=WAL', 'SELECT 1')
        s = s.replace('PRAGMA foreign_keys=ON', 'SELECT 1')
        s = s.replace('PRAGMA busy_timeout=8000', 'SELECT 1')
        if '%s' not in s:
            s = s.replace('?', '%s')
        return s
    def execute(self, sql, params=None):
        s = sql.strip()
        up = s.upper()
        if up in ('BEGIN IMMEDIATE', 'BEGIN', 'BEGIN TRANSACTION'):
            self._pconn._in_tx = True
            return self
        if up == 'COMMIT':
            try: self._pconn._conn.commit()
            except: pass
            self._pconn._in_tx = False
            return self
        if up == 'ROLLBACK':
            try: self._pconn._conn.rollback()
            except: pass
            self._pconn._in_tx = False
            return self
        if up.startswith('PRAGMA'):
            return self
        sql_t = self._translate(sql)
        params = params or ()
        is_insert = up.startswith('INSERT')
        # INSERT with RETURNING id
        if is_insert and 'RETURNING' not in up:
            try:
                self._cursor.execute(sql_t.rstrip(';') + ' RETURNING id', params)
                r = self._cursor.fetchone()
                if r: self.lastrowid = r[0]
                self.rowcount = 1
                if not self._pconn._in_tx:
                    self._pconn._conn.commit()
                return self
            except:
                try: self._pconn._conn.rollback()
                except: pass
        try:
            self._cursor.execute(sql_t, params)
            self.rowcount = self._cursor.rowcount
        except Exception:
            try: self._pconn._conn.rollback()
            except: pass
            self._cursor.execute(sql, params)
            self.rowcount = self._cursor.rowcount
        # Auto-commit if not in explicit transaction and it's a write
        if not self._pconn._in_tx and not up.startswith('SELECT'):
            try: self._pconn._conn.commit()
            except: pass
        return self
    def fetchone(self):
        r = self._cursor.fetchone()
        if r is None: return None
        cols = [d[0] for d in self._cursor.description] if self._cursor.description else []
        return DictRow(r, cols)
    def fetchall(self):
        rows = self._cursor.fetchall()
        cols = [d[0] for d in self._cursor.description] if self._cursor.description else []
        return [DictRow(r, cols) for r in rows]


class PGConnection:
    def __init__(self, url):
        m = re.match(r'postgresql://([^:]+):([^@]+)@([^/:]+)(?::(\d+))?/([^?]+)', url)
        if not m: raise ValueError('Invalid DATABASE_URL')
        user, pwd, host, port, db = m.groups()
        self._conn = pg8000.dbapi.connect(
            user=user, password=pwd, host=host,
            port=int(port) if port else 5432, database=db
        )
        self._conn.autocommit = False
        self._in_tx = False
    def execute(self, sql, params=None):
        cur = PGCursor(self); cur.execute(sql, params); return cur
    def cursor(self): return PGCursor(self)
    def commit(self):
        try: self._conn.commit()
        except: pass
        self._in_tx = False
    def rollback(self):
        try: self._conn.rollback()
        except: pass
        self._in_tx = False
    def close(self):
        try:
            if not self._in_tx:
                self._conn.commit()
        except: pass
        try: self._conn.close()
        except: pass
