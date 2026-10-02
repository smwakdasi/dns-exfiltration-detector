"""Step 5a: SQLite logging (queries, alerts, blocks). One connection per thread-safe call."""
import json
import sqlite3
import threading

import config

_lock = threading.Lock()
SCHEMA = """
CREATE TABLE IF NOT EXISTS queries(id INTEGER PRIMARY KEY, ts REAL, src_ip TEXT, fqdn TEXT, qtype TEXT,
    entropy REAL, score INTEGER, suspicious INTEGER);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, src_ip TEXT, domain TEXT, score INTEGER,
    reasons TEXT, action TEXT);
CREATE TABLE IF NOT EXISTS blocks(id INTEGER PRIMARY KEY, ts REAL, kind TEXT, target TEXT, dry_run INTEGER,
    expires REAL, active INTEGER DEFAULT 1);
"""


class Storage:
    def __init__(self, path=config.DB_PATH):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)

    def _exec(self, sql, args=()):
        with _lock:
            self.db.execute(sql, args)
            self.db.commit()

    def log_query(self, ev, f, v):
        self._exec("INSERT INTO queries(ts,src_ip,fqdn,qtype,entropy,score,suspicious) VALUES(?,?,?,?,?,?,?)",
                   (ev.ts, ev.src_ip, ev.fqdn, ev.qtype, f.entropy, v.score, int(v.suspicious)))

    def log_alert(self, ts, src, domain, score, reasons, action):
        self._exec("INSERT INTO alerts(ts,src_ip,domain,score,reasons,action) VALUES(?,?,?,?,?,?)",
                   (ts, src, domain, score, json.dumps(reasons), action))

    def log_block(self, ts, kind, target, dry_run, expires):
        self._exec("INSERT INTO blocks(ts,kind,target,dry_run,expires) VALUES(?,?,?,?,?)",
                   (ts, kind, target, int(dry_run), expires))

    def deactivate_block(self, kind, target):
        self._exec("UPDATE blocks SET active=0 WHERE kind=? AND target=? AND active=1", (kind, target))

    def rows(self, sql, args=()):
        with _lock:
            cur = self.db.execute(sql, args)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
