import json
import sqlite3
import time
from contextlib import contextmanager

@contextmanager
def connect(path):
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def init(path):
    with connect(path) as db:
        db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS vendor_snapshots(id TEXT PRIMARY KEY, document TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS hosts(id TEXT PRIMARY KEY, document TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS baselines(id TEXT PRIMARY KEY, document TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, created REAL NOT NULL, status TEXT NOT NULL, document TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS bindings(id TEXT PRIMARY KEY, document TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, created REAL NOT NULL, status TEXT NOT NULL, document TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, created REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL);
        ''')
        # An interrupted collection or upgrade can never become a verified/completed result.
        db.execute("UPDATE runs SET status='error' WHERE status='running'")
        db.execute("UPDATE jobs SET status='error' WHERE status IN ('running_plan','running')")

def audit(db, actor, action, subject):
    db.execute('INSERT INTO audit(created,actor,action,subject) VALUES(?,?,?,?)', (time.time(), actor, action, subject))

def get(db, table, key):
    row = db.execute(f'SELECT document FROM {table} WHERE id=?', (key,)).fetchone()
    if row is None: raise ValueError('Record not found')
    return json.loads(row['document'])
