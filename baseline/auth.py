"""Password hashing and server-side session management."""
import hashlib
import hmac
import os
import secrets
import time

ITERATIONS = 200_000
SESSION_LIFETIME = 86400
COOKIE_NAME = 'baseline_session'

def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
    return f'{salt.hex()}${digest.hex()}'

def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split('$')
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), ITERATIONS)
    return hmac.compare_digest(digest, expected)

def create_session(db, username, role):
    now = time.time()
    # Sweeping expired sessions here (a write path that already opens its own
    # implicit transaction) rather than in lookup_session keeps the read-only
    # session check free of writes -- callers like /api/runs immediately
    # follow a role() check with their own BEGIN IMMEDIATE on the same
    # connection, and sqlite3 refuses to start a transaction within one.
    db.execute('DELETE FROM sessions WHERE expires<?', (now,))
    token = secrets.token_hex(32)
    db.execute('INSERT INTO sessions(token,username,role,created,expires) VALUES(?,?,?,?,?)',
               (token, username, role, now, now + SESSION_LIFETIME))
    return token

def lookup_session(db, token):
    row = db.execute('SELECT username,role FROM sessions WHERE token=? AND expires>=?', (token, time.time())).fetchone()
    return (row['role'], row['username']) if row else None

def delete_session(db, token):
    db.execute('DELETE FROM sessions WHERE token=?', (token,))

def delete_sessions_for(db, username):
    db.execute('DELETE FROM sessions WHERE username=?', (username,))

def cookie_header(token, max_age):
    return f'{COOKIE_NAME}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}'
