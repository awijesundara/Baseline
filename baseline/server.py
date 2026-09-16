"""Baseline single-controller preview: durable jobs and scoped HTTP API."""
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from . import auth, __version__
from .policy import FIELDS, OPS, validate, digest
from .runner import execute, validate_address
from .store import init, connect, get, audit

ROOT = Path(__file__).resolve().parents[1]
COMMIT = (ROOT / 'COMMIT').read_text().strip() if (ROOT / 'COMMIT').is_file() else 'dev'
VERSION = f'{__version__}+{COMMIT}'

USERNAME_RE = re.compile(r'[a-z][a-z0-9_.-]{2,31}')

def configuration():
    admin_user = os.environ.get('BASELINE_ADMIN_USERNAME', '')
    admin_password = os.environ.get('BASELINE_ADMIN_PASSWORD', '')
    if not USERNAME_RE.fullmatch(admin_user): raise ValueError('Set BASELINE_ADMIN_USERNAME to a lowercase username (letters/digits/._- , 3-32 chars)')
    if len(admin_password) < 12: raise ValueError('Set BASELINE_ADMIN_PASSWORD to a passphrase of at least 12 characters')
    integration_token = os.environ.get('BASELINE_INTEGRATION_TOKEN', '')
    if integration_token and len(integration_token) < 32: raise ValueError('BASELINE_INTEGRATION_TOKEN must be at least 32 characters')
    # Host-key trust is pluggable (see runner.ssh_common_args): a static
    # known_hosts file is the default, but BASELINE_KNOWN_HOSTS_COMMAND lets a
    # site with centrally managed host keys (e.g. FreeIPA/SSSD's
    # sss_ssh_knownhostsproxy) delegate trust to that system instead. Setting
    # BASELINE_KNOWN_HOSTS_COMMAND opts out of the file default so the two
    # can't silently both apply.
    known_hosts_command = os.environ.get('BASELINE_KNOWN_HOSTS_COMMAND', '')
    known_hosts = os.environ.get('BASELINE_KNOWN_HOSTS', '' if known_hosts_command else '/run/secrets/known_hosts')
    if known_hosts and known_hosts_command:
        raise ValueError('Set only one of BASELINE_KNOWN_HOSTS or BASELINE_KNOWN_HOSTS_COMMAND')
    return {'admin_user': admin_user, 'admin_password': admin_password, 'integration_token': integration_token,
            'db': os.environ.get('BASELINE_DB', str(ROOT / 'data/baseline.db')),
            'networks': os.environ.get('BASELINE_ALLOWED_NETWORKS', '').split(','),
            'ssh_key': os.environ.get('BASELINE_SSH_KEY', '/run/secrets/ssh_key'),
            'ssh_cert': os.environ.get('BASELINE_SSH_CERT', ''),
            'known_hosts': known_hosts, 'known_hosts_command': known_hosts_command,
            'ansible': os.environ.get('BASELINE_ANSIBLE', 'ansible-playbook'), 'timeout': 300}

def document(db, table, identifier, value):
    db.execute(f'INSERT INTO {table}(id,document) VALUES(?,?)', (identifier, json.dumps(value)))

def find_binding(db, external_system, ticket_id):
    # Most recent binding wins if a ticket was ever bound more than once.
    for row in db.execute('SELECT document FROM bindings ORDER BY rowid DESC').fetchall():
        binding = json.loads(row['document'])
        if binding['external_system'] == external_system and binding['ticket_id'] == ticket_id:
            return binding
    return None

def verification(db, binding):
    rows = db.execute('SELECT status,document FROM runs ORDER BY created DESC').fetchall()
    # The newest attempt supersedes older passes, including running/failed attempts.
    for row in rows:
        run = json.loads(row['document'])
        if run.get('binding_id') != binding['id']: continue
        fresh = run.get('started_at', 0) >= binding['not_before'] and time.time() - run.get('completed_at', 0) <= binding['max_age_seconds']
        exact = run['baseline']['id'] == binding['baseline_id'] and sorted(h['id'] for h in run['hosts']) == sorted(binding['host_ids'])
        verified = row['status'] == 'pass' and fresh and exact
        return {'verified': verified, 'status': 'verified' if verified else ('expired' if row['status'] == 'pass' and not fresh else row['status']),
                'binding_id': binding['id'], 'external_system': binding['external_system'], 'ticket_id': binding['ticket_id'],
                'run_id': run['id'], 'evidence_sha256': run.get('evidence_sha256'), 'completed_at': run.get('completed_at')}
    return {'verified': False, 'status': 'not_run', 'binding_id': binding['id']}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def send(self, data, status=200, content_type='application/json', headers=None):
        body = json.dumps(data).encode() if content_type == 'application/json' else data
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        for key, value in (headers or {}).items(): self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def session_token(self):
        header = self.headers.get('Cookie')
        if not header: return None
        jar = SimpleCookie()
        jar.load(header)
        morsel = jar.get(auth.COOKIE_NAME)
        return morsel.value if morsel else None

    def role(self, db):
        supplied = self.headers.get('Authorization', '').removeprefix('Bearer ')
        integration = self.server.settings['integration_token']
        if integration and supplied and hmac.compare_digest(supplied, integration): return 'integration', 'integration'
        token = self.session_token()
        if token:
            session = auth.lookup_session(db, token)
            if session: return session
        return None

    def do_GET(self): self.dispatch('GET')
    def do_POST(self): self.dispatch('POST')

    def dispatch(self, method):
        path = urlsplit(self.path).path
        settings = self.server.settings
        try:
            if method == 'GET' and path in {'/health', '/ready'}:
                with connect(settings['db']) as db: db.execute('SELECT 1').fetchone()
                return self.send({'status': 'ok', 'version': VERSION})
            static = {'/': 'index.html', '/app.js': 'app.js', '/styles.css': 'styles.css'}
            if method == 'GET' and path in static:
                name = static[path]
                return self.send((ROOT / 'static' / name).read_bytes(), content_type={'html': 'text/html; charset=utf-8', 'js': 'text/javascript', 'css': 'text/css'}[name.split('.')[-1]])
            if method == 'POST':
                origin = self.headers.get('Origin')
                mismatched = bool(origin) and urlsplit(origin).netloc != self.headers.get('Host')
                # A session cookie is the only ambient credential a browser
                # attaches automatically; a request carrying one but no
                # Origin header at all is exactly the shape a legacy browser
                # ignoring SameSite would produce in a cross-site POST, so it
                # is rejected rather than silently let through. Bearer-token
                # callers (integration) never send this cookie and are
                # unaffected.
                if mismatched or (self.session_token() and not origin): return self.send({'error': 'Cross-origin request denied'}, 403)
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json': raise ValueError('JSON body required')
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 128000: raise ValueError('Body must be 1–128000 bytes')
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict): raise ValueError('JSON object required')
            with connect(settings['db']) as db:
                if method == 'POST' and path == '/api/login': return self.login(db, payload)
                if method == 'POST' and path == '/api/logout': return self.logout(db)
                identity = self.role(db)
                if not identity: return self.send({'error': 'Authentication required'}, 401)
                role, actor = identity
                if method == 'POST' and role == 'reader': return self.send({'error': 'Read-only credential'}, 403)
                if method == 'GET':
                    if path == '/api/templates':
                        return self.send({'data': [json.loads(p.read_text()) for p in sorted((ROOT / 'examples').glob('*.json'))]})
                    if path == '/api/catalog':
                        host_keys_configured = Path(settings['known_hosts']).is_file() if settings['known_hosts'] else bool(settings['known_hosts_command'])
                        return self.send({'fields': sorted(FIELDS), 'operators': sorted(OPS), 'role': role, 'username': actor, 'version': VERSION,
                                          'runner_available': bool(shutil.which(settings['ansible'])),
                                          'ssh_configured': Path(settings['ssh_key']).is_file() and host_keys_configured})
                    if path == '/api/users' and role == 'admin':
                        rows = db.execute('SELECT username,role FROM users ORDER BY username').fetchall()
                        return self.send({'data': [dict(r) for r in rows]})
                    for table in ('hosts', 'baselines', 'bindings', 'runs'):
                        if path == '/api/' + table:
                            rows = db.execute(f'SELECT * FROM {table}' + (' ORDER BY created DESC LIMIT 100' if table == 'runs' else ' ORDER BY rowid DESC')).fetchall()
                            data = []
                            for row in rows:
                                item = json.loads(row['document'])
                                if table == 'runs': item['status'] = row['status']
                                data.append(item)
                            return self.send({'data': data})
                    if path == '/api/audit':
                        return self.send({'data': [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 200')]})
                    if path == '/api/verification':
                        query = parse_qs(urlsplit(self.path).query)
                        system = (query.get('external_system') or [''])[0]
                        ticket = (query.get('ticket_id') or [''])[0]
                        if system not in {'serviceops', 'flowops'} or not ticket:
                            raise ValueError('external_system and ticket_id are required')
                        binding = find_binding(db, system, ticket)
                        if binding is None:
                            return self.send({'verified': False, 'status': 'not_bound', 'external_system': system, 'ticket_id': ticket})
                        return self.send(verification(db, binding))
                    match = re.fullmatch(r'/api/bindings/([a-f0-9]+)/verification', path)
                    if match: return self.send(verification(db, get(db, 'bindings', match[1])))
                    match = re.fullmatch(r'/api/runs/([a-f0-9]+)', path)
                    if match:
                        run = get(db, 'runs', match[1])
                        run['status'] = db.execute('SELECT status FROM runs WHERE id=?', (match[1],)).fetchone()[0]
                        return self.send(run)
                elif method == 'POST':
                    identifier = secrets.token_hex(12)
                    if path in {'/api/hosts', '/api/baselines', '/api/bindings', '/api/users'} and role != 'admin':
                        return self.send({'error': 'Administrator credential required'}, 403)
                    if path == '/api/users':
                        username = str(payload.get('username', '')).strip().lower()
                        password = str(payload.get('password', ''))
                        urole = payload.get('role')
                        if not USERNAME_RE.fullmatch(username): raise ValueError('Username must be lowercase letters/digits/._- , 3-32 chars')
                        if len(password) < 12: raise ValueError('Password must be at least 12 characters')
                        if urole not in {'admin', 'reader'}: raise ValueError('role must be admin or reader')
                        if db.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone(): raise ValueError('That username already exists')
                        db.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)', (username, auth.hash_password(password), urole))
                        item = {'username': username, 'role': urole}
                        audit(db, actor, 'users.created', username)
                        db.commit()
                        return self.send(item, 201)
                    match = re.fullmatch(r'/api/users/(' + USERNAME_RE.pattern + r')/revoke', path)
                    if match:
                        if role != 'admin': return self.send({'error': 'Administrator credential required'}, 403)
                        target = db.execute('SELECT role FROM users WHERE username=?', (match[1],)).fetchone()
                        if target is None: raise ValueError('No such user')
                        remaining_admins = db.execute("SELECT COUNT(*) AS n FROM users WHERE role='admin'").fetchone()['n']
                        if target['role'] == 'admin' and remaining_admins <= 1: raise ValueError('Cannot revoke the only administrator account')
                        db.execute('DELETE FROM users WHERE username=?', (match[1],))
                        auth.delete_sessions_for(db, match[1])
                        audit(db, actor, 'users.revoked', match[1])
                        db.commit()
                        return self.send({'username': match[1], 'revoked': True})
                    match = re.fullmatch(r'/api/users/(' + USERNAME_RE.pattern + r')/reset', path)
                    if match:
                        if role != 'admin': return self.send({'error': 'Administrator credential required'}, 403)
                        password = str(payload.get('password', ''))
                        if len(password) < 12: raise ValueError('Password must be at least 12 characters')
                        if not db.execute('SELECT 1 FROM users WHERE username=?', (match[1],)).fetchone(): raise ValueError('No such user')
                        db.execute('UPDATE users SET password_hash=? WHERE username=?', (auth.hash_password(password), match[1]))
                        auth.delete_sessions_for(db, match[1])
                        audit(db, actor, 'users.password_reset', match[1])
                        db.commit()
                        return self.send({'username': match[1], 'reset': True})
                    if path == '/api/hosts':
                        name = str(payload.get('name', '')).strip()
                        user = str(payload.get('ssh_user', ''))
                        if not name or len(name) > 120 or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user): raise ValueError('Valid name and SSH user required')
                        port = payload.get('port', 22)
                        if type(port) is not int or not 1 <= port <= 65535: raise ValueError('Invalid SSH port')
                        item = {'id': identifier, 'name': name, 'address': validate_address(str(payload.get('address', '')), settings['networks']), 'ssh_user': user, 'port': port, 'tags': str(payload.get('tags', ''))[:500]}
                        document(db, 'hosts', identifier, item)
                    elif path == '/api/baselines':
                        item = validate(payload)
                        item = {'id': identifier, 'name': item['name'][:120], 'checks': item['checks'], 'created_at': time.time()}
                        item['revision_sha256'] = digest(item)
                        document(db, 'baselines', identifier, item)
                    elif path == '/api/bindings':
                        get(db, 'baselines', str(payload.get('baseline_id', '')))
                        hosts = payload.get('host_ids')
                        if not isinstance(hosts, list) or not 1 <= len(hosts) <= 50 or not all(isinstance(h, str) for h in hosts) or len(set(hosts)) != len(hosts): raise ValueError('Select 1–50 unique hosts')
                        for host in hosts: get(db, 'hosts', host)
                        if payload.get('external_system') not in {'serviceops', 'flowops'}: raise ValueError('Select ServiceOps or FlowOps')
                        ticket = str(payload.get('ticket_id', '')).strip()
                        if not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,120}', ticket): raise ValueError('A valid ticket/task reference is required')
                        age = payload.get('max_age_seconds', 3600)
                        after = payload.get('not_before', time.time())
                        if type(age) is not int or not 60 <= age <= 86400: raise ValueError('Evidence lifetime must be 60–86400 seconds')
                        if type(after) not in (int, float) or not 0 <= after <= time.time() + 86400: raise ValueError('Invalid upgrade completion time')
                        item = {'id': identifier, 'baseline_id': payload['baseline_id'], 'host_ids': hosts, 'external_system': payload['external_system'], 'ticket_id': ticket, 'max_age_seconds': age, 'not_before': after}
                        document(db, 'bindings', identifier, item)
                    elif path == '/api/runs':
                        binding = get(db, 'bindings', str(payload.get('binding_id', '')))
                        if time.time() < binding['not_before']: raise ValueError('Upgrade completion boundary is in the future')
                        # BEGIN IMMEDIATE serializes job admission across request threads.
                        db.execute('BEGIN IMMEDIATE')
                        if db.execute("SELECT 1 FROM runs WHERE status IN ('queued','running')").fetchone():
                            return self.send({'error': 'A collection is already queued or running'}, 409)
                        item = {'id': identifier, 'binding_id': binding['id'], 'baseline': get(db, 'baselines', binding['baseline_id']), 'hosts': [get(db, 'hosts', h) for h in binding['host_ids']], 'status': 'queued', 'created_at': time.time()}
                        db.execute('INSERT INTO runs VALUES(?,?,?,?)', (identifier, item['created_at'], 'queued', json.dumps(item)))
                    else: return self.send({'error': 'Not found'}, 404)
                    audit(db, actor, path[5:] + '.created', identifier)
                    db.commit()
                    return self.send(item, 201)
            return self.send({'error': 'Not found'}, 404)
        except (ValueError, KeyError, TypeError) as exc:
            return self.send({'error': str(exc)}, 400)
        except Exception:
            return self.send({'error': 'Internal server error'}, 500)

    def login(self, db, payload):
        username = str(payload.get('username', '')).strip().lower()
        password = str(payload.get('password', ''))
        row = db.execute('SELECT password_hash,role FROM users WHERE username=?', (username,)).fetchone()
        if row is None or not auth.verify_password(password, row['password_hash']):
            time.sleep(0.3)
            audit(db, username or '-', 'login.failed', username or '-')
            db.commit()
            return self.send({'error': 'Invalid username or password'}, 401)
        token = auth.create_session(db, username, row['role'])
        audit(db, username, 'login.success', username)
        db.commit()
        return self.send({'username': username, 'role': row['role']}, headers={'Set-Cookie': auth.cookie_header(token, auth.SESSION_LIFETIME)})

    def logout(self, db):
        token = self.session_token()
        if token: auth.delete_session(db, token)
        db.commit()
        return self.send({'status': 'ok'}, headers={'Set-Cookie': auth.cookie_header('', 0)})

def worker(server):
    while not server.stop_worker.wait(0.5):
        with connect(server.settings['db']) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT id FROM runs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if row: db.execute("UPDATE runs SET status='running' WHERE id=?", (row['id'],))
        if row: execute(row['id'], server.settings['db'], server.settings)

def bootstrap_admin(db_path, username, password):
    with connect(db_path) as db:
        # Bootstrap only runs while no accounts exist yet, so a password
        # changed later through the API survives a restart with the old
        # BASELINE_ADMIN_PASSWORD still set in the environment.
        if db.execute('SELECT 1 FROM users').fetchone(): return
        db.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)', (username, auth.hash_password(password), 'admin'))

def make_server(settings, address=('127.0.0.1', 8090), start_worker=True):
    Path(settings['db']).parent.mkdir(parents=True, exist_ok=True)
    init(settings['db'])
    bootstrap_admin(settings['db'], settings['admin_user'], settings['admin_password'])
    server = ThreadingHTTPServer(address, Handler)
    server.settings = settings
    server.stop_worker = threading.Event()
    if start_worker: threading.Thread(target=worker, args=(server,), daemon=True).start()
    return server

def main():
    server = make_server(configuration(), (os.environ.get('BASELINE_BIND', '127.0.0.1'), int(os.environ.get('BASELINE_PORT', '8090'))))
    print('Baseline listening on port ' + str(server.server_port), flush=True)
    try: server.serve_forever()
    finally:
        server.stop_worker.set()
        server.server_close()

if __name__ == '__main__': main()
