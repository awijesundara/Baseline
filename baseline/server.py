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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from .policy import FIELDS, OPS, validate, digest
from .runner import execute, validate_address
from .store import init, connect, get, audit

ROOT = Path(__file__).resolve().parents[1]

def configuration():
    token = os.environ.get('BASELINE_ADMIN_TOKEN', '')
    if len(token) < 32: raise ValueError('Set BASELINE_ADMIN_TOKEN to a random secret of at least 32 characters')
    tokens = {'admin': token, 'integration': os.environ.get('BASELINE_INTEGRATION_TOKEN', ''), 'reader': os.environ.get('BASELINE_READ_TOKEN', '')}
    populated = [v for v in tokens.values() if v]
    if any(len(v) < 32 for v in populated) or len(set(populated)) != len(populated):
        raise ValueError('Configured role tokens must be distinct and at least 32 characters')
    return {'tokens': tokens, 'db': os.environ.get('BASELINE_DB', str(ROOT / 'data/baseline.db')),
            'networks': os.environ.get('BASELINE_ALLOWED_NETWORKS', '').split(','),
            'ssh_key': os.environ.get('BASELINE_SSH_KEY', '/run/secrets/ssh_key'),
            'known_hosts': os.environ.get('BASELINE_KNOWN_HOSTS', '/run/secrets/known_hosts'),
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

    def send(self, data, status=200, content_type='application/json'):
        body = json.dumps(data).encode() if content_type == 'application/json' else data
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def role(self):
        supplied = self.headers.get('Authorization', '').removeprefix('Bearer ')
        for role, token in self.server.settings['tokens'].items():
            if token and hmac.compare_digest(supplied, token): return role
        return None

    def do_GET(self): self.dispatch('GET')
    def do_POST(self): self.dispatch('POST')

    def dispatch(self, method):
        path = urlsplit(self.path).path
        settings = self.server.settings
        try:
            if method == 'GET' and path in {'/health', '/ready'}:
                with connect(settings['db']) as db: db.execute('SELECT 1').fetchone()
                return self.send({'status': 'ok'})
            static = {'/': 'index.html', '/app.js': 'app.js', '/styles.css': 'styles.css'}
            if method == 'GET' and path in static:
                name = static[path]
                return self.send((ROOT / 'static' / name).read_bytes(), content_type={'html': 'text/html; charset=utf-8', 'js': 'text/javascript', 'css': 'text/css'}[name.split('.')[-1]])
            role = self.role()
            if not role: return self.send({'error': 'Authentication required'}, 401)
            if method == 'POST':
                if role == 'reader': return self.send({'error': 'Read-only credential'}, 403)
                origin = self.headers.get('Origin')
                if origin and urlsplit(origin).netloc != self.headers.get('Host'): return self.send({'error': 'Cross-origin request denied'}, 403)
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json': raise ValueError('JSON body required')
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 128000: raise ValueError('Body must be 1–128000 bytes')
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict): raise ValueError('JSON object required')
            with connect(settings['db']) as db:
                if method == 'GET':
                    if path == '/api/templates':
                        return self.send({'data': [json.loads(p.read_text()) for p in sorted((ROOT / 'examples').glob('*.json'))]})
                    if path == '/api/catalog':
                        return self.send({'fields': sorted(FIELDS), 'operators': sorted(OPS), 'role': role,
                                          'runner_available': bool(shutil.which(settings['ansible'])),
                                          'ssh_configured': Path(settings['ssh_key']).is_file() and Path(settings['known_hosts']).is_file()})
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
                    if path in {'/api/hosts', '/api/baselines', '/api/bindings'} and role != 'admin':
                        return self.send({'error': 'Administrator credential required'}, 403)
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
                    audit(db, role, path[5:] + '.created', identifier)
                    db.commit()
                    return self.send(item, 201)
            return self.send({'error': 'Not found'}, 404)
        except (ValueError, KeyError, TypeError) as exc:
            return self.send({'error': str(exc)}, 400)
        except Exception:
            return self.send({'error': 'Internal server error'}, 500)

def worker(server):
    while not server.stop_worker.wait(0.5):
        with connect(server.settings['db']) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT id FROM runs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if row: db.execute("UPDATE runs SET status='running' WHERE id=?", (row['id'],))
        if row: execute(row['id'], server.settings['db'], server.settings)

def make_server(settings, address=('127.0.0.1', 8090), start_worker=True):
    Path(settings['db']).parent.mkdir(parents=True, exist_ok=True)
    init(settings['db'])
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
