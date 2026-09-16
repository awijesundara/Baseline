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
from .inventory import validate_host, prepare_bulk, MAX_HOSTS
from .vendors import SOURCES, refresh as refresh_vendor, source_by_id, model_key
from .upgrader import run_plan, execute_job

JOB_ACTIVE_STATUSES = ('planning', 'running_plan', 'queued', 'running')

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
            'bmc_credentials': os.environ.get('BASELINE_BMC_CREDENTIALS', '/run/secrets/bmc_profiles.json'),
            'ansible': os.environ.get('BASELINE_ANSIBLE', 'ansible-playbook'), 'timeout': 300,
            'upgrade_timeout': int(os.environ.get('BASELINE_UPGRADE_TIMEOUT', '900'))}

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
                    if path == '/api/vendors':
                        snapshots = {r['id']: json.loads(r['document']) for r in db.execute('SELECT * FROM vendor_snapshots')}
                        query = parse_qs(urlsplit(self.path).query)
                        model = (query.get('model') or [''])[0].casefold()
                        vendors = []
                        for source in SOURCES:
                            snapshot = snapshots.get(source['id'], {})
                            candidates = snapshot.get('candidates', [])
                            if model and source['id']=='dell': candidates = [c for c in candidates if any(model_key(model) == model_key(m) for m in c.get('models', []))]
                            vendors.append({**source, 'snapshot_status':snapshot.get('status','not_refreshed'),
                                            'retrieved_at':snapshot.get('retrieved_at'), 'sha256':snapshot.get('sha256'),
                                            'stale':bool(snapshot.get('retrieved_at') and time.time()-snapshot['retrieved_at']>86400),
                                            'last_error':snapshot.get('last_error'), 'last_attempt_at':snapshot.get('last_attempt_at'),
                                            'candidate_count':len(candidates), 'candidates':candidates[:250],
                                            'truncated':len(candidates)>250})
                        return self.send({'data':vendors})
                    if path == '/api/templates':
                        return self.send({'data': [json.loads(p.read_text()) for p in sorted((ROOT / 'examples').glob('*.json'))]})
                    if path == '/api/catalog':
                        return self.send({'fields': sorted(FIELDS), 'operators': sorted(OPS), 'role': role,
                                          'runner_available': bool(shutil.which(settings['ansible'])),
                                          'max_hosts_per_run':MAX_HOSTS, 'max_parallelism':20,
                                          'ssh_configured': Path(settings['ssh_key']).is_file() and Path(settings['known_hosts']).is_file()})
                    for table in ('hosts', 'baselines', 'bindings', 'runs', 'jobs'):
                        if path == '/api/' + table:
                            rows = db.execute(f'SELECT * FROM {table}' + (' ORDER BY created DESC LIMIT 100' if table in ('runs', 'jobs') else ' ORDER BY rowid DESC')).fetchall()
                            data = []
                            for row in rows:
                                item = json.loads(row['document'])
                                if table in ('runs', 'jobs'): item['status'] = row['status']
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
                    match = re.fullmatch(r'/api/jobs/([a-f0-9]+)', path)
                    if match:
                        job = get(db, 'jobs', match[1])
                        job['status'] = db.execute('SELECT status FROM jobs WHERE id=?', (match[1],)).fetchone()[0]
                        return self.send(job)
                elif method == 'POST':
                    identifier = secrets.token_hex(12)
                    if path in {'/api/hosts', '/api/hosts/import', '/api/baselines', '/api/bindings', '/api/jobs'} and role != 'admin':
                        return self.send({'error': 'Administrator credential required'}, 403)
                    match = re.fullmatch(r'/api/jobs/([a-f0-9]+)/(confirm|cancel)', path)
                    if match:
                        if role != 'admin': return self.send({'error': 'Administrator credential required'}, 403)
                        job_id, action = match.groups()
                        job = get(db, 'jobs', job_id)
                        status = db.execute('SELECT status FROM jobs WHERE id=?', (job_id,)).fetchone()[0]
                        if action == 'confirm':
                            if status != 'planned': return self.send({'error': 'Job is not awaiting confirmation'}, 409)
                            if time.time() < job.get('not_before', 0): return self.send({'error': 'Maintenance window has not started'}, 400)
                            db.execute("UPDATE jobs SET status='queued' WHERE id=?", (job_id,))
                            audit(db, role, 'job.confirmed', job_id); db.commit()
                            job['status'] = 'queued'
                        else:
                            if status not in ('planned', 'no_changes', 'queued'): return self.send({'error': 'Job can no longer be cancelled'}, 409)
                            db.execute("UPDATE jobs SET status='cancelled' WHERE id=?", (job_id,))
                            audit(db, role, 'job.cancelled', job_id); db.commit()
                            job['status'] = 'cancelled'
                        return self.send(job)
                    if path == '/api/vendors/refresh':
                        if role != 'admin': return self.send({'error':'Administrator credential required'},403)
                        source_id = str(payload.get('source_id',''))
                        source_by_id(source_id)
                        try:
                            snapshot = refresh_vendor(source_id)
                        except Exception as exc:
                            row = db.execute('SELECT document FROM vendor_snapshots WHERE id=?',(source_id,)).fetchone()
                            snapshot = json.loads(row['document']) if row else {'id':source_id,'status':'unavailable','candidates':[]}
                            snapshot.update(last_error='Vendor retrieval failed: '+type(exc).__name__,last_attempt_at=time.time())
                        db.execute('INSERT OR REPLACE INTO vendor_snapshots VALUES(?,?)',(source_id,json.dumps(snapshot)))
                        audit(db,role,'vendor.refreshed',source_id);db.commit()
                        return self.send({'source_id':source_id,'status':snapshot['status'],'error':snapshot.get('last_error'),'candidate_count':len(snapshot['candidates'])})
                    elif path in {'/api/hosts','/api/hosts/import'}:
                        db.execute('BEGIN IMMEDIATE')
                        existing = [json.loads(r['document']) for r in db.execute('SELECT document FROM hosts')]
                        items, errors = prepare_bulk(payload if path.endswith('/import') else {'hosts':[payload]},settings,existing)
                        if errors: return self.send({'error':'Inventory was not changed; correct the highlighted rows','errors':errors},400)
                        if payload.get('preview') is True: return self.send({'data':items,'count':len(items),'preview':True})
                        for item in items:
                            document(db,'hosts',item['id'],item)
                            audit(db,role,'host.created',item['id'])
                        db.commit()
                        return self.send({'data':items,'count':len(items)} if path.endswith('/import') else items[0],201)
                    elif path == '/api/baselines':
                        item = validate(payload)
                        item = {'id': identifier, 'name': item['name'][:120], 'checks': item['checks'], 'created_at': time.time()}
                        source_ids = payload.get('source_ids',[])
                        if not isinstance(source_ids,list) or len(source_ids)>6 or not all(isinstance(i,str) for i in source_ids): raise ValueError('Invalid vendor source references')
                        item['vendor_references'] = []
                        for source_id in source_ids:
                            snapshot = get(db,'vendor_snapshots',source_id)
                            if not snapshot.get('sha256'): raise ValueError('Vendor source has no successful snapshot')
                            item['vendor_references'].append({'source_id':source_id,'url':source_by_id(source_id)['url'],'retrieved_at':snapshot['retrieved_at'],'sha256':snapshot['sha256']})
                        item['revision_sha256'] = digest(item)
                        document(db, 'baselines', identifier, item)
                    elif path == '/api/bindings':
                        get(db, 'baselines', str(payload.get('baseline_id', '')))
                        hosts = payload.get('host_ids')
                        if not isinstance(hosts, list) or not 1 <= len(hosts) <= MAX_HOSTS or not all(isinstance(h, str) for h in hosts) or len(set(hosts)) != len(hosts): raise ValueError('Select 1–200 unique hosts')
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
                        parallelism = payload.get('parallelism',5)
                        if type(parallelism) is not int or not 1 <= parallelism <= 20: raise ValueError('Parallelism must be 1–20')
                        binding_id = payload.get('binding_id')
                        if binding_id:
                            binding = get(db,'bindings',str(binding_id))
                            if time.time() < binding['not_before']: raise ValueError('Upgrade completion boundary is in the future')
                            host_ids = binding['host_ids']
                            baseline = get(db,'baselines',binding['baseline_id'])
                        else:
                            host_ids = payload.get('host_ids')
                            if not isinstance(host_ids,list) or not 1 <= len(host_ids) <= MAX_HOSTS or not all(isinstance(h,str) for h in host_ids) or len(set(host_ids))!=len(host_ids): raise ValueError('Select 1–200 unique hosts')
                            baseline = get(db,'baselines',str(payload['baseline_id'])) if payload.get('baseline_id') else None
                        db.execute('BEGIN IMMEDIATE')
                        if db.execute("SELECT 1 FROM runs WHERE status IN ('queued','running')").fetchone():
                            return self.send({'error':'A collection is already queued or running'},409)
                        item = {'id':identifier,'binding_id':binding_id,'baseline':baseline,
                                'hosts':[get(db,'hosts',h) for h in host_ids], 'parallelism':parallelism,
                                'status':'queued','created_at':time.time()}
                        db.execute('INSERT INTO runs VALUES(?,?,?,?)', (identifier, item['created_at'], 'queued', json.dumps(item)))
                    elif path == '/api/jobs':
                        name = str(payload.get('name', '')).strip()[:120]
                        description = str(payload.get('description', '')).strip()[:2000]
                        baseline = get(db, 'baselines', str(payload.get('baseline_id', '')))
                        binding_id = payload.get('binding_id')
                        if binding_id:
                            binding = get(db, 'bindings', str(binding_id))
                            host_ids = binding['host_ids']
                        else:
                            host_ids = payload.get('host_ids')
                            if not isinstance(host_ids,list) or not 1 <= len(host_ids) <= MAX_HOSTS or not all(isinstance(h,str) for h in host_ids) or len(set(host_ids))!=len(host_ids): raise ValueError('Select 1–200 unique hosts')
                        hosts = [get(db, 'hosts', h) for h in host_ids]
                        parallelism = payload.get('parallelism', 5)
                        if type(parallelism) is not int or not 1 <= parallelism <= 20: raise ValueError('Parallelism must be 1–20')
                        batch_size = payload.get('batch_size', 0)
                        if type(batch_size) is not int or isinstance(batch_size,bool) or not 0 <= batch_size <= len(host_ids): raise ValueError('Invalid batch size')
                        not_before = payload.get('not_before', time.time())
                        if type(not_before) not in (int, float) or not 0 <= not_before <= time.time() + 86400: raise ValueError('Invalid maintenance window start')
                        db.execute('BEGIN IMMEDIATE')
                        if db.execute(f"SELECT 1 FROM jobs WHERE status IN ({','.join('?' * len(JOB_ACTIVE_STATUSES))})", JOB_ACTIVE_STATUSES).fetchone():
                            return self.send({'error': 'An upgrade job is already planning or running'}, 409)
                        item = {'id':identifier,'name':name or None,'description':description or None,'binding_id':binding_id,'baseline_id':baseline['id'],'baseline':baseline,
                                'host_ids':host_ids,'hosts':hosts,'parallelism':parallelism,
                                'batch_size':batch_size,'not_before':not_before,'status':'planning','created_at':time.time()}
                        db.execute('INSERT INTO jobs VALUES(?,?,?,?)', (identifier, item['created_at'], 'planning', json.dumps(item)))
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

def job_worker(server):
    # Two independent stages, drained one tick at a time: a dry-run plan never
    # mutates a host, so it is not gated by the same admission check as a real
    # upgrade run further below.
    while not server.stop_worker.wait(0.5):
        with connect(server.settings['db']) as db:
            db.execute('BEGIN IMMEDIATE')
            planning = db.execute("SELECT id FROM jobs WHERE status='planning' ORDER BY created LIMIT 1").fetchone()
            if planning: db.execute("UPDATE jobs SET status='running_plan' WHERE id=?", (planning['id'],))
        if planning: run_plan(planning['id'], server.settings['db'], server.settings)
        with connect(server.settings['db']) as db:
            db.execute('BEGIN IMMEDIATE')
            queued = db.execute("SELECT id FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if queued: db.execute("UPDATE jobs SET status='running' WHERE id=?", (queued['id'],))
        if queued: execute_job(queued['id'], server.settings['db'], server.settings)

def make_server(settings, address=('127.0.0.1', 8090), start_worker=True):
    Path(settings['db']).parent.mkdir(parents=True, exist_ok=True)
    init(settings['db'])
    server = ThreadingHTTPServer(address, Handler)
    server.settings = settings
    server.stop_worker = threading.Event()
    if start_worker:
        threading.Thread(target=worker, args=(server,), daemon=True).start()
        threading.Thread(target=job_worker, args=(server,), daemon=True).start()
    return server

def main():
    server = make_server(configuration(), (os.environ.get('BASELINE_BIND', '127.0.0.1'), int(os.environ.get('BASELINE_PORT', '8090'))))
    print('Baseline listening on port ' + str(server.server_port), flush=True)
    try: server.serve_forever()
    finally:
        server.stop_worker.set()
        server.server_close()

if __name__ == '__main__': main()
