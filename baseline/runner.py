import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from .policy import evaluate, digest
from .store import connect, get, audit

ROOT = Path(__file__).resolve().parents[1]

def validate_address(address, networks):
    try: addr = ipaddress.ip_address(address)
    except ValueError: raise ValueError('Use a literal management IP address')
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        raise ValueError('Loopback, link-local, multicast and unspecified targets are forbidden')
    if not any(addr in ipaddress.ip_network(n.strip()) for n in networks if n.strip()):
        raise ValueError('Management IP is outside BASELINE_ALLOWED_NETWORKS')
    return str(addr)

def execute(run_id, db_path, settings):
    with connect(db_path) as db:
        run = get(db, 'runs', run_id)
    report = dict(run)
    report['started_at'] = time.time()
    status = 'error'
    try:
        with tempfile.TemporaryDirectory(prefix='baseline-') as tmp:
            evidence = Path(tmp) / 'evidence.jsonl'
            inventory = {'all': {'children': {'baseline_targets': {'hosts': {}}}}}
            for host in run['hosts']:
                address = validate_address(host['address'], settings['networks'])
                inventory['all']['children']['baseline_targets']['hosts'][host['id']] = {
                    'ansible_host': address, 'ansible_user': host['ssh_user'], 'ansible_port': host['port'],
                    'ansible_connection': 'ssh', 'ansible_ssh_private_key_file': settings['ssh_key'],
                    'ansible_ssh_common_args': '-o StrictHostKeyChecking=yes -o UserKnownHostsFile=' + settings['known_hosts'],
                }
            inv = Path(tmp) / 'inventory.json'
            inv.write_text(json.dumps(inventory))
            env = {k: v for k, v in os.environ.items() if not k.startswith('ANSIBLE_') and k not in {'BASELINE_ADMIN_TOKEN', 'BASELINE_INTEGRATION_TOKEN', 'BASELINE_READ_TOKEN'}}
            env.update({'ANSIBLE_CONFIG': str(ROOT / 'ansible/ansible.cfg'),
                        'ANSIBLE_CALLBACK_PLUGINS': str(ROOT / 'ansible/callback_plugins'),
                        'ANSIBLE_CALLBACKS_ENABLED': 'baseline', 'ANSIBLE_HOST_KEY_CHECKING': 'True',
                        'ANSIBLE_RETRY_FILES_ENABLED': 'False', 'BASELINE_EVIDENCE_FILE': str(evidence)})
            # A process group allows timeout to stop Ansible and its SSH children.
            with open(os.devnull, 'w') as output:
                proc = subprocess.Popen([settings['ansible'], '-i', str(inv), str(ROOT / 'ansible/verify.yml'), '--forks', '5', '--timeout', '15'],
                                        cwd=ROOT / 'ansible', env=env, stdout=output, stderr=output, start_new_session=True)
                try: rc = proc.wait(timeout=settings['timeout'])
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                    raise RuntimeError('Collection timed out; verification denied')
            observed = {}
            if evidence.exists():
                if evidence.stat().st_size > 8_000_000: raise RuntimeError('Evidence size limit exceeded')
                for line in evidence.read_text().splitlines():
                    item = json.loads(line)
                    if item['host'] in observed: raise RuntimeError('Duplicate host evidence')
                    observed[item['host']] = item['facts']
            report['results'] = [{'host_id': h['id'], 'facts': observed.get(h['id'], {}),
                                  **evaluate(run['baseline'], observed.get(h['id'], {}))} for h in run['hosts']]
            status = 'pass' if rc == 0 and all(r['status'] == 'pass' for r in report['results']) else 'fail'
            if rc: report['error'] = 'Ansible failed or a host was unreachable; verification denied'
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        report['error'] = 'Collection failed: ' + type(exc).__name__
    report.update(status=status, completed_at=time.time())
    report['evidence_sha256'] = digest(report)
    with connect(db_path) as db:
        db.execute('UPDATE runs SET status=?,document=? WHERE id=?', (status, json.dumps(report), run_id))
        audit(db, 'runner', 'run.' + status, run_id)
