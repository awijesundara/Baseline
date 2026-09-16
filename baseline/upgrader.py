"""Ansible-executed OS package upgrades: plan, apply in batches, verify, and
automatically roll back a batch whose post-upgrade verification fails.

Mirrors runner.py's shape deliberately: shared inventory/playbook helpers,
per-host error isolation, nothing swallowed silently. A batch that does not
end 'upgraded' halts the whole job -- later batches never start."""
import json
import re
import tempfile
import time
from pathlib import Path
from .policy import evaluate, digest
from .runner import ROOT, write_inventory, run_playbook, ssh_collect
from .store import connect, get, audit

KERNEL_PACKAGE_NAMES = {'kernel', 'kernel-core', 'kernel-modules'}
PACKAGE_NAME_RE = re.compile(r'[A-Za-z0-9_.+-]{1,200}')
KERNEL_PATH_RE = re.compile(r'/boot/[A-Za-z0-9_./+-]{1,200}')
TRANSACTION_ID_RE = re.compile(r'[0-9]{1,10}')

def read_evidence(path, allowed_ids, key):
    observed = {}
    if path.exists():
        if path.stat().st_size > 8_000_000: raise RuntimeError('Job evidence size limit exceeded')
        for line in path.read_text().splitlines():
            item = json.loads(line)
            if item['host'] not in allowed_ids or item['host'] in observed or not isinstance(item.get(key), dict):
                raise ValueError('Invalid or duplicate host evidence')
            observed[item['host']] = item[key]
    return observed

def plan_batch(hosts, settings, parallelism):
    if not hosts: return {}, 0
    with tempfile.TemporaryDirectory(prefix='baseline-plan-') as tmp:
        evidence = Path(tmp) / 'evidence.jsonl'
        inv = write_inventory(hosts, settings, tmp)
        rc = run_playbook(ROOT / 'ansible/plan.yml', inv, settings, parallelism, extra_env={'BASELINE_EVIDENCE_FILE': str(evidence)})
        return read_evidence(evidence, {h['id'] for h in hosts}, 'result'), rc

def upgrade_batch(hosts, package_names, reboot_required, settings, parallelism, timeout):
    if not hosts: return {}, 0
    safe_names = [n for n in package_names if PACKAGE_NAME_RE.fullmatch(n)]
    with tempfile.TemporaryDirectory(prefix='baseline-upgrade-') as tmp:
        evidence = Path(tmp) / 'evidence.jsonl'
        hostvars = {h['id']: {'baseline_packages': ' '.join(safe_names), 'baseline_reboot': reboot_required} for h in hosts}
        inv = write_inventory(hosts, settings, tmp, extra_hostvars=hostvars)
        rc = run_playbook(ROOT / 'ansible/upgrade.yml', inv, settings, parallelism, extra_env={'BASELINE_EVIDENCE_FILE': str(evidence)}, timeout=timeout)
        return read_evidence(evidence, {h['id'] for h in hosts}, 'result'), rc

def rollback_batch(hosts, batch_state, settings, parallelism, timeout):
    if not hosts: return {}, 0
    with tempfile.TemporaryDirectory(prefix='baseline-rollback-') as tmp:
        evidence = Path(tmp) / 'evidence.jsonl'
        hostvars = {}
        for h in hosts:
            state = batch_state[h['id']]
            transaction_id = str(state.get('upgrade', {}).get('transaction_id') or '')
            previous_kernel = str(state.get('pre', {}).get('kernel.default') or '')
            hostvars[h['id']] = {
                'baseline_transaction_id': transaction_id if TRANSACTION_ID_RE.fullmatch(transaction_id) else '',
                'baseline_previous_kernel': previous_kernel if KERNEL_PATH_RE.fullmatch(previous_kernel) else '',
                'baseline_reboot': state.get('reboot_required', False),
            }
        inv = write_inventory(hosts, settings, tmp, extra_hostvars=hostvars)
        rc = run_playbook(ROOT / 'ansible/rollback.yml', inv, settings, parallelism, extra_env={'BASELINE_EVIDENCE_FILE': str(evidence)}, timeout=timeout)
        return read_evidence(evidence, {h['id'] for h in hosts}, 'result'), rc

def compute_batches(host_ids, batch_size):
    size = batch_size if batch_size and batch_size > 0 else len(host_ids)
    return [host_ids[i:i + size] for i in range(0, len(host_ids), size)]

def rollback_policy(pre_facts, reboot_required):
    checks = [{'id': 'packages-reverted', 'field': 'rpm.packages', 'op': 'eq', 'expected': pre_facts.get('rpm.packages'), 'required': True}]
    if reboot_required:
        checks.append({'id': 'kernel-reverted', 'field': 'kernel.release', 'op': 'eq', 'expected': pre_facts.get('kernel.release'), 'required': True})
    return {'name': 'rollback-identity', 'checks': checks}

def run_plan(job_id, db_path, settings):
    with connect(db_path) as db: job = get(db, 'jobs', job_id)
    try:
        results, rc = plan_batch(job['hosts'], settings, job.get('parallelism', 5))
        for h in job['hosts']:
            if h['id'] not in results: raise RuntimeError('Plan evidence unavailable for ' + h['name'])
        candidates = {}
        for r in results.values():
            for c in r.get('candidates', []):
                if isinstance(c.get('name'), str) and PACKAGE_NAME_RE.fullmatch(c['name']):
                    candidates[c['name']] = c
        job['plan'] = {'per_host': results, 'candidates': sorted(candidates.values(), key=lambda c: c['name'])}
        job['status'] = 'planned' if candidates else 'no_changes'
    except Exception as exc:
        job['plan'] = {'error': type(exc).__name__}
        job['status'] = 'error'
    job['planned_at'] = time.time()
    with connect(db_path) as db:
        db.execute('UPDATE jobs SET status=?,document=? WHERE id=?', (job['status'], json.dumps(job), job_id))
        audit(db, 'worker', 'job.' + job['status'], job_id)

def execute_job(job_id, db_path, settings):
    with connect(db_path) as db: job = get(db, 'jobs', job_id)
    job['started_at'] = time.time()
    hosts_by_id = {h['id']: h for h in job['hosts']}
    baseline = job['baseline']
    names = [c['name'] for c in job['plan'].get('candidates', [])]
    reboot_required = any(n in KERNEL_PACKAGE_NAMES for n in names)
    parallelism = job.get('parallelism', 5)
    timeout = settings.get('upgrade_timeout', 900)
    batches = job.get('batches') or compute_batches(job['host_ids'], job.get('batch_size', 0))
    job['batch_results'] = []
    overall = 'upgraded'
    with connect(db_path) as db: audit(db, 'worker', 'job.upgrade_started', job_id)
    for index, batch_ids in enumerate(batches):
        batch_hosts = [hosts_by_id[i] for i in batch_ids]
        batch = {'index': index, 'host_ids': batch_ids, 'hosts': {}}
        try:
            pre_facts, _ = ssh_collect(batch_hosts, settings, parallelism)
        except Exception as exc:
            batch.update(status='error', error='Pre-upgrade collection failed: ' + type(exc).__name__)
            job['batch_results'].append(batch); overall = 'error'; break
        for hid in batch_ids:
            batch['hosts'][hid] = {'pre': pre_facts.get(hid, {}), 'reboot_required': reboot_required}
        try:
            upgrade_results, _ = upgrade_batch(batch_hosts, names, reboot_required, settings, parallelism, timeout)
        except Exception as exc:
            batch.update(status='error', error='Upgrade execution failed: ' + type(exc).__name__)
            job['batch_results'].append(batch); overall = 'error'; break
        errors = {}
        for hid in batch_ids:
            result = upgrade_results.get(hid)
            batch['hosts'][hid]['upgrade'] = result or {}
            if result is None or result.get('rc') != 0:
                errors[hid] = 'Upgrade did not complete cleanly'
        post_facts = {}
        if len(errors) < len(batch_ids):
            try: post_facts, _ = ssh_collect(batch_hosts, settings, parallelism)
            except Exception: post_facts = {}
        for hid in batch_ids:
            if hid in errors:
                batch['hosts'][hid]['post_verify'] = {'status': 'error'}
                continue
            facts = post_facts.get(hid)
            if facts is None:
                errors[hid] = 'Post-upgrade collection unavailable'
                batch['hosts'][hid]['post_verify'] = {'status': 'error'}
                continue
            verdict = evaluate(baseline, facts)
            batch['hosts'][hid]['post_verify'] = verdict
            if verdict['status'] != 'pass': errors[hid] = 'Post-upgrade verification failed'
        if not errors:
            batch['status'] = 'upgraded'
            job['batch_results'].append(batch)
            with connect(db_path) as db: audit(db, 'worker', 'job.batch_upgraded', job_id)
            continue
        with connect(db_path) as db: audit(db, 'worker', 'job.rollback_started', job_id)
        try:
            rollback_results, _ = rollback_batch(batch_hosts, batch['hosts'], settings, parallelism, timeout)
        except Exception as exc:
            batch.update(status='rollback_failed', error='Rollback execution failed: ' + type(exc).__name__)
            job['batch_results'].append(batch); overall = 'rollback_failed'
            with connect(db_path) as db: audit(db, 'worker', 'job.rollback_failed', job_id)
            break
        try: rollback_facts, _ = ssh_collect(batch_hosts, settings, parallelism)
        except Exception: rollback_facts = {}
        rollback_ok = True
        for hid in batch_ids:
            batch['hosts'][hid]['rollback'] = rollback_results.get(hid, {})
            facts = rollback_facts.get(hid)
            pre = batch['hosts'][hid]['pre']
            if facts is None or evaluate(rollback_policy(pre, reboot_required), facts)['status'] != 'pass':
                rollback_ok = False
                batch['hosts'][hid]['rollback_verify'] = {'status': 'error'}
            else:
                batch['hosts'][hid]['rollback_verify'] = {'status': 'ok'}
        batch['status'] = 'rolled_back' if rollback_ok else 'rollback_failed'
        job['batch_results'].append(batch)
        overall = batch['status']
        with connect(db_path) as db: audit(db, 'worker', 'job.' + batch['status'], job_id)
        break
    job['status'] = overall
    job['completed_at'] = time.time()
    job['evidence_sha256'] = digest(job)
    with connect(db_path) as db:
        db.execute('UPDATE jobs SET status=?,document=? WHERE id=?', (overall, json.dumps(job), job_id))
        audit(db, 'worker', 'job.completed', job_id)
