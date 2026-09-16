"""Real local HTTP server + real SQLite, matching tests/test_baseline.py's style.
Ansible itself is stubbed via the same subprocess.Popen patch pattern already
used there -- these tests exercise the plan/confirm/batch/rollback state
machine in upgrader.py and server.py, not real dnf/grubby behavior (that is
covered separately by tools/check_upgrade_ansible.py against real Ansible)."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch
from baseline.server import make_server
from baseline.upgrader import run_plan, execute_job

BASELINE = {'name': 'Target kernel', 'checks': [{'id': 'kernel', 'field': 'kernel.release', 'op': 'eq', 'expected': 'target-kernel'}]}

def facts(kernel, packages):
    return lambda hids: {hid: {'host': hid, 'facts': {'kernel.release': kernel, 'rpm.packages': packages}} for hid in hids}

def plan_result(candidates, kernel_default='/boot/vmlinuz-old', rc=100):
    return lambda hids: {hid: {'host': hid, 'result': {'candidates': candidates, 'kernel_default': kernel_default, 'check_update_rc': rc}} for hid in hids}

def upgrade_result(rc=0, transaction_id='5'):
    return lambda hids: {hid: {'host': hid, 'result': {'rc': rc, 'after': {'kernel': 'new'}, 'transaction_id': transaction_id, 'kernel_default': '/boot/vmlinuz-new'}} for hid in hids}

def rollback_result(rc=0):
    return lambda hids: {hid: {'host': hid, 'result': {'rc': rc, 'stderr': '', 'kernel_rc': 0}} for hid in hids}

class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = {'db': self.tmp.name + '/db.sqlite', 'tokens': {'admin': 'a' * 40, 'reader': 'r' * 40, 'integration': 'i' * 40},
                          'networks': ['10.0.0.0/8'], 'ansible': 'missing-ansible', 'ssh_key': '/missing/key',
                          'known_hosts': '/missing/known', 'timeout': 2, 'upgrade_timeout': 2}
        self.server = make_server(self.settings, ('127.0.0.1', 0), False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.tmp.cleanup()

    def request(self, path, body=None, role='admin', headers=None):
        req = Request(self.url + path, data=json.dumps(body).encode() if body is not None else None,
                       headers={'Authorization': 'Bearer ' + self.settings['tokens'].get(role, ''), 'Content-Type': 'application/json', **(headers or {})})
        try:
            with urlopen(req) as r: return r.status, json.load(r)
        except HTTPError as e: return e.code, json.load(e)

    def add_host(self, name, address):
        _, h = self.request('/api/hosts', {'name': name, 'address': address, 'ssh_user': 'baseline'})
        return h

    def fake(self, behaviors):
        def process(argv, **kwargs):
            inventory = json.loads(Path(argv[2]).read_text())
            host_ids = list(inventory['all']['children']['baseline_targets']['hosts'].keys())
            queue = behaviors.get(Path(argv[3]).name)
            if queue:
                writer = queue.pop(0)
                with open(kwargs['env']['BASELINE_EVIDENCE_FILE'], 'a') as f:
                    for payload in writer(host_ids).values():
                        f.write(json.dumps(payload) + '\n')
            class Proc:
                def wait(self, timeout=None): return 0
            return Proc()
        return process

    def test_plan_confirm_and_clean_upgrade_passes(self):
        h = self.add_host('HFT-01', '10.1.2.3')
        _, b = self.request('/api/baselines', BASELINE)
        _, job = self.request('/api/jobs', {'baseline_id': b['id'], 'host_ids': [h['id']]})
        self.assertEqual(job['status'], 'planning')
        behaviors = {'plan.yml': [plan_result([{'name': 'kernel', 'current': 'old', 'candidate': 'new', 'repo': 'baseos'}])],
                     'verify.yml': [facts('old-kernel', 'pkg-old'), facts('target-kernel', 'pkg-new')],
                     'upgrade.yml': [upgrade_result()]}
        with patch('baseline.runner.subprocess.Popen', side_effect=self.fake(behaviors)):
            run_plan(job['id'], self.settings['db'], self.settings)
            _, job = self.request('/api/jobs/' + job['id'])
            self.assertEqual(job['status'], 'planned')
            self.assertEqual([c['name'] for c in job['plan']['candidates']], ['kernel'])
            status, job = self.request('/api/jobs/' + job['id'] + '/confirm', {})
            self.assertEqual(status, 200); self.assertEqual(job['status'], 'queued')
            execute_job(job['id'], self.settings['db'], self.settings)
        _, job = self.request('/api/jobs/' + job['id'])
        self.assertEqual(job['status'], 'upgraded')
        self.assertEqual(job['batch_results'][0]['status'], 'upgraded')

    def test_no_changes_plan_cannot_be_confirmed(self):
        h = self.add_host('HFT-02', '10.1.2.4')
        _, b = self.request('/api/baselines', BASELINE)
        _, job = self.request('/api/jobs', {'baseline_id': b['id'], 'host_ids': [h['id']]})
        with patch('baseline.runner.subprocess.Popen', side_effect=self.fake({'plan.yml': [plan_result([])]})):
            run_plan(job['id'], self.settings['db'], self.settings)
        _, job = self.request('/api/jobs/' + job['id'])
        self.assertEqual(job['status'], 'no_changes')
        status, _ = self.request('/api/jobs/' + job['id'] + '/confirm', {})
        self.assertEqual(status, 409)

    def test_failed_post_verify_triggers_automatic_rollback(self):
        h = self.add_host('HFT-03', '10.1.2.5')
        _, b = self.request('/api/baselines', BASELINE)
        _, job = self.request('/api/jobs', {'baseline_id': b['id'], 'host_ids': [h['id']]})
        behaviors = {'plan.yml': [plan_result([{'name': 'kernel', 'current': 'old', 'candidate': 'new', 'repo': 'baseos'}])],
                     'verify.yml': [facts('old-kernel', 'pkg-old'), facts('still-old-kernel', 'pkg-broken'), facts('old-kernel', 'pkg-old')],
                     'upgrade.yml': [upgrade_result()], 'rollback.yml': [rollback_result()]}
        with patch('baseline.runner.subprocess.Popen', side_effect=self.fake(behaviors)):
            run_plan(job['id'], self.settings['db'], self.settings)
            self.request('/api/jobs/' + job['id'] + '/confirm', {})
            execute_job(job['id'], self.settings['db'], self.settings)
        _, job = self.request('/api/jobs/' + job['id'])
        self.assertEqual(job['status'], 'rolled_back')
        self.assertEqual(job['batch_results'][0]['status'], 'rolled_back')

    def test_rollback_failure_surfaces_and_halts_remaining_batches(self):
        h1 = self.add_host('HFT-04', '10.1.2.6')
        h2 = self.add_host('HFT-05', '10.1.2.7')
        _, b = self.request('/api/baselines', BASELINE)
        _, job = self.request('/api/jobs', {'baseline_id': b['id'], 'host_ids': [h1['id'], h2['id']], 'batch_size': 1})
        behaviors = {'plan.yml': [plan_result([{'name': 'kernel', 'current': 'old', 'candidate': 'new', 'repo': 'baseos'}])],
                     # batch 1 (single host): pre, failing post, failing rollback-verify -> rollback_failed, halts before batch 2
                     'verify.yml': [facts('old-kernel', 'pkg-old'), facts('broken', 'pkg-broken'), facts('still-broken', 'pkg-broken')],
                     'upgrade.yml': [upgrade_result()], 'rollback.yml': [rollback_result()]}
        with patch('baseline.runner.subprocess.Popen', side_effect=self.fake(behaviors)):
            run_plan(job['id'], self.settings['db'], self.settings)
            self.request('/api/jobs/' + job['id'] + '/confirm', {})
            execute_job(job['id'], self.settings['db'], self.settings)
        _, job = self.request('/api/jobs/' + job['id'])
        self.assertEqual(job['status'], 'rollback_failed')
        self.assertEqual(len(job['batch_results']), 1, 'the second batch must never start once the first fails to roll back')

    def test_maintenance_window_gate_blocks_early_confirm(self):
        h = self.add_host('HFT-06', '10.1.2.8')
        _, b = self.request('/api/baselines', BASELINE)
        _, job = self.request('/api/jobs', {'baseline_id': b['id'], 'host_ids': [h['id']], 'not_before': time.time() + 3600})
        with patch('baseline.runner.subprocess.Popen', side_effect=self.fake({'plan.yml': [plan_result([{'name': 'kernel', 'current': 'old', 'candidate': 'new', 'repo': 'baseos'}])]})):
            run_plan(job['id'], self.settings['db'], self.settings)
        status, body = self.request('/api/jobs/' + job['id'] + '/confirm', {})
        self.assertEqual(status, 400)
        self.assertIn('window', body['error'])

    def test_one_mutating_job_at_a_time(self):
        h = self.add_host('HFT-07', '10.1.2.9')
        _, b = self.request('/api/baselines', BASELINE)
        status, _ = self.request('/api/jobs', {'baseline_id': b['id'], 'host_ids': [h['id']]})
        self.assertEqual(status, 201)
        status, body = self.request('/api/jobs', {'baseline_id': b['id'], 'host_ids': [h['id']]})
        self.assertEqual(status, 409)
        self.assertIn('already', body['error'])

    def test_cancel_before_confirm_then_confirm_refused(self):
        h = self.add_host('HFT-08', '10.1.2.10')
        _, b = self.request('/api/baselines', BASELINE)
        _, job = self.request('/api/jobs', {'baseline_id': b['id'], 'host_ids': [h['id']]})
        with patch('baseline.runner.subprocess.Popen', side_effect=self.fake({'plan.yml': [plan_result([{'name': 'kernel', 'current': 'old', 'candidate': 'new', 'repo': 'baseos'}])]})):
            run_plan(job['id'], self.settings['db'], self.settings)
        status, job = self.request('/api/jobs/' + job['id'] + '/cancel', {})
        self.assertEqual(status, 200); self.assertEqual(job['status'], 'cancelled')
        status, _ = self.request('/api/jobs/' + job['id'] + '/confirm', {})
        self.assertEqual(status, 409)

    def test_reader_and_integration_cannot_create_or_confirm_jobs(self):
        h = self.add_host('HFT-09', '10.1.2.11')
        _, b = self.request('/api/baselines', BASELINE)
        for role in ('reader', 'integration'):
            status, _ = self.request('/api/jobs', {'baseline_id': b['id'], 'host_ids': [h['id']]}, role=role)
            self.assertEqual(status, 403)

if __name__ == '__main__':
    unittest.main()
