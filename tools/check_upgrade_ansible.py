"""Exercise the real plan/upgrade/rollback playbooks and callback on disposable local
inventory aliases. Mirrors tools/check_ansible.py's approach for verify.yml."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]

def run(playbook, hostvars):
    with tempfile.TemporaryDirectory(prefix='baseline-ansible-test-') as tmp:
        inventory = Path(tmp) / 'inventory.json'
        evidence = Path(tmp) / 'evidence.jsonl'
        hosts = {'local_a': {'ansible_connection': 'local', 'baseline_os_family': 'linux', **hostvars},
                 'local_b': {'ansible_connection': 'local', 'baseline_os_family': 'linux', **hostvars}}
        inventory.write_text(json.dumps({'all': {'children': {'baseline_targets': {'hosts': hosts}}}}))
        env = {k: v for k, v in os.environ.items() if not k.startswith(('ANSIBLE_', 'BASELINE_'))}
        env.update(ANSIBLE_CONFIG=str(root / 'ansible/ansible.cfg'), ANSIBLE_CALLBACK_PLUGINS=str(root / 'ansible/callback_plugins'),
                    ANSIBLE_STDOUT_CALLBACK='baseline', BASELINE_EVIDENCE_FILE=str(evidence),
                    ANSIBLE_LOCAL_TEMP=tmp + '/ansible', ANSIBLE_REMOTE_TEMP=tmp + '/remote', ANSIBLE_HOME=tmp + '/home')
        result = subprocess.run([sys.executable, '-m', 'ansible.cli.playbook', '-i', str(inventory), str(root / 'ansible' / playbook), '--forks', '2'],
                                 env=env, cwd=root / 'ansible', capture_output=True, text=True, timeout=90)
        if result.returncode:
            print(result.stdout, result.stderr); raise SystemExit(result.returncode)
        rows = [json.loads(line) for line in evidence.read_text().splitlines()] if evidence.exists() else []
        return {r['host']: r['result'] for r in rows}

plan = run('plan.yml', {})
assert set(plan) == {'local_a', 'local_b'}, plan
assert 'candidates' in plan['local_a'] and 'check_update_rc' in plan['local_a'], plan
print('PASS: plan.yml ran and reported', plan['local_a']['check_update_rc'], 'from dnf check-update (0/1/100 all valid on a real dnf host)')

upgrade = run('upgrade.yml', {'baseline_packages': '', 'baseline_reboot': False})
assert set(upgrade) == {'local_a', 'local_b'}, upgrade
assert upgrade['local_a']['rc'] == 0 and upgrade['local_a']['note'] == 'No packages named by the plan', upgrade
print('PASS: upgrade.yml with an empty package set is a safe no-op, as required')

rollback = run('rollback.yml', {'baseline_transaction_id': '', 'baseline_previous_kernel': '', 'baseline_reboot': False})
assert set(rollback) == {'local_a', 'local_b'}, rollback
assert rollback['local_a']['rc'] == 1 and 'No transaction id' in rollback['local_a']['stderr'], rollback
print('PASS: rollback.yml refuses to guess without a captured transaction id, as required')
print('This is controller-platform validation only, not a real dnf/grubby acceptance run against a managed host.')
