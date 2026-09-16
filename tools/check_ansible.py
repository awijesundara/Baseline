"""Exercise the real playbook and callback on two disposable local inventory aliases."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='baseline-ansible-test-') as tmp:
    inventory=Path(tmp)/'inventory.json';evidence=Path(tmp)/'evidence.jsonl'
    inventory.write_text(json.dumps({'all':{'children':{'baseline_targets':{'hosts':{'local_a':{'ansible_connection':'local'},'local_b':{'ansible_connection':'local'}}}}}}))
    env={k:v for k,v in os.environ.items() if not k.startswith(('ANSIBLE_','BASELINE_'))}
    env.update(ANSIBLE_CONFIG=str(root/'ansible/ansible.cfg'),ANSIBLE_CALLBACK_PLUGINS=str(root/'ansible/callback_plugins'),ANSIBLE_STDOUT_CALLBACK='baseline',BASELINE_EVIDENCE_FILE=str(evidence),ANSIBLE_LOCAL_TEMP=tmp+'/ansible',ANSIBLE_REMOTE_TEMP=tmp+'/remote',ANSIBLE_HOME=tmp+'/home')
    result=subprocess.run([sys.executable,'-m','ansible.cli.playbook','-i',str(inventory),str(root/'ansible/verify.yml'),'--forks','2'],env=env,cwd=root/'ansible',capture_output=True,text=True,timeout=60)
    if result.returncode:print(result.stdout,result.stderr);raise SystemExit(result.returncode)
    if not evidence.exists(): print(result.stdout,result.stderr);raise SystemExit('Callback did not capture evidence')
    rows=[json.loads(line) for line in evidence.read_text().splitlines()]
    assert {r['host'] for r in rows}=={'local_a','local_b'},rows
    assert all(r['facts'].get('kernel.release') for r in rows)
    print('PASS: actual Ansible playbook and callback collected both local aliases; this is controller-platform validation, not remote Linux or BMC acceptance')
