import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import shlex
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

def write_inventory(hosts, settings, tmp, extra_hostvars=None):
    inventory = {'all': {'children': {'baseline_targets': {'hosts': {}}}}}
    for host in hosts:
        address = validate_address(host['address'], settings['networks'])
        attrs = {'ansible_host': address, 'ansible_user': host['ssh_user'], 'ansible_port': host['port'],
                 'ansible_connection': 'ssh', 'ansible_ssh_private_key_file': settings['ssh_key'],
                 'baseline_os_family':host.get('os_family','linux'),
                 'ansible_ssh_common_args':'-o StrictHostKeyChecking=yes -o UserKnownHostsFile=' + shlex.quote(settings['known_hosts'])}
        if host.get('os_family')=='windows': attrs['ansible_shell_type']='powershell'
        if extra_hostvars: attrs.update(extra_hostvars.get(host['id'], {}))
        inventory['all']['children']['baseline_targets']['hosts'][host['id']] = attrs
    inv = Path(tmp) / 'inventory.json'; inv.write_text(json.dumps(inventory))
    return inv

def run_playbook(playbook, inv, settings, parallelism, extra_env=None, timeout=None):
    env = {k:v for k,v in os.environ.items() if not k.startswith(('ANSIBLE_','BASELINE_'))}
    env.update({'ANSIBLE_CONFIG':str(ROOT/'ansible/ansible.cfg'),'ANSIBLE_CALLBACK_PLUGINS':str(ROOT/'ansible/callback_plugins'),
                'ANSIBLE_STDOUT_CALLBACK':'baseline','ANSIBLE_HOST_KEY_CHECKING':'True','ANSIBLE_RETRY_FILES_ENABLED':'False'})
    if extra_env: env.update(extra_env)
    with open(os.devnull,'w') as output:
        proc=subprocess.Popen([settings['ansible'],'-i',str(inv),str(playbook),'--forks',str(parallelism),'--timeout','15'],
                              cwd=ROOT/'ansible',env=env,stdout=output,stderr=output,start_new_session=True)
        try: return proc.wait(timeout=timeout or settings['timeout'])
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid,signal.SIGKILL);proc.wait();raise RuntimeError('Playbook run timed out')

def ssh_collect(hosts, settings, parallelism):
    if not hosts: return {}, 0
    with tempfile.TemporaryDirectory(prefix='baseline-') as tmp:
        evidence = Path(tmp) / 'evidence.jsonl'
        inv = write_inventory(hosts, settings, tmp)
        rc = run_playbook(ROOT/'ansible/verify.yml', inv, settings, parallelism, extra_env={'BASELINE_EVIDENCE_FILE':str(evidence)})
        observed={}
        if evidence.exists():
            if evidence.stat().st_size>32_000_000:raise RuntimeError('Evidence size limit exceeded')
            allowed={h['id'] for h in hosts}
            for line in evidence.read_text().splitlines():
                item=json.loads(line)
                if item['host'] not in allowed or item['host'] in observed or not isinstance(item['facts'],dict):raise ValueError('Invalid or duplicate host evidence')
                observed[item['host']]=item['facts']
        return observed,rc

def execute(run_id, db_path, settings):
    from .redfish import collect as bmc_collect
    with connect(db_path) as db:run=get(db,'runs',run_id)
    report=dict(run);report['started_at']=time.time()
    observed,errors={},{}
    parallelism=run.get('parallelism',5)
    ssh_hosts=[h for h in run['hosts'] if h.get('protocol','ssh') in {'ssh','both'}]
    try:
        observed,rc=ssh_collect(ssh_hosts,settings,parallelism)
        for h in ssh_hosts:
            if h['id'] not in observed:errors[h['id']]='SSH evidence unavailable'
        if rc:report['error']='Ansible reported a collection failure'
    except (OSError,RuntimeError,ValueError,KeyError) as exc:
        for h in ssh_hosts:errors[h['id']]='SSH collection failed: '+type(exc).__name__
    bmc_hosts=[h for h in run['hosts'] if h.get('protocol') in {'redfish','both'}]
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as pool:
        pending={pool.submit(bmc_collect,h,settings):h for h in bmc_hosts}
        for future in concurrent.futures.as_completed(pending):
            host=pending[future]
            try:
                facts=future.result()
                previous=observed.get(host['id'],{})
                for identity in ('hardware.serial','hardware.model'):
                    if previous.get(identity) and facts.get(identity) and previous[identity].strip()!=facts[identity].strip():
                        raise ValueError('OS and BMC system identity do not match')
                observed.setdefault(host['id'],{}).update(facts)
            except Exception as exc:errors[host['id']]='BMC collection failed: '+type(exc).__name__
    report['results']=[]
    for host in run['hosts']:
        facts=observed.get(host['id'],{})
        result={'host_id':host['id'],'host_name':host['name'],'facts':facts,'collection_status':'error' if host['id'] in errors else 'collected'}
        if run.get('baseline'):result.update(evaluate(run['baseline'],facts))
        else:result.update(status='collected' if facts else 'error',checks=[])
        if host['id'] in errors:result.update(error=errors[host['id']],status='error')
        report['results'].append(result)
    if errors:status='error'
    elif report.get('error'):status='fail'
    elif run.get('baseline'):status='pass' if all(r['status']=='pass' for r in report['results']) else 'fail'
    else:status='collected'
    report.update(status=status,completed_at=time.time())
    report['evidence_sha256']=digest(report)
    with connect(db_path) as db:
        db.execute('UPDATE runs SET status=?,document=? WHERE id=?',(status,json.dumps(report),run_id))
        audit(db,'runner','run.'+status,run_id)
