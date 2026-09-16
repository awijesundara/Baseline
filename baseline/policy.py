"""Strict, fail-closed evaluation of immutable baseline revisions."""
import hashlib
import json
import math

FIELDS = {
    'hardware.manufacturer', 'hardware.model', 'hardware.serial', 'hardware.health', 'hardware.power',
    'firmware.versions', 'firmware.inventory', 'os.name', 'os.family',
    'os.id', 'os.version', 'kernel.release', 'kernel.cmdline', 'kernel.tainted',
    'boot.id', 'bios.version', 'bios.date', 'cpu.isolated', 'cpu.nohz_full',
    'cpu.governors', 'memory.hugepages_total', 'memory.hugepages_free',
    'memory.thp', 'dkms.status', 'modules.loaded', 'services.failed',
    'time.synchronized', 'time.ptp4l_active', 'time.phc2sys_active',
    'nic.drivers', 'nic.firmware', 'nic.links', 'rpm.packages', 'kernel.packages',
    'kernel.default', 'kernel.headers_running', 'cpu.architecture', 'cpu.flags', 'os.centos7_eol',
}
OPS = {'eq', 'contains', 'not_contains', 'gte', 'lte', 'set_eq'}

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def validate(policy):
    if not isinstance(policy, dict) or not isinstance(policy.get('name'), str) or not policy['name'].strip():
        raise ValueError('A baseline name is required')
    checks = policy.get('checks')
    if not isinstance(checks, list) or not 1 <= len(checks) <= 100:
        raise ValueError('A baseline requires 1–100 checks')
    seen = set()
    for check in checks:
        if not isinstance(check, dict) or not isinstance(check.get('id'), str) or not check['id'] or check['id'] in seen:
            raise ValueError('Check IDs must be unique nonempty strings')
        seen.add(check['id'])
        if check.get('field') not in FIELDS or check.get('op') not in OPS or 'expected' not in check:
            raise ValueError('Unknown field, operator, or missing expected value')
        if type(check.get('required', True)) is not bool:
            raise ValueError('required must be boolean')
        expected = check['expected']
        if check['op'] in {'gte', 'lte'} and (type(expected) not in (int, float) or not math.isfinite(expected)):
            raise ValueError('Numeric comparisons require a finite number')
        if check['op'] == 'set_eq' and (not isinstance(expected, list) or not all(isinstance(x, str) for x in expected)):
            raise ValueError('set_eq requires a list of strings')
        if check['op'] in {'contains', 'not_contains'} and not isinstance(expected, str):
            raise ValueError('Contains checks require a string')
    if not any(c.get('required', True) for c in checks):
        raise ValueError('At least one check must be required')
    return policy

def evaluate(policy, facts):
    results = []
    for c in validate(policy)['checks']:
        actual = facts.get(c['field'])
        status = 'unknown'
        if actual is not None:
            expected, op = c['expected'], c['op']
            try:
                if op == 'eq': passed = type(actual) is type(expected) and actual == expected
                elif op == 'contains': passed = expected in actual
                elif op == 'not_contains': passed = expected not in actual
                elif op == 'set_eq': passed = isinstance(actual, list) and set(actual) == set(expected)
                else:
                    if type(actual) not in (int, float) or not math.isfinite(actual): raise ValueError()
                    passed = actual >= expected if op == 'gte' else actual <= expected
                status = 'pass' if passed else 'fail'
            except (TypeError, ValueError):
                pass
        results.append({**c, 'actual': actual, 'status': status})
    return {'status': 'pass' if all(r['status'] == 'pass' for r in results if r.get('required', True)) else 'fail', 'checks': results}
