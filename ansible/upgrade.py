#!/bin/sh
""":"
for interpreter in python3 /usr/libexec/platform-python python2 python; do
    if command -v "$interpreter" >/dev/null 2>&1; then
        exec "$interpreter" "$0" "$@"
    fi
done
exit 127
":"""
"""Apply a bounded package upgrade. Executed transiently by Ansible; the exact
package set is decided by the controller from a prior dry-run, never 'everything'."""
import json
import subprocess
import sys

def command(*argv, timeout=600):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return subprocess.CompletedProcess(argv, 1, '', type(exc).__name__)

def upgrade(names):
    if not names:
        return {'rc': 0, 'after': {}, 'transaction_id': None, 'note': 'No packages named by the plan'}
    result = command('dnf', 'upgrade', '-y', *names)
    after = {name: (lambda p: p.stdout.strip() if p.returncode == 0 else None)(command('rpm', '-q', name, '--qf', '%{VERSION}-%{RELEASE}')) for name in names}
    history = command('dnf', 'history', 'list')
    transaction_id = None
    for line in (history.stdout or '').splitlines():
        stripped = line.strip()
        if stripped and stripped[0].isdigit():
            transaction_id = stripped.split()[0]
            break
    kernel_default = command('grubby', '--default-kernel')
    return {'rc': result.returncode, 'stderr': (result.stderr or '')[-2000:], 'after': after,
            'transaction_id': transaction_id, 'kernel_default': kernel_default.stdout.strip() if kernel_default.returncode == 0 else None}

if __name__ == '__main__':
    print(json.dumps(upgrade(sys.argv[1:])))
