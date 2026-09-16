#!/bin/sh
""":"
for interpreter in python3 /usr/libexec/platform-python python2 python; do
    if command -v "$interpreter" >/dev/null 2>&1; then
        exec "$interpreter" "$0" "$@"
    fi
done
exit 127
":"""
"""Read-only dry-run of pending package upgrades. Executed transiently by Ansible; makes no changes."""
import json
import subprocess

def command(*argv, timeout=120):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return subprocess.CompletedProcess(argv, 1, '', type(exc).__name__)

def plan():
    result = command('dnf', 'check-update')
    candidates = []
    # dnf check-update exits 100 when updates are available, 0 when none, 1 on a real error.
    if result.returncode in (0, 100):
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) != 3 or '.' not in parts[0]: continue
            name_arch, version, repo = parts
            name = name_arch.rsplit('.', 1)[0]
            current = command('rpm', '-q', name, '--qf', '%{VERSION}-%{RELEASE}')
            candidates.append({'name': name, 'current': current.stdout.strip() if current.returncode == 0 else None,
                                'candidate': version, 'repo': repo})
    kernel_default = command('grubby', '--default-kernel')
    return {'candidates': candidates, 'kernel_default': kernel_default.stdout.strip() if kernel_default.returncode == 0 else None,
            'check_update_rc': result.returncode}

if __name__ == '__main__':
    print(json.dumps(plan()))
