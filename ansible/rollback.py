#!/bin/sh
""":"
for interpreter in python3 /usr/libexec/platform-python python2 python; do
    if command -v "$interpreter" >/dev/null 2>&1; then
        exec "$interpreter" "$0" "$@"
    fi
done
exit 127
":"""
"""Undo a previous dnf transaction and restore the previous default kernel.
Executed transiently by Ansible, only after a post-upgrade verification failure."""
import json
import subprocess
import sys

def command(*argv, timeout=600):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return subprocess.CompletedProcess(argv, 1, '', type(exc).__name__)

def rollback(transaction_id, previous_kernel):
    if not transaction_id:
        return {'rc': 1, 'stderr': 'No transaction id was captured; cannot roll back automatically'}
    result = command('dnf', 'history', 'undo', transaction_id, '-y')
    kernel_result = command('grubby', '--set-default', previous_kernel) if previous_kernel else None
    return {'rc': result.returncode, 'stderr': (result.stderr or '')[-2000:],
            'kernel_rc': kernel_result.returncode if kernel_result else None}

if __name__ == '__main__':
    tid = sys.argv[1] if len(sys.argv) > 1 else ''
    prev_kernel = sys.argv[2] if len(sys.argv) > 2 else ''
    print(json.dumps(rollback(tid, prev_kernel)))
