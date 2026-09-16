#!/bin/sh
""":"
for interpreter in python3 /usr/libexec/platform-python python2 python; do
    if command -v "$interpreter" >/dev/null 2>&1; then
        exec "$interpreter" "$0" "$@"
    fi
done
exit 127
":"""
"""Read-only Linux snapshot. Executed transiently by Ansible; no daemon installed."""
import glob
import json
import os
import platform
import subprocess
import threading

def read(path):
    try:
        with open(path) as f: return f.read().strip()
    except OSError: return None

def command(*argv):
    try:
        env = dict(os.environ, LC_ALL='C')
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        timer = threading.Timer(10, p.kill)
        timer.start()
        try:
            stdout, _ = p.communicate()
        finally:
            timer.cancel()
        return stdout.decode('utf-8', 'replace').strip() if p.returncode == 0 else None
    except OSError: return None

def collect():
    facts = {'kernel.release': platform.release(), 'cpu.architecture': platform.machine(), 'os.family': platform.system()}
    if platform.system() != 'Linux':
        facts.update({'os.id': platform.system().lower(), 'os.name': platform.system(), 'os.version': platform.release()})
        if platform.system() == 'AIX':
            facts['os.version'] = command('oslevel', '-s')
            facts['hardware.model'] = command('uname', '-M')
            facts['bios.version'] = command('lsattr', '-El', 'sys0', '-a', 'fwversion', '-F', 'value')
        return facts
    release = read('/etc/os-release') or ''
    values = dict(line.split('=', 1) for line in release.splitlines() if '=' in line)
    facts.update({'os.id': values.get('ID', '').strip('"'), 'os.version': values.get('VERSION_ID', '').strip('"'), 'os.name': values.get('PRETTY_NAME', '').strip('"')})
    paths = {'kernel.cmdline': '/proc/cmdline', 'boot.id': '/proc/sys/kernel/random/boot_id',
             'hardware.manufacturer': '/sys/class/dmi/id/sys_vendor', 'hardware.model': '/sys/class/dmi/id/product_name',
             'hardware.serial': '/sys/class/dmi/id/product_serial', 'bios.version': '/sys/class/dmi/id/bios_version', 'bios.date': '/sys/class/dmi/id/bios_date',
             'cpu.isolated': '/sys/devices/system/cpu/isolated', 'cpu.nohz_full': '/sys/devices/system/cpu/nohz_full',
             'memory.thp': '/sys/kernel/mm/transparent_hugepage/enabled'}
    facts.update({k: read(v) for k, v in paths.items()})
    taint = read('/proc/sys/kernel/tainted')
    facts['kernel.tainted'] = int(taint) if taint and taint.isdigit() else None
    governors = [read(p) for p in glob.glob('/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor')]
    facts['cpu.governors'] = sorted(set(governors)) if governors and all(g is not None for g in governors) else None
    mem = read('/proc/meminfo') or ''
    for source, dest in [('HugePages_Total', 'memory.hugepages_total'), ('HugePages_Free', 'memory.hugepages_free')]:
        matches = [line.split(':')[1].strip() for line in mem.splitlines() if line.startswith(source + ':')]
        facts[dest] = int(matches[0]) if matches and matches[0].isdigit() else None
    modules = read('/proc/modules')
    facts['modules.loaded'] = [line.split()[0] for line in modules.splitlines()] if modules is not None else None
    facts['dkms.status'] = command('dkms', 'status')
    facts['rpm.packages'] = command('rpm', '-qa', '--qf', '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n')
    facts['kernel.packages'] = command('rpm', '-q', 'kernel', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}\n')
    facts['kernel.default'] = command('grubby', '--default-kernel')
    facts['kernel.headers_running'] = command('rpm', '-q', 'kernel-devel-' + platform.release())
    cpuinfo = read('/proc/cpuinfo') or ''
    facts['cpu.flags'] = next((line.split(':', 1)[1].strip().split() for line in cpuinfo.splitlines() if line.startswith('flags')), None)
    facts['os.centos7_eol'] = (values.get('ID', '').strip('"') == 'centos' and values.get('VERSION_ID', '').strip('"').split('.')[0] == '7')
    facts['services.failed'] = command('systemctl', '--failed', '--no-legend', '--plain', '--no-pager')
    facts['time.synchronized'] = command('timedatectl', 'show', '--property=NTPSynchronized', '--value')
    for svc in ('ptp4l', 'phc2sys'):
        facts['time.' + svc + '_active'] = command('systemctl', 'is-active', svc)
    drivers, firmware, links = [], [], []
    complete = True
    for path in sorted(glob.glob('/sys/class/net/*')):
        if not os.path.exists(path + '/device'): continue
        nic = os.path.basename(path)
        info = command('ethtool', '-i', nic)
        if info is None:
            complete = False
            continue
        attrs = dict(line.split(': ', 1) for line in info.splitlines() if ': ' in line)
        drivers.append(nic + ':' + attrs.get('driver', '') + ':' + attrs.get('version', ''))
        firmware.append(nic + ':' + attrs.get('firmware-version', ''))
        links.append(nic + ':' + (read(path + '/operstate') or 'unknown'))
    facts['nic.drivers'] = drivers if complete and drivers else None
    facts['nic.firmware'] = firmware if complete and firmware else None
    facts['nic.links'] = links if complete and links else None
    return facts

if __name__ == '__main__':
    print(json.dumps(collect(), sort_keys=True))
