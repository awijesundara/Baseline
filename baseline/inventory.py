"""Atomic inventory admission shared by single-host and bulk workflows."""
import csv
import io
import re
import secrets
from .runner import validate_address

MAX_HOSTS = 200

def validate_host(payload, settings):
    if not isinstance(payload, dict): raise ValueError('Each host must be an object')
    name = str(payload.get('name', '')).strip()
    protocol = payload.get('protocol', 'ssh')
    family = payload.get('os_family', 'linux')
    user = str(payload.get('ssh_user', '')).strip()
    if not name or len(name) > 120: raise ValueError('Host name is required (maximum 120 characters)')
    if protocol not in {'ssh','redfish','both'}: raise ValueError('Protocol must be ssh, redfish or both')
    if family not in {'linux','windows','unix'}: raise ValueError('OS family must be linux, windows or unix')
    if protocol != 'redfish' and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.\\@-]{0,63}', user): raise ValueError('Valid SSH user required')
    try: port = int(payload.get('port', 22))
    except (ValueError,TypeError): raise ValueError('Invalid SSH port')
    if isinstance(payload.get('port'),bool) or not 1 <= port <= 65535: raise ValueError('Invalid SSH port')
    host = {'id':secrets.token_hex(12),'name':name,'protocol':protocol,'os_family':family,'ssh_user':user,'port':port}
    host['address'] = validate_address(str(payload.get('address','')),settings['networks'])
    for field in ('tags','manufacturer','model'):
        host[field] = str(payload.get(field, '')).strip()[:200]
    host['bmc_address'] = ''
    host['credential_profile'] = ''
    if protocol in {'redfish','both'}:
        host['bmc_address'] = validate_address(str(payload.get('bmc_address') or host['address']),settings['networks'])
        profile = str(payload.get('credential_profile',''))
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',profile): raise ValueError('A named BMC credential profile is required')
        host['credential_profile'] = profile
    return host

def prepare_bulk(payload, settings, existing):
    rows = payload.get('hosts')
    if 'csv' in payload:
        if not isinstance(payload['csv'], str): raise ValueError('CSV must be text')
        reader = csv.DictReader(io.StringIO(payload['csv'].lstrip('\ufeff')))
        if not reader.fieldnames or not {'name','address'}.issubset(reader.fieldnames): raise ValueError('CSV requires name and address headers')
        rows = list(reader)
    if not isinstance(rows,list) or not 1 <= len(rows) <= MAX_HOSTS: raise ValueError('Import 1–200 hosts at a time')
    results, errors = [], []
    addresses = {(h['address'],h.get('port',22)) for h in existing}
    names = {h['name'].casefold() for h in existing}
    for index,row in enumerate(rows,1):
        try:
            host = validate_host(row,settings)
            if (host['address'],host['port']) in addresses: raise ValueError('Duplicate management address and port')
            if host['name'].casefold() in names: raise ValueError('Duplicate host name')
            addresses.add((host['address'],host['port']));names.add(host['name'].casefold())
            results.append(host)
        except (ValueError,TypeError) as exc: errors.append({'row':index,'error':str(exc)})
    return results, errors
