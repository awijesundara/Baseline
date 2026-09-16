"""Read-only Redfish discovery with verified TLS and same-controller links."""
import base64
import ipaddress
import json
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirects are not permitted')

class Client:
    def __init__(self, address, credential):
        address = str(ipaddress.ip_address(address))
        self.base = 'https://' + ('[' + address + ']' if ':' in address else address)
        context = ssl.create_default_context(cafile=credential.get('ca_file') or None)
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))
        self.auth = 'Basic ' + base64.b64encode((credential['username']+':'+credential['password']).encode()).decode()
        self.calls = 0
        self.deadline = time.monotonic() + 60
    def get(self, path):
        if time.monotonic() > self.deadline: raise ValueError('Redfish collection deadline exceeded')
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith('/redfish/v1/') or parsed.query or parsed.fragment:
            raise ValueError('Invalid Redfish resource link')
        if '..' in path or '%' in path or '\\' in path: raise ValueError('Invalid Redfish path')
        self.calls += 1
        if self.calls > 256: raise ValueError('Redfish resource limit exceeded')
        request = Request(self.base + path, headers={'Authorization':self.auth,'Accept':'application/json'})
        with self.opener.open(request,timeout=5) as response:
            body = response.read(2_000_001)
            if len(body)>2_000_000: raise ValueError('Redfish response too large')
            doc = json.loads(body)
            if not isinstance(doc,dict): raise ValueError('Invalid Redfish JSON')
            return doc
    def members(self, path):
        collection = self.get(path)
        # Do not pretend a truncated collection is complete.
        if collection.get('Members@odata.nextLink'): raise ValueError('Paginated inventory requires an adapter')
        members = collection.get('Members')
        if not isinstance(members,list) or len(members)>128: raise ValueError('Invalid Redfish collection')
        return [self.get(item['@odata.id']) for item in members]

def collect(host, settings, client_factory=Client):
    from .runner import validate_address
    address = validate_address(host['bmc_address'],settings['networks'])
    profiles = json.loads(Path(settings['bmc_credentials']).read_text())
    credentials = profiles.get(host['credential_profile'])
    if not isinstance(credentials,dict) or not credentials.get('username') or not credentials.get('password'):
        raise ValueError('BMC credential profile is unavailable')
    client = client_factory(address,credentials)
    root = client.get('/redfish/v1/')
    systems = client.members(root['Systems']['@odata.id'])
    # Multi-node enclosures need explicit system selection, never choose arbitrarily.
    if len(systems)!=1: raise ValueError('Expected exactly one system per BMC')
    system = systems[0]
    facts = {'hardware.manufacturer':system.get('Manufacturer'),'hardware.model':system.get('Model'),
             'hardware.serial':system.get('SerialNumber'),'bios.version':system.get('BiosVersion'),
             'hardware.health':system.get('Status',{}).get('Health'), 'hardware.power':system.get('PowerState')}
    update = client.get(root['UpdateService']['@odata.id'])
    components = client.members(update['FirmwareInventory']['@odata.id'])
    # Stable component identifiers avoid matching firmware from another component.
    facts['firmware.versions'] = sorted(c['Id'] + ':' + c['Version'] for c in components if c.get('Id') and c.get('Version') and c.get('Status',{}).get('State')=='Enabled' and not c['Id'].lower().startswith(('available','staging','pending'))) or None
    facts['firmware.inventory'] = [{'id':c.get('Id'),'name':c.get('Name'),'version':c.get('Version'),
                                     'updateable':c.get('Updateable'),'status':c.get('Status'), 'software_id':c.get('SoftwareId')} for c in components]
    return facts
