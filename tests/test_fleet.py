import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from baseline.inventory import prepare_bulk
from baseline.redfish import Client, collect
from baseline.runner import execute
from baseline.store import connect
from baseline.vendors import parse, source_by_id, refresh, model_key
import test_baseline

class FleetApiTests(unittest.TestCase):
    setUp = test_baseline.ApiTests.setUp
    tearDown = test_baseline.ApiTests.tearDown
    request = test_baseline.ApiTests.request
    setup_binding = test_baseline.ApiTests.setup_binding
    # Keep a dedicated fixture without duplicating inherited regression cases.
    def test_bulk_preview_atomic_errors_and_duplicates(self):
        csv='name,address,ssh_user,protocol,os_family,manufacturer,model\na,10.1.1.1,baseline,ssh,linux,Dell,R750\nb,10.1.1.2,baseline,ssh,linux,HPE,DL380\n'
        status,result=self.request('/api/hosts/import',{'csv':csv,'preview':True})
        self.assertEqual(status,200);self.assertEqual(result['count'],2)
        self.assertEqual(self.request('/api/hosts')[1]['data'],[])
        invalid=csv.replace('10.1.1.2','127.0.0.1')
        status,result=self.request('/api/hosts/import',{'csv':invalid})
        self.assertEqual(status,400);self.assertEqual(result['errors'][0]['row'],2)
        self.assertEqual(self.request('/api/hosts')[1]['data'],[])
        self.assertEqual(self.request('/api/hosts/import',{'csv':csv})[0],201)
        self.assertEqual(self.request('/api/hosts/import',{'csv':csv})[0],400)
        self.assertEqual(len(self.request('/api/hosts')[1]['data']),2)
    def test_bulk_and_vendor_admin_permissions(self):
        for role in ('reader','integration'):
            self.assertEqual(self.request('/api/hosts/import',{'hosts':[]},role=role)[0],403)
            self.assertEqual(self.request('/api/vendors/refresh',{'source_id':'rocky'},role=role)[0],403)
    def test_scan_two_hosts_preserves_partial_failure(self):
        _,result=self.request('/api/hosts/import',{'hosts':[{'name':str(n),'address':'10.1.1.'+str(n),'ssh_user':'baseline'} for n in (1,2)]})
        ids=[h['id'] for h in result['data']]
        status,run=self.request('/api/runs',{'host_ids':ids,'parallelism':2})
        self.assertEqual(status,201)
        with patch('baseline.runner.ssh_collect',return_value=({ids[0]:{'os.id':'rocky','bios.version':'1.0'}},4)):
            execute(run['id'],self.settings['db'],self.settings)
        report=self.request('/api/runs/'+run['id'])[1]
        self.assertEqual(report['status'],'error');self.assertEqual(len(report['results']),2)
        self.assertEqual(report['results'][0]['status'],'collected');self.assertEqual(report['results'][1]['status'],'error')
    def test_two_host_verification_requires_all_hosts(self):
        b=self.setup_binding()
        _,host=self.request('/api/hosts',{'name':'HFT-02','address':'10.1.2.4','ssh_user':'baseline'})
        b['host_ids'].append(host['id']);_,b=self.request('/api/bindings',b)
        _,run=self.request('/api/runs',{'binding_id':b['id'],'parallelism':2})
        with patch('baseline.runner.ssh_collect',return_value=({b['host_ids'][0]:{'kernel.release':'5.14.0-target'}},0)):
            execute(run['id'],self.settings['db'],self.settings)
        self.assertFalse(self.request('/api/bindings/'+b['id']+'/verification')[1]['verified'])
    def test_bulk_200_and_limits(self):
        rows=[{'name':str(n),'address':'10.1.1.'+str(n),'ssh_user':'baseline'} for n in range(1,201)]
        self.assertEqual(self.request('/api/hosts/import',{'hosts':rows})[0],201)
        ids=[h['id'] for h in self.request('/api/hosts')[1]['data']]
        self.assertEqual(self.request('/api/runs',{'host_ids':ids,'parallelism':21})[0],400)
        self.assertEqual(self.request('/api/runs',{'host_ids':ids,'parallelism':20})[0],201)
    def test_vendor_refresh_outage_preserves_snapshot(self):
        snapshot={'id':'rocky','status':'candidates_available','retrieved_at':123,'sha256':'abc','candidates':[{'version':'9.6'}]}
        with patch('baseline.server.refresh_vendor',return_value=snapshot):
            self.assertEqual(self.request('/api/vendors/refresh',{'source_id':'rocky'})[0],200)
        with patch('baseline.server.refresh_vendor',side_effect=TimeoutError):
            self.request('/api/vendors/refresh',{'source_id':'rocky'})
        vendor=next(v for v in self.request('/api/vendors')[1]['data'] if v['id']=='rocky')
        self.assertEqual(vendor['retrieved_at'],123);self.assertEqual(vendor['candidate_count'],1);self.assertIn('TimeoutError',vendor['last_error'])
    def test_arbitrary_vendor_url_is_not_accepted(self):
        self.assertEqual(self.request('/api/vendors/refresh',{'source_id':'https://127.0.0.1'})[0],400)

class VendorTests(unittest.TestCase):
    def test_rocky_versions_from_links_not_unrelated_dates(self):
        parsed=parse(source_by_id('rocky'),b'<a href="9.6/">release</a><a href="10.1/">release</a><a href="9/">alias</a><p>2026.09</p>')
        self.assertEqual([r['version'] for r in parsed],['9.6','10.1'])
    def test_redhat_ga_kernel_not_latest_claim(self):
        parsed=parse(source_by_id('rhel'),b'<table><tr><td>RHEL 9.6</td><td>2025-05-20</td><td>5.14.0-570</td></tr></table>')
        self.assertEqual(parsed[0]['status'],'ga_reference_only')
    def test_changed_source_fails(self):
        with self.assertRaises(ValueError):parse(source_by_id('rhel'),b'<html>Sign in</html>')
    def test_dell_model_and_component_scoping(self):
        body=b'<Manifest xmlns="urn:dell"><SoftwareComponent vendorVersion="1.2.3" componentID="159"><Name><Display>BIOS</Display></Name><SupportedSystems><Brand><Model systemID="abc"><Display>PowerEdge R750</Display></Model></Brand></SupportedSystems></SoftwareComponent></Manifest>'
        candidate=parse(source_by_id('dell'),body)[0]
        self.assertEqual(candidate['models'],['PowerEdge R750']);self.assertEqual(candidate['version'],'1.2.3')
        self.assertEqual(candidate['status'],'candidate_review_required')
    def test_model_alias_preserves_suffix(self):
        self.assertEqual(model_key('PowerEdge R750'), model_key('R750'))
        self.assertNotEqual(model_key('PowerEdge R750xa'), model_key('R750'))
    def test_xml_entity_rejected(self):
        with self.assertRaises(ValueError):parse(source_by_id('dell'),b'<!DOCTYPE x [<!ENTITY x "x">]><x/>')
    def test_snapshot_records_provenance(self):
        snapshot=refresh('rocky',lambda source:b'<a href="9.6/">9.6</a>')
        self.assertEqual(len(snapshot['sha256']),64);self.assertGreater(snapshot['retrieved_at'],0)

class RedfishTests(unittest.TestCase):
    def test_foreign_links_rejected_before_network(self):
        client=Client('10.1.2.3',{'username':'test','password':'test'})
        for path in ('https://evil.example/redfish/v1/Systems','//evil/redfish/v1/Systems','/redfish/v1/../secret','/redfish/v1/%2e%2e/secret'):
            with self.assertRaises(ValueError):client.get(path)
    def test_inventory_from_standard_resource_links(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'creds.json';path.write_text(json.dumps({'lab':{'username':'user','password':'pass'}}))
            class FakeClient:
                def __init__(self,*args):pass
                def get(self,path):
                    if path=='/redfish/v1/':return {'Systems':{'@odata.id':'/redfish/v1/Systems'},'UpdateService':{'@odata.id':'/redfish/v1/UpdateService'}}
                    return {'FirmwareInventory':{'@odata.id':'/redfish/v1/UpdateService/FirmwareInventory'}}
                def members(self,path):
                    if path.endswith('Systems'):return [{'Manufacturer':'HPE','Model':'DL380','BiosVersion':'U32','SerialNumber':'serial'}]
                    return [{'Id':'iLO','Name':'iLO','Version':'3.0','Updateable':True,'Status':{'State':'Enabled'}}]
            facts=collect({'bmc_address':'10.1.2.3','credential_profile':'lab'},{'networks':['10.0.0.0/8'],'bmc_credentials':str(path)},FakeClient)
            self.assertEqual(facts['firmware.versions'],['iLO:3.0']);self.assertEqual(facts['hardware.model'],'DL380')
