import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch
from osbaseline.policy import evaluate, validate
from osbaseline.runner import execute, validate_address
from osbaseline.server import make_server, verification
from osbaseline.store import connect, init

POLICY = {'name':'Rocky 9 target', 'checks':[{'id':'kernel','field':'kernel.release','op':'eq','expected':'5.14.0-target'}]}

class PolicyTests(unittest.TestCase):
    def test_missing_required_fails_closed(self):
        result=evaluate(POLICY,{})
        self.assertEqual(result['status'],'fail');self.assertEqual(result['checks'][0]['status'],'unknown')
    def test_exact_kernel_no_prefix_matching(self):
        self.assertEqual(evaluate(POLICY,{'kernel.release':'5.14.0-target-old'})['status'],'fail')
        self.assertEqual(evaluate(POLICY,{'kernel.release':'5.14.0-target'})['status'],'pass')
    def test_advisory_unknown_does_not_block(self):
        p=json.loads(json.dumps(POLICY));p['checks'].append({'id':'nic','field':'nic.firmware','op':'eq','expected':'v1','required':False})
        self.assertEqual(evaluate(p,{'kernel.release':'5.14.0-target'})['status'],'pass')
    def test_empty_or_all_optional_rejected(self):
        for checks in ([],[{'id':'x','field':'kernel.release','op':'eq','expected':'x','required':False}]):
            with self.assertRaises(ValueError):validate({'name':'x','checks':checks})
    def test_invalid_types_and_operators_rejected(self):
        for change in ({'required':'false'},{'op':'shell'},{'field':'command'},{'op':'gte','expected':'10'},{'op':'set_eq','expected':'abc'}):
            p=json.loads(json.dumps(POLICY));p['checks'][0].update(change)
            with self.assertRaises(ValueError):validate(p)
    def test_numeric_type_confusion_is_unknown(self):
        p={'name':'n','checks':[{'id':'n','field':'memory.hugepages_free','op':'gte','expected':2}]}
        self.assertEqual(evaluate(p,{'memory.hugepages_free':'20'})['checks'][0]['status'],'unknown')
    def test_network_boundary(self):
        for address in ('127.0.0.1','169.254.169.254','::1','hostname','10.9.1.2;whoami','192.168.1.2'):
            with self.assertRaises(ValueError):validate_address(address,['10.0.0.0/8'])
        self.assertEqual(validate_address('10.1.2.3',['10.0.0.0/8']),'10.1.2.3')
    def test_distro_starters_fail_without_customization(self):
        for path in Path('examples').glob('*.json'):
            p=validate(json.loads(path.read_text()))
            self.assertEqual(evaluate(p,{})['status'],'fail')
    def test_centOS_eol_gate_blocks(self):
        p={'name':'lifecycle','checks':[{'id':'eol','field':'os.centos7_eol','op':'eq','expected':False}]}
        self.assertEqual(evaluate(p,{'os.centos7_eol':True})['status'],'fail')

class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.settings={'db':self.tmp.name+'/db.sqlite','tokens':{'admin':'a'*40,'reader':'r'*40,'integration':'i'*40},'networks':['10.0.0.0/8'],'ansible':'missing-ansible','ssh_key':'/missing/key','known_hosts':'/missing/known','timeout':2}
        self.server=make_server(self.settings,('127.0.0.1',0),False)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url='http://127.0.0.1:'+str(self.server.server_port)
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.tmp.cleanup()
    def request(self,path,body=None,role='admin',headers=None):
        req=Request(self.url+path,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':'Bearer '+self.settings['tokens'].get(role,''),'Content-Type':'application/json',**(headers or {})})
        try:
            with urlopen(req) as r:return r.status,json.load(r)
        except HTTPError as e:return e.code,json.load(e)
    def setup_binding(self):
        _,h=self.request('/api/hosts',{'name':'HFT-01','address':'10.1.2.3','ssh_user':'baseline'})
        _,b=self.request('/api/baselines',POLICY)
        status,binding=self.request('/api/bindings',{'external_system':'serviceops','ticket_id':'CHG-42','baseline_id':b['id'],'host_ids':[h['id']]})
        self.assertEqual(status,201)
        return binding
    def finish(self,run,status='pass',**changes):
        run.update(started_at=time.time(),completed_at=time.time(),status=status,**changes)
        with connect(self.settings['db']) as db:db.execute('UPDATE runs SET status=?,document=? WHERE id=?',(status,json.dumps(run),run['id']))
    def test_auth_and_scopes(self):
        self.assertEqual(self.request('/api/hosts',role='missing')[0],401)
        self.assertEqual(self.request('/api/hosts',{},role='reader')[0],403)
        self.assertEqual(self.request('/api/hosts',{},role='integration')[0],403)
        self.assertEqual(self.request('/api/hosts',role='reader')[0],200)
    def test_cross_origin_rejected(self):
        self.assertEqual(self.request('/api/baselines',POLICY,headers={'Origin':'https://evil.invalid'})[0],403)
    def test_binding_rejects_duplicate_hosts(self):
        b=self.setup_binding();b['host_ids']*=2
        self.assertEqual(self.request('/api/bindings',b)[0],400)
    def test_immutable_snapshot_and_success(self):
        b=self.setup_binding();_,run=self.request('/api/runs',{'binding_id':b['id']},role='integration')
        self.assertEqual(run['baseline']['checks'],POLICY['checks'])
        self.finish(run)
        _,v=self.request('/api/bindings/'+b['id']+'/verification');self.assertTrue(v['verified'])
        self.assertEqual(v['ticket_id'],'CHG-42')
    def test_latest_attempt_supersedes_pass(self):
        b=self.setup_binding();_,run=self.request('/api/runs',{'binding_id':b['id']});self.finish(run)
        _,new=self.request('/api/runs',{'binding_id':b['id']})
        _,v=self.request('/api/bindings/'+b['id']+'/verification');self.assertFalse(v['verified'])
        self.finish(new,'fail')
        _,v=self.request('/api/bindings/'+b['id']+'/verification');self.assertFalse(v['verified'])
    def test_stale_or_pre_upgrade_or_wrong_host_cannot_verify(self):
        b=self.setup_binding();_,run=self.request('/api/runs',{'binding_id':b['id']})
        for changes in ({'completed_at':time.time()-4000},{'started_at':b['not_before']-1},{'hosts':[]}):
            copy=dict(run);copy.update(started_at=time.time(),completed_at=time.time(),status='pass');copy.update(changes)
            with connect(self.settings['db']) as db:
                db.execute('UPDATE runs SET status=?,document=? WHERE id=?',('pass',json.dumps(copy),run['id']))
                self.assertFalse(verification(db,b)['verified'])
    def test_collection_unavailable_never_passes(self):
        b=self.setup_binding();_,run=self.request('/api/runs',{'binding_id':b['id']})
        execute(run['id'],self.settings['db'],self.settings)
        _,report=self.request('/api/runs/'+run['id']);self.assertEqual(report['status'],'error')
        self.assertIn('evidence_sha256',report)
    def test_serial_job_admission(self):
        b=self.setup_binding();self.assertEqual(self.request('/api/runs',{'binding_id':b['id']})[0],201)
        self.assertEqual(self.request('/api/runs',{'binding_id':b['id']})[0],409)
    def test_restart_preserves_records_and_invalidates_interrupted_run(self):
        b=self.setup_binding();_,run=self.request('/api/runs',{'binding_id':b['id']})
        with connect(self.settings['db']) as db:db.execute("UPDATE runs SET status='running'")
        init(self.settings['db'])
        self.assertEqual(self.request('/api/runs/'+run['id'])[1]['status'],'error')
        self.assertEqual(len(self.request('/api/hosts')[1]['data']),1)
    def test_verification_lookup_by_ticket(self):
        b=self.setup_binding()
        status,v=self.request('/api/verification?external_system=serviceops&ticket_id=CHG-42',role='reader')
        self.assertEqual(status,200);self.assertFalse(v['verified']);self.assertEqual(v['status'],'not_run')
        status,v=self.request('/api/verification?external_system=serviceops&ticket_id=CHG-999',role='reader')
        self.assertEqual(v['status'],'not_bound')
        _,run=self.request('/api/runs',{'binding_id':b['id']});self.finish(run)
        _,v=self.request('/api/verification?external_system=serviceops&ticket_id=CHG-42',role='integration')
        self.assertTrue(v['verified'])
    def test_callback_evidence_and_all_host_gate(self):
        b=self.setup_binding();_,run=self.request('/api/runs',{'binding_id':b['id']})
        def process(argv,**kwargs):
            Path(kwargs['env']['OSBASELINE_EVIDENCE_FILE']).write_text(json.dumps({'host':b['host_ids'][0],'facts':{'kernel.release':'5.14.0-target'}})+'\n')
            self.assertNotIn('OSBASELINE_ADMIN_TOKEN',kwargs['env'])
            class Proc:
                def wait(self,timeout=None):return 0
            return Proc()
        with patch('osbaseline.runner.subprocess.Popen',side_effect=process):execute(run['id'],self.settings['db'],self.settings)
        self.assertTrue(self.request('/api/bindings/'+b['id']+'/verification')[1]['verified'])

if __name__=='__main__':unittest.main()
