"""Real Chromium workflow for the upgrade-job UI against a disposable Baseline
database (no managed hosts, no worker thread -- mirrors tests/browser_fleet.py's
approach: this proves the UI wiring, not a completed upgrade)."""
import tempfile
import threading
from playwright.sync_api import sync_playwright
from baseline.server import make_server

with tempfile.TemporaryDirectory() as tmp:
    server=make_server({'db':tmp+'/db','tokens':{'admin':'a'*40},'networks':['10.0.0.0/8'],'ansible':'missing','ssh_key':'/missing','known_hosts':'/missing'},('127.0.0.1',0),False)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with sync_playwright() as pw:
            browser=pw.chromium.launch(channel='chrome',headless=True)
            page=browser.new_page(viewport={'width':1440,'height':1000})
            errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
            page.on('console',lambda m:errors.append('CSP: '+m.text) if 'Content Security Policy' in m.text else None)
            page.goto('http://127.0.0.1:'+str(server.server_port))
            page.get_by_label('Access token').fill('a'*40);page.get_by_role('button',name='Connect',exact=True).click()
            page.get_by_role('heading',name='Verification overview').wait_for()
            page.get_by_role('button',name='Baseline policies',exact=True).click()
            page.get_by_role('button',name='Create baseline',exact=True).click()
            page.get_by_role('button',name='Save',exact=True).click()
            page.get_by_text('Linux upgrade acceptance',exact=False).wait_for()
            page.get_by_role('button',name='Servers',exact=True).click()
            page.get_by_role('button',name='Import CSV',exact=True).click()
            page.get_by_label('Server CSV',exact=True).fill('name,address,ssh_user,manufacturer,model\nhft-01,10.1.1.1,baseline,Dell,PowerEdge R750\nhft-02,10.1.1.2,baseline,HPE,DL380\n')
            page.get_by_role('button',name='Validate and preview').click()
            page.get_by_text('2 valid servers. Save to import all rows.').wait_for()
            page.get_by_role('button',name='Save',exact=True).click()
            page.get_by_text('hft-01',exact=True).wait_for()
            page.get_by_label('Select all visible servers').check()
            page.get_by_role('button',name='Upgrade selected (2)',exact=True).click()
            page.get_by_text('Nothing on any host changes until you review the dry-run plan').wait_for()
            page.get_by_label('Job name',exact=True).fill('Test upgrade job')
            page.get_by_role('button',name='Next',exact=True).click()
            page.get_by_text('servers selected on Host inventory',exact=False).wait_for()
            page.get_by_role('button',name='Next',exact=True).click()
            page.get_by_label('Target baseline',exact=False).wait_for()
            page.get_by_role('button',name='Next',exact=True).click()
            page.get_by_text('Test upgrade job',exact=False).wait_for()
            page.get_by_role('button',name='Launch upgrade',exact=True).click()
            page.get_by_role('button',name='Upgrade jobs',exact=True).click()
            page.get_by_text('planning',exact=False).wait_for()
            page.get_by_role('button',name='View',exact=True).click()
            page.get_by_text('Baseline: Linux upgrade acceptance',exact=False).wait_for()
            from pathlib import Path
            Path('docs/screenshots').mkdir(parents=True,exist_ok=True)
            page.screenshot(path='docs/screenshots/upgrade-job-detail.png',full_page=True)
            page.get_by_role('button',name='Close job detail').click()
            assert not errors,errors
            browser.close()
            print('PASS: baseline creation, host import, upgrade-selected editor, job created and visible in Upgrade jobs, job detail dialog, no JS errors')
    finally:
        server.shutdown();server.server_close();thread.join()
