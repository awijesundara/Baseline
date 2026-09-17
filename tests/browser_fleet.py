"""Real Chromium workflow against a disposable Baseline database (no managed hosts)."""
import json
from pathlib import Path
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
            # A CSP violation (e.g. a reintroduced inline style="") doesn't raise a pageerror --
            # the browser just silently drops the effect -- so it must be caught here explicitly.
            page.on('console',lambda m:errors.append('CSP: '+m.text) if 'Content Security Policy' in m.text else None)
            page.goto('http://127.0.0.1:'+str(server.server_port))
            page.get_by_label('Access token').fill('a'*40);page.get_by_role('button',name='Connect',exact=True).click()
            page.get_by_role('heading',name='Verification overview').wait_for()
            page.get_by_role('button',name='Servers',exact=True).click()
            page.get_by_role('button',name='Import CSV',exact=True).click()
            page.get_by_label('Server CSV',exact=True).fill('name,address,ssh_user,manufacturer,model\nhft-01,10.1.1.1,baseline,Dell,PowerEdge R750\nhft-02,10.1.1.2,baseline,HPE,DL380\n')
            page.get_by_role('button',name='Validate and preview').click()
            page.get_by_text('2 valid servers. Save to import all rows.').wait_for()
            page.get_by_role('button',name='Save',exact=True).click()
            page.get_by_text('hft-01',exact=True).wait_for()
            page.get_by_label('Select all visible servers').check()
            page.get_by_role('button',name='Scan selected (2)',exact=True).click()
            page.get_by_label('Concurrent servers (1–20)').fill('2')
            page.get_by_role('button',name='Save',exact=True).click()
            page.get_by_text('Inventory discovery',exact=True).wait_for()
            page.get_by_role('button',name='View report',exact=True).click()
            page.get_by_text('queued · 2 servers · 2 concurrent').wait_for()
            page.get_by_role('button',name='Close report').click()
            page.get_by_role('button',name='Firmware inventory',exact=True).click()
            page.get_by_role('heading',name='Firmware inventory').wait_for()
            page.get_by_role('button',name='Vendor references',exact=True).click()
            page.get_by_role('heading',name='Dell PowerEdge',exact=True).wait_for()
            page.get_by_role('button',name='Servers',exact=True).click()
            page.get_by_label('Search servers').fill('Dell')
            assert page.get_by_text('hft-02',exact=True).count()==0
            page.get_by_label('Search servers').fill('')
            Path('docs/screenshots').mkdir(parents=True,exist_ok=True)
            page.screenshot(path='docs/screenshots/fleet-desktop.png',full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile page overflow'
            page.screenshot(path='docs/screenshots/fleet-mobile.png',full_page=True)
            assert not errors,errors
            browser.close()
            print('PASS: CSV preview/import, two-host selection and scan, reports, firmware, vendor page, search, desktop/mobile overflow, no JS errors')
    finally:
        server.shutdown();server.server_close();thread.join()
