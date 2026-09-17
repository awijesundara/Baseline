"""Vendor source snapshots. Published candidates never silently change policies."""
import gzip
import hashlib
from html.parser import HTMLParser
import io
import json
import re
import time
from urllib.request import Request, build_opener, ProxyHandler
from xml.etree import ElementTree as ET
from .redfish import NoRedirect

SOURCES = [
 {'id':'rhel','name':'Red Hat Enterprise Linux','kind':'os','url':'https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates','mode':'release_table','note':'GA release kernels are not the latest errata kernels. Check the subscribed repository and EUS stream.'},
 {'id':'rocky','name':'Rocky Linux','kind':'os','url':'https://download.rockylinux.org/pub/rocky/','mode':'directory','note':'Published release directories; architecture, repositories and errata must be checked separately.'},
 {'id':'centos','name':'CentOS','kind':'os','url':'https://www.centos.org/centos-linux/','mode':'reference','note':'CentOS Linux 7 reached end of life on 2024-06-30. Archive versions do not imply current vendor support.'},
 {'id':'dell','name':'Dell PowerEdge','kind':'firmware','url':'https://downloads.dell.com/catalog/Catalog.xml.gz','mode':'dell_catalog','note':'Exact model and component applicability required; some older generations are absent from current catalogs.'},
 {'id':'hpe','name':'HPE / HP ProLiant','kind':'firmware','url':'https://downloads.linux.hpe.com/','mode':'reference','note':'Use generation-specific SPP/Firmware Pack and support matrices. Some downloads require entitlement.'},
 {'id':'ibm','name':'IBM Power / System firmware','kind':'firmware','url':'https://www.ibm.com/support/fixcentral/','mode':'reference','note':'Select machine type/model and review OS/HMC dependencies. Entitlement may be required.'},
]

class Page(HTMLParser):
    def __init__(self):
        super().__init__();self.links=[];self.rows=[];self.row=None;self.cell=None
    def handle_starttag(self,tag,attrs):
        if tag=='a':self.links.append(dict(attrs).get('href',''))
        if tag=='tr':self.row=[]
        if tag in {'td','th'}:self.cell=[]
    def handle_data(self,value):
        if self.cell is not None:self.cell.append(value)
    def handle_endtag(self,tag):
        if tag in {'td','th'} and self.cell is not None:
            if self.row is not None:self.row.append(' '.join(''.join(self.cell).split()))
            self.cell=None
        if tag=='tr' and self.row is not None:self.rows.append(self.row);self.row=None

def source_by_id(identifier):
    source=next((s for s in SOURCES if s['id']==identifier),None)
    if source is None:raise ValueError('Unknown vendor source')
    return source

def parse(source,body):
    if source['mode']=='dell_catalog':
        if body.startswith(b'\x1f\x8b'):
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as zipped: body=zipped.read(96_000_001)
        if len(body)>96_000_000:raise ValueError('Expanded catalog too large')
        if b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():raise ValueError('XML entities are forbidden')
        root=ET.fromstring(body)
        for element in root.iter():element.tag=element.tag.split('}')[-1]
        candidates=[]
        for component in root.iter('SoftwareComponent'):
            version=component.get('vendorVersion')
            if not version:continue
            models=[m.findtext('Display') or m.get('name') or m.get('systemID') for m in component.findall('.//SupportedSystems/Brand/Model')]
            candidates.append({'version':version,'component':component.findtext('Name/Display') or component.get('packageID',''),
                               'models':sorted(set(m for m in models if m)), 'package_id':component.get('packageID'),
                               'component_id':component.get('componentID'), 'release_date':component.get('dateTime'),
                               'status':'candidate_review_required'})
            if len(candidates)>25000:raise ValueError('Too many catalog entries')
        if not candidates:raise ValueError('No firmware candidates found in vendor catalog')
        return candidates
    page=Page();page.feed(body.decode('utf-8','replace'))
    if source['mode']=='directory':
        versions=sorted(set(link.rstrip('/') for link in page.links if re.fullmatch(r'\d+\.\d+/',link)),key=lambda v:tuple(map(int,v.split('.'))))
        if not versions:raise ValueError('No release directories found; source format may have changed')
        return [{'version':v,'status':'published_release'} for v in versions]
    if source['mode']=='release_table':
        rows=[]
        for row in page.rows:
            if len(row)>=3 and re.fullmatch(r'(?:RHEL )?\d+\.\d+(?:\s.*)?',row[0]):
                kernel=next((cell for cell in reversed(row[1:]) if re.search(r'\d+\.\d+\.\d+-',cell)),None)
                if kernel:rows.append({'version':row[0].removeprefix('RHEL '),'release_date':row[1],'shipped_kernel':kernel,'status':'ga_reference_only'})
        if not rows:raise ValueError('No release rows found; source may require access or a parser update')
        return rows
    return []

def fetch(source):
    opener=build_opener(ProxyHandler({}),NoRedirect())
    with opener.open(Request(source['url'],headers={'User-Agent':'Baseline/0.2 vendor-reference-reader','Accept':'*/*'}),timeout=20) as response:
        body=response.read(32_000_001)
        if len(body)>32_000_000:raise ValueError('Vendor response too large')
        return body

def refresh(identifier, fetcher=fetch):
    source=source_by_id(identifier)
    body=fetcher(source)
    records=parse(source,body)
    return {'id':identifier,'source':source,'retrieved_at':time.time(),'sha256':hashlib.sha256(body).hexdigest(),
            'status':'candidates_available' if records else 'reference_only','candidates':records}


def model_key(model):
    # Dell catalogs abbreviate PowerEdge R750 as R750; retain model suffixes.
    return re.sub(r'^(?:dell\s+)?(?:poweredge\s+)', '', model.casefold().strip())
