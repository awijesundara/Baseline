'use strict';
let token = '', page = 'overview', data = {}, catalog = {}, editorKind = '', report = null, selected = new Set(), hostQuery = '', vendorModel = '';
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path, body) {
  const r = await fetch('/api/' + path, {method:body ? 'POST':'GET', headers:{Authorization:'Bearer '+token,...(body ? {'Content-Type':'application/json'}:{})}, ...(body ? {body:JSON.stringify(body)}:{})});
  const result = await r.json(); if (!r.ok) throw Error((result.error || 'Request failed') + (result.errors ? '\n' + result.errors.map(e=>'Row '+e.row+': '+e.error).join('\n') : '')); return result;
}
function message(error) { $('message').textContent = error.message || String(error); }
function badge(status) { return `<span class="badge ${esc(status)}">${esc(String(status).replaceAll('_',' '))}</span>`; }
const ICONS = {
  server:'<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><circle cx="7" cy="7" r=".6" fill="currentColor" stroke="none"/><circle cx="7" cy="17" r=".6" fill="currentColor" stroke="none"/>',
  shield:'<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
  check:'<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
  bar:'<path d="M4 20V10M12 20V4M20 20v-7"/>',
};
function statIcon(icon,cls) { return `<span class="stat-icon ${cls}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">${ICONS[icon]}</svg></span>`; }
function donutChart(segments, total, centerLabel) {
  const r=52, c=2*Math.PI*r; let offset=0;
  const arcs=total?segments.filter(s=>s.value>0).map(s=>{const dash=s.value/total*c; const el=`<circle cx="70" cy="70" r="${r}" fill="none" stroke="${s.color}" stroke-width="16" stroke-dasharray="${dash} ${c-dash}" stroke-dashoffset="${-offset}" transform="rotate(-90 70 70)"/>`;offset+=dash;return el;}).join(''):`<circle cx="70" cy="70" r="${r}" fill="none" stroke="#eef1f6" stroke-width="16"/>`;
  return `<svg width="140" height="140" viewBox="0 0 140 140" role="img" aria-label="${esc(centerLabel)}: ${total}">${arcs}<text x="70" y="66" text-anchor="middle" font-size="22" font-weight="800" fill="#1b2c43">${total}</text><text x="70" y="85" text-anchor="middle" font-size="11" fill="#7c8ba3">${esc(centerLabel)}</text></svg>`;
}
function barChart(rows) {
  const max=Math.max(1,...rows.map(r=>r.value));
  return `<div class="bars">${rows.map(r=>`<div class="bar-row"><span>${esc(r.label)}</span><div class="bar-track"><div class="bar-fill ${esc(r.cls||'default')}" data-width="${Math.round(r.value/max*100)}"></div></div><strong>${r.value}</strong></div>`).join('')}</div>`;
}
// CSP (style-src 'self') blocks inline style="" attributes; dynamic widths are set
// via the CSSOM (el.style.width=), which CSP does not restrict, after insertion.
function hydrateWidths(root) { root.querySelectorAll('[data-width]').forEach(el=>{el.style.width=el.dataset.width+'%';}); }
function name(table, id) { return data[table].find(x=>x.id===id)?.name || id; }
function table(headers, rows) { return rows.length ? `<div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th scope="col">${h}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : '<div class="panel empty">No records yet. Add inventory and an approved baseline to get started.</div>'; }
async function refresh() {
  try {
    catalog = await api('catalog');
    const keys = ['hosts','baselines','bindings','runs','audit','templates','vendors','jobs'];
    const results = await Promise.all(keys.map(k=>api(k==='vendors'&&vendorModel?'vendors?model='+encodeURIComponent(vendorModel):k)));
    keys.forEach((k,i)=>data[k]=results[i].data);
    data.verifications = Object.fromEntries(await Promise.all(data.bindings.map(async b=>[b.id,await api(`bindings/${b.id}/verification`)])));
    $('login').hidden=true; $('workspace').hidden=false; $('message').textContent=''; render();
  } catch (e) { message(e); }
}
function render() {
  const titles = {overview:'Verification overview',hosts:'Host inventory',baselines:'Baseline policies',bindings:'Upgrade verification',jobs:'Upgrade jobs',runs:'Evidence reports',audit:'Audit history',firmware:'Firmware inventory',vendors:'Vendor references'};
  $('page-title').textContent=titles[page];
  document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',b.dataset.page===page));
  $('runner').textContent = catalog.runner_available && catalog.ssh_configured ? 'Ansible controller ready · Read-only SSH collection · Strict host-key verification' : 'Controller setup required: install Ansible and configure the SSH key, known hosts, and approved management networks.';
  let html='';
  if (page==='overview') {
    const cards=[['server','blue','Managed hosts',data.hosts.length],['shield','purple','Baseline revisions',data.baselines.length],['check','green','Verified upgrades',Object.values(data.verifications).filter(v=>v.verified).length],['bar','amber','Collection runs',data.runs.length]];
    const jobBuckets={Completed:0,Failed:0,'In progress':0,Pending:0};
    for (const j of data.jobs) {
      if (['upgraded','rolled_back'].includes(j.status)) jobBuckets.Completed++;
      else if (['rollback_failed','error'].includes(j.status)) jobBuckets.Failed++;
      else if (['planning','running_plan','queued','running'].includes(j.status)) jobBuckets['In progress']++;
      else jobBuckets.Pending++;
    }
    const jobTotal=data.jobs.length;
    const legend=[['Completed','completed','#1caa6b'],['In progress','in-progress','#7c5cf0'],['Pending','pending','#e2a512'],['Failed','failed','#e6465f']];
    const runCounts={};
    for (const r of data.runs) runCounts[r.status]=(runCounts[r.status]||0)+1;
    const runClasses={pass:'pass',fail:'fail',error:'error',collected:'collected'};
    const barRows=Object.entries(runCounts).map(([status,n])=>({label:status.replaceAll('_',' '),value:n,cls:runClasses[status]||'default'}));
    html=`<div class="cards">${cards.map(([icon,cls,label,n])=>`<div class="card"><div class="card-top">${statIcon(icon,cls)}</div><strong>${n}</strong><small>${label}</small></div>`).join('')}</div>
<div class="chart-row">
<section class="panel"><h2>Upgrade job status</h2>${jobTotal?`<div class="donut-wrap">${donutChart(legend.map(([l,,c])=>({value:jobBuckets[l],color:c})),jobTotal,'Upgrade jobs')}<ul class="chart-legend">${legend.map(([l,cls])=>`<li><span class="swatch ${cls}"></span>${esc(l)}<strong>${jobBuckets[l]}</strong></li>`).join('')}</ul></div>`:'<p class="muted">No upgrade jobs yet. Plan one from Host inventory → Upgrade selected.</p>'}</section>
<section class="panel"><h2>Evidence report outcomes</h2>${barRows.length?barChart(barRows):'<p class="muted">No collection runs yet.</p>'}</section>
</div>
<section class="panel"><h2>Recent upgrade jobs</h2>${data.jobs.length?table(['Job','Baseline','Status','Created'],data.jobs.slice(0,5).map(j=>[esc(j.name||j.id.slice(0,12)),esc(j.baseline?.name||'—'),badge(j.status),new Date(j.created_at*1000).toLocaleString()])):'<p class="muted">No upgrade jobs yet.</p>'}</section>
<section class="panel"><h2>Evidence behind every upgrade</h2><div class="flow"><div><strong>01 · Define the target</strong><p class="muted">Register management IPs and publish an immutable baseline with the exact versions and HFT settings you require.</p></div><div><strong>02 · Collect and compare</strong><p class="muted">Bind the ticket to its hosts. Run Ansible checks after the upgrade and inspect every result.</p></div><div><strong>03 · Verify the change</strong><p class="muted">ServiceOps and FlowOps can query the verification API. Fresh evidence and a complete pass are required.</p></div></div></section>`;
  }
  if (page==='hosts') html=hostInventory();
  if (page==='firmware') html=firmwareInventory();
  if (page==='vendors') html=vendorReferences();
  if (page==='baselines') html=table(['Policy','Revision','Checks','Created'],data.baselines.map(b=>[esc(b.name),esc(b.revision_sha256.slice(0,12)),b.checks.length,new Date(b.created_at*1000).toLocaleString()]));
  if (page==='bindings') html=table(['Ticket / task','System','Baseline','Hosts','Verification','Action'],data.bindings.map(b=>[esc(b.ticket_id),esc(b.external_system),esc(name('baselines',b.baseline_id)),b.host_ids.length,badge(data.verifications[b.id].status),`<button data-verify="${b.id}">${data.verifications[b.id].verified?'Reverify':'Run verification'}</button>`]));
  if (page==='jobs') html=table(['Job','Baseline','Hosts','Batches','Status','Created','Action'],data.jobs.map(j=>[esc(j.name||j.id.slice(0,12)),esc(j.baseline?.name||'—'),j.host_ids?.length||0,j.batch_results?.length||0,badge(j.status),new Date(j.created_at*1000).toLocaleString(),`<button data-job="${j.id}">View</button>`]));
  if (page==='runs') html=table(['Run','Baseline','Status','Created','Evidence'],data.runs.map(r=>[esc(r.id.slice(0,12)),esc(r.baseline?.name || 'Inventory discovery'),badge(r.status),new Date(r.created_at*1000).toLocaleString(),`<button data-report="${r.id}">View report</button>`]));
  if (page==='audit') html=table(['Time','Actor','Action','Record'],data.audit.map(a=>[new Date(a.created*1000).toLocaleString(),esc(a.actor),esc(a.action),esc(a.subject)]));
  if (['baselines','bindings'].includes(page) && catalog.role==='admin') html=`<div class="toolbar"><span class="muted">${page==='baselines'?'Changes are saved as new, immutable revisions.':page==='bindings'?'Bind an exact host set and baseline to an upgrade ticket.':'Manage the servers available for verification.'}</span><button class="primary" id="add">${{hosts:'Add host',baselines:'Create baseline',bindings:'Bind upgrade'}[page]}</button></div>`+html;
  $('content').innerHTML=html; hydrateWidths($('content')); wireFleet();
  $('add')?.addEventListener('click',()=>openEditor(page));
  document.querySelectorAll('[data-verify]').forEach(b=>{b.disabled=catalog.role==='reader';b.onclick=async()=>{try{b.disabled=true;await api('runs',{binding_id:b.dataset.verify});page='runs';await refresh();}catch(e){message(e);b.disabled=false;}};});
  document.querySelectorAll('[data-report]').forEach(b=>b.onclick=async()=>{try{report=await api('runs/'+b.dataset.report);showReport(report);}catch(e){message(e);}});
  document.querySelectorAll('[data-job]').forEach(b=>b.onclick=async()=>{try{showJob(await api('jobs/'+b.dataset.job));}catch(e){message(e);}});
}
const sample={name:'Linux upgrade acceptance — customize before use',checks:[{id:'os-release',field:'os.version',op:'eq',expected:'REPLACE_WITH_APPROVED_VERSION',required:true},{id:'running-kernel',field:'kernel.release',op:'eq',expected:'REPLACE_WITH_APPROVED_KERNEL',required:true},{id:'kernel-clean',field:'kernel.tainted',op:'eq',expected:0,required:true},{id:'failed-services',field:'services.failed',op:'eq',expected:'',required:true},{id:'dkms-module',field:'dkms.status',op:'contains',expected:'REPLACE_WITH_MODULE_VERSION_KERNEL_AND_INSTALLED_STATUS',required:true}]};
function field(label,name,type='text',value='') { return `<label>${label}<input name="${name}" type="${type}" value="${esc(value)}" required></label>`; }
function openEditor(kind) {
  editorKind=kind; $('editor-title').textContent={hosts:'Add management host',baselines:'Create baseline revision',bindings:'Bind upgrade ticket',bulk:'Import servers',scan:'Scan selected servers',upgrade:'Plan an OS package upgrade'}[kind];
  let fields='';
  if(kind==='hosts') fields=`<div class="form-grid">${field('Host name','name')}${field('Management IP address','address')}<label>Collection method<select name="protocol"><option value="ssh">OS over SSH</option><option value="both">OS + Redfish firmware</option><option value="redfish">Redfish firmware only</option></select></label><label>OS family<select name="os_family"><option value="linux">Linux</option><option value="windows">Windows (OpenSSH + PowerShell)</option><option value="unix">Unix / AIX / BSD</option></select></label>${field('SSH user','ssh_user','text','baseline')}${field('SSH port','port','number','22')}<label>Manufacturer<input name="manufacturer" placeholder="Dell, HPE, IBM, other"></label><label>Model<input name="model" placeholder="Exact server model"></label><label>BMC management IP<input name="bmc_address" placeholder="Required for OS + firmware"></label><label>BMC credential profile<input name="credential_profile" placeholder="Named server-side profile"></label></div><label>Tags<input name="tags" placeholder="Tokyo, HFT, production"></label><p class="muted">Model labels help organize inventory. Verification uses collected hardware identity. BMC passwords stay on the controller.</p>`;
  if(kind==='bulk') fields=`<p>Paste a CSV or choose a file. Up to 200 servers; all rows are validated before anything is saved.</p><label>CSV file<input id="csv-file" type="file" accept=".csv,text/csv"></label><label>Server CSV<textarea name="csv" id="csv-input" required spellcheck="false" placeholder="name,address,ssh_user,protocol,os_family,manufacturer,model,tags&#10;hft-01,10.20.0.11,baseline,ssh,linux,Dell,PowerEdge R750,Tokyo&#10;hft-02,10.20.0.12,baseline,ssh,linux,HPE,ProLiant DL380 Gen11,Tokyo"></textarea></label><button type="button" id="preview-import">Validate and preview</button><div id="import-preview" aria-live="polite"></div><p class="muted">Optional columns: port, bmc_address, credential_profile. Protocol: ssh, redfish, or both.</p>`;
  if(kind==='scan') fields=`<p>Collect evidence from <strong>${selected.size} selected servers</strong>. SSH and Redfish checks run in parallel within the configured limit.</p><label>Baseline policy<select name="baseline_id"><option value="">Inventory discovery only</option>${data.baselines.map(b=>`<option value="${b.id}">${esc(b.name)}</option>`).join('')}</select></label>${field('Concurrent servers (1–20)','parallelism','number','5')}<p class="muted">Discovery shows installed versions. A ticket-bound verification is required for a verified upgrade.</p>`;
  if(kind==='upgrade') fields=`<div class="wizard-steps">${['Basic info','Select targets','Upgrade options','Review & launch'].map((label,i)=>`<div class="wizard-step ${i===0?'active':''}"><span class="num">${i+1}</span><span class="label">${esc(label)}</span></div>`).join('')}</div>
<div class="wizard-panel" data-panel="1"><p class="muted">Nothing on any host changes until you review the dry-run plan and explicitly launch it.</p><label>Job name<input name="name" placeholder="e.g. RHEL 8 to 9 — web servers" maxlength="120"></label><label>Description<textarea name="description" class="wizard-note" placeholder="Optional notes for this upgrade" maxlength="2000"></textarea></label></div>
<div class="wizard-panel" data-panel="2" hidden><p class="muted">${selected.size} server${selected.size===1?'':'s'} selected on Host inventory. Close this wizard and adjust your selection there if needed.</p><div class="pill-list">${[...selected].map(id=>`<span>${esc(name('hosts',id))}</span>`).join('')}</div></div>
<div class="wizard-panel" data-panel="3" hidden><label>Target baseline (defines the pass/fail check after upgrading)<select name="baseline_id" required>${data.baselines.map(b=>`<option value="${b.id}">${esc(b.name)}</option>`).join('')}</select></label><label>Batch size<input name="batch_size" type="number" value="0" min="0"></label><p class="muted">0 upgrades all selected servers as one batch. A smaller number upgrades and verifies that many servers at a time before moving on.</p><label>Maintenance window start (optional)<input name="not_before" type="datetime-local"></label></div>
<div class="wizard-panel" data-panel="4" hidden><p class="muted">A batch whose post-upgrade check fails is automatically rolled back, and no later batch starts.</p><dl class="review-grid" id="wizard-review"></dl></div>
<div class="wizard-nav"><button type="button" id="wizard-back" disabled>Back</button><button type="button" id="wizard-next" class="primary">Next</button></div>`;
  if(kind==='baselines') fields=`<label>Distribution starter<select id="starter"><option value="">Generic Linux</option>${data.templates.map((t,i)=>`<option value="${i}">${esc(t.name)}</option>`).join('')}</select></label><p>Use exact approved versions. Missing required facts block verification. Version strings are compared exactly.</p><label>Baseline JSON<textarea name="policy" spellcheck="false" required>${esc(JSON.stringify(sample,null,2))}</textarea></label><details><summary>Available fields and comparisons</summary><p>${esc(catalog.fields.join(', '))}</p><p>Operators: ${esc(catalog.operators.join(', '))}</p></details>`;
  if(kind==='bindings') fields='<label>System<select name="external_system"><option value="serviceops">ServiceOps</option><option value="flowops">FlowOps</option></select></label>'+field('Ticket or task reference','ticket_id')+`<label>Baseline revision<select name="baseline_id" required>${data.baselines.map(b=>`<option value="${b.id}">${esc(b.name)} · ${b.revision_sha256.slice(0,8)}</option>`).join('')}</select></label><label>Hosts (select all affected servers)<select name="host_ids" multiple required>${data.hosts.map(h=>`<option value="${h.id}">${esc(h.name)} · ${esc(h.address)}</option>`).join('')}</select></label>`+field('Evidence lifetime (seconds)','max_age_seconds','number','3600')+'<p>Evidence must be collected after this binding is created. The API also accepts an explicit upgrade completion timestamp.</p>';
  $('editor-fields').innerHTML=fields; wireEditor(kind); if(kind==='baselines')$('starter').onchange=e=>{document.querySelector('[name=policy]').value=JSON.stringify(e.target.value===''?sample:data.templates[Number(e.target.value)],null,2);}; $('editor').showModal();
}
$('editor-form').onsubmit=async e=>{e.preventDefault();try{const form=new FormData(e.target);let body=Object.fromEntries(form);if(editorKind==='baselines')body=JSON.parse(body.policy);if(editorKind==='hosts')body.port=Number(body.port);if(editorKind==='bindings'){body.host_ids=form.getAll('host_ids');body.max_age_seconds=Number(body.max_age_seconds);}if(editorKind==='scan'){body.host_ids=[...selected];body.parallelism=Number(body.parallelism);}if(editorKind==='upgrade'){body.host_ids=[...selected];body.batch_size=Number(body.batch_size);if(body.not_before)body.not_before=Math.floor(new Date(body.not_before).getTime()/1000);else delete body.not_before;} await api(editorKind==='bulk'?'hosts/import':editorKind==='scan'?'runs':editorKind==='upgrade'?'jobs':editorKind,body);if(editorKind==='scan')page='runs';if(editorKind==='upgrade'){page='jobs';selected.clear();}$('editor').close();await refresh();}catch(err){message(err);let p=$('editor-error');if(!p){p=document.createElement('p');p.id='editor-error';p.setAttribute('role','alert');$('editor-fields').append(p);}p.textContent=err.message;}};
$('login-form').onsubmit=e=>{e.preventDefault();token=$('token').value;$('token').value='';refresh();};
$('logout').onclick=()=>{token='';data={};selected.clear();$('workspace').hidden=true;$('login').hidden=false;};
$('refresh').onclick=refresh;
$('close-editor').onclick=()=>$('editor').close();$('close-report').onclick=()=>$('report').close();$('close-job').onclick=()=>$('job-detail').close();
$('download').onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='baseline-'+report.id+'.json';a.click();URL.revokeObjectURL(url);};
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{if(!token)return;page=b.dataset.page;render();});
const JOB_ACTIVE_STATUSES=['planning','running_plan','queued','running'];
setInterval(()=>{if(token && (data.runs?.some(r=>['queued','running'].includes(r.status)) || data.jobs?.some(j=>JOB_ACTIVE_STATUSES.includes(j.status))))refresh();},3000);

function latestResults() {
  const results={};
  for(const run of data.runs) for(const r of run.results||[]) if(!results[r.host_id]) results[r.host_id]={...r,run_id:run.id,completed_at:run.completed_at};
  return results;
}
function hostInventory() {
  const results=latestResults();
  const visible=data.hosts.filter(h=>[h.name,h.address,h.tags,h.manufacturer,h.model].join(' ').toLowerCase().includes(hostQuery.toLowerCase()));
  return `<div class="fleet-banner"><div><h2>Your server fleet</h2><p>Discover OS and firmware across Linux, Windows, and management controllers.</p></div><span class="badge">${data.hosts.length} servers</span></div><div class="toolbar fleet-tools"><label class="search-label">Search servers<input id="host-search" type="search" value="${esc(hostQuery)}" placeholder="Name, IP, model or tag"></label><div class="actions">${catalog.role==='admin'?'<button id="add-host">Add server</button><button id="bulk-hosts">Import CSV</button>':''}<button class="primary" id="scan-hosts" ${selected.size && catalog.role!=='reader'?'':'disabled'}>Scan selected (${selected.size})</button>${catalog.role==='admin'?`<button id="upgrade-hosts" ${selected.size?'':'disabled'}>Upgrade selected (${selected.size})</button>`:''}</div></div>${table(['<input type="checkbox" id="select-all-hosts" aria-label="Select all visible servers">','Server','Management','Collection','Hardware label','Latest collection'],visible.map(h=>[`<input type="checkbox" data-select="${h.id}" aria-label="Select ${esc(h.name)}" ${selected.has(h.id)?'checked':''}>`,`<strong>${esc(h.name)}</strong><small>${esc(h.tags||'No tags')}</small>`,esc(h.address),badge(h.protocol||'ssh')+'<small>'+esc(h.os_family||'linux')+'</small>',esc([h.manufacturer,h.model].filter(Boolean).join(' ')||'Discover on scan'),badge(results[h.id]?.collection_status||'not_scanned')]))}<p class="muted">Select up to 200 servers per scan or upgrade. An upgrade always starts with a dry-run plan; nothing changes until you review and confirm it.</p>`;
}
function firmwareInventory() {
  const results=latestResults();
  return `<div class="notice">Installed versions come from collected evidence. Compare them with an approved baseline; vendor candidates require model and component review.</div>${table(['Server','Discovered hardware','OS / kernel','BIOS','Firmware components','Evidence'],data.hosts.map(h=>{const r=results[h.id],f=r?.facts||{};return [esc(h.name),esc([f['hardware.manufacturer'],f['hardware.model']].filter(Boolean).join(' ')||'Unknown'),esc([f['os.name']||f['os.id'],f['os.version'],f['kernel.release']].filter(Boolean).join(' / ')||'Unknown'),esc(f['bios.version']||'Unknown'),esc(f['firmware.inventory']?.length ? f['firmware.inventory'].map(c=>`${c.name||c.id}: ${c.version||'Unknown'}`).join(' · ') : (f['nic.firmware']||[]).join(' · ')||'Unknown'),r?`<button data-report="${r.run_id}">View ${esc(r.status)}</button><small>${new Date(r.completed_at*1000).toLocaleString()}</small>`:'Not scanned'];}))}`;
}
function vendorReferences() {
  return `<div class="notice">Published releases and firmware candidates are reference material. They do not automatically become approved baselines. HPE and IBM currently provide official reference links; automated catalog parsing is available for Dell, Rocky and Red Hat.</div><label class="search-label">Dell exact model filter<input id="vendor-model" value="${esc(vendorModel)}" placeholder="For example: PowerEdge R750"></label><button id="filter-vendors">Apply model filter</button><div class="vendor-grid">${data.vendors.map(v=>`<section class="panel"><div class="heading"><h2>${esc(v.name)}</h2>${badge(v.stale?'stale':v.snapshot_status)}</div><p>${esc(v.note)}</p><a href="${esc(v.url)}" target="_blank" rel="noopener noreferrer">Official vendor source ↗</a><p class="muted">Retrieved: ${v.retrieved_at?new Date(v.retrieved_at*1000).toLocaleString():'Not refreshed'}<br>${v.candidate_count} candidates${v.truncated?' · showing first 250; filter by exact model':''}</p>${v.last_error?`<p role="status">${esc(v.last_error)} · previous snapshot retained</p>`:''}${catalog.role==='admin'?`<button data-vendor-refresh="${v.id}">Refresh from vendor</button>`:''}<details><summary>Release and firmware candidates</summary>${table(['Version','Component / shipped kernel','Applicability'],v.candidates.map(c=>[esc(c.version),esc(c.component||c.shipped_kernel||'OS release'),esc(c.models?.join(', ')||c.status)]))}</details></section>`).join('')}</div>`;
}
function wireFleet() {
  $('add-host')?.addEventListener('click',()=>openEditor('hosts'));
  $('bulk-hosts')?.addEventListener('click',()=>openEditor('bulk'));
  $('scan-hosts')?.addEventListener('click',()=>openEditor('scan'));
  $('upgrade-hosts')?.addEventListener('click',()=>openEditor('upgrade'));
  $('host-search')?.addEventListener('input',e=>{const pos=e.target.selectionStart;hostQuery=e.target.value;render();$('host-search').focus();$('host-search').setSelectionRange(pos,pos);});
  const updateSelection=()=>{const boxes=[...document.querySelectorAll('[data-select]')];if($('select-all-hosts')){$('select-all-hosts').checked=!!boxes.length&&boxes.every(c=>c.checked);$('select-all-hosts').indeterminate=boxes.some(c=>c.checked)&&!boxes.every(c=>c.checked);} $('scan-hosts').textContent=`Scan selected (${selected.size})`;$('scan-hosts').disabled=!selected.size||catalog.role==='reader';if($('upgrade-hosts')){$('upgrade-hosts').textContent=`Upgrade selected (${selected.size})`;$('upgrade-hosts').disabled=!selected.size;}};
  if($('scan-hosts'))updateSelection();
  document.querySelectorAll('[data-select]').forEach(c=>c.onchange=()=>{if(c.checked)selected.add(c.dataset.select);else selected.delete(c.dataset.select);updateSelection();});
  $('select-all-hosts')?.addEventListener('change',e=>{document.querySelectorAll('[data-select]').forEach(c=>{c.checked=e.target.checked;if(c.checked)selected.add(c.dataset.select);else selected.delete(c.dataset.select);});updateSelection();});
  document.querySelectorAll('[data-vendor-refresh]').forEach(b=>b.onclick=async()=>{try{b.disabled=true;b.textContent='Retrieving…';const r=await api('vendors/refresh',{source_id:b.dataset.vendorRefresh});await refresh();if(r.error)message(r.error);}catch(e){message(e);b.disabled=false;b.textContent='Refresh from vendor';}});
  $('filter-vendors')?.addEventListener('click',async()=>{try{vendorModel=$('vendor-model').value;data.vendors=(await api('vendors?model='+encodeURIComponent(vendorModel))).data;render();}catch(e){message(e);}});
}
function wireEditor(kind) {
  $('editor-save').hidden=kind==='upgrade';
  if(kind==='upgrade') {
    let step=1; const total=4;
    const panels=[...document.querySelectorAll('.wizard-panel')];
    const steps=[...document.querySelectorAll('.wizard-step')];
    const show=()=>{
      panels.forEach((p,i)=>p.hidden=i+1!==step);
      steps.forEach((s,i)=>{s.classList.toggle('active',i+1===step);s.classList.toggle('done',i+1<step);});
      $('wizard-back').disabled=step===1;
      $('wizard-next').textContent=step===total?'Launch upgrade':'Next';
      if(step===total) {
        const form=new FormData($('editor-form'));
        const b=data.baselines.find(x=>x.id===form.get('baseline_id'));
        const rows=[['Job name',form.get('name')||'(unnamed)'],['Servers',selected.size],['Target baseline',b?b.name:'Choose one on step 3'],['Batch size',form.get('batch_size')&&form.get('batch_size')!=='0'?form.get('batch_size'):'0 — all at once'],['Maintenance window',form.get('not_before')||'Starts immediately']];
        $('wizard-review').innerHTML=rows.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join('');
      }
    };
    $('wizard-back').onclick=()=>{step=Math.max(1,step-1);show();};
    $('wizard-next').onclick=()=>{
      if(step<total) {
        const invalid=[...panels[step-1].querySelectorAll('[required]')].find(el=>!el.checkValidity());
        if(invalid){invalid.reportValidity();return;}
        step++;show();
      } else {
        $('editor-form').requestSubmit();
      }
    };
    show();
  }
  if(kind==='hosts') {
    const protocol=document.querySelector('[name=protocol]');
    const update=()=>{document.querySelector('[name=ssh_user]').required=protocol.value!=='redfish';document.querySelector('[name=credential_profile]').required=protocol.value!=='ssh';document.querySelector('[name=bmc_address]').required=protocol.value==='both';};
    protocol.onchange=update;update();
  }
  if(kind==='bulk') {
    $('csv-file').onchange=async e=>{try{const file=e.target.files[0];if(file){if(file.size>120000)throw Error('CSV exceeds 120 KB');$('csv-input').value=await file.text();}}catch(err){message(err);}};
    $('preview-import').onclick=async()=>{try{const r=await api('hosts/import',{csv:$('csv-input').value,preview:true});$('import-preview').innerHTML=`<p class="success-text">${r.count} valid servers. Save to import all rows.</p>`+table(['Name','Address','Method','Model'],r.data.map(h=>[esc(h.name),esc(h.address),esc(h.protocol),esc(h.model)]));}catch(e){$('import-preview').textContent=e.message;}};
  }
}
function jobHostOutcomes(job) {
  const seen={};
  for (const b of job.batch_results||[]) for (const [hid,s] of Object.entries(b.hosts||{})) seen[hid]=s;
  let successful=0, failed=0, rolledBack=0;
  for (const hid of job.host_ids||[]) {
    const s=seen[hid];
    if (!s) continue;
    if (s.rollback_verify) { if (s.rollback_verify.status==='ok') rolledBack++; else failed++; }
    else if (s.post_verify?.status==='pass') successful++;
    else failed++;
  }
  return {successful, failed, rolledBack, skipped:Math.max(0,(job.host_ids||[]).length-successful-failed-rolledBack)};
}
function jobConsoleLines(job) {
  const lines=[`$ baseline upgrade plan --hosts ${job.host_ids?.length||0} --baseline "${job.baseline?.name||''}"`];
  if (job.plan?.error) lines.push(`ERROR planning failed: ${job.plan.error}`);
  else if (job.plan?.candidates) lines.push(job.plan.candidates.length?`${job.plan.candidates.length} package(s) pending: ${job.plan.candidates.map(c=>c.name).join(', ')}`:'No pending package changes found.');
  for (const b of job.batch_results||[]) {
    lines.push(`\n== Batch ${b.index+1} (${b.host_ids.length} host${b.host_ids.length===1?'':'s'}) ==`);
    for (const [hid,s] of Object.entries(b.hosts||{})) {
      const hn=name('hosts',hid);
      if (s.upgrade && 'rc' in s.upgrade) lines.push(`[${hn}] upgrade rc=${s.upgrade.rc} transaction=${s.upgrade.transaction_id||'—'}`);
      if (s.post_verify) lines.push(`[${hn}] post-upgrade check: ${s.post_verify.status}`);
      if (s.rollback && 'rc' in s.rollback) lines.push(`[${hn}] rollback rc=${s.rollback.rc}`);
      if (s.rollback_verify) lines.push(`[${hn}] rollback verify: ${s.rollback_verify.status}`);
    }
    lines.push(`== Batch ${b.index+1} result: ${b.status}${b.error?' — '+b.error:''} ==`);
  }
  if (job.status && !['planning','running_plan','queued','running'].includes(job.status)) lines.push(`\n$ job ${job.status}`);
  return lines;
}
function showJob(job) {
  $('job-json').textContent=JSON.stringify(job,null,2);
  $('job-detail-title').textContent=job.name||'Upgrade job';
  const canConfirm=job.status==='planned', canCancel=['planned','no_changes','queued'].includes(job.status), admin=catalog.role==='admin';
  $('job-actions').innerHTML=`${badge(job.status)} ${canConfirm&&admin?'<button id="confirm-job" class="primary">Confirm and run</button>':''}${canCancel&&admin?'<button id="cancel-job">Cancel</button>':''}`;
  $('confirm-job')?.addEventListener('click',async()=>{try{await api('jobs/'+job.id+'/confirm',{});$('job-detail').close();page='jobs';await refresh();}catch(e){message(e);}});
  $('cancel-job')?.addEventListener('click',async()=>{try{await api('jobs/'+job.id+'/cancel',{});$('job-detail').close();page='jobs';await refresh();}catch(e){message(e);}});

  const totalBatches=Math.max(1,Math.ceil((job.host_ids?.length||1)/(job.batch_size||job.host_ids?.length||1)));
  const doneBatches=(job.batch_results||[]).length;
  const active=['planning','running_plan','queued','running'].includes(job.status);
  const pct=active?Math.min(95,Math.round(doneBatches/totalBatches*100)):100;
  const outcomes=jobHostOutcomes(job);
  const tiles=[['Total targets',job.host_ids?.length||0],['Successful',outcomes.successful]];
  if (outcomes.rolledBack) tiles.push(['Rolled back',outcomes.rolledBack]);
  tiles.push(['Failed',outcomes.failed],['Skipped',outcomes.skipped]);

  const candidates=job.plan?.candidates||[];
  const planTable=candidates.length?table(['Package','Current','Candidate','Repo'],candidates.map(c=>[esc(c.name),esc(c.current||'unknown'),esc(c.candidate),esc(c.repo)])):'<p class="muted">No pending package changes were found for this host set.</p>';
  const batches=(job.batch_results||[]).map(b=>`<section class="panel report-host"><h3>Batch ${b.index+1} ${badge(b.status||'in progress')}</h3>${b.error?`<p>${esc(b.error)}</p>`:''}${table(['Server','Pre-upgrade kernel','Upgrade result','Post-upgrade check','Rollback check'],Object.entries(b.hosts||{}).map(([hid,s])=>[esc(name('hosts',hid)),esc(s.pre?.['kernel.release']||'unknown'),s.upgrade?.rc===0?'Applied':s.upgrade?.rc!==undefined?'Failed (rc '+s.upgrade.rc+')':'—',badge(s.post_verify?.status||'—'),s.rollback_verify?badge(s.rollback_verify.status):'—']))}</section>`).join('');
  const consoleHtml=jobConsoleLines(job).map(l=>`<div class="${/error|failed|fail\b/i.test(l)?'line-error':/pass|rc=0|upgraded|rolled_back|: ok/i.test(l)?'line-ok':''}">${esc(l)}</div>`).join('');

  $('job-summary').innerHTML=`<p>Baseline: <strong>${esc(job.baseline?.name||'—')}</strong> · ${job.host_ids?.length||0} servers · batch size ${job.batch_size||job.host_ids?.length||0}</p>
${job.description?`<p class="muted">${esc(job.description)}</p>`:''}
${active?`<div class="progress"><div class="progress-fill" data-width="${pct}"></div></div><p class="muted">Batch ${doneBatches} of ${totalBatches}${doneBatches<totalBatches?' running…':''}</p>`:''}
${doneBatches||!active?`<div class="summary-stats">${tiles.map(([l,n])=>`<div class="stat"><strong>${n}</strong><span>${esc(l)}</span></div>`).join('')}</div>`:''}
<h3>Dry-run plan</h3>${planTable}
<h3>Console</h3><div class="console">${consoleHtml}</div>
${batches}`;
  hydrateWidths($('job-summary'));
  $('job-detail').showModal();
}
function showReport(value) {
  report=value;$('report-json').textContent=JSON.stringify(value,null,2);
  $('report-summary').innerHTML=`<p>${badge(value.status)} · ${value.hosts.length} servers · ${value.parallelism||5} concurrent</p>${(value.results||[]).map(r=>`<section class="panel report-host"><h3>${esc(r.host_name||name('hosts',r.host_id))} ${badge(r.status)}</h3>${r.error?`<p>${esc(r.error)}</p>`:''}${r.checks.length?table(['Check','Expected','Observed','Result'],r.checks.map(c=>[esc(c.id),esc(JSON.stringify(c.expected)),esc(JSON.stringify(c.actual)),badge(c.status)])):`<p>Inventory collected. No baseline comparison was requested.</p>${table(['Fact','Observed'],Object.entries(r.facts).filter(([k])=>!['rpm.packages','modules.loaded','cpu.flags'].includes(k)).map(([k,v])=>[esc(k),esc(JSON.stringify(v))]))}`}</section>`).join('')}`;
  $('report').showModal();
}
