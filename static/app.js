'use strict';
let loggedIn = false, page = 'overview', data = {}, catalog = {}, editorKind = '', report = null;
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path, body) {
  const r = await fetch('/api/' + path, {method:body ? 'POST':'GET', headers:body ? {'Content-Type':'application/json'}:{}, ...(body ? {body:JSON.stringify(body)}:{})});
  if (r.status === 401 && path !== 'login') { loggedIn = false; $('workspace').hidden = true; $('login').hidden = false; }
  const result = await r.json(); if (!r.ok) throw Error(result.error || 'Request failed'); return result;
}
function message(error) { $('message').textContent = error.message || String(error); }
function badge(status) { return `<span class="badge ${esc(status)}">${esc(status)}</span>`; }
function name(table, id) { return data[table].find(x=>x.id===id)?.name || id; }
function table(headers, rows) { return rows.length ? `<div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th scope="col">${h}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : '<div class="panel empty">No records yet. Add inventory and an approved baseline to get started.</div>'; }
async function refresh() {
  try {
    catalog = await api('catalog');
    const keys = ['hosts','baselines','bindings','runs','audit','templates'];
    const results = await Promise.all(keys.map(k=>api(k)));
    keys.forEach((k,i)=>data[k]=results[i].data);
    data.verifications = Object.fromEntries(await Promise.all(data.bindings.map(async b=>[b.id,await api(`bindings/${b.id}/verification`)])));
    if (catalog.role==='admin') data.users = (await api('users')).data;
    loggedIn = true;
    $('login').hidden=true; $('workspace').hidden=false; $('message').textContent=''; render();
  } catch (e) { message(e); }
}
function render() {
  const titles = {overview:'Verification overview',hosts:'Host inventory',baselines:'Baseline policies',bindings:'Upgrade verification',runs:'Evidence reports',audit:'Audit history',users:'Access'};
  $('page-title').textContent=titles[page];
  document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',b.dataset.page===page));
  $('runner').textContent = catalog.runner_available && catalog.ssh_configured ? 'Ansible controller ready · Read-only SSH collection · Strict host-key verification' : 'Controller setup required: install Ansible and configure the SSH key, known hosts, and approved management networks.';
  $('nav-users').hidden = catalog.role!=='admin';
  $('version-footer').textContent = catalog.version ? `v${catalog.version}` : '';
  let html='';
  if (page==='overview') {
    const cards=[['Managed hosts',data.hosts.length],['Baseline revisions',data.baselines.length],['Verified upgrades',Object.values(data.verifications).filter(v=>v.verified).length],['Collection runs',data.runs.length]];
    html=`<div class="cards">${cards.map(([label,n])=>`<div class="card"><span class="muted">${label}</span><strong>${n}</strong></div>`).join('')}</div><section class="panel"><h2>Evidence behind every upgrade</h2><div class="flow"><div><strong>01 · Define the target</strong><p class="muted">Register management IPs and publish an immutable baseline with the exact versions and HFT settings you require.</p></div><div><strong>02 · Collect and compare</strong><p class="muted">Bind the ticket to its hosts. Run Ansible checks after the upgrade and inspect every result.</p></div><div><strong>03 · Verify the change</strong><p class="muted">ServiceOps and FlowOps can query the verification API. Fresh evidence and a complete pass are required.</p></div></div></section>`;
  }
  if (page==='hosts') html=table(['Host','Management IP','SSH user','Tags'],data.hosts.map(h=>[esc(h.name),esc(h.address)+':'+h.port,esc(h.ssh_user),esc(h.tags)]));
  if (page==='baselines') html=table(['Policy','Revision','Checks','Created'],data.baselines.map(b=>[esc(b.name),esc(b.revision_sha256.slice(0,12)),b.checks.length,new Date(b.created_at*1000).toLocaleString()]));
  if (page==='bindings') html=table(['Ticket / task','System','Baseline','Hosts','Verification','Action'],data.bindings.map(b=>[esc(b.ticket_id),esc(b.external_system),esc(name('baselines',b.baseline_id)),b.host_ids.length,badge(data.verifications[b.id].status),`<button data-verify="${b.id}">${data.verifications[b.id].verified?'Reverify':'Run verification'}</button>`]));
  if (page==='runs') html=table(['Run','Baseline','Status','Created','Evidence'],data.runs.map(r=>[esc(r.id.slice(0,12)),esc(r.baseline.name),badge(r.status),new Date(r.created_at*1000).toLocaleString(),`<button data-report="${r.id}">View report</button>`]));
  if (page==='audit') html=table(['Time','Actor','Action','Record'],data.audit.map(a=>[new Date(a.created*1000).toLocaleString(),esc(a.actor),esc(a.action),esc(a.subject)]));
  if (page==='users') html=table(['Username','Role','Actions'],(data.users||[]).map(u=>[esc(u.username),esc(u.role),catalog.role==='admin'?`<button data-reset="${esc(u.username)}">Reset password</button> <button data-revoke="${esc(u.username)}">Revoke</button>`:'']));
  if (['hosts','baselines','bindings','users'].includes(page) && catalog.role==='admin') html=`<div class="toolbar"><span class="muted">${page==='baselines'?'Changes are saved as new, immutable revisions.':page==='bindings'?'Bind an exact host set and baseline to an upgrade ticket.':page==='users'?'Grant sign-in access to another administrator or read-only reviewer.':'Manage the servers available for verification.'}</span><button class="primary" id="add">${{hosts:'Add host',baselines:'Create baseline',bindings:'Bind upgrade',users:'Add user'}[page]}</button></div>`+html;
  $('content').innerHTML=html;
  $('add')?.addEventListener('click',()=>openEditor(page));
  document.querySelectorAll('[data-verify]').forEach(b=>{b.disabled=catalog.role==='reader';b.onclick=async()=>{try{b.disabled=true;await api('runs',{binding_id:b.dataset.verify});page='runs';await refresh();}catch(e){message(e);b.disabled=false;}};});
  document.querySelectorAll('[data-report]').forEach(b=>b.onclick=async()=>{try{report=await api('runs/'+b.dataset.report);$('report-json').textContent=JSON.stringify(report,null,2);$('report').showModal();}catch(e){message(e);}});
  document.querySelectorAll('[data-revoke]').forEach(b=>b.onclick=async()=>{if(!confirm(`Revoke access for ${b.dataset.revoke}? They will be signed out immediately.`))return;try{await api(`users/${b.dataset.revoke}/revoke`,{});await refresh();}catch(e){message(e);}});
  document.querySelectorAll('[data-reset]').forEach(b=>b.onclick=async()=>{const password=prompt(`New temporary password for ${b.dataset.reset} (12+ characters). Share it out of band.`);if(!password)return;try{await api(`users/${b.dataset.reset}/reset`,{password});message({message:`Password reset for ${b.dataset.reset}. Their existing session was signed out.`});}catch(e){message(e);}});
}
const sample={name:'Linux upgrade acceptance — customize before use',checks:[{id:'os-release',field:'os.version',op:'eq',expected:'REPLACE_WITH_APPROVED_VERSION',required:true},{id:'running-kernel',field:'kernel.release',op:'eq',expected:'REPLACE_WITH_APPROVED_KERNEL',required:true},{id:'kernel-clean',field:'kernel.tainted',op:'eq',expected:0,required:true},{id:'failed-services',field:'services.failed',op:'eq',expected:'',required:true},{id:'dkms-module',field:'dkms.status',op:'contains',expected:'REPLACE_WITH_MODULE_VERSION_KERNEL_AND_INSTALLED_STATUS',required:true}]};
function field(label,name,type='text',value='') { return `<label>${label}<input name="${name}" type="${type}" value="${esc(value)}" required></label>`; }
function openEditor(kind) {
  editorKind=kind; $('editor-title').textContent={hosts:'Add management host',baselines:'Create baseline revision',bindings:'Bind upgrade ticket',users:'Add access account'}[kind];
  let fields='';
  if(kind==='hosts') fields=field('Host name','name')+field('Management IP address','address')+field('SSH user','ssh_user','text','baseline')+field('SSH port','port','number','22')+'<label>Tags<input name="tags" placeholder="Tokyo, HFT, production"></label>';
  if(kind==='baselines') fields=`<label>Distribution starter<select id="starter"><option value="">Generic Linux</option>${data.templates.map((t,i)=>`<option value="${i}">${esc(t.name)}</option>`).join('')}</select></label><p>Use exact approved versions. Missing required facts block verification. Version strings are compared exactly.</p><label>Baseline JSON<textarea name="policy" spellcheck="false" required>${esc(JSON.stringify(sample,null,2))}</textarea></label><details><summary>Available fields and comparisons</summary><p>${esc(catalog.fields.join(', '))}</p><p>Operators: ${esc(catalog.operators.join(', '))}</p></details>`;
  if(kind==='bindings') fields='<label>System<select name="external_system"><option value="serviceops">ServiceOps</option><option value="flowops">FlowOps</option></select></label>'+field('Ticket or task reference','ticket_id')+`<label>Baseline revision<select name="baseline_id" required>${data.baselines.map(b=>`<option value="${b.id}">${esc(b.name)} · ${b.revision_sha256.slice(0,8)}</option>`).join('')}</select></label><label>Hosts (select all affected servers)<select name="host_ids" multiple required>${data.hosts.map(h=>`<option value="${h.id}">${esc(h.name)} · ${esc(h.address)}</option>`).join('')}</select></label>`+field('Evidence lifetime (seconds)','max_age_seconds','number','3600')+'<p>Evidence must be collected after this binding is created. The API also accepts an explicit upgrade completion timestamp.</p>';
  if(kind==='users') fields=field('Username','username')+field('Temporary password (12+ characters)','password','password')+'<label>Role<select name="role"><option value="reader">Read-only</option><option value="admin">Administrator</option></select></label><p>Share the temporary password out of band. There is no self-service password change yet.</p>';
  $('editor-fields').innerHTML=fields; if(kind==='baselines')$('starter').onchange=e=>{document.querySelector('[name=policy]').value=JSON.stringify(e.target.value===''?sample:data.templates[Number(e.target.value)],null,2);}; $('editor').showModal();
}
$('editor-form').onsubmit=async e=>{e.preventDefault();try{const form=new FormData(e.target);let body=Object.fromEntries(form);if(editorKind==='baselines')body=JSON.parse(body.policy);if(editorKind==='hosts')body.port=Number(body.port);if(editorKind==='bindings'){body.host_ids=form.getAll('host_ids');body.max_age_seconds=Number(body.max_age_seconds);}await api(editorKind,body);$('editor').close();await refresh();}catch(err){message(err);let p=$('editor-error');if(!p){p=document.createElement('p');p.id='editor-error';p.setAttribute('role','alert');$('editor-fields').append(p);}p.textContent=err.message;}};
$('login-form').onsubmit=async e=>{e.preventDefault();const username=$('username').value,password=$('password').value;$('password').value='';try{await api('login',{username,password});await refresh();}catch(err){message(err);}};
$('logout').onclick=async()=>{try{await api('logout',{});}catch(e){}loggedIn=false;data={};$('workspace').hidden=true;$('login').hidden=false;};
$('refresh').onclick=refresh;
$('close-editor').onclick=()=>$('editor').close();$('close-report').onclick=()=>$('report').close();
$('download').onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='baseline-'+report.id+'.json';a.click();URL.revokeObjectURL(url);};
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{if(!loggedIn)return;page=b.dataset.page;render();});
fetch('/health').then(r=>r.json()).then(d=>{if(d.version)$('version-login').textContent=`v${d.version}`;}).catch(()=>{});
setInterval(()=>{if(loggedIn && data.runs?.some(r=>['queued','running'].includes(r.status)))refresh();},3000);
