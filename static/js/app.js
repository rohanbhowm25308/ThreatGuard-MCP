'use strict';
const $ = id => document.getElementById(id);
const notice = (text, error=false) => { $('notice').textContent=text; $('notice').className=error?'notice error':'notice'; };
const events = (title, detail) => { const row=document.createElement('div'); row.className='event'; const icon=document.createElement('span');icon.className='event-icon';icon.textContent='✓';const wrap=document.createElement('div');const b=document.createElement('b');b.textContent=title;const small=document.createElement('small');small.textContent=detail;wrap.append(b,small);row.append(icon,wrap);$('events').prepend(row);while($('events').children.length>5)$('events').lastElementChild.remove(); };
async function api(path){const res=await fetch(path,{headers:{Accept:'application/json'}});let data;try{data=await res.json()}catch{throw new Error('Invalid server response')}if(!res.ok)throw new Error(data.error||'Request failed');return data;}
function render(items,title){$('table-title').textContent=title;$('result-count').textContent=`${items.length} results`;$('rows').replaceChildren();if(!items.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=5;td.className='empty';td.textContent='No matching entries in CISA KEV. This does not mean a CVE is safe.';tr.append(td);$('rows').append(tr);return;}for(const item of items){const tr=document.createElement('tr');for(const value of [item.cveID,`${item.vendorProject} / ${item.product}`,item.vulnerabilityName,item.dateAdded]){const td=document.createElement('td');td.textContent=value;tr.append(td);}const td=document.createElement('td'),btn=document.createElement('button');btn.textContent='Details ↗';btn.addEventListener('click',()=>showDetails(item));td.append(btn);tr.append(td);$('rows').append(tr);}}
function showDetails(item){$('modalTitle').textContent=item.cveID;$('modalBody').replaceChildren();const labels=[['Vulnerability',item.vulnerabilityName],['Vendor / Product',`${item.vendorProject} / ${item.product}`],['Description',item.shortDescription],['Required action',item.requiredAction],['Date added',item.dateAdded],['Due date',item.dueDate],['Known ransomware use',item.knownRansomwareCampaignUse],['Notes',item.notes]];for(const [label,value] of labels){const d=document.createElement('div');d.className='detail';const b=document.createElement('b'),p=document.createElement('p');b.textContent=label.toUpperCase();p.textContent=value||'Not provided';d.append(b,p);$('modalBody').append(d);}$('modal').classList.remove('hidden');$('closeModal').focus();}
let currentMode='demo', currentItems=[];
async function load(){if(currentMode==='demo'){const data=await api('/api/demo');applyDataset(data.items,'Demo examples','demo');return;}if(currentMode==='upload'){applyDataset(currentItems,'Uploaded preview','upload');return;} notice('Syncing official CISA KEV intelligence…');try{const [s,data]=await Promise.all([api('/api/stats'),api('/api/latest?limit=25')]);for(const key of ['total','vendors','ransomware'])$(key).textContent=s[key].toLocaleString();render(data.items,'Recently added vulnerabilities');notice(`● Live catalog ready · Released: ${s.updated} · CISA KEV`);events('Threat feed synchronized',`${s.total.toLocaleString()} known exploited vulnerabilities loaded`);currentItems=data.items;updateChatSource();}catch(err){notice(err.message,true);$('rows').replaceChildren();const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=5;td.className='empty';td.textContent='Unable to load CISA data. Check your connection and retry.';tr.append(td);$('rows').append(tr);events('Feed unavailable',err.message);}}
async function doSearch(){const q=$('query').value.trim();if(currentMode!=='live'){if(!q){applyDataset(currentItems,currentMode==='demo'?'Demo examples':'Uploaded preview',currentMode);return;}const match=currentItems.filter(x=>[x.cveID,x.vendorProject,x.product,x.vulnerabilityName,x.shortDescription].join(' ').toLowerCase().includes(q.toLowerCase()));render(match,`Search results for “${q}”`);notice(`${match.length} results in ${currentMode} data`);return;}if(!q){await load();return;}notice('Searching intelligence catalog…');try{const data=await api('/api/search?q='+encodeURIComponent(q)+'&limit=25');render(data.items,`Search results for “${q}”`);notice(`Found ${data.items.length} matching entries (up to 25 displayed)`);events('Intelligence search',`Query: ${q.slice(0,60)}`);}catch(err){notice(err.message,true);events('Search rejected',err.message);}}
function applyDataset(items,title,mode){currentMode=mode;currentItems=items;const vendors=new Set(items.map(x=>x.vendorProject).filter(Boolean));$('total').textContent=items.length.toLocaleString();$('vendors').textContent=vendors.size.toLocaleString();$('ransomware').textContent=items.filter(x=>String(x.knownRansomwareCampaignUse).toLowerCase()==='known').length.toLocaleString();render(items,title);$('sourceBadge').textContent=mode==='demo'?'DEMO DATA':mode==='upload'?'USER UPLOAD':'LIVE CISA';$('sourceHint').textContent=mode==='demo'?'Bundled illustrative examples — not live':mode==='upload'?'Temporary user-selected dataset — not saved':'Official CISA KEV feed';notice(`${title} ready · ${items.length} records`);events('Data source selected',title);if(typeof refreshFeatureChoices==='function')refreshFeatureChoices();updateChatSource();}
function openSource(){ $('sourceModal').classList.remove('hidden');$('sourceClose').classList.remove('hidden');$('sourceError').textContent=''; }
function closeSource(){ $('sourceModal').classList.add('hidden'); }
$('chooseSource').addEventListener('click',openSource);$('switchSource').addEventListener('click',openSource);$('sourceClose').addEventListener('click',closeSource);
$('demoChoice').addEventListener('click',async()=>{try{const d=await api('/api/demo');applyDataset(d.items,'Demo examples','demo');closeSource();}catch(e){$('sourceError').textContent=e.message;}});
$('uploadChoice').addEventListener('click',()=>{closeSource();navigate('upload');$('uploadFile').focus();});
$('uploadSubmit').addEventListener('click',async()=>{const file=$('uploadFile').files[0];if(!file){$('sourceError').textContent='Please select a file.';return;}const form=new FormData();form.append('file',file);$('sourceError').textContent='Validating file…';try{const response=await fetch('/api/preview-upload',{method:'POST',body:form});let d;try{d=await response.json();}catch{throw new Error('Upload failed: server returned a non-JSON response. Check file size or server logs.');}if(!response.ok)throw new Error(d.error||'Upload rejected');applyDataset(d.items,'Uploaded preview','upload');$('sourceError').textContent='';navigate('explorer');}catch(e){$('sourceError').textContent=e.message;}});
$('liveChoice').addEventListener('click',async()=>{currentMode='live';closeSource();$('sourceBadge').textContent='LIVE CISA';$('sourceHint').textContent='Official live catalog';await load();});
$('searchBtn').addEventListener('click',doSearch);$('query').addEventListener('keydown',e=>{if(e.key==='Enter')doSearch();});$('refresh').addEventListener('click',load);$('closeModal').addEventListener('click',()=>$('modal').classList.add('hidden'));$('modal').addEventListener('click',e=>{if(e.target===$('modal'))$('modal').classList.add('hidden');});document.addEventListener('keydown',e=>{if(e.key==='Escape')$('modal').classList.add('hidden');});
// Dedicated sidebar workspaces: no long overlapping one-page scrolling.
const pageMap={overview:['overview','overviewExtras'],explorer:['explorer'],activity:['activity'],architecture:['architecture'],upload:['upload'],chat:['chat'],risk:['risk'],lab:['lab'],reports:['reports']};
const viewSections=['overview','overviewExtras','explorer','activity','architecture','upload','chat','risk','lab','reports'];
function navigate(name){
 if(!pageMap[name])name='overview';
 for(const id of viewSections)$(id).classList.toggle('workspace-hidden',!pageMap[name].includes(id));
 document.querySelectorAll('.sidebar .nav').forEach(a=>{const active=a.getAttribute('href')==='#'+name;a.classList.toggle('active',active);if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});
 document.querySelector('.breadcrumb').textContent='PLATFORM / '+({overview:'OVERVIEW',explorer:'CVE EXPLORER',activity:'ACTIVITY FEED',architecture:'MCP ARCHITECTURE',upload:'CSV / JSON UPLOAD',chat:'GROQ AI CHAT',risk:'AI RISK PREDICTOR',lab:'INVESTIGATION LAB',reports:'SECURITY REPORTS'}[name]);
 window.scrollTo({top:0,behavior:'instant'});
 if(location.hash!=='#'+name)history.replaceState(null,'','#'+name);
}
// Place the existing validated upload form in its own visible section.
$('uploadMount').append($('uploadPanel'));
$('uploadPanel').classList.remove('hidden');
$('sourceError').remove();
const errorArea=document.createElement('div');errorArea.id='sourceError';errorArea.className='source-error';errorArea.setAttribute('role','alert');$('uploadPanel').append(errorArea);
document.querySelectorAll('a[href^="#"]').forEach(a=>a.addEventListener('click',e=>{const page=a.getAttribute('href').slice(1);if(pageMap[page]){e.preventDefault();navigate(page);}}));
window.addEventListener('hashchange',()=>navigate(location.hash.slice(1)));
navigate(location.hash.slice(1)||'overview');
// Open the dashboard immediately. The source chooser opens only from the two source buttons.
closeSource();
load().catch(err => notice('Could not load demo data: ' + err.message, true));

// Dedicated Groq AI chat. Key is only read by the Python backend.
const chatForm=$('chatForm'),chatInput=$('chatInput'),chatSend=$('chatSend');
// Summarize the active dataset, not just the first few rows. Never send all 20,000 rows to the LLM.
function activeDatasetContext(message){
 const items=currentItems||[];
 if(!items.length)return {source:currentMode,total:0,records:[],summary:null};
 const counts=(key)=>{const map=new Map();for(const row of items){const name=String(row[key]||'Unknown').trim();map.set(name,(map.get(name)||0)+1);}return [...map].sort((a,b)=>b[1]-a[1]).slice(0,8).map(([name,count])=>({name,count}));};
 const query=(message.match(/CVE-\d{4}-\d{4,}/i)||[])[0];
 let relevant=query?items.filter(x=>String(x.cveID).toUpperCase()===query.toUpperCase()):[];
 if(!relevant.length){const words=message.toLowerCase().split(/[^a-z0-9]+/).filter(x=>x.length>3&&!['uploaded','details','about','file','tell','dataset','please','information','explain','what','have','given'].includes(x));if(words.length)relevant=items.filter(x=>words.some(w=>[x.cveID,x.vendorProject,x.product,x.vulnerabilityName].join(' ').toLowerCase().includes(w))).slice(0,12);}
 if(!relevant.length)relevant=items.slice(0,12);
 return {source:currentMode,total:items.length,records:relevant.slice(0,12),summary:{vendors:counts('vendorProject'),products:counts('product'),knownRansomware:items.filter(x=>String(x.knownRansomwareCampaignUse).toLowerCase()==='known').length,firstCveIds:items.slice(0,8).map(x=>x.cveID)}};
}
function updateChatSource(){const el=$('chatDatasetStatus');if(!el)return;el.textContent=currentMode==='upload'?`Uploaded dataset active: ${currentItems.length.toLocaleString()} CVEs. Ask me to summarize the file.`:currentMode==='demo'?`Demo dataset active: ${currentItems.length} illustrative CVEs. Upload a CSV for your own analysis.`:'Live CISA selected. Search a CVE or choose an uploaded dataset for file analysis.';}

function chatBubble(text,role){const node=document.createElement('div');node.className='ai-bubble '+role;node.textContent=text;$('chatMessages').append(node);$('chatMessages').scrollTop=$('chatMessages').scrollHeight;return node;}
// Record microphone audio and transcribe on the server with Groq Whisper.
// This works in Edge/Chrome without relying on the browser SpeechRecognition service.
const chatMic=$('chatMic'), voiceStatus=$('voiceStatus');
let voiceListening=false, recorder=null, micStream=null, chunks=[], voiceTimer=null;
function setVoiceState(active,message){voiceListening=active;chatMic.classList.toggle('listening',active);chatMic.setAttribute('aria-pressed',String(active));chatMic.setAttribute('aria-label',active?'Stop recording':'Start voice input');chatMic.title=active?'Stop recording':'Record voice message';voiceStatus.textContent=message||'';}
function releaseMic(){if(voiceTimer){clearTimeout(voiceTimer);voiceTimer=null;}if(micStream){micStream.getTracks().forEach(track=>track.stop());micStream=null;}}
async function uploadVoice(blob,format){
  voiceStatus.textContent='Transcribing your voice with Groq…';chatMic.disabled=true;
  try{
    const form=new FormData();form.append('audio',blob,format.includes('mp4')?'voice.mp4':format.includes('ogg')?'voice.ogg':format.includes('wav')?'voice.wav':'voice.webm');
    const res=await fetch('/api/transcribe',{method:'POST',body:form});
    const data=await res.json().catch(()=>({error:'Transcription service returned an invalid response.'}));if(!res.ok)throw new Error(data.error||'Transcription failed');
    chatInput.value=[chatInput.value.trim(),data.text].filter(Boolean).join(' ').slice(0,2000);
    voiceStatus.textContent='Voice converted to text. Review and press Send.';chatInput.focus();
  }catch(err){voiceStatus.textContent=err.message||'Voice transcription failed.';}
  finally{chatMic.disabled=false;}
}
async function startVoice(){
  if(!navigator.mediaDevices?.getUserMedia||!window.MediaRecorder){voiceStatus.textContent='Microphone recording is unavailable. Use Chrome or Edge on localhost or HTTPS.';return;}
  try{
    micStream=await navigator.mediaDevices.getUserMedia({audio:true});
    const types=['audio/webm;codecs=opus','audio/webm','audio/mp4','audio/ogg'];
    const type=types.find(t=>MediaRecorder.isTypeSupported(t))||'';
    recorder=new MediaRecorder(micStream,type?{mimeType:type}:undefined);
    chunks=[];
    recorder.ondataavailable=e=>{if(e.data.size)chunks.push(e.data);};
    recorder.onerror=()=>{releaseMic();setVoiceState(false,'Microphone recording failed. Try again.');};
    recorder.onstop=()=>{const blob=new Blob(chunks,{type:recorder.mimeType||'audio/webm'});releaseMic();setVoiceState(false,'Recording complete.');if(blob.size)uploadVoice(blob,blob.type);else voiceStatus.textContent='No audio captured. Please try again.';};
    recorder.start();setVoiceState(true,'Recording… speak now. Click the microphone again to transcribe.');
    voiceTimer=setTimeout(()=>{if(recorder?.state==='recording')recorder.stop();},45000);
  }catch(err){releaseMic();setVoiceState(false,err.name==='NotAllowedError'?'Microphone access denied. Allow it in browser permissions.':'Could not access microphone. Check your device and permissions.');}
}
// Use Groq Whisper consistently: browser speech recognition can fail with a network error.
// Click once to record, click again to transcribe into the editable chat input.
chatMic.addEventListener('click',()=>{
  if(voiceListening){if(recorder?.state==='recording')recorder.stop();}
  else if(!chatMic.disabled)startVoice();
});
chatForm.addEventListener('submit',async event=>{event.preventDefault();if(voiceListening||chatMic.disabled){voiceStatus.textContent='Finish recording and transcription before sending.';return;}const message=chatInput.value.trim();if(!message){$('chatError').textContent='Type a question or use the microphone before pressing Send.';chatInput.focus();return;}chatBubble(message,'user');chatInput.value='';chatSend.disabled=true;chatSend.textContent='Thinking…';$('chatError').textContent='';const pending=chatBubble('Analyzing your question…','assistant');try{const context=activeDatasetContext(message);const response=await fetch('/api/ai-chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message,records:context.records,dataset:context.summary,source:context.source,total:context.total})});const data=await response.json();if(!response.ok)throw new Error(data.error||'AI request failed');if(typeof data.reply!=='string'||!data.reply.trim())throw new Error('The AI returned an empty response. Please retry.');pending.textContent=data.reply;}catch(error){pending.remove();$('chatError').textContent=error.message;}finally{chatSend.disabled=false;chatSend.textContent='Send ↗';}});

// Original, lightweight animated dotted-star network background.
const canvas=$('stars'),ctx=canvas.getContext('2d');let dots=[],w=0,h=0;const reduced=window.matchMedia('(prefers-reduced-motion: reduce)').matches;function resize(){w=canvas.width=window.innerWidth;h=canvas.height=window.innerHeight;const count=Math.min(120,Math.max(35,Math.floor(w*h/13500)));dots=Array.from({length:count},()=>({x:Math.random()*w,y:Math.random()*h,r:Math.random()*1.5+.35,vx:(Math.random()-.5)*.25,vy:(Math.random()-.5)*.25}));}window.addEventListener('resize',resize);resize();function draw(){ctx.clearRect(0,0,w,h);for(let i=0;i<dots.length;i++){const d=dots[i];ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fillStyle='rgba(93,194,239,.48)';ctx.fill();if(!reduced){d.x=(d.x+d.vx+w)%w;d.y=(d.y+d.vy+h)%h;}for(let j=i+1;j<dots.length;j++){const e=dots[j],dist=Math.hypot(d.x-e.x,d.y-e.y);if(dist<100){ctx.beginPath();ctx.moveTo(d.x,d.y);ctx.lineTo(e.x,e.y);ctx.strokeStyle=`rgba(57,151,202,${(1-dist/100)*.09})`;ctx.stroke();}}}if(!reduced)requestAnimationFrame(draw);}draw(); // Source chooser opens only on user request; live CISA is never fetched automatically.


// Advanced investigation workspaces: untrusted record content is always inserted as text.
function featureRecords(){return currentMode==='live'?[]:currentItems;}
function refreshFeatureChoices(){
 for(const id of ['riskSelect','labSelect']){const el=$(id),old=el.value;el.replaceChildren();const items=featureRecords();if(!items.length){const o=new Option(currentMode==='live'?'Select demo or upload data to investigate':'No CVE records available','');el.add(o);continue;}items.slice(0,2000).forEach((item,i)=>el.add(new Option(`${item.cveID} — ${(item.product||'Unknown product').slice(0,70)}`,String(i))));if([...el.options].some(o=>o.value===old))el.value=old;}
}
function selectedFeature(id){const value=$(id).value;return value===''?null:featureRecords()[Number(value)]||null;}
function riskFactors(item){
 const ransomware=String(item.knownRansomwareCampaignUse||'').toLowerCase()==='known';
 const due=String(item.dueDate||'').slice(0,10),date=/^\d{4}-\d{2}-\d{2}$/.test(due)?new Date(due+'T00:00:00Z'):null;
 const overdue=date&&!isNaN(date.getTime())&&date.getTime()<Date.now();
 let score=55;const factors=['Listed in the selected CVE intelligence dataset (+55)'];
 if(ransomware){score+=25;factors.push('Known ransomware campaign use (+25)');}
 if(overdue){score+=15;factors.push('Remediation due date has passed (+15)');}
 if(item.requiredAction&&String(item.requiredAction).trim()){score+=5;factors.push('Documented required action (+5)');}
 return {score:Math.min(100,score),factors,label:score>=80?'Urgent review':score>=65?'High priority':'Review required'};
}
function makeNode(label,value,kind){const el=document.createElement('div');el.className='graph-node '+kind;const b=document.createElement('strong');b.textContent=label;const span=document.createElement('span');span.textContent=String(value||'Not provided').slice(0,300);el.append(b,span);return el;}
$('riskAnalyze').addEventListener('click',()=>{const item=selectedFeature('riskSelect'),out=$('riskOutput');out.replaceChildren();if(!item){out.textContent='Select a dataset with CVE records first.';return;}const r=riskFactors(item);const h=document.createElement('h3');h.textContent=`${item.cveID} · ${r.score}/100 · ${r.label}`;const meter=document.createElement('progress');meter.max=100;meter.value=r.score;meter.setAttribute('aria-label','Risk prioritization score');const list=document.createElement('ul');r.factors.forEach(f=>{const li=document.createElement('li');li.textContent=f;list.append(li);});const note=document.createElement('p');note.textContent='Heuristic prioritization only; not CVSS, EPSS, or a forecast. Missing evidence is not proof of safety. Verify against official advisories.';out.append(h,meter,list,note);});
$('labGraph').addEventListener('click',()=>{const item=selectedFeature('labSelect'),out=$('labGraphOutput');out.replaceChildren();$('labAIOutput').textContent='';if(!item){out.textContent='Select a CVE dataset first.';return;}out.append(makeNode('CVE',item.cveID,'cve'),makeNode('Vendor',item.vendorProject,'vendor'),makeNode('Product',item.product,'product'),makeNode('Vulnerability',item.vulnerabilityName,'issue'),makeNode('Defensive action',item.requiredAction||'Consult vendor advisory','action'));});
$('labAI').addEventListener('click',async()=>{const item=selectedFeature('labSelect'),out=$('labAIOutput');if(!item){out.textContent='Select a CVE first.';return;}out.textContent='Groq is analyzing this vulnerability…';$('labAI').disabled=true;try{const message=`Provide a concise defensive investigation briefing for ${item.cveID}: explain the vulnerability, affected product, impact, verification steps, and mitigation. Identify uncertainties. Do not invent references.`;const res=await fetch('/api/ai-chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message,records:[item]})});const data=await res.json();if(!res.ok)throw Error(data.error||'AI request failed');out.textContent=data.reply||'No response returned.';}catch(e){out.textContent=e.message;}finally{$('labAI').disabled=false;}});
$('reportDownload').addEventListener('click',async()=>{const out=$('reportStatus'),records=featureRecords().slice(0,Number($('reportCount').value));if(!records.length){out.textContent='Choose Demo data or upload a CVE dataset before generating a report.';return;}out.textContent='Generating report…';$('reportDownload').disabled=true;try{const res=await fetch('/api/security-report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({records,source:currentMode})});if(!res.ok){const data=await res.json().catch(()=>({}));throw Error(data.error||'Report generation failed');}const blob=await res.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='ThreatGuard_Security_Report.pdf';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2000);out.textContent='PDF generated. Check your Downloads folder.';}catch(e){out.textContent=e.message;}finally{$('reportDownload').disabled=false;}});
refreshFeatureChoices();
