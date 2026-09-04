"use strict";
// Shared infra used by every tab module: DOM/fetch helpers, modal form
// builder, table renderer, nft_route.json config state (CFG/CFG_MTIME),
// the websocket stream, and the tab-switch registry. Loaded FIRST (before
// any tab_*.js) -- everything here is a plain global, same scope as every
// other module (this is one inline <script>, not ES modules).
var ws=null;
function $(id){return document.getElementById(id)}
function el(t,c,txt){var e=document.createElement(t);if(c)e.className=c;if(txt!=null)e.textContent=txt;return e}
function toast(msg,cls){var d=el("div",cls||"",msg);$("toast").appendChild(d);setTimeout(function(){d.remove()},5000)}
function hhmmss(ts){var d=new Date(ts*1000);function p(n,l){n=""+n;while(n.length<(l||2))n="0"+n;return n}
 return p(d.getHours())+":"+p(d.getMinutes())+":"+p(d.getSeconds())+"."+p(d.getMilliseconds()%1000,3).slice(0,1)}
function flagOf(cc){if(!cc)return "";if(cc.length!=2)return cc;var s="";
 for(var i=0;i<2;i++){var c=cc.toUpperCase().charCodeAt(i);if(c<65||c>90)return cc;s+=String.fromCodePoint(127462+c-65)}return s}
function api(p,init){return fetch(p,init).then(function(x){return x.json()})}
function putRows(t,cols,rows){
 t.innerHTML="";   // self-clearing: repeated refreshes must not accumulate rows
 var th=document.createElement("thead");var tr=document.createElement("tr");
 cols.forEach(function(c){tr.appendChild(el("th","",c))});th.appendChild(tr);t.appendChild(th);
 var tb=document.createElement("tbody");
 rows.forEach(function(r){var tr=el("tr");r.forEach(function(c){
   var td=el("td");
   if(c&&c.nodeType){td.appendChild(c)}
   else{td.textContent=(c==null?"":String(c))}
   tr.appendChild(td)});tb.appendChild(tr)});
 t.appendChild(tb)}

// ---------- modal infra ----------
function closeModal(){var o=$("modal_ov");if(o)o.remove()}
function openModal(title,buildFn,okLabel,onSave){
 closeModal();
 var ov=el("div","modal");ov.id="modal_ov";
 var card=el("div","modalcard");
 var h=el("div","bar");h.appendChild(el("b","",title));
 var x=el("button","dim","✕");x.style.marginLeft="auto";x.onclick=closeModal;h.appendChild(x);
 card.appendChild(h);
 var body=el("div");card.appendChild(body);
 var bar=el("div","bar");bar.style.marginTop="12px";
 var ok=el("button","good",okLabel||"保存");ok.onclick=function(){onSave(body)};
 var cancel=el("button","dim","取消");cancel.onclick=closeModal;
 bar.appendChild(ok);bar.appendChild(cancel);card.appendChild(bar);
 ov.appendChild(card);
 ov.onclick=function(e){if(e.target===ov)closeModal()};
 document.body.appendChild(ov);
 document.onkeydown=function(e){if(e.key==="Escape")closeModal()};
 if(buildFn)buildFn(body);
 return body}
function mgroup(body,title){var s=el("div","msec");s.appendChild(el("b","",title));body.appendChild(s);return s}
function mgrid(parent){var g=el("div","mgrid");parent.appendChild(g);return g}
function mfields(body,defs,cur){
 defs.forEach(function(d){
  var k=d[0];var row=el("div","mfield");
  row.appendChild(el("label","dim",d[1]||k));
  var inp;
  if(d[2]=="select"){inp=document.createElement("select");
   var e0=el("option","","(无)");e0.value="";inp.appendChild(e0);
   (d[3]||[]).forEach(function(o){var op=el("option","",String(o));op.value=String(o);
    if(String(cur[k])===String(o))op.selected=true;inp.appendChild(op)});
   if(cur[k]!=null&&String(cur[k])!==""&&(d[3]||[]).map(String).indexOf(String(cur[k]))<0){
    var ex=el("option","",String(cur[k]));ex.value=String(cur[k]);ex.selected=true;inp.appendChild(ex)}}
  else{inp=document.createElement("input");inp.type=d[2]=="num"?"number":"text";
   inp.value=cur[k]==null?"":String(cur[k]);if(d[4])inp.placeholder=d[4]}
  inp.dataset.fk=k;row.appendChild(inp);body.appendChild(row)})}
function mbools(parent,keys,cur,labels){
 var row=el("div","mchips");
 keys.forEach(function(k){var lb=el("label");
  var cb=document.createElement("input");cb.type="checkbox";cb.dataset.fk=k;cb.checked=!!cur[k];
  lb.appendChild(cb);lb.appendChild(document.createTextNode(" "+((labels&&labels[k])||k)));row.appendChild(lb)});
 parent.appendChild(row);return row}

// ---------- shared nft_route.json config state ----------
var CFG=null, CFG_MTIME=null;
function knownOnly(o,keys){var r={};for(var k in o){if(keys.indexOf(k)<0)r[k]=o[k]}return r}
function markDirty(){localStorage.setItem("nft_dirty","1");updateDirtyUI()}
function updateDirtyUI(){
 var d=localStorage.getItem("nft_dirty")==="1";
 var dot=document.getElementById("nav-dirty");if(dot)dot.style.display=d?"inline":"none"}
function pushCfg(cb){
 var payload={config:CFG,reload:false,base_mtime:CFG_MTIME,ui_ver:(typeof UI_VER!=="undefined"?UI_VER:"")};
 var force=(cb===true); if(force)payload.force=true; else if(typeof cb!=="function")cb=null;
 return api("/api/config",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify(payload)}).then(function(r){
   if(r.stale){
    if(confirm("检测到配置文件在本页面加载后被外部修改过（例如直接在服务器上改/修复）。\n\n直接保存会覆盖那些修改。\n\n『确定』= 重新加载最新配置，请再改一次再保存\n『取消』= 仍要以本页内容强制覆盖保存")){loadCfg()}
    else pushCfg(true);
    return}
   if(r.errors){var em=(r.errors||[]).join("\n");toast("拒绝保存:\n"+em,"bad");
    $("c-msg")&&($("c-msg").innerHTML="<span class=bad>"+em.replace(/\n/g,"<br>")+"</span>");return}
   if(r.ok){if(r.mtime)CFG_MTIME=r.mtime;toast("已写入配置文件(未重载) — 到 状态 页点『重载主进程』生效","good");markDirty();if(cb)cb()}
   else if(!r.stale&&!r.errors){toast("保存失败: "+(r.error||JSON.stringify(r)),"bad")}
   else{var msg=(r.errors||[r.error||JSON.stringify(r)]).join("\n");
    toast("拒绝保存:\n"+msg,"bad");$("c-msg")&&($("c-msg").innerHTML="<span class=bad>"+msg.replace(/\n/g,"<br>")+"</span>")}})}
function loadCfg(cb){api("/api/config").then(function(d){
 CFG=d.config;CFG_MTIME=d.mtime||null;$("c-box").value=JSON.stringify(d.config,null,3);$("c-path").textContent=d.path||"";
 $("c-msg").innerHTML="<span class=dim>已加载 "+(d.path||"")+"</span>";
 if(cb)cb();renderProxy();renderRules()}).catch(function(e){toast("读取失败 "+e,"bad")})}

// ---------- tab switch registry ----------
// each tab module calls onTabSelect(name, fn) at load time; fn runs every
// time that tab becomes active. Keeps this dispatcher from needing to know
// about any tab's internals (adding tab_dns.js needed zero edits here).
var TAB_ON_SELECT={};
function onTabSelect(name,fn){TAB_ON_SELECT[name]=fn}
var tabs=document.querySelectorAll("nav button");
tabs.forEach(function(b){b.onclick=function(){
 tabs.forEach(function(x){x.classList.remove("sel")});b.classList.add("sel");
 document.querySelectorAll("main>section").forEach(function(s){s.classList.remove("sel")});
 $("s-"+b.dataset.t).classList.add("sel");
 var fn=TAB_ON_SELECT[b.dataset.t];if(fn)fn()}});

// ---------- websocket stream ----------
// single socket serves both the flow table (tab_flow.js: push()) and live
// MTR progress (tab_mtr.js: renderJob()/loadJobs(), window.__mtr_id).
function connect(){
 var proto=location.protocol=="https:"?"wss://":"ws://";
 ws=new WebSocket(proto+location.host+"/ws/stream");
 ws.onopen=function(){$("d-ws").className="dot on"};
 ws.onclose=function(){$("d-ws").className="dot err";setTimeout(connect,2000)};
 ws.onerror=function(){ws.close()};
 ws.onmessage=function(ev){
  var m;try{m=JSON.parse(ev.data)}catch(e){return}
  if(m.t=="snap"){rows=m.rows.slice(-MAXROWS);evtTotal+=rows.length;rerender();
   $("n-evt").textContent=evtTotal;return}
  if(m.t=="mtr"){if(window.__mtr_id&&String(m.id)===String(window.__mtr_id)){
    window.__mtr_last=m;renderJob(m);
    if(m.status!=="running"){if(mtrTimer){clearInterval(mtrTimer);mtrTimer=null}loadJobs()}}return}
  if(m.t=="bw"){if(window.__bw_on)window.__bw_on(m);return}
  if(m.t=="iftop"){if(window.__iftop_on)window.__iftop_on(m);return}
  if(m.t=="ping"){if(window.__ping_on)window.__ping_on(m);return}
  if(m.t=="status"){if(window.__status_on)window.__status_on(m);return}
  if(m.t=="gap"){window.__gap=(window.__gap||0)+m.n;$("n-evt").textContent=evtTotal+" (丢"+window.__gap+")";return}
  if(m.t=="hello"||!m.dst)return;
  push(m)}}

// ---------- header status dots + info tab: server pushes t=status frames
// (health_snapshot every 4s while any WS client is attached; one frame
// immediately on connect). No polling. ----------
window.__status_on=function(d){if(!d)return;window.__status_last=d;
 var w=d.webadmin||{};
 $("d-master").className="dot "+(d.master&&d.master.alive&&d.master.is_router?"on":"err");
 $("d-redis").className="dot "+((w.redis_stream!==undefined?w.redis_stream:d.redis_stream)?"on":"err");
 if($("s-info").classList.contains("sel")&&window.loadInfo)loadInfo(d)};

// ---------- stacked list editor (secondary popup) ----------
// Edits an array of strings in place; onDone receives the cleaned array
// (trimmed, de-duped, order preserved). Sits on top of an already-open modal
// (z-index 60 > .modal's 50) and never calls closeModal(), so the underlying
// edit dialog survives.
function openListEditor(title,values,onDone){
 var ov=el("div","modal");ov.style.zIndex="60";
 var card=el("div","modalcard");card.style.maxWidth="520px";
 var h=el("div","bar");h.appendChild(el("b","",title));
 var x=el("button","dim","✕");x.style.marginLeft="auto";x.onclick=function(){ov.remove()};
 h.appendChild(x);card.appendChild(h);
 var body=el("div");card.appendChild(body);
 var cur=values.slice();
 function render(){
  body.innerHTML="";
  if(!cur.length)body.appendChild(el("div","dim","（空）"));
  cur.forEach(function(v,i){
   var row=el("div");row.style.cssText="display:flex;gap:6px;align-items:center;margin:4px 0";
   var inp=document.createElement("input");inp.value=v;inp.style.flex="1";
   inp.onchange=function(){var nv=inp.value.trim();if(!nv)cur.splice(i,1);else cur[i]=nv;render()};
   inp.onkeydown=function(e){if(e.key==="Enter")inp.blur()};
   var del=el("button"," bad","删除");del.onclick=function(){cur.splice(i,1);render()};
   row.appendChild(inp);row.appendChild(del);body.appendChild(row)});
  var wrap=el("div");wrap.style.cssText="display:flex;gap:6px;align-items:center;margin-top:8px";
  var ni=document.createElement("input");ni.placeholder="输入后点添加（回车添加）";ni.style.flex="1";
  ni.onkeydown=function(e){if(e.key==="Enter")add()};
  var ab=el("button","dim","+ 添加");ab.onclick=add;
  function add(){var nv=(ni.value||"").trim();if(!nv)return;
   if(cur.indexOf(nv)>=0){ni.value="";return}
   cur.push(nv);render();
   var again=body.querySelector("input[data-newval]");if(again)again.focus()}
  wrap.appendChild(ni);wrap.appendChild(ab);body.appendChild(wrap)}
 render();
 var bar=el("div","bar");bar.style.marginTop="12px";
 var ok=el("button","good","保存");ok.onclick=function(){
  var clean=[];cur.forEach(function(v){v=(v||"").trim();if(v&&clean.indexOf(v)<0)clean.push(v)});
  ov.remove();onDone(clean)};
 var cancel=el("button","dim","取消");cancel.onclick=function(){ov.remove()};
 bar.appendChild(ok);bar.appendChild(cancel);card.appendChild(bar);
 ov.appendChild(card);
 document.body.appendChild(ov);
 setTimeout(function(){var f=body.querySelector("input");if(f)f.focus()},0)}

connect();
