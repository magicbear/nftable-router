# -*- coding: utf-8 -*-
"""Embedded single-page UI for webadmin (no external assets / CDN)."""

INDEX_HTML = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nft-route 管理台</title>
<style>
:root{--bg:#12151b;--panel:#1a1f28;--line:#2a3140;--fg:#cfd6e4;--dim:#7a8496;
--green:#3fb96b;--red:#e05252;--yellow:#d9a03f;--cyan:#4bb8c9;--purple:#9a6dd6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:13px/1.5 ui-monospace,"Cascadia Mono",Consolas,"Noto Sans Mono CJK SC",monospace}
header{display:flex;gap:16px;align-items:center;padding:8px 14px;background:var(--panel);
border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5;flex-wrap:wrap}
header b{color:var(--cyan)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#555;margin-right:4px;vertical-align:0}
.dot.on{background:var(--green)}.dot.err{background:var(--red)}.dot.warn{background:var(--yellow)}
nav{display:flex;gap:2px;margin-left:auto}
nav button{background:none;border:1px solid transparent;color:var(--dim);padding:4px 12px;cursor:pointer;border-radius:6px;font:inherit}
nav button.sel{color:var(--fg);border-color:var(--line);background:var(--bg)}
main{padding:10px 14px;max-width:1500px}
section{display:none}section.sel{display:block}
table{border-collapse:collapse;width:100%}
th,td{padding:2px 8px;border-bottom:1px solid #202532;text-align:left;white-space:nowrap}
th{color:var(--dim);font-weight:normal;position:sticky;top:0;background:var(--bg);z-index:2;box-shadow:0 1px 0 var(--line)}
#flowwrap{height:calc(100vh - 150px);overflow:auto;border:1px solid var(--line);border-radius:6px}
.bar{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
input,select,textarea{background:#0c0f14;color:var(--fg);border:1px solid var(--line);
border-radius:6px;padding:4px 8px;font:inherit}
textarea{width:100%;height:60vh;resize:vertical}
button{background:#232a38;border:1px solid var(--line);color:var(--fg);border-radius:6px;
padding:4px 12px;cursor:pointer;font:inherit}
button:hover{border-color:var(--cyan)}
.p6{color:#4bb8c9}.p17{color:#8f7ee8}.p1{color:#69b06a}
td.line{color:var(--purple)}td.dst{color:var(--cyan)}td.src{color:#c9b458}
.bad{color:var(--red)}.good{color:var(--green)}.warn{color:var(--yellow)}.dim{color:var(--dim)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px;margin:8px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:8px}
td.ell{max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer}
td.ell.wrap{white-space:normal;word-break:break-all;text-overflow:clip}
#colsbox{margin:0 0 8px}#colsbox label{display:inline-block;margin:2px 12px 2px 0;color:var(--fg);cursor:pointer;user-select:none}
#colsbox label input{vertical-align:-2px}#colsbox button{margin-left:10px}
#toast{position:fixed;right:14px;bottom:14px;max-width:420px}
#toast div{margin-top:6px;padding:8px 12px;border-radius:8px;background:#20283a;border:1px solid var(--line)}
label{color:var(--dim)}
</style></head><body>
<header><b>nft-route 管理台</b>
 <span><i id=d-ws class=dot></i>WS</span>
 <span><i id=d-master class=dot></i>主进程</span>
 <span><i id=d-redis class=dot></i>流</span>
 <span class=dim>行 <i id=n-rows>0</i>/1000 事件 <i id=n-evt>0</i></span>
 <nav>
  <button data-t=flow class=sel>实时流量</button>
  <button data-t=bind>出口绑定</button>
  <button data-t=cfg>配置编辑</button>
  <button data-t=info>状态</button>
 </nav></header>
<main>
<section id=s-flow class=sel>
 <div class=bar>
  <button id=b-pause>⏸ 暂停</button><button id=b-clear>清空</button><button id=b-cols>⚙ 列</button>
  <input id=f-text placeholder="过滤: IP / 线路 / 国家 / 运营商关键字" style=width:280px>
  <label><input type=checkbox id=f-new> 仅新连接</label>
  <span class=dim>上限 1000 行(旧行自动淘汰)</span>
 </div>
 <div id=colsbox class=card style="display:none"></div>
 <div id=flowwrap><table><thead id=flowhead></thead>
 <tbody id=flowbody></tbody></table></div>
</section>

<section id=s-bind>
 <div class=card><b>已绑定 (egress_marks)</b><table id=tbl-bound></table></div>
 <div class=card><b>公网出口候选</b><span class=dim>（本机实时扫描，跳过内网/链路本地）</span>
  <table id=tbl-cand></table></div>
 <div class=card><b>新增绑定</b><div class=grid>
  <span><label>接口</label><br><select id=b-iface></select></span>
  <span><label>IP (静态必填 / 动态留空)</label><br><input id=b-ip list=b-iplist style=width:220px><datalist id=b-iplist></datalist></span>
  <span><label>类型</label><br><select id=b-dyn><option value=0>静态(按IP)</option><option value=1>动态(按接口)</option></select></span>
  <span><label>fwmark（复用线路或自定义）</label><br><select id=b-mark></select> <input id=b-markx placeholder=自定义 width:90px style=width:90px disabled></span>
  <span><label>网关 (动态可填 auto)</label><br><input id=b-gw placeholder="93.184.216.35 / auto"></span>
  <span style=align-self:end><button id=b-add>绑定并重载</button></span>
 </div></div>
</section>

<section id=s-cfg>
 <div class=bar>
  <button id=c-reload>读取配置</button><button id=c-fmt>格式化</button>
  <button id=c-check>校验</button>
  <label><input type=checkbox id=c-autoreload checked> 保存后 SIGUSR1 重载主进程</label>
  <button id=c-save class=good>保存 (自动备份 .bak)</button>
  <span class=dim id=c-path></span>
 </div>
 <textarea id=c-box spellcheck=false></textarea>
 <div class=card id=c-msg></div>
</section>

<section id=s-info><div class=card><pre id=info-box class=dim>loading...</pre></div></section>
</main>
<div id=toast></div>
<script>
"use strict";
var MAXROWS=1000, rows=[], paused=false, evtTotal=0, ws=null;
var PROTO={1:"ICMP",6:"TCP",17:"UDP",58:"ICMP6",47:"GRE"};
function $(id){return document.getElementById(id)}
function el(t,c,txt){var e=document.createElement(t);if(c)e.className=c;if(txt!=null)e.textContent=txt;return e}
function toast(msg,cls){var d=el("div",cls||"",msg);$("toast").appendChild(d);setTimeout(function(){d.remove()},5000)}
function hhmmss(ts){var d=new Date(ts*1000);function p(n,l){n=""+n;while(n.length<(l||2))n="0"+n;return n}
 return p(d.getHours())+":"+p(d.getMinutes())+":"+p(d.getSeconds())+"."+p(d.getMilliseconds()%1000,3).slice(0,1)}

// ---------- flow table ----------
var COLS=[
 {id:"time", label:"时间",     def:1, get:function(r){return hhmmss(r.ts)}},
 {id:"proto",label:"协议",     def:1, cls:function(r){return "p"+r.proto}, get:function(r){return PROTO[r.proto]||r.proto}},
 {id:"src",  label:"源",       def:1, cls:function(){return "src"},  get:function(r){return r.src}},
 {id:"sport",label:"源端口",   def:1, get:function(r){return r.sport!=null?r.sport:""}},
 {id:"dst",  label:"目的",     def:1, cls:function(){return "dst"},  get:function(r){return r.dst}},
 {id:"dport",label:"目的端口", def:1, get:function(r){return r.dport!=null?r.dport:""}},
 {id:"qname",label:"域名",     def:1, cls:function(){return "dim ell"}, get:function(r){return r.qname||""}},
 {id:"cc",   label:"国家",     def:1, get:function(r){var g=r.geo||{};return g.cc?flagOf(g.cc):""}},
 {id:"cname",label:"国家名",   def:0, get:function(r){var g=r.geo||{};return g.cn||""}},
 {id:"region",label:"地区",    def:0, get:function(r){var g=r.geo||{};return g.rg||""}},
 {id:"city", label:"城市",     def:0, get:function(r){var g=r.geo||{};return g.ct||""}},
 {id:"isp",  label:"运营商",   def:0, cls:function(){return "dim"},  get:function(r){var g=r.geo||{};return g.isp||""}},
 {id:"tags", label:"标签",     def:0, cls:function(){return "warn"}, get:function(r){var g=r.geo||{};var t=[];if(g.ac)t.push("任播");if(g.idc)t.push("IDC");return t.join(" ")}},
 {id:"line", label:"线路",     def:1, cls:function(){return "line"}, get:function(r){return r.line||"-"}},
 {id:"mark", label:"mark",     def:1, get:function(r){return r.mark!=null?("0x"+(r.mark>>>0).toString(16)):"-"}},
 {id:"pri",  label:"规则",     def:0, cls:function(){return "dim"},  get:function(r){return r.pri>=0?("#"+r.pri):""}},
 {id:"sess", label:"会话",     def:0, cls:function(){return "dim"},  get:function(r){var s=["","存活","ECMP","ICMP","QoS"][r.sess]||"";if(r.fc)s="fullcone "+s;return s}},
 {id:"ms",   label:"ms",       def:1, cls:function(){return "dim"},  get:function(r){return r.ms!=null?r.ms.toFixed(1):""}}
];
function flagOf(cc){if(!cc)return "";if(cc.length!=2)return cc;var s="";
 for(var i=0;i<2;i++){var c=cc.toUpperCase().charCodeAt(i);if(c<65||c>90)return cc;s+=String.fromCodePoint(127462+c-65)}return s}
function defaultSel(){return COLS.filter(function(c){return c.def}).map(function(c){return c.id})}
function curSel(){try{var x=JSON.parse(localStorage.getItem("nft_cols"));
 if(x&&x instanceof Array){var ok={};COLS.forEach(function(c){ok[c.id]=1});return x.filter(function(i){return ok[i]})}}catch(e){}
 return defaultSel()}
function visibleCols(){var w={};curSel().forEach(function(i){w[i]=1});return COLS.filter(function(c){return w[c.id]})}
function searchText(r){var g=r.geo||{};
 return [r.src,r.dst,r.line,r.mark,r.qname,g.cc,g.cn,g.rg,g.ct,g.isp,PROTO[r.proto]||r.proto].join(" ").toLowerCase()}
function rowMatch(r,q){if(!q)return true;return searchText(r).indexOf(q)>=0}
function trOf(r){
 var tr=el("tr");
 visibleCols().forEach(function(c){
  var v=c.get(r);var txt=v!=null?String(v):"";
  var td=el("td",c.cls?c.cls(r):"",txt);
  if(txt)td.title=txt;
  if(c.cls&&/\bell\b/.test(c.cls(r)))td.onclick=function(){this.classList.toggle("wrap")};
  tr.appendChild(td)});
 tr.dataset.k=searchText(r);
 if(r.sess==2)tr.style.opacity=.55;
 return tr}
function buildHead(){
 var h=$("flowhead");h.innerHTML="";var tr=el("tr");
 visibleCols().forEach(function(c){tr.appendChild(el("th","",c.label))});
 if(!tr.childNodes.length)tr.appendChild(el("th","dim","(未选列 — 点 ⚙列 勾选)"));
 h.appendChild(tr)}
function buildColsBox(){
 var box=$("colsbox");var sel=curSel();box.innerHTML="";
 COLS.forEach(function(c){
  var lb=document.createElement("label"),cb=document.createElement("input");
  cb.type="checkbox";cb.dataset.id=c.id;cb.checked=sel.indexOf(c.id)>=0;cb.onchange=applySel;
  lb.appendChild(cb);lb.appendChild(document.createTextNode(" "+c.label));box.appendChild(lb)});
 var rst=el("button","","恢复默认");rst.onclick=function(){localStorage.removeItem("nft_cols");applySel()};
 box.appendChild(rst)}
function applySel(){
 var ids=[];document.querySelectorAll("#colsbox input:checked").forEach(function(cb){ids.push(cb.dataset.id)});
 localStorage.setItem("nft_cols",JSON.stringify(ids));
 buildHead();buildColsBox();rerender()}
function visNow(r){
 var q=($("f-text").value||"").toLowerCase();
 return rowMatch(r,q)&&(! $("f-new").checked || r.sess==0)}
function trim(){
 // cap 1000 with filter-aware eviction: non-visible (old, filtered-out) rows
 // go first; visible (matching) rows are kept unless the WHOLE buffer matches
 var i=0;
 while(rows.length>MAXROWS&&i<rows.length){if(!visNow(rows[i]))rows.splice(i,1);else i++}
 var dropped=0;
 while(rows.length>MAXROWS){rows.shift();dropped++}   // all-visible: oldest yields
 var b=$("flowbody");
 for(var k=0;k<dropped&&b.firstChild;k++)b.removeChild(b.firstChild)}
function push(r){
 rows.push(r);evtTotal++;trim();
 if(paused)return;
 var q=($("f-text").value||"").toLowerCase();
 if(!rowMatch(r,q))return;
 if($("f-new").checked&&r.sess!=0)return;
 var b=$("flowbody");b.appendChild(trOf(r));
 var w=$("flowwrap");if(w.scrollHeight-w.scrollTop-w.clientHeight<400)w.scrollTop=w.scrollHeight;
 $("n-rows").textContent=rows.length;$("n-evt").textContent=evtTotal}
function rerender(){
 var b=$("flowbody");b.innerHTML="";var q=($("f-text").value||"").toLowerCase();
 var frag=document.createDocumentFragment();var n=0;
 for(var i=rows.length-1;i>=0&&n<MAXROWS;i--){
  var r=rows[i];if(!rowMatch(r,q))continue;
  if($("f-new").checked&&r.sess!=0)continue;
  frag.insertBefore(trOf(r),frag.firstChild);n++}
 b.appendChild(frag);$("n-rows").textContent=n}
$("f-text").addEventListener("input",rerender);
$("f-new").addEventListener("change",rerender);
$("b-pause").onclick=function(){paused=!paused;this.textContent=paused?"▶ 继续":"⏸ 暂停"};
$("b-clear").onclick=function(){rows=[];$("flowbody").innerHTML="";$("n-rows").textContent=0};
$("b-cols").onclick=function(){var b=$("colsbox");b.style.display=b.style.display=="none"?"block":"none"};
buildHead();buildColsBox();

// ---------- websocket ----------
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
  if(m.t=="hello"||!m.dst)return;
  push(m)}}
connect();

// ---------- tabs ----------
var tabs=document.querySelectorAll("nav button");
tabs.forEach(function(b){b.onclick=function(){
 tabs.forEach(function(x){x.classList.remove("sel")});b.classList.add("sel");
 document.querySelectorAll("main>section").forEach(function(s){s.classList.remove("sel")});
 $("s-"+b.dataset.t).classList.add("sel");
 if(b.dataset.t=="bind")loadBind();
 if(b.dataset.t=="info")loadInfo();}});

// ---------- bind tab ----------
var ifData=null;
function api(p,init){return fetch(p,init).then(function(x){return x.json()})}
function loadBind(){
 api("/api/interfaces").then(function(d){
  ifData=d;
  var tb=$("tbl-bound");tb.innerHTML="";
  var cols=["接口/IP","类型","mark","网关","状态"];cols.forEach(function(c){tb.tHead=tb.tHead||document.createElement("thead");tb.tHead.appendChild(el("th","",c))});
  var body=document.createElement("tbody");(d.bindings||[]).forEach(function(b){
   var tr=el("tr");
   tr.appendChild(el("td","",(b.ip||"")+(b.iface?(" @"+b.iface):"")));
   tr.appendChild(el("td","dim",b.dynamic?"动态":"静态"));
   tr.appendChild(el("td","good","0x"+(b.mark>>>0).toString(16)+" ("+b.mark+")"));
   tr.appendChild(el("td","dim",((b.iprule||{}).gateway)||"未设置"));
   tr.appendChild(el("td","dim","生效由主进程对账"));
   body.appendChild(tr)});
  tb.appendChild(body);
  var tc=$("tbl-cand");tc.innerHTML="";
  tc.tHead=tc.tHead||document.createElement("thead");tc.tHead.innerHTML="<tr><th>接口</th><th>地址</th><th>获取方式</th><th>绑定</th></tr>";
  var cb=document.createElement("tbody");
  (d.candidates||[]).forEach(function(c){
   var tr=el("tr");
   tr.appendChild(el("td","",c.ifname));
   tr.appendChild(el("td","",c.ip?c.ip+"/"+c.prefixlen:""));
   tr.appendChild(el("td","dim",c.method+(c.dynamic?" · 动态":"")));
   tr.appendChild(el("td",c.bound?"good":"warn",c.bound?("已绑定 mark "+c.mark):"未绑定"));
   cb.appendChild(tr)});
  tc.appendChild(cb);
  // form options
  var sel=$("b-iface");sel.innerHTML="";
  Object.keys(d.interfaces||{}).sort().forEach(function(n){
   if(n=="lo")return;
   sel.appendChild(el("option","",n))});
  var dl=$("b-iplist");dl.innerHTML="";
  (d.candidates||[]).forEach(function(c){if(!c.bound)dl.appendChild(el("option","",c.ip))});
  var mk=$("b-mark");mk.innerHTML="";
  Object.keys(d.proxy_lines||{}).forEach(function(k){
   mk.appendChild(el("option","",k+" (mark "+d.proxy_lines[k]+")")).dataset.v=d.proxy_lines[k]});
  mk.appendChild(el("option","","自定义数值…")).dataset.v="x";
  mk.onchange=function(){$("b-markx").disabled=this.dataset.v!="x"};
 }).catch(function(e){toast("接口扫描失败: "+e,"bad")})}
$("b-add").onclick=function(){
 if(!ifData)return toast("先等候选列表加载","warn");
 var dyn=$("b-dyn").value=="1";
 var ipv=$("b-ip").value.trim();
 var mk=$("b-mark"),mark=mk.dataset.v=="x"?parseInt($("b-markx").value,0):parseInt(mk.options[mk.selectedIndex].dataset.v,10);
 if(!mark||isNaN(mark))return toast("mark 无效","bad");
 var body={ifname:$("b-iface").value,ip:ipv,dynamic:dyn,mark:mark,gateway:$("b-gw").value.trim()};
 if(!dyn&&!ipv)return toast("静态绑定必须填 IP","bad");
 if(dyn&&!body.gateway)body.gateway="auto";
 api("/api/bind",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
 .then(function(r){
  if(r.ok){toast("已绑定: "+body.ifname+" mark 0x"+mark.toString(16)+" · 主进程已收到重载","good");loadBind()}
  else toast("拒绝: "+(r.error||JSON.stringify(r.errors||r)),"bad")}).catch(function(e){toast("请求失败 "+e,"bad")})};

// ---------- config tab ----------
function loadCfg(){api("/api/config").then(function(d){
 $("c-box").value=JSON.stringify(d.config,null,3);$("c-path").textContent=d.path||"";
 $("c-msg").innerHTML="<span class=dim>已加载 "+(d.path||"")+"</span>"}).catch(function(e){toast("读取失败 "+e,"bad")})}
$("c-reload").onclick=loadCfg;
$("c-fmt").onclick=function(){try{$("c-box").value=JSON.stringify(JSON.parse($("c-box").value),null,3);$("c-msg").innerHTML="<span class=good>已格式化</span>"}catch(e){$("c-msg").innerHTML="<span class=bad>"+e+"</span>"}};
$("c-check").onclick=function(){var cfg;try{cfg=JSON.parse($("c-box").value)}catch(e){return $("c-msg").innerHTML="<span class=bad>JSON 错误: "+e+"</span>"}
 api("/api/validate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({config:cfg})}).then(function(r){
  $("c-msg").innerHTML=r.ok?"<span class=good>校验通过</span>":("<span class=bad>错误:</span><br>"+r.errors.map(function(x){return "· "+x}).join("<br>"))})};
$("c-save").onclick=function(){var cfg;try{cfg=JSON.parse($("c-box").value)}catch(e){return toast("JSON 错误: "+e,"bad")}
 if(!confirm("保存配置"+($("c-autoreload").checked?" 并通知主进程重载(SIGUSR1)":"")+"？"))return;
 api("/api/config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({config:cfg,reload:$("c-autoreload").checked})}).then(function(r){
  if(r.ok){toast("已保存"+(r.reload&&r.reload.ok?" · 主进程已重载(pid "+r.reload.pid+")":" · 未发送信号"), "good");loadCfg()}
  else{var msg=(r.errors||[r.error||JSON.stringify(r)]).join("\\n");toast("拒绝保存:\\n"+msg,"bad");$("c-msg").innerHTML="<span class=bad>"+msg.replace(/\\n/g,"<br>")+"</span>"}})};
loadCfg();

// ---------- status ----------
function loadInfo(){api("/api/status").then(function(d){$("info-box").textContent=JSON.stringify(d,null,2)}).catch(function(e){$("info-box").textContent=e})}
setInterval(function(){api("/api/status").then(function(d){
 $("d-master").className="dot "+(d.master&&d.master.alive&&d.master.is_router?"on":"err");
 $("d-redis").className="dot "+(d.redis_stream?"on":"err");
 if($("s-info").classList.contains("sel"))$("info-box").textContent=JSON.stringify(d,null,2)}).catch(function(){})},4000);
loadBind();
</script></body></html>
"""
