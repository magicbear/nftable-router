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
.modal{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:50;display:flex;align-items:flex-start;justify-content:center;overflow:auto}
.modalcard{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:5vh auto;max-width:1000px;width:92vw;box-shadow:0 8px 30px rgba(0,0,0,.45)}
.modalcard .bar{margin:0}
.msec{margin-top:14px}
.msec>b{display:block;color:var(--cyan);font-size:12px;border-bottom:1px solid var(--line);padding-bottom:4px;margin-bottom:8px}
.mgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(215px,1fr));gap:8px 14px}
.itabs{display:flex;gap:5px;align-items:center;margin:2px 0 10px;flex-wrap:wrap}
.itab{background:#232a38;border:1px solid var(--line);color:var(--dim);padding:3px 12px;cursor:pointer;border-radius:14px;font:inherit}
.itab.sel{color:var(--fg);border-color:var(--cyan);background:var(--bg)}
.itab.bad{color:var(--red)}
.ipane{border:1px dashed var(--line);border-radius:8px;padding:8px 10px}
.mfield{display:flex;flex-direction:column;gap:3px;min-width:0}
.mfield label{font-size:11px}
.mfield input,.mfield select{width:100%;min-width:0}
.mchips{display:flex;flex-wrap:wrap;gap:6px 16px}
.mchips label{color:var(--fg)}
.mchips input{vertical-align:-2px}
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
  <button data-t=proxy>线路管理</button>
  <button data-t=rules>路由规则</button>
  <button data-t=mtr>链路MTR</button>
  <button data-t=rt>路由表</button>
  <button data-t=cfg>配置JSON</button>
  <button data-t=info>状态<span id="nav-dirty" class="warn" style="display:none"> ●</span></button>
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

<section id=s-proxy>
 <div class=bar><button id=p-refresh>刷新</button><button id=p-add>+ 新增线路</button>
  <span class=dim>托管线路(daemon)与 ip-rule 线路统一在此管理；unknown 字段在高级 JSON 中保留</span></div>
 <div id=ptable></div>
</section>

<section id=s-rules>
 <div class=bar><button id=r-refresh>刷新</button><button id=r-add>+ 新增优先级</button>
  <span class=dim>规则自上而下匹配；每优先级可映射多条线路；条件键同 nft_route.json rules 语义</span></div>
 <div id=rtable></div>
</section>
<section id=s-mtr>
 <div class=bar>
  <select id="m-line" style="min-width:230px"></select>
  <input id="m-target" placeholder="目标 IP / 域名" style="width:240px">
  <label>发包</label><input id="m-cycles" type="number" value="10" style="width:60px">
  <label>TTL</label><input id="m-ttl" type="number" value="18" style="width:60px">
  <label>间隔s</label><input id="m-int" value="0.2" style="width:60px">
  <label>IP族</label><select id="m-fam"><option value="auto">自动</option><option value="4">IPv4</option><option value="6">IPv6</option></select>
  <button id="m-run" class="good">▶ 开始MTR</button>
  <button id="m-refresh">刷新</button>
  <span id="m-err" class="bad"></span>
 </div>
 <div class=card id="m-result"><span class=dim>选择线路与目标，回车开测。指定线路通过 SO_MARK 命中 `ip rule fwmark → 表`，与真实业务同路径。</span></div>
 <div class=card><b>历史任务</b><table id="m-history"></table></div>
</section>
<section id=s-cfg>
 <div class=bar>
  <button id=c-reload>读取配置</button><button id=c-fmt>格式化</button>
  <button id=c-check>校验</button>
  <button id=c-save class=good>保存 (自动备份 .bak)</button>
  <span class=dim id=c-path></span>
 </div>
 <textarea id=c-box spellcheck=false></textarea>
 <div class=card id=c-msg></div>
</section>

<section id=s-rt>
 <div class=bar>
  <select id="rt-table" style="min-width:190px"></select>
  <button id="rt-refresh">刷新</button>
  <button id="rt-add" class="good">+ 新增/替换路由</button>
  <span class=dim id=rt-info></span></div>
 <div class=card><div style=overflow:auto><table id="rt-tbl"></table></div></div>
 <div class=card><b>ip rule 策略规则</b><div style=overflow:auto;max-height:260px><table id="rt-rules"></table></div></div>
</section>
<section id=s-info>
 <div class=bar><button id=i-refresh>刷新</button><button id=i-testnow class=good>▶ 立即测试线路</button>
  <button id=i-reload class=good>⟳ 重载主进程 (SIGUSR1)</button>
  <span id=i-dirty class=warn></span>
  <span class=dim id=i-round></span><span class=dim>状态每4秒自动刷新</span></div>
 <div class=card id=i-master></div>
 <div class=card><b>线路测试状态</b><div style=overflow:auto><table id=i-lines></table></div></div>
 <div class=card><b>托管代理进程</b><div style=overflow:auto><table id=i-prox></table></div></div>
 <div class=card><b>进程 (router master 子进程树)</b><div style=overflow:auto><table id=i-procs></table></div></div>
 <div class=card id=i-extwrap style="display:none"><b>外部代理进程 (非router托管: supervisord/手工)</b><div style=overflow:auto><table id=i-ext></table></div></div>
 <div class=card><details><summary class=dim>原始JSON</summary><pre id=info-box class=dim></pre></details></div>
</section>
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
  if(m.t=="mtr"){if(window.__mtr_id&&String(m.id)===String(window.__mtr_id)){
    window.__mtr_last=m;renderJob(m);
    if(m.status!=="running"){if(mtrTimer){clearInterval(mtrTimer);mtrTimer=null}loadJobs()}}return}
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
 if(b.dataset.t=="proxy"){if(!CFG)loadCfg(renderProxy);else renderProxy()}
 if(b.dataset.t=="rules"){if(!CFG)loadCfg(renderRules);else renderRules()}
 if(b.dataset.t=="info")loadInfo();
 if(b.dataset.t=="mtr"){loadMtrLines();loadJobs()}
 if(b.dataset.t=="rt")rtOpts()}});

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
  if(r.ok){toast("已绑定: "+body.ifname+" mark 0x"+mark.toString(16)+"(未重载,状态页可重载)","good");markDirty();loadBind()}
  else toast("拒绝: "+(r.error||JSON.stringify(r.errors||r)),"bad")}).catch(function(e){toast("请求失败 "+e,"bad")})};

// ---------- shared config state ----------
var CFG=null;
function knownOnly(o,keys){var r={};for(var k in o){if(keys.indexOf(k)<0)r[k]=o[k]}return r}
function markDirty(){localStorage.setItem("nft_dirty","1");updateDirtyUI()}
function updateDirtyUI(){
 var d=localStorage.getItem("nft_dirty")==="1";
 var dot=document.getElementById("nav-dirty");if(dot)dot.style.display=d?"inline":"none"}
function pushCfg(cb){
 api("/api/config",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({config:CFG,reload:false})}).then(function(r){
   if(r.ok){toast("已写入配置文件(未重载) — 到 状态 页点『重载主进程』生效","good");markDirty();if(cb)cb()}
   else{var msg=(r.errors||[r.error||JSON.stringify(r)]).join("\\n");
    toast("拒绝保存:\\n"+msg,"bad");$("c-msg")&&($("c-msg").innerHTML="<span class=bad>"+msg.replace(/\\n/g,"<br>")+"</span>")}})}

// ---------- proxy lines ----------
var PROXY_COLS=["mark","weight","port","upstream","daemon","uid","server","server_port","cipher",
 "password","password_file","plugin","plugin_opts","bind_addr","obfs","obfs_param","protocol","protocol_param","mode","binary","config","instances",
 "bind","proxy_ip","test_dns","test_url","ipv4","ipv6","udp_v4","udp_v6","fullcone","autostart","restart"];
function proxyReferrers(name){
 var refs=[];
 Object.keys(CFG.proxy||{}).forEach(function(k){if(CFG.proxy[k]&&CFG.proxy[k].upstream==name)refs.push("proxy:"+k)});
 (CFG.rules||[]).forEach(function(rr,i){if(rr&&Object.prototype.hasOwnProperty.call(rr,name))refs.push("rules#"+i)});
 return refs}
function renderProxy(){
 var box=$("ptable");box.innerHTML="";if(!CFG)return;
 var t=el("table");t.innerHTML="<thead><tr><th>线路</th><th>mark</th><th>端口/ip-rule</th><th>托管</th><th>上游链</th><th>能力</th><th>bind</th><th>测试</th><th>引用</th><th></th></tr></thead>";
 var tb=document.createElement("tbody");
 Object.keys(CFG.proxy||{}).forEach(function(name){
  var c=CFG.proxy[name]||{};var tr=el("tr");
  tr.appendChild(el("td","good",name));
  tr.appendChild(el("td","",c.mark!=null?("0x"+(c.mark>>>0).toString(16)+" ("+c.mark+")"):"-"));
  tr.appendChild(el("td","",c.port?("tproxy :"+c.port):"ip-rule"));
  tr.appendChild(el("td",c.daemon?"line":"dim",c.daemon||"-"));
  tr.appendChild(el("td","dim",c.upstream?("→ "+c.upstream):""));
  var caps=[];["ipv4","ipv6","udp_v4","udp_v6","fullcone"].forEach(function(k){if(c[k])caps.push(k.replace("_"," "))});
  tr.appendChild(el("td","dim",caps.join(" ")));
  tr.appendChild(el("td","dim",c.bind||""));
  tr.appendChild(el("td","dim",c.test_url?"ok":"-"));
  var refs=proxyReferrers(name);
  tr.appendChild(el("td","dim",refs.length+"" ));
  var td=el("td");
  var be=el("button","","编辑");be.onclick=function(){editProxy(name)};td.appendChild(be);
  var bd=el("button"," bad"," 删");bd.onclick=function(){delProxy(name)};td.appendChild(bd);
  tr.appendChild(td);tb.appendChild(tr)});
 t.appendChild(tb);box.appendChild(t)}
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
function editProxy(name){
 var isNew=!name;
 var src=(CFG.proxy||{})[name]||{mark:nextMark(),weight:1,ipv4:true,ipv6:false};
 var c=JSON.parse(JSON.stringify(src));
 var cur={name:name||"",mark:c.mark,weight:c.weight,port:c.port,upstream:c.upstream,daemon:c.daemon,
  uid:c.uid,server:c.server||c.proxy_ip,server_port:c.server_port,cipher:c.cipher,password:c.password,
  password_file:c.password_file,plugin:c.plugin,plugin_opts:c.plugin_opts,bind_addr:c.bind_addr,
  mode:c.mode,bind:c.bind,test_url:c.test_url,
  test_dns:(c.test_dns instanceof Array)?c.test_dns.join(", "):(c.test_dns||""),
  restart_max:(c.restart||{}).max,restart_window:(c.restart||{}).window};
  var lines=Object.keys(CFG.proxy||{}).filter(function(x){return x!=name});
  cur.autostart_x=String(c.autostart!==false);
  var CAP_LABELS={ipv4:"IPv4",ipv6:"IPv6",udp_v4:"UDP v4",udp_v6:"UDP v6",fullcone:"FullCone"};
  // ---- instances: SOLE source of connection params (默认线路页已移除) ----
  // legacy line-level protocol fields are flattened into self-contained
  // instances ONCE at modal load (backend INSTANCE_SCOPED_FIELDS would not
  // inherit them anyway once instances exist); on save the line keeps none.
  var line_srv={mode:c.mode||"",plugin:c.plugin||"",plugin_opts:c.plugin_opts||"",
   bind_addr:c.bind_addr||"",server:c.server||c.proxy_ip||"",
   server_port:c.server_port!=null?String(c.server_port):"",
   cipher:c.cipher||c.method||"",password:c.password||"",password_file:c.password_file||""};
  var raw_insts=(c.instances instanceof Array)?JSON.parse(JSON.stringify(c.instances)):[];
  function materialize(o,i){
   var r={name:String(o.name||("i"+i))};
   if(o.port!=null&&o.port!=="")r.port=parseInt(o.port,10);
   ["mode","plugin","plugin_opts","bind_addr","server","cipher","password","password_file"].forEach(function(k){
    var v=(o[k]!=null&&String(o[k])!=="")?String(o[k]):(line_srv[k]||"");
    if(v!=="")r[k]=v});
   var sp=(o.server_port!=null&&String(o.server_port)!=="")?String(o.server_port):(line_srv.server_port||"");
   if(sp!=="")r.server_port=parseInt(sp,10);
   if(!r.mode)r.mode="tcp";
   return r}
  var insts=raw_insts.map(materialize);
  if(!insts.length){insts=[materialize({},0)];insts[0].name="main"}
  var cur_inst={i:0};
  var itabs=null, ipane=null;
  var IF=[["iname","实例名","text"],["imode","模式","select",["tcp","tcp_and_udp","udp"]],
   ["iplugin","传输插件(plugin)","text",null,"如 v2ray-plugin"],
   ["iopts","插件参数(plugin-opts)","text",null,"mode=websocket;tls;host=x;path=/dev"],
   ["ibind","监听地址(-b)","text",null,"默认0.0.0.0, IPv6用 ::0"],
   ["iserver","服务器地址","text"],["isp","服务器端口","num"],
   ["icipher","加密算法","text"],
   ["ipw","密码(内联,ps可见慎用)","text"],["ipwf","密码文件","text"],
   ["iport","透明端口覆盖(留空=用线路端口)","num"]];
  function gv(k){var e=ipane&&ipane.querySelector('[data-fk="'+k+'"]');return e?(e.value||"").trim():""}
  function inst_commit(){
   if(!ipane||cur_inst.i<0||!insts[cur_inst.i])return;
   var KEYMAP={imode:"mode",iplugin:"plugin",iopts:"plugin_opts",ibind:"bind_addr",
    iserver:"server",icipher:"cipher",ipw:"password",ipwf:"password_file"};
   var o={name:gv("iname")||insts[cur_inst.i].name};
   if(gv("iport"))o.port=parseInt(gv("iport"),10);
   Object.keys(KEYMAP).forEach(function(k){var v=gv(k);if(v!=="")o[KEYMAP[k]]=v});
   var sp=gv("isp");if(sp!=="")o.server_port=parseInt(sp,10);
   if(!o.mode)o.mode="tcp";
   insts[cur_inst.i]=o}
  function itabs_render(){
   if(!itabs)return;
   itabs.innerHTML="";ipane.innerHTML="";
   insts.forEach(function(o,i){
    var tb=el("button","itab"+(i===cur_inst.i?" sel":""),String(o.name||("i"+i)));
    tb.onclick=function(){if(i===cur_inst.i)return;inst_commit();cur_inst.i=i;itabs_render()};
    itabs.appendChild(tb)});
   var ba=el("button","itab","+ 实例");
   ba.onclick=function(){inst_commit();var n=1;
    while(insts.some(function(o){return String(o.name)==="i"+n}))n++;
    var copy=JSON.parse(JSON.stringify(insts[cur_inst.i]||{}));copy.name="i"+n;
    insts.push(copy);cur_inst.i=insts.length-1;itabs_render()};
   itabs.appendChild(ba);
   if(insts.length===1&&insts[0].name==="main"){
    var qp=el("button","itab","+ TCP/UDP 双实例(常用)");
    qp.title="TCP插件 + UDP裸连 常用组合，参数从当前配置各自复制";
    qp.onclick=function(){inst_commit();var b=insts[0];
     insts=[Object.assign(JSON.parse(JSON.stringify(b)),{name:"tcp",mode:"tcp"}),
            Object.assign(JSON.parse(JSON.stringify(b)),{name:"udp",mode:"udp",plugin:"",plugin_opts:""})];
     cur_inst.i=0;itabs_render()};
    itabs.appendChild(qp)}
   if(insts.length>1){
    var bd=el("button","itab bad","× 删除本实例");
    bd.onclick=function(){if(!confirm("删除实例 "+((insts[cur_inst.i]||{}).name||"")+" ?"))return;
     insts.splice(cur_inst.i,1);cur_inst.i=Math.min(cur_inst.i,insts.length-1);itabs_render()};
    itabs.appendChild(bd)}
   var o=insts[cur_inst.i]||{};
   mfields(ipane,IF,{iname:o.name||"",imode:o.mode||"tcp",iplugin:o.plugin||"",iopts:o.plugin_opts||"",
    ibind:o.bind_addr||"",iserver:o.server||"",isp:o.server_port!=null?o.server_port:"",
    icipher:o.cipher||"",ipw:o.password||"",ipwf:o.password_file||"",
    iport:o.port!=null?o.port:""});
   var iname=ipane.querySelector('[data-fk="iname"]');
   iname&&(iname.onchange=function(){inst_commit();itabs_render()});
  }
  openModal(isNew?"新增线路":"编辑线路: "+name,function(body){
   var g=mgrid(mgroup(body,"基本信息"));
   mfields(g,[
    ["name","线路名","text"],["mark","fwmark","num"],["weight","权重","num"],
    ["port","透明端口(空=ip-rule)","num"],
    ["upstream","上游线路(chaining)","select",lines]],cur);
   g=mgrid(mgroup(body,"托管进程"));
   mfields(g,[
    ["daemon","托管进程","select",["ss-redir","v2ray","sing-box","custom"]],
    ["uid","运行用户","text"],["autostart_x","自动启动","select",["true","false"]]],cur);
   g=mgroup(body,"能力 / 探测");
   mbools(g,["ipv4","ipv6","udp_v4","udp_v6","fullcone"],c,CAP_LABELS);
   mfields(mgrid(g),[
    ["test_url","探测 URL (test_url)","text",null,"http://connectivitycheck.../generate_204"],
    ["test_dns","探测 DNS (逗号分隔)","text",null,"116.228.111.118, 223.5.5.5"],
    ["bind","探测源 ip:port(bind)","text",null,"192.168.200.2:10051"]],cur);
   g=mgrid(mgroup(body,"重启抑制"));
   mfields(g,[["restart_max","重启上限","num"],["restart_window","重启窗口(秒)","num"]],cur);
   var ig=mgroup(body,"连接参数（实例制：每实例=一个进程，参数自包含；线路级不再保留协议字段）");
   itabs=el("div","itabs");ipane=el("div","ipane");ig.appendChild(itabs);ig.appendChild(ipane);
   itabs_render();
   var adv=document.createElement("details");adv.style.marginTop="14px";
   adv.appendChild(el("summary","dim","高级字段(其余键保留，可直接编辑JSON)"));
   var ta=document.createElement("textarea");ta.className="padv";
   ta.value=JSON.stringify(knownOnly(c,PROXY_COLS),null,2);ta.style.height="150px";
   adv.appendChild(ta);body.appendChild(adv)},
 isNew?"创建":"保存线路",function(body){
  function g(k){var x=body.querySelector('[data-fk="'+k+'"]');return x?(x.value||"").trim():""}
  function gi(k){var v=g(k);return v===""?null:parseInt(v,10)}
  var out={};
  out.mark=gi("mark");out.weight=gi("weight");
  var p=gi("port");if(p!=null)out.port=p;
  if(g("upstream"))out.upstream=g("upstream");
  if(g("daemon"))out.daemon=g("daemon");
  ["uid","bind","test_url"].forEach(function(f){if(g(f))out[f]=g(f)});
  if(g("test_dns"))out.test_dns=g("test_dns").split(/[,，\s]+/).filter(function(x){return x.length});
  inst_commit();
  var inames={};
  for(var ii=0;ii<insts.length;ii++){
   var it0=insts[ii];
   if(!it0.name)return toast("实例缺少名字","bad");
   if(inames[it0.name])return toast("实例名重复: "+it0.name,"bad");
   inames[it0.name]=1;
   if(out.daemon==="ss-redir"&&(!it0.server||(!it0.password&&!it0.password_file)))
    return toast("实例 "+it0.name+": ss-redir 需要 server 和 password(或 password_file)","bad")}
  out.instances=insts;
  if(insts[0].server)out.proxy_ip=insts[0].server;   // mirror for ip-rule/test tooling
  if(insts.length===1&&insts[0].name==="main"){
   // single-process compat: mirror scoped fields onto the line entry so a
   // router build WITHOUT instances support keeps working after restart
   ["mode","plugin","plugin_opts","bind_addr","server","cipher","password","password_file"].forEach(function(k){
    if(insts[0][k]!=null&&insts[0][k]!=="")out[k]=insts[0][k]});
   if(insts[0].server_port!=null)out.server_port=insts[0].server_port;
   if(insts[0].port!=null)out.port=insts[0].port}
  var adv;try{adv=JSON.parse(body.querySelector(".padv").value||"{}")}catch(e){return toast("高级字段不是合法JSON","bad")}
  for(var ak in adv)out[ak]=adv[ak];
  if(out.mark==null)return toast("mark 必填","bad");
  var newName=g("name")||name;
  if(!newName)return toast("线路名必填","bad");
  if(newName!=name&&CFG.proxy[newName])return toast("线路名已存在","bad");
  if(newName!=name)delete CFG.proxy[name];
  CFG.proxy=CFG.proxy||{};CFG.proxy[newName]=out;
  closeModal();
  pushCfg(function(){renderProxy();renderRules()})})}
function nextMark(){var used={};Object.keys(CFG.proxy||{}).forEach(function(k){used[(CFG.proxy[k]||{}).mark]=1});
 var m=1;while(used[m]||m===0x99||m===0x100)m++;return m}
function delProxy(name){
 var refs=proxyReferrers(name);
 if(refs.length)return toast("无法删除: 被 "+refs.join(", ")+" 引用（先改上游/规则）","bad");
 if(!confirm("删除线路 "+name+" 并重载?"))return;
 delete CFG.proxy[name];
 pushCfg(function(){renderProxy();renderRules()})}
$("p-refresh").onclick=function(){loadCfg(renderProxy)};
$("p-add").onclick=function(){editProxy(null)};

// ---------- rules ----------
var GEO_KEYS=["any","from","resolve","cidr","country_name","region_name","city_name","owner_domain",
 "isp_domain","country_code","anycast","idc","base_station"];
var VAL_KEYS={anycast:["","ANYCAST"],idc:["","IDC"],base_station:["","基站"]};
function ruleLabel(cond){
 if(cond===true)return "any";
 if(typeof cond!="object")return "?";
 var parts=[];Object.keys(cond).forEach(function(k){
  var v=cond[k];
  if(k=="any"&&v){parts.push("any");return}
  if(v instanceof Array)parts.push(k+"="+v.length+"项");
  else parts.push(k+"="+String(v))});
 return parts.join(" · ")}
function renderRules(){
 var box=$("rtable");box.innerHTML="";if(!CFG)return;
 CFG.rules=CFG.rules||[];
 CFG.rules.forEach(function(prio,pi){
  var card=el("div","card");
  var head=el("div","bar");
  head.appendChild(el("b","","优先级 "+pi));
  var up=el("button","dim","↑");up.onclick=function(){if(pi>0){var a=CFG.rules;var x=a.splice(pi,1)[0];a.splice(pi-1,0,x);pushCfg(renderRules)}};
  var dn=el("button","dim","↓");dn.onclick=function(){if(pi<CFG.rules.length-1){var a=CFG.rules;var x=a.splice(pi,1)[0];a.splice(pi+1,0,x);pushCfg(renderRules)}};
  var rm=el("button"," bad","删除优先级");rm.onclick=function(){if(!confirm("删除优先级 "+pi+"?"))return;CFG.rules.splice(pi,1);pushCfg(renderRules)};
  head.appendChild(up);head.appendChild(dn);head.appendChild(rm);card.appendChild(head);
  Object.keys(prio||{}).forEach(function(line){
   var row=el("div");row.style.cssText="display:flex;gap:8px;align-items:center;margin:4px 0";
   var sel=document.createElement("select");
   Object.keys(CFG.proxy||{}).forEach(function(pn){var op=el("option","",pn);op.value=pn;if(pn==line)op.selected=true;sel.appendChild(op)});
   sel.onchange=function(){var v=prio[line];delete prio[line];prio[sel.value]=v;pushCfg(renderRules)};
   row.appendChild(sel);
   var cond=prio[line];
   var txt=el("span","dim",ruleLabel(cond));row.appendChild(txt);
   var ed=el("button","dim","编辑条件");ed.onclick=function(){editCond(pi,line)};row.appendChild(ed);
   var dl=el("button"," bad","移除");dl.onclick=function(){if(!confirm("从优先级 "+pi+" 移除 "+line+"?"))return;delete prio[line];pushCfg(renderRules)};
   row.appendChild(dl);card.appendChild(row)});
  var addl=el("button","dim","+ 本优先级加线路");
  addl.onclick=function(){
   var name=prompt("线路名 (必须已在线路管理中存在)","");
   if(!name)return;if(!CFG.proxy[name])return toast("线路不存在: "+name,"bad");
   if(prio[name])return toast("已存在","warn");
   prio[name]={any:true};pushCfg(renderRules)};
  card.appendChild(addl);
  box.appendChild(card)})}
function editCond(pi,line){
 var prio=CFG.rules[pi];var cur=prio[line];
 if(cur===true)cur={any:true};
 if(typeof cur!="object"||!cur)cur={};
 var LIST=["from","cidr","resolve","country_code","country_name","region_name","city_name","owner_domain","isp_domain"];
 var curf={any:cur.any?"true":""};
 LIST.forEach(function(k){curf[k]=(cur[k]||[]).join(", ")});
 openModal("条件编辑: 优先级 "+pi+" · "+line,function(body){
  var COND_LABELS={from:"源地址/网段 (from)",cidr:"目的网段 (cidr)",resolve:"域名 (resolve)",
   country_code:"国家代码",country_name:"国家名",region_name:"省份/地区",city_name:"城市",
   owner_domain:"归属域",isp_domain:"运营商域"};
  function flds(arr,parent){mfields(parent,arr.map(function(k){
   return [k,COND_LABELS[k]||k,"text",null,"逗号分隔多值"]}),curf)}
  var g=mgrid(mgroup(body,"总控"));
  mfields(g,[["any","any(匹配全部)","select",["true"]]],curf);
  g=mgrid(mgroup(body,"地理匹配"));flds(["country_code","country_name","region_name","city_name"],g);
  g=mgrid(mgroup(body,"网络匹配"));flds(["from","cidr","resolve"],g);
  g=mgrid(mgroup(body,"域名匹配"));flds(["owner_domain","isp_domain"],g);
  g=mgroup(body,"节点标签");var trow=el("div","mchips");
  [["anycast","ANYCAST"],["idc","IDC"],["base_station","基站"]].forEach(function(t){
   var lb=el("label");
   var cb=document.createElement("input");cb.type="checkbox";cb.dataset.key=t[0];
   cb.checked=!!(cur[t[0]]&&cur[t[0]].length);
   lb.appendChild(cb);lb.appendChild(document.createTextNode(" "+t[0]+" ("+t[1]+")"));trow.appendChild(lb)});
  g.appendChild(trow)},
 "保存条件",function(body){
  function g(k){var x=body.querySelector('[data-fk="'+k+'"]');return x?(x.value||"").trim():""}
  var out={};
  if(g("any")==="true")out.any=true;
  LIST.forEach(function(k){
   var arr=g(k).split(/[,，\s]+/).filter(function(s){return s.length>0});
   if(arr.length)out[k]=arr});
  body.querySelectorAll("input[data-key]").forEach(function(cb){
   if(cb.checked)out[cb.dataset.key]=[VAL_KEYS[cb.dataset.key][1]]});
  if(!Object.keys(out).length)return toast("至少设置一个条件","bad");
  if(out.any&&Object.keys(out).length>1)delete out.any;
  prio[line]=out;
  closeModal();
  pushCfg(function(){renderRules()})})}
$("r-refresh").onclick=function(){loadCfg(renderRules)};
$("r-add").onclick=function(){if(!Object.keys(CFG.proxy||{}).length)return toast("先创建线路","bad");
 CFG.rules.push({});pushCfg(renderRules)};

// ---------- config tab ----------
function loadCfg(cb){api("/api/config").then(function(d){
 CFG=d.config;$("c-box").value=JSON.stringify(d.config,null,3);$("c-path").textContent=d.path||"";
 $("c-msg").innerHTML="<span class=dim>已加载 "+(d.path||"")+"</span>";
 if(cb)cb();renderProxy();renderRules()}).catch(function(e){toast("读取失败 "+e,"bad")})}
$("c-reload").onclick=loadCfg;
$("c-fmt").onclick=function(){try{$("c-box").value=JSON.stringify(JSON.parse($("c-box").value),null,3);$("c-msg").innerHTML="<span class=good>已格式化</span>"}catch(e){$("c-msg").innerHTML="<span class=bad>"+e+"</span>"}};
$("c-check").onclick=function(){var cfg;try{cfg=JSON.parse($("c-box").value)}catch(e){return $("c-msg").innerHTML="<span class=bad>JSON 错误: "+e+"</span>"}
 api("/api/validate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({config:cfg})}).then(function(r){
  $("c-msg").innerHTML=r.ok?"<span class=good>校验通过</span>":("<span class=bad>错误:</span><br>"+r.errors.map(function(x){return "· "+x}).join("<br>"))})};
$("c-save").onclick=function(){var cfg;try{cfg=JSON.parse($("c-box").value)}catch(e){return toast("JSON 错误: "+e,"bad")}
 if(!confirm("保存整份配置到 nft_route.json？(仅写文件，不通知主进程)"))return;
 api("/api/config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({config:cfg,reload:false})}).then(function(r){
  if(r.ok){toast("已保存(未重载) — 到 状态 页点『重载主进程』生效","good");markDirty();loadCfg()}
  else{var msg=(r.errors||[r.error||JSON.stringify(r)]).join("\\n");toast("拒绝保存:\\n"+msg,"bad");$("c-msg").innerHTML="<span class=bad>"+msg.replace(/\\n/g,"<br>")+"</span>"}})};
loadCfg();

// ---------- routing tables tab ----------
var rtLines=[];
function rtOpts(){api("/api/routes/tables").then(function(d){
 var sel=$("rt-table");var cur=sel.value;sel.innerHTML="";
 var names={};
 (d.rules||[]).forEach(function(r){if(r.table&&!names[r.table]){names[r.table]=1;
  var op=el("option","",r.table+"  (ip rule)");op.value=r.table;sel.appendChild(op)}});
 (d.tables||[]).forEach(function(tb){var k=String(tb.name);if(names[k])return;names[k]=1;
  var op=el("option","",(tb.src==="rt_tables"?k:k+" ("+tb.id+")")+"  ["+tb.src+"]");
  op.value=tb.name;sel.appendChild(op)});
 var pre=["main"].concat(Object.keys(names));
 pre.forEach(function(p){if([].some.call(sel.options,function(o){return o.value===p}))sel.value=p});
 if(cur&&[].some.call(sel.options,function(o){return o.value===cur}))sel.value=cur;
 rtRenderRules(d.rules||[]);rtLoad()}).catch(function(e){toast("tables: "+e,"bad")})}
function rtRenderRules(rs){var t=$("rt-rules");t.innerHTML="";
 putRows(t,["优先级","匹配","目标表"],rs.map(function(r){
  var cell=el("td");var a=el("a","",r.table||"");a.style.cursor=r.table?"pointer":"default";
  if(r.table)a.onclick=function(){$("rt-table").value=r.table;rtLoad()};
  cell.appendChild(a);return [String(r.prio),r.sel,cell]}))}
function rtLoad(){var tb=$("rt-table").value;if(!tb)return;
 api("/api/routes?table="+encodeURIComponent(tb)).then(function(d){
  rtLines=d.lines||[];
  $("rt-info").textContent=(d.ok?"":"读取失败: "+(d.error||""))+" 共 "+(d.count||0)+" 条 @ "+tb;
  var t=$("rt-tbl");t.innerHTML="";
  var rows=rtLines.map(function(r){
   var loss=0;
   var ops=el("td");
   var be=el("button","dim","编辑");be.onclick=function(){rtForm(r.dst,r,true)};
   var bd=el("button"," bad","删");bd.onclick=function(){rtDel(r.dst)};
   ops.appendChild(be);ops.appendChild(document.createTextNode(" "));ops.appendChild(bd);
   return [el("span",r.dst.indexOf(":")>0?"p17":"dst",r.dst||r.type),
    r.opts.via||"",r.opts.dev||"",r.opts.proto||"",r.opts.scope||"",r.opts.src||"",
    r.opts.metric!=null?String(r.opts.metric):"",
    (r.bare&&r.bare.length)?r.bare.join(" "):"",ops]});
  putRows(t,["目标","网关","设备","协议","作用域","源","metric","其他","操作"],rows)
 }).catch(function(e){toast("routes: "+e,"bad")})}
function rtForm(dst,route,editing){
 var o=(route&&route.opts)||{};
 openModal((editing?"编辑路由 @ ":"新增路由 @ ")+$("rt-table").value,function(body){
  mfields(body,[
   ["dst","目标 (CIDR 或 default)","text",null,"10.0.0.0/24"],
   ["via","网关","text"],["dev","设备","text"],
   ["src","绑定源","text"],["scope","scope","select",["global","link","host"]],
   ["proto","proto","text",null,"kernel/static可选"],
   ["metric","metric","num"],["mtu","mtu","num"]],
   {dst:dst||"",via:o.via||"",dev:o.dev||"",src:o.src||"",scope:o.scope&&o.scope!=="global"?o.scope:"",
    proto:o.proto||"",metric:o.metric||"",mtu:o.mtu||""});
  var ck=el("label");var cbx=document.createElement("input");cbx.type="checkbox";cbx.id="rt_onlink";
  ck.appendChild(cbx);ck.appendChild(document.createTextNode(" onlink (网关非直连)"));body.appendChild(ck)},
 "应用(ip route replace)",function(body){
  function g(k){var x=body.querySelector('[data-fk="'+k+'"]');return x?(x.value||"").trim():""}
  var payload={op:"replace",table:$("rt-table").value,dst:g("dst"),via:g("via"),dev:g("dev"),
   src:g("src"),scope:g("scope"),proto:g("proto"),metric:g("metric"),mtu:g("mtu"),
   onlink:$("rt_onlink").checked};
  if(!payload.dst)return toast("目标必填","bad");
  if(!confirm("ip route replace 到表 "+payload.table+" ?\\n路由改动直接影响转发/回程，请核对！"))return;
  api("/api/routes",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)})
   .then(function(r){if(r.ok){toast("已生效: "+r.cmd,"good");rtLoad()}else toast("失败: "+(r.out||r.error||"","bad"))}).catch(function(e){toast(""+e,"bad")})})}
function rtDel(dst){
 if(!confirm("删除路由?\\nip route del "+dst+" table "+$("rt-table").value+"\\n(会立即影响流量，谨慎!)"))return;
 api("/api/routes",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({op:"del",table:$("rt-table").value,dst:dst})}).then(function(r){
   if(r.ok){toast("已删除","good");rtLoad()}else toast("删除失败: "+(r.out||r.error||"","bad"))}).catch(function(e){toast(""+e,"bad")})}
$("rt-refresh").onclick=rtOpts;
$("rt-table").onchange=rtLoad;
$("rt-add").onclick=function(){rtForm("",null,false)};

// ---------- mtr tab ----------
var mtrLines={}, mtrTimer=null;
function loadMtrLines(){api("/api/mtr/lines").then(function(d){
 mtrLines=d.lines||{};
 var sel=$("m-line");sel.innerHTML="";
 var o=el("option","","default (主路由/默认表)");o.value="default";sel.appendChild(o);
 Object.keys(mtrLines).sort().forEach(function(k){
  var L=mtrLines[k];
  var op=el("option","",(k.split(":")[1])+"  ["+L.kind+" · 0x"+L.mark.toString(16)+(L.via?(" · "+L.via):"")+"]");
  op.value=k;sel.appendChild(op)});
 if(!d.mtr_bin||!d.mtr_bin.length)$("m-err").textContent="mtr 未安装";
 $("m-err").textContent=d.ok===false?("加载失败: "+d.error):"";
}).catch(function(e){$("m-err").textContent="lines: "+e})}
var mtrGeo={},mtrGeoPend={};
function geoTxt(ip){var g=mtrGeo[ip];if(!g)return g===null?"-":"…";
 var s=(g.cc?flagOf(g.cc)+" ":"")+(g.cn||"");
 if(g.rg&&g.rg!==g.cn)s+=" "+g.rg;
 if(g.isp)s+=" · "+g.isp;
 if(g.idc)s+=" [IDC]";if(g.ac)s+=" [任播]";
 return s}
function ensureGeo(j){
 var ips=[];(j.hops||[]).forEach(function(h){if(/^\d+\.\d+\.\d+\.\d+$/.test(h.host)&&!(h.host in mtrGeo)&&!(h.host in mtrGeoPend))ips.push(h.host)});
 if(!ips.length)return;
 ips.forEach(function(x){mtrGeoPend[x]=1});
 api("/api/geo?ips="+ips.join(",")).then(function(d){
  Object.keys(d.geo||{}).forEach(function(k){mtrGeo[k]=d.geo[k];delete mtrGeoPend[k]});
  if(window.__mtr_last&&String(window.__mtr_last.target)===String(j.target))renderJob(window.__mtr_last,true)
 }).catch(function(){ips.forEach(function(x){delete mtrGeoPend[x]})})}
function renderJob(j,nogeo){
 if(!nogeo&&j.hops)window.__mtr_geojob=j,ensureGeo(j);
 var box=$("m-result");box.innerHTML="";
 var h1=el("div");h1.appendChild(el("b","",(j.line||"")+"  →  "+(j.target||"")+"  "));
 h1.appendChild(el("span","dim","status="+(j.status||"")+(j.total?(" · 轮 "+(j.pass||0)+"/"+j.total):"")+(j.ms?(" · "+j.ms+"ms"):"")+(j.mark?(" · mark 0x"+j.mark.toString(16)):"")));
 box.appendChild(h1);
 if(j.error)box.appendChild(el("div","bad",String(j.error)));
 if(j.hops&&j.hops.length){
  var rows=j.hops.map(function(h){var loss=parseFloat(h.loss)||0;
   return [h.hop,el("span",loss>=100?"bad":(loss>0?"warn":"good"),h.host),
    el("span","dim",geoTxt(h.host)),h.loss,h.snt,h.last,h.avg,h.best,h.wrst,h.stdev]});
  var t=el("table");t.style.marginTop="6px";
  putRows(t,["跳","主机","地理","丢包","发","最近","平均","最佳","最差","σ"],rows);
  box.appendChild(t)}
 else if(j.status==="running"){box.appendChild(el("div","warn","探测运行中..."))}
 if(j.raw){var det=el("details");det.style.marginTop="8px";
  det.appendChild(el("summary","dim","原始输出"));
  det.appendChild(el("pre","dim",j.raw));box.appendChild(det)}}
$("m-run").onclick=function(){
 var tgt=$("m-target").value.trim();
 if(!tgt)return toast("填写目标 IP / 域名","warn");
 api("/api/mtr",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({target:tgt,line:$("m-line").value,
   cycles:parseInt($("m-cycles").value,10)||10,max_ttl:parseInt($("m-ttl").value,10)||18,
   interval:parseFloat($("m-int").value)||0.2,family:$("m-fam").value})}).then(function(r){
    if(!r.ok)return toast(String(r.error),"bad");
    toast("MTR任务 #"+r.id+" 已启动","good");
    window.__mtr_id=r.id;window.__mtr_last=null;
    if(mtrTimer)clearInterval(mtrTimer);
    mtrTimer=setInterval(function(){          // fallback when WS silent
     api("/api/mtr/job/"+r.id).then(function(j){if(!window.__mtr_last)renderJob(j);
      if(j.status!=="running"){clearInterval(mtrTimer);mtrTimer=null;loadJobs()}}).catch(function(){})},2500)
   }).catch(function(e){toast("请求失败 "+e,"bad")})};
function loadJobs(){api("/api/mtr/jobs").then(function(list){
 var t=$("m-history");t.innerHTML="";
 var rows=list.map(function(j){return [String(j.id),j.line,j.target,
  el("span",j.status==="done"?"good":(j.status==="running"?"warn":"bad"),j.status),
  j.ms||"",j.mark?("0x"+j.mark.toString(16)):"",new Date(j.started*1000).toLocaleTimeString()]});
 putRows(t,["#","线路","目标","状态","ms","mark","时间"],rows);
 t.querySelectorAll("tbody tr").forEach(function(tr,i){tr.style.cursor="pointer";
  tr.onclick=function(){api("/api/mtr/job/"+rows[i][0]).then(renderJob)}})})}
$("m-refresh").onclick=function(){loadMtrLines();loadJobs()};
$("m-target").addEventListener("keydown",function(e){if(e.key==="Enter")$("m-run").click()});

// ---------- status ----------
function lvl(v){if(v==null||isNaN(v))return"⚫";if(v<0)return"🔴";if(v<=0)return"⚫";
 if(v<=0.1)return"🟢";if(v<=0.2)return"🔵";if(v<=0.4)return"🟣";if(v<=0.6)return"🟡";if(v<=0.8)return"🟠";return"🟤"}
function ago(t){if(t==null)return"-";var s=Math.max(0,Date.now()/1000-t);
 return s<90?Math.round(s)+"s前":s<5400?Math.round(s/60)+"m前":Math.round(s/3600)+"h前"}
function tdTb(tbl,rows){var t=$(tbl);t.innerHTML="";if(t.tHead)t.tHead.remove();return t}
function putRows(t,cols,rows){
 var th=document.createElement("thead");var tr=document.createElement("tr");
 cols.forEach(function(c){tr.appendChild(el("th","",c))});th.appendChild(tr);t.appendChild(th);
 var tb=document.createElement("tbody");
 rows.forEach(function(r){var tr=el("tr");r.forEach(function(c){
   var td=el("td");
   if(c&&c.nodeType){td.appendChild(c)}
   else{td.textContent=(c==null?"":String(c))}
   tr.appendChild(td)});tb.appendChild(tr)});
 t.appendChild(tb)}
function loadInfo(){api("/api/health").then(function(d){
 var cm=d.config_mtime, lr=d.last_reload;
 var stale_ui=localStorage.getItem("nft_dirty")==="1";
 var stale=(cm&&(!lr||cm>lr))||stale_ui;
 var box=$("i-dirty");
 if(box){box.textContent=stale?("⚠ 配置已修改尚未重载 · 配置 "+(cm?new Date(cm*1000).toLocaleTimeString():"?")+" / 上次重载 "+(lr?new Date(lr*1000).toLocaleTimeString():"从未")):"";
  box.style.color="var(--yellow)"}
 if(!stale&&lr&&cm&&cm<=lr){localStorage.removeItem("nft_dirty")}
 updateDirtyUI();
 $("info-box").textContent=JSON.stringify(d,null,2);
 var m=d.master||{};
 var mw=$("i-master");mw.innerHTML="";
 var line1=el("div");line1.appendChild(el("b","",(m.status==="down"||!m.pid)?"主进程: 未运行":"主进程运行中"));
 line1.appendChild(el("span","dim","  pid="+(m.pid||"-")+" state="+(m.status||"-")+
   " uptime="+Math.round((m.uptime||0)/60)+"min rss="+(m.rss_mb||"?")+"MB threads="+(m.threads||"?")+" 子进程="+(m.children||"?")));
 mw.appendChild(line1);
 var w=d.webadmin||{};
 var line2=el("div","dim","webadmin: pid "+w.pid+" · 运行 "+Math.round((w.uptime||0)/60)+"min · WS客户端 "+(w.ws_clients||0)+
  " · 环形 "+(w.ring||0)+"/1000 · redis流:"+(w.redis_stream?"连接":"断开"));
 line2.style.color="var(--dim)";mw.appendChild(line2);
 // test tab
 var t=d.test||{};
 $("i-round").textContent=t.round_at?("上轮测试 "+ago(t.round_at)):(t.error?("test读取失败:"+t.error):"暂无测试数据");
 if(t.pending_now){var pn=el("span","warn"," ⏳ 测试请求已提交，等待主进程...");pn&&($("i-round").appendChild(pn))}
 var lt=$("i-lines");lt.innerHTML="";
 var proxy_cfg={};(d.proxies&&d.proxies.managed||[]).forEach(function(p){proxy_cfg[p.managed]=p});
 var names={};Object.keys(t.v4||{}).forEach(function(k){names[k]=1});Object.keys(t.v6||{}).forEach(function(k){names[k]=1});
 var rows=[];Object.keys(names).sort().forEach(function(k){
  var v4=(t.v4||{})[k],v6=(t.v6||{})[k];
  function fmt(ms){return ms==null||isNaN(ms)?"⚫":(ms<0?"失败":(ms<10?Math.round(ms*1000)+"ms":ms.toFixed(1)+"s"))}
  rows.push([k,v4?el("span","",lvl(v4.ms)+" "+fmt(v4.ms)):"⚫",
   v6?el("span","",lvl(v6.ms)+" "+fmt(v6.ms)):"⚫",
   (v4&&v4.ip)||"",v6&&v6.ip&&v6.ip!==v4.ip?v6.ip:"",ago(t.round_at)])});
 if(rows.length)putRows(lt,["线路","IPv4","IPv6","探测IP(v4)","探测IP(v6)","时间"],rows);
 else lt.appendChild(el("div","dim","无测试数据(线路缺少test_url或router未跑过测试轮)"));
 // managed proxies
 var mp=(d.proxies&&d.proxies.managed)||[];
 var pr=$("i-prox");pr.innerHTML="";
 var prows=[];mp.forEach(function(p){
  var its=(p.instances&&p.instances.length)?p.instances:[{tag:"default",state:p.state,pid:p.pid,uptime:p.uptime,cpu:p.cpu,port:p.port}];
  its.forEach(function(e){var st=e.state||"-";
   var stTxt=st+(p.instances?(" ("+ (p.running||"?") +")"):"");
   prows.push([(e.tag==="default"?p.managed:p.managed+"#"+e.tag),p.daemon||"",
    (e.port?(":"+e.port):"ip-rule"),p.upstream?("→ "+p.upstream):"",
    el("span",st.indexOf("running")>=0?"good":(st==="not running"?"bad":"dim"),stTxt),
    e.pid||"",e.uptime!=null?Math.round(e.uptime/60)+"m":"",e.cpu!=null?e.cpu+"%":""]);});});
 if(prows.length)putRows(pr,["线路","daemon","端口","上游","状态","pid","运行","cpu"],prows);
 else pr.appendChild(el("div","dim","无托管代理(配置加 daemon 字段后接管)"));
 // workers tree
 var wks=d.workers||[];var pt=$("i-procs");pt.innerHTML="";
 putRows(pt,["类型","pid","状态","cpu","rss MB","运行min","cmd"],
  [ [ "🅳 DNS", (d.dns&&d.dns.pid)||"-", (d.dns&&d.dns.status)||"missing",
      (d.dns&&d.dns.cpu!=null)?d.dns.cpu+"%":"", (d.dns&&d.dns.rss_mb)||"",
      (d.dns&&d.dns.uptime!=null)?Math.round(d.dns.uptime/60):"", (d.dns&&d.dns.name)||"" ] ]
  .concat(wks.map(function(w){return [w.kind==="proxy"?"🅿 proxy":"🆆 worker",w.pid,w.status,w.cpu!=null?w.cpu+"%":"",
      w.rss_mb||"",w.uptime!=null?Math.round(w.uptime/60):"",w.name]})));
 var ext=(d.proxies&&d.proxies.external)||[];
 $("i-extwrap").style.display=ext.length?"block":"none";
 if(ext.length)putRows($("i-ext"),["pid","ppid","user","cmd"],ext.map(function(e){return[e.pid,e.ppid,e.user,e.cmd]}));
 if(d.error){var er=el("div","bad","health: "+d.error);$("i-master").appendChild(er)}
 }).catch(function(e){$("i-round").textContent="health 加载失败: "+e})}
$("i-refresh").onclick=loadInfo;
$("i-reload").onclick=function(){
 if(!confirm("向主进程发送 SIGUSR1 执行完整重载？\\n(重读配置:egress/链/规则/worker全部重启)"))return;
 api("/api/reload",{method:"POST"}).then(function(r){
  if(r.ok){toast("已重载 (pid "+r.pid+")","good");localStorage.removeItem("nft_dirty");updateDirtyUI();loadInfo()}
  else toast("重载失败: "+(r.error||""),"bad")}).catch(function(e){toast(""+e,"bad")})};
$("i-testnow").onclick=function(){
 api("/api/test_now",{method:"POST"}).then(function(r){
  toast(r.ok?"已请求立即测试线路（轮询周期1s，稍候看结果）":"触发失败: "+(r.error||""),r.ok?"good":"bad");
  setTimeout(loadInfo,5000);setTimeout(loadInfo,12000);
 }).catch(function(e){toast("请求失败 "+e,"bad")})};
setInterval(function(){api("/api/status").then(function(d){
 $("d-master").className="dot "+(d.master&&d.master.alive&&d.master.is_router?"on":"err");
 $("d-redis").className="dot "+(d.redis_stream?"on":"err");
 if($("s-info").classList.contains("sel"))loadInfo()}).catch(function(){})},4000);
loadBind();
</script></body></html>
"""
