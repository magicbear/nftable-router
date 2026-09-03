// ---------- flow table ----------
var MAXROWS=1000, rows=[], paused=false, evtTotal=0;
var PROTO={1:"ICMP",6:"TCP",17:"UDP",58:"ICMP6",47:"GRE"};
var COLS=[
 {id:"time", label:"时间",     def:1, get:function(r){return hhmmss(r.ts)}},
 {id:"proto",label:"协议",     def:1, cls:function(r){return "p"+r.proto}, get:function(r){return PROTO[r.proto]||r.proto}},
 {id:"src",  label:"源",       def:1, cls:function(){return "src"},  get:function(r){return r.src}},
 {id:"dev",  label:"源设备",   def:1, cls:function(){return "dim"}, get:function(r){return r.dev||""}},
 {id:"sport",label:"源端口",   def:1, get:function(r){return r.sport!=null?r.sport:""}},
 {id:"dst",  label:"目的",     def:1, cls:function(){return "dst"},  get:function(r){return r.dst}},
 {id:"dport",label:"目的端口", def:1, get:function(r){return r.dport!=null?r.dport:""}},
 {id:"qname",label:"域名",     def:1, cls:function(){return "dim ell"}, get:function(r){return (r.qname||"")+(r.qtype?(" "+({1:"(A)",28:"(AAAA)",5:"(CNAME)",12:"(PTR)",16:"(TXT)",6:"(SOA)",15:"(MX)"}[r.qtype]||"")):"")}},
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
function defaultSel(){return COLS.filter(function(c){return c.def}).map(function(c){return c.id})}
function curSel(){try{var x=JSON.parse(localStorage.getItem("nft_cols"));
 if(x&&x instanceof Array){var ok={};COLS.forEach(function(c){ok[c.id]=1});return x.filter(function(i){return ok[i]})}}catch(e){}
 return defaultSel()}
function visibleCols(){var w={};curSel().forEach(function(i){w[i]=1});return COLS.filter(function(c){return w[c.id]})}
function searchText(r){var g=r.geo||{};
 return [r.src,r.dev||"",r.dst,r.line,r.mark,r.qname,g.cc,g.cn,g.rg,g.ct,g.isp,PROTO[r.proto]||r.proto].join(" ").toLowerCase()}
// Android-Studio-style query: space-separated terms all must match (AND);
// a leading '-' EXCLUDES the term, a leading '~' makes it a REGEX (i flag),
// anything else is a plain substring. Examples:
//   192.168.32 ~^tcp .*:22$ -google  -> tcp rows to port 22, from 32-net, not google
var _qcache={};
function parseQuery(q){
 if(_qcache[q])return _qcache[q];
 var arr=[];
 (q||"").trim().split(/\s+/).forEach(function(w){
  var neg=0,re=null,t=w;
  if((w[0]=="-"||w[0]=="~")&&w.length>1){neg=w[0]=="-";if(w[0]=="~"){try{re=new RegExp(w.slice(1),"i")}catch(e){re=new RegExp(w.slice(1).replace(/[.*+?^${}()|[\]\\]/g,"\\$&"),"i")}}t=w.slice(1)}
  else if(w.length==1&&w[0]=="-")return;
  arr.push({neg:neg,re:re,t:t.toLowerCase()})});
 if(Object.keys(_qcache).length>64)_qcache={};
 _qcache[q]=arr;return arr}
function rowMatch(r,q){var arr=parseQuery(q);if(!arr.length)return true;
 var t=searchText(r);
 for(var i=0;i<arr.length;i++){var c=arr[i];
  var hit=c.re?c.re.test(t):t.indexOf(c.t)>=0;
  if(c.neg?hit:!hit)return false}
 return true}
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
 var q=$("f-text").value||"";
 return rowMatch(r,q)&&(! $("f-new").checked || r.sess==0)}
function trim(){
 // INTENDED behaviour (restored 2026-09-04; an earlier "oldest-first only"
 // rewrite mis-killed it): while a filter is active, the MATCHING rows are
 // protected from eviction -- the buffer overflows by dropping the OLDEST
 // NON-MATCHING rows first, so "筛选出来的结果不要被清空". Only when every
 // row matches (or no filter) does the oldest matching row yield, keeping the
 // DOM in sync one-for-one for exactly those rows.
 var i=0;
 while(rows.length>MAXROWS&&i<rows.length){if(!visNow(rows[i]))rows.splice(i,1);else i++}
 var dropped=0;
 while(rows.length>MAXROWS){rows.shift();dropped++}
 var b=$("flowbody");
 for(var k=0;k<dropped&&b.firstChild;k++)b.removeChild(b.firstChild)}
function push(r){
 rows.push(r);evtTotal++;trim();
 if(paused)return;
 var q=$("f-text").value||"";
 if(!rowMatch(r,q))return;
 if($("f-new").checked&&r.sess!=0)return;
 var b=$("flowbody");b.appendChild(trOf(r));
 var w=$("flowwrap");if(w.scrollHeight-w.scrollTop-w.clientHeight<400)w.scrollTop=w.scrollHeight;
 $("n-rows").textContent=rows.length;$("n-evt").textContent=evtTotal}
function rerender(){
 var b=$("flowbody");b.innerHTML="";var q=$("f-text").value||"";
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
