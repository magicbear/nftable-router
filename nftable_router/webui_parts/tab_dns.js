// ---------- DNS (PowerDNS) tab ----------
// Same load-whole-blob / mutate-client-side / save-whole-blob pattern as
// CFG/pushCfg for nft_route.json (see common.js) -- just a separate state
// object (DCFG) so it never collides with the router config.
var DCFG=null, DCFG_MTIME=null, DP_IPS=null, DP_MTIME=null, curDnsSub="rules";

function loadDns(){
 api("/api/pdns/config").then(function(d){
  if(!d.ok){DCFG=null;$("dns-path").innerHTML="<span class=warn>"+(d.error||"PowerDNS 管理未启用")+"</span>";
   $("dr-tbl").innerHTML="";$("df-tbl").innerHTML="";$("ds-tbl").innerHTML="";$("dg-tbl").innerHTML="";return}
  DCFG=d.config;DCFG_MTIME=d.mtime;
  $("dns-path").textContent=d.path+(d.host?("  ·  远程主机 "+d.host+" (经 ssh)"):"  ·  本机");
  dnsSubSelect(curDnsSub)}).catch(function(e){toast("DNS 配置加载失败: "+e,"bad")});
 api("/api/pdns/poison").then(function(d){
  if(!d.ok){DP_IPS=null;return}
  DP_IPS=d.ips||[];DP_MTIME=d.mtime;
  if(curDnsSub==="poison")renderDnsPoison()}).catch(function(){DP_IPS=null});
}
function pushDnsCfg(cb){
 return api("/api/pdns/config",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({config:DCFG,base_mtime:DCFG_MTIME})}).then(function(r){
   if(r.stale){toast("pdns 配置已被外部修改，请刷新后重新编辑","bad");return}
   if(r.errors){toast("拒绝保存:\n"+r.errors.join("\n"),"bad");return}
   if(r.ok){if(r.mtime)DCFG_MTIME=r.mtime;if(r.config)DCFG=r.config;
    toast("已保存 pdns 配置(未 reload) — 点『重载 PowerDNS』生效","good");if(cb)cb()}
   else toast("保存失败: "+(r.error||JSON.stringify(r)),"bad")}).catch(function(e){toast("请求失败 "+e,"bad")})}

// ---------- "rich" reference dropdowns (id + what it actually points to) ----------
// mfields() renders <option> text == value (bare id) which is fine for most
// forms, but a bare forwarder_id/rc_id/src_group_id number tells you
// nothing -- these need the resolved target visible right in the dropdown,
// not just after saving. Kept local to this file (mfields itself untouched,
// other forms rely on its plain id==label behavior).
function dnsFwdOptions(){
 return Object.keys(DCFG.forwarders||{}).sort().map(function(id){
  return [id, id+"  ("+DCFG.forwarders[id]+")"]})}
function dnsRcOptions(){
 return Object.keys(DCFG.result_group||{}).sort().map(function(id){
  var recs=(DCFG.result_group[id]||[]).map(function(r){return r.type+" "+r.value}).join(", ");
  return [id, id+"  ("+(recs||"空")+")"]})}
function dnsSgOptions(){
 return Object.keys(DCFG.source_group||{}).sort().map(function(id){
  return [id, id+"  ("+(DCFG.source_group[id]||[]).join(", ")+")"]})}
function richSelect(parent, key, label, cur, options){
 var row=el("div","mfield");
 row.appendChild(el("label","dim",label));
 var inp=document.createElement("select");
 var e0=el("option","","(无)");e0.value="";inp.appendChild(e0);
 options.forEach(function(pair){
  var op=el("option","",pair[1]);op.value=pair[0];
  if(cur!=null&&String(cur)===String(pair[0]))op.selected=true;
  inp.appendChild(op)});
 if(cur!=null&&String(cur)!==""&&!options.some(function(p){return String(p[0])===String(cur)})){
  var ex=el("option","",String(cur)+"  ⚠ 不存在");ex.value=String(cur);ex.selected=true;inp.appendChild(ex)}
 inp.dataset.fk=key;row.appendChild(inp);parent.appendChild(row);return inp}

// ---------- sub-tab switch ----------
function dnsSubSelect(name){
 curDnsSub=name;
 document.querySelectorAll('#s-dns [data-dt]').forEach(function(b){b.classList.toggle("sel",b.dataset.dt===name)});
 ["rules","fwd","sg","rg","poison"].forEach(function(n){var p=$("dt-"+n);if(p)p.style.display=(n===name)?"":"none"});
 if(!DCFG&&name!=="poison")return;
 if(name==="rules")renderDnsRules();
 else if(name==="fwd")renderDnsFwd();
 else if(name==="sg")renderDnsSg();
 else if(name==="rg")renderDnsRg();
 else if(name==="poison")renderDnsPoison();
}
document.querySelectorAll('#s-dns [data-dt]').forEach(function(b){b.onclick=function(){dnsSubSelect(b.dataset.dt)}});

// ---------- rules ----------
function renderDnsRules(){
 if(!DCFG){$("dr-tbl").innerHTML="";$("dr-count").textContent="";return}
 var q=($("dr-q").value||"").toLowerCase();
 var domains=Object.keys(DCFG.rules||{}).sort();
 var rows=[];
 domains.forEach(function(dm){
  var entries=DCFG.rules[dm]||[];
  var summary=entries.map(function(en){
   if(en.action==="forwarder"){
    var f=(DCFG.forwarders||{})[en.forwarder_id];
    return "→ "+en.forwarder_id+(f?(" ("+f+")"):" ⚠缺失")+(en.src_group_id?(" [src="+en.src_group_id+"]"):"")}
   if(en.action==="result")return "= "+en.rc_id+(en.src_group_id?(" [src="+en.src_group_id+"]"):"");
   return "? "+en.action}).join("  ;  ");
  var hay=(dm+" "+summary).toLowerCase();
  if(q&&hay.indexOf(q)<0)return;
  var badDot=dm!=="default"&&dm!=="."&&dm.charAt(0)!==".";
  var dmCell=el("span",badDot?"bad":"",dm);
  if(badDot)dmCell.title="缺少前导点：只会匹配裸域名精确查询，子域名永远不生效。保存时会自动补成 ."+dm;
  var td=el("td");
  var eb=el("button","dim","编辑");eb.onclick=function(){editDnsRule(dm)};td.appendChild(eb);
  var db=el("button"," bad"," 删");db.onclick=function(){delDnsRule(dm)};td.appendChild(db);
  rows.push([dmCell,entries.length,summary,td])});
 putRows($("dr-tbl"),["域名","条目数","规则","操作"],rows);
 $("dr-count").textContent=rows.length+" / "+domains.length+" 条"}
$("dr-q").addEventListener("input",renderDnsRules);
$("dr-add").onclick=function(){if(!DCFG)return toast("先等配置加载","warn");editDnsRule(null)};
function delDnsRule(dm){
 if(!confirm("删除规则 "+dm+" ?"))return;
 delete DCFG.rules[dm];
 pushDnsCfg(renderDnsRules)}
function editDnsRule(domain){
 var isNew=!domain;
 var entries=isNew?[{action:"forwarder"}]:JSON.parse(JSON.stringify(DCFG.rules[domain]||[]));
 var wrap;
 function readRow(i){
  var row=wrap.children[i];if(!row)return;
  function gv(k){var e=row.querySelector('[data-fk="'+k+'"]');return e?(e.value||"").trim():""}
  var en=entries[i];
  if(en.action==="forwarder"){var v=gv("fwd");if(v)en.forwarder_id=v;else delete en.forwarder_id;delete en.rc_id}
  else{var v2=gv("rc");if(v2)en.rc_id=v2;else delete en.rc_id;delete en.forwarder_id}
  var sg=gv("sg");if(sg)en.src_group_id=sg;else delete en.src_group_id}
 function renderEntries(){
  wrap.innerHTML="";
  entries.forEach(function(en,i){
   var row=el("div","card");
   var bar=el("div","bar");
   bar.appendChild(el("span","dim","条目 "+(i+1)+" "));
   var sel=document.createElement("select");
   [["forwarder","转发(forwarder)"],["result","直接应答(result)"]].forEach(function(a){
    var op=el("option","",a[1]);op.value=a[0];if((en.action||"forwarder")===a[0])op.selected=true;sel.appendChild(op)});
   sel.onchange=function(){readRow(i);entries[i].action=sel.value;renderEntries()};
   bar.appendChild(sel);
   var rm=el("button"," bad","删除本条");rm.onclick=function(){entries.splice(i,1);renderEntries()};
   bar.appendChild(rm);row.appendChild(bar);
   var fg=mgrid(row);
   if((en.action||"forwarder")==="forwarder")
    richSelect(fg,"fwd","forwarder_id",en.forwarder_id,dnsFwdOptions());
   else
    richSelect(fg,"rc","rc_id (result_group)",en.rc_id,dnsRcOptions());
   richSelect(fg,"sg","限定源地址组(可选,留空=不限)",en.src_group_id,dnsSgOptions());
   fg.querySelectorAll("select").forEach(function(s){s.addEventListener("change",function(){readRow(i)})});
   wrap.appendChild(row)})}
 openModal(isNew?"新增规则":"编辑规则: "+domain,function(body){
   var g=mgrid(mgroup(body,"匹配域名"));
   mfields(g,[["domain","域名","text",null,".youtube.com. / default / 留空前导点会自动补上"]],{domain:domain||""});
   var eg=mgroup(body,"规则条目(按顺序匹配，先命中先生效)");
   wrap=el("div");eg.appendChild(wrap);
   renderEntries();
   var addb=el("button","dim","+ 加一条(例如限定不同源地址组)");
   addb.onclick=function(){entries.push({action:"forwarder"});renderEntries()};
   eg.appendChild(addb)},
 isNew?"创建":"保存",function(body){
  entries.forEach(function(_,i){readRow(i)});
  var dm=body.querySelector('[data-fk="domain"]').value.trim();
  if(!dm)return toast("域名必填","bad");
  if(!entries.length)return toast("至少一条规则条目","bad");
  for(var i=0;i<entries.length;i++){
   var en=entries[i];
   if(en.action==="forwarder"&&!en.forwarder_id)return toast("条目"+(i+1)+": 请选择 forwarder_id","bad");
   if(en.action==="result"&&!en.rc_id)return toast("条目"+(i+1)+": 请选择 rc_id","bad")}
  var nk=(dm==="default"||dm===".")?dm:(dm.charAt(0)==="."?dm:("."+dm));
  DCFG.rules=DCFG.rules||{};
  if(!isNew&&nk!==domain)delete DCFG.rules[domain];
  if(DCFG.rules[nk]&&nk!==domain)
   entries=DCFG.rules[nk].concat(entries);   // same merge semantics as backend normalize_rules
  DCFG.rules[nk]=entries;
  closeModal();
  pushDnsCfg(function(){renderDnsRules()})})}

// ---------- forwarders ----------
function dnsForwarderRefs(id){
 var refs=[];
 Object.keys(DCFG.rules||{}).forEach(function(dm){(DCFG.rules[dm]||[]).forEach(function(en,i){
  if(en.action==="forwarder"&&String(en.forwarder_id)===String(id))refs.push(dm+"#"+i)})});
 return refs}
function renderDnsFwd(){
 if(!DCFG)return;
 var rows=[];
 Object.keys(DCFG.forwarders||{}).sort().forEach(function(id){
  var refs=dnsForwarderRefs(id);
  var td=el("td");
  var eb=el("button","dim","编辑");eb.onclick=function(){editDnsFwd(id)};td.appendChild(eb);
  var db=el("button"," bad"," 删");db.onclick=function(){delDnsFwd(id)};td.appendChild(db);
  rows.push([id,DCFG.forwarders[id],refs.length,td])});
 putRows($("df-tbl"),["id","host:port","被引用规则数","操作"],rows)}
$("df-add").onclick=function(){if(!DCFG)return toast("先等配置加载","warn");editDnsFwd(null)};
function editDnsFwd(id){
 var isNew=!id;
 openModal(isNew?"新增上游服务器":"编辑上游: "+id,function(body){
  mfields(body,[["id","id","text",null,"如 30"],
   ["value","地址","text",null,"1.1.1.1:53 或 1.1.1.1,8.8.8.8:53"]],
   {id:id||"",value:id?DCFG.forwarders[id]:""})},
 isNew?"创建":"保存",function(body){
  function g(k){var x=body.querySelector('[data-fk="'+k+'"]');return x?(x.value||"").trim():""}
  var nid=g("id"),val=g("value");
  if(!nid)return toast("id 必填","bad");
  if(!val)return toast("地址必填","bad");
  if(isNew&&DCFG.forwarders[nid])return toast("id 已存在","bad");
  if(!isNew&&nid!==id){
   delete DCFG.forwarders[id];
   Object.keys(DCFG.rules||{}).forEach(function(dm){(DCFG.rules[dm]||[]).forEach(function(en){
    if(en.action==="forwarder"&&String(en.forwarder_id)===String(id))en.forwarder_id=nid})})}
  DCFG.forwarders=DCFG.forwarders||{};DCFG.forwarders[nid]=val;
  closeModal();pushDnsCfg(function(){renderDnsFwd();renderDnsRules()})})}
function delDnsFwd(id){
 var refs=dnsForwarderRefs(id);
 if(refs.length)return toast("无法删除: 被 "+refs.join(", ")+" 引用（先改规则）","bad");
 if(!confirm("删除上游 "+id+" ?"))return;
 delete DCFG.forwarders[id];
 pushDnsCfg(renderDnsFwd)}

// ---------- source groups ----------
function dnsSgRefs(id){
 var refs=[];
 Object.keys(DCFG.rules||{}).forEach(function(dm){(DCFG.rules[dm]||[]).forEach(function(en,i){
  if(en.src_group_id!=null&&String(en.src_group_id)===String(id))refs.push(dm+"#"+i)})});
 return refs}
function renderDnsSg(){
 if(!DCFG)return;
 var rows=[];
 Object.keys(DCFG.source_group||{}).sort().forEach(function(id){
  var refs=dnsSgRefs(id);
  var td=el("td");
  var eb=el("button","dim","编辑");eb.onclick=function(){editDnsSg(id)};td.appendChild(eb);
  var db=el("button"," bad"," 删");db.onclick=function(){delDnsSg(id)};td.appendChild(db);
  rows.push([id,(DCFG.source_group[id]||[]).join(", "),refs.length,td])});
 putRows($("ds-tbl"),["id","CIDR 列表","被引用规则数","操作"],rows)}
$("ds-add").onclick=function(){if(!DCFG)return toast("先等配置加载","warn");editDnsSg(null)};
function editDnsSg(id){
 var isNew=!id;
 openModal(isNew?"新增源地址组":"编辑源地址组: "+id,function(body){
  mfields(body,[["id","id","text",null,"如 1"],
   ["cidrs","CIDR(逗号分隔)","text",null,"172.16.211.0/24, 10.0.0.0/8"]],
   {id:id||"",cidrs:id?(DCFG.source_group[id]||[]).join(", "):""})},
 isNew?"创建":"保存",function(body){
  function g(k){var x=body.querySelector('[data-fk="'+k+'"]');return x?(x.value||"").trim():""}
  var nid=g("id"),cidrs=g("cidrs").split(/[,，\s]+/).filter(function(x){return x.length});
  if(!nid)return toast("id 必填","bad");
  if(!cidrs.length)return toast("至少一个 CIDR","bad");
  if(isNew&&DCFG.source_group[nid])return toast("id 已存在","bad");
  if(!isNew&&nid!==id){
   delete DCFG.source_group[id];
   Object.keys(DCFG.rules||{}).forEach(function(dm){(DCFG.rules[dm]||[]).forEach(function(en){
    if(en.src_group_id!=null&&String(en.src_group_id)===String(id))en.src_group_id=nid})})}
  DCFG.source_group=DCFG.source_group||{};DCFG.source_group[nid]=cidrs;
  closeModal();pushDnsCfg(function(){renderDnsSg();renderDnsRules()})})}
function delDnsSg(id){
 var refs=dnsSgRefs(id);
 if(refs.length)return toast("无法删除: 被 "+refs.join(", ")+" 引用（先改规则）","bad");
 if(!confirm("删除源地址组 "+id+" ?"))return;
 delete DCFG.source_group[id];
 pushDnsCfg(renderDnsSg)}

// ---------- result groups ----------
function dnsRgRefs(id){
 var refs=[];
 Object.keys(DCFG.rules||{}).forEach(function(dm){(DCFG.rules[dm]||[]).forEach(function(en,i){
  if(en.action==="result"&&String(en.rc_id)===String(id))refs.push(dm+"#"+i)})});
 return refs}
function renderDnsRg(){
 if(!DCFG)return;
 var rows=[];
 Object.keys(DCFG.result_group||{}).sort().forEach(function(id){
  var refs=dnsRgRefs(id);
  var recs=(DCFG.result_group[id]||[]).map(function(r){return r.type+" "+r.value+" ttl"+r.ttl}).join(" ; ");
  var td=el("td");
  var eb=el("button","dim","编辑");eb.onclick=function(){editDnsRg(id)};td.appendChild(eb);
  var db=el("button"," bad"," 删");db.onclick=function(){delDnsRg(id)};td.appendChild(db);
  rows.push([id,recs,refs.length,td])});
 putRows($("dg-tbl"),["id","记录","被引用规则数","操作"],rows)}
$("dg-add").onclick=function(){if(!DCFG)return toast("先等配置加载","warn");editDnsRg(null)};
function editDnsRg(id){
 var isNew=!id;
 var recs=isNew?[{type:"A",value:"",ttl:15}]:JSON.parse(JSON.stringify(DCFG.result_group[id]||[]));
 var wrap;
 function readRow(i){
  var row=wrap.children[i];if(!row)return;
  function gv(k){var e=row.querySelector('[data-fk="'+k+'"]');return e?(e.value||"").trim():""}
  recs[i].type=gv("type")||"A";recs[i].value=gv("value");
  var t=parseInt(gv("ttl"),10);recs[i].ttl=isNaN(t)?15:t}
 function renderRecs(){
  wrap.innerHTML="";
  recs.forEach(function(r,i){
   var row=el("div","card");
   var fg=mgrid(row);
   mfields(fg,[["type","type","select",["A","AAAA","CNAME","TXT"]],["value","value","text"],["ttl","ttl","num"]],
    {type:r.type||"A",value:r.value||"",ttl:r.ttl!=null?r.ttl:15});
   fg.querySelectorAll("select,input").forEach(function(e){e.addEventListener("change",function(){readRow(i)})});
   var rm=el("button"," bad","删除本条");rm.onclick=function(){recs.splice(i,1);renderRecs()};row.appendChild(rm);
   wrap.appendChild(row)})}
 openModal(isNew?"新增应答组":"编辑应答组: "+id,function(body){
  var g=mgrid(mgroup(body,"基本"));
  mfields(g,[["id","id","text",null,"如 1"]],{id:id||""});
  var eg=mgroup(body,"静态记录");
  wrap=el("div");eg.appendChild(wrap);renderRecs();
  var addb=el("button","dim","+ 加一条记录");addb.onclick=function(){recs.push({type:"A",value:"",ttl:15});renderRecs()};
  eg.appendChild(addb)},
 isNew?"创建":"保存",function(body){
  recs.forEach(function(_,i){readRow(i)});
  var nid=body.querySelector('[data-fk="id"]').value.trim();
  if(!nid)return toast("id 必填","bad");
  if(!recs.length)return toast("至少一条记录","bad");
  for(var i=0;i<recs.length;i++){if(!recs[i].value)return toast("记录"+(i+1)+": value 必填","bad")}
  if(isNew&&DCFG.result_group[nid])return toast("id 已存在","bad");
  if(!isNew&&nid!==id){
   delete DCFG.result_group[id];
   Object.keys(DCFG.rules||{}).forEach(function(dm){(DCFG.rules[dm]||[]).forEach(function(en){
    if(en.action==="result"&&String(en.rc_id)===String(id))en.rc_id=nid})})}
  DCFG.result_group=DCFG.result_group||{};DCFG.result_group[nid]=recs;
  closeModal();pushDnsCfg(function(){renderDnsRg();renderDnsRules()})})}
function delDnsRg(id){
 var refs=dnsRgRefs(id);
 if(refs.length)return toast("无法删除: 被 "+refs.join(", ")+" 引用（先改规则）","bad");
 if(!confirm("删除应答组 "+id+" ?"))return;
 delete DCFG.result_group[id];
 pushDnsCfg(renderDnsRg)}

// ---------- poison list ----------
function renderDnsPoison(){
 if(DP_IPS==null){$("dp-box").value="";$("dp-count").textContent="未启用(未配置 --pdns-poison-list)";return}
 $("dp-box").value=DP_IPS.join("\n");
 $("dp-count").textContent=DP_IPS.length+" 条"}
$("dp-save").onclick=function(){
 var ips=$("dp-box").value.split(/\r?\n/).map(function(x){return x.trim()}).filter(function(x){return x.length});
 api("/api/pdns/poison",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({ips:ips,base_mtime:DP_MTIME})}).then(function(r){
   if(r.stale){toast("污染IP列表已被外部修改，请刷新后重新编辑","bad");return}
   if(r.ok){DP_IPS=r.ips;DP_MTIME=r.mtime;$("dp-box").value=DP_IPS.join("\n");$("dp-count").textContent=DP_IPS.length+" 条";
    toast("已保存 "+(r.note||""),"good")}
   else toast("保存失败: "+(r.error||JSON.stringify(r)),"bad")}).catch(function(e){toast("请求失败 "+e,"bad")})};

// ---------- top bar ----------
$("dns-refresh").onclick=loadDns;
$("dns-reload").onclick=function(){
 if(!confirm("执行 rec_control reload-lua-script ?\n只重载 forwarders/source_group/result_group/rules；污染IP列表需要转发进程自身支持热加载才会同步生效。"))return;
 api("/api/pdns/reload",{method:"POST"}).then(function(r){
  if(r.ok)toast("已重载 PowerDNS Lua 脚本","good");
  else toast("重载失败: "+(r.error||r.output||""),"bad")}).catch(function(e){toast("请求失败 "+e,"bad")})};
$("dnsmasq-reload").onclick=function(){
 if(!confirm("systemctl reload dnsmasq (本机)？\n重新加载 /etc/dnsmasq.d/nft_route.conf 等配置，不影响现有 DHCP 租约。"))return;
 api("/api/dnsmasq/reload",{method:"POST"}).then(function(r){
  if(r.ok)toast("已重载本机 dnsmasq","good");
  else toast("重载失败: "+(r.error||r.output||""),"bad")}).catch(function(e){toast("请求失败 "+e,"bad")})};
onTabSelect("dns",loadDns);
