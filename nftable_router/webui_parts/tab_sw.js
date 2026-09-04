// ---------- switches (SNMP ARP/MAC collectors) ----------
// Config lives in the shared nft_route.json (CFG.switches) and is saved via
// the same pushCfg() path as every other tab; live health comes from
// /api/switches (each collector's SW::STATUS heartbeat in redis).
var SWSTAT=null, ARPROWS=[];

function swSection(){
 CFG.switches=CFG.switches||{};
 if(!(CFG.switches.devices instanceof Array))CFG.switches.devices=[];
 return CFG.switches}
function agoTxt(ts){
 if(!ts)return "从未";
 var s=Math.max(0,Date.now()/1000-ts);
 return s<90?Math.round(s)+"s前":(s<5400?Math.round(s/60)+"m前":Math.round(s/3600)+"h前")}
function loadSw(){
 if(!CFG)return loadCfg(function(){loadSw()});
 api("/api/switches").then(function(d){SWSTAT=d;renderSw()})
  .catch(function(e){toast("采集器状态读取失败: "+e,"bad");SWSTAT=null;renderSw()});
 loadArp()}
function renderSw(){
 if(!CFG)return;
 var sw=swSection();
 var live={};((SWSTAT||{}).devices||[]).forEach(function(x){live[x.name]=x});
 var poll=sw.poll_interval||300;
 var rows=(sw.devices||[]).map(function(d,i){
  var name=String(d.name||d.ip||"");
  var st=live[name]||{};
  var enabled=d.enabled!==false;
  var stateTxt,stateCls;
  if(!enabled){stateTxt="已禁用";stateCls="dim"}
  else if(st.error){
   var em=String(st.error).replace(/^RuntimeError:\s*/,"");
   stateTxt="错误"+(em?(" "+(em.length>28?em.slice(0,28)+"…":em)):"");
   stateCls="bad"}
  else if(!st.state){stateTxt="未运行";stateCls="warn"}
  else if(st.last_poll&&(Date.now()/1000-st.last_poll)>poll*3){stateTxt="数据陈旧";stateCls="warn"}
  else{stateTxt=st.state;stateCls=st.state==="running"?"good":"warn"}
  var c=st.counts||{};
  var ops=el("td");
  var be=el("button","dim","编辑");be.onclick=function(){editSw(i)};ops.appendChild(be);
  var bt=el("button","dim",enabled?"禁用":"启用");
  bt.onclick=function(){sw.devices[i].enabled=!enabled;pushCfg(function(){loadSw()})};ops.appendChild(bt);
  var bd=el("button"," bad","删");bd.onclick=function(){delSw(i)};ops.appendChild(bd);
  var stCell=el("span",stateCls,stateTxt);
  if(st.error)stCell.title=st.error;
  return [name,d.ip,d.user?"v3":(d.community?"v2c":"-"),st.sysname||"",
   (st.wlan?"WLAN AC":(st.vrp===true?"VRP8/CE":(st.vrp===false?"VRP5/S":""))),
   stCell,st.pid||"",agoTxt(st.last_poll),
   (c.arp==null?"":c.arp),(c.sta==null?"":c.sta),(c.mac==null?"":c.mac),(c.int==null?"":c.int),ops]});
 putRows($("sw-tbl"),["名称","IP","认证","sysName","型号","状态","pid","上次采集","ARP","STA","MAC","接口","操作"],rows);
 var note=[];
 note.push((sw.devices||[]).length+" 台");
 if(sw.enabled===false)note.push("采集总开关已关闭");
 if(SWSTAT&&SWSTAT.python)note.push("解释器 "+SWSTAT.python);
 if(sw.log_dir)note.push("日志 "+sw.log_dir);
 if(SWSTAT&&SWSTAT.error)note.push("⚠ "+SWSTAT.error);
 $("sw-info").textContent=note.join("  ·  ")}
function editSw(idx){
 var sw=swSection();
 var isNew=(idx==null);
 var d=isNew?{enabled:true,snmp_port:161}:JSON.parse(JSON.stringify(sw.devices[idx]));
 openModal(isNew?"新增交换机":"编辑交换机: "+(d.name||d.ip),function(body){
  var g=mgrid(mgroup(body,"设备"));
  mfields(g,[["name","名称(用于日志/状态键)","text",null,"sw-ce6881"],
   ["ip","管理 IP","text",null,"192.168.11.1"],
   ["snmp_port","SNMP 端口","num",null,"161"],
   ["enabled_x","启用","select",["true","false"]]],
   {name:d.name||"",ip:d.ip||"",snmp_port:d.snmp_port||161,enabled_x:String(d.enabled!==false)});
  g=mgrid(mgroup(body,"SNMP v2c (community) — 与 v3 二选一"));
  mfields(g,[["community","community","text"]],{community:d.community||""});
  g=mgrid(mgroup(body,"SNMP v3 (华为=SHA256+AES128; Cisco NX-OS 常见=SHA+AES128)"));
  mfields(g,[["user","用户名","text",null,"monitor"],
   ["auth_key","认证密钥(authKey)","text"],
   ["priv_key","加密密钥(privKey)","text"],
   ["auth_proto","认证算法","select",["sha256","sha","sha224","sha384","sha512","md5"]],
   ["priv_proto","加密算法","select",["aes128","aes192","aes256","des","3des"]]],
   {user:d.user||"",auth_key:d.auth_key||d.authKey||"",priv_key:d.priv_key||d.privKey||"",
    auth_proto:d.auth_proto||d.authProto||"sha256",priv_proto:d.priv_proto||d.privProto||"aes128"});
  var h=el("div","dim","提示: 采集器进程的命令行对本机 root 可见(/proc)，密钥会出现在其中；这与原 supervisor 配置的暴露面一致。");
  h.style.marginTop="8px";body.appendChild(h)},
 isNew?"创建":"保存",function(body){
  function g(k){var x=body.querySelector('[data-fk="'+k+'"]');return x?(x.value||"").trim():""}
  var out={};
  out.ip=g("ip");if(!out.ip)return toast("管理 IP 必填","bad");
  out.name=g("name")||out.ip;
  var p=parseInt(g("snmp_port"),10);if(p)out.snmp_port=p;
  out.enabled=g("enabled_x")!=="false";
  ["community","user","auth_key","priv_key","auth_proto","priv_proto"].forEach(function(f){var v=g(f);if(v)out[f]=v});
  if(out.user&&out.auth_proto==="sha256")delete out.auth_proto;   // keep config diffs clean
  if(out.user&&out.priv_proto==="aes128")delete out.priv_proto;
  if(!out.community&&!(out.user&&out.auth_key))
   return toast("需要 community(v2c) 或 用户名+认证密钥(v3)","bad");
  var dup=(sw.devices||[]).some(function(x,i){return i!==idx&&String(x.name||x.ip)===out.name});
  if(dup)return toast("名称重复: "+out.name,"bad");
  if(isNew)sw.devices.push(out);else sw.devices[idx]=out;
  if(sw.enabled===undefined)sw.enabled=true;
  closeModal();
  pushCfg(function(){loadSw()})})}
function delSw(idx){
 var sw=swSection();
 var d=sw.devices[idx]||{};
 if(!confirm("删除交换机 "+(d.name||d.ip)+" ?\n只改配置；重载主进程后其采集进程才会停止。\nredis 中已采集的历史数据不会自动清除。"))return;
 sw.devices.splice(idx,1);
 pushCfg(function(){loadSw()})}
$("sw-settings").onclick=function(){
 if(!CFG)return toast("先等配置加载","warn");
 var sw=swSection();
 openModal("采集设置",function(body){
  var g=mgrid(mgroup(body,"通用"));
  mfields(g,[["enabled_x","采集总开关","select",["true","false"]],
   ["python","Python 解释器(需装有 pysnmp)","text",null,"留空=主进程同款解释器，如 python3.9"],
   ["log_dir","日志目录(留空=不写日志)","text",null,"/var/log/nft_route"],
   ["poll_interval","ARP/MAC 轮询间隔(秒)","num",null,"300"],
   ["iface_interval","接口表刷新间隔(秒)","num",null,"1800"]],
   {enabled_x:String(sw.enabled!==false),python:sw.python||"",log_dir:sw.log_dir||"",
    poll_interval:sw.poll_interval||300,iface_interval:sw.iface_interval||1800});
  var h=el("div","dim","部署提醒: 若主进程解释器没装 pysnmp，必须在此指定装了 pysnmp 的解释器，否则采集子进程会启动即退出。");
  h.style.marginTop="8px";body.appendChild(h)},
 "保存",function(body){
  function g(k){var x=body.querySelector('[data-fk="'+k+'"]');return x?(x.value||"").trim():""}
  sw.enabled=g("enabled_x")!=="false";
  ["python","log_dir"].forEach(function(f){var v=g(f);if(v)sw[f]=v;else delete sw[f]});
  ["poll_interval","iface_interval"].forEach(function(f){
   var v=parseInt(g(f),10);if(v>0)sw[f]=v;else delete sw[f]});
  closeModal();
  pushCfg(function(){loadSw()})})};
$("sw-add").onclick=function(){if(!CFG)return toast("先等配置加载","warn");editSw(null)};
$("sw-refresh").onclick=function(){loadCfg(function(){loadSw()})};

// ---------- ARP / MAC browser ----------
function loadArp(){
 api("/api/arp").then(function(d){
  if(!d.ok){ARPROWS=[];putRows($("sw-arp"),["提示"],[[el("span","bad",d.error||"读取失败")]]);return}
  ARPROWS=d.rows||[];renderArp()}).catch(function(){ARPROWS=[]})}
function renderArp(){
 var q=($("sw-q").value||"").toLowerCase();
 var rows=ARPROWS.filter(function(r){
  if(!q)return true;
  return [r.ip,r.mac,r.sysname,r.ifName_L3,r.ap_name,r.ssid,r.port,r.port_sw].join(" ").toLowerCase().indexOf(q)>=0})
  .slice(0,500).map(function(r){
   return [el("span","dst",r.ip),el("span","dim",r.mac),r.sysname,
    r.ap_name||r.ifName_L3||"",r.ssid||"",
    r.vlan==null?"":r.vlan,el("span","line",r.port||""),el("span","dim",r.port_sw||"")]});
 putRows($("sw-arp"),["IP","MAC","来源","AP / 三层接口","SSID","VLAN","接入端口","端口所在"],rows)}
$("sw-q").addEventListener("input",renderArp);
onTabSelect("sw",loadSw);
