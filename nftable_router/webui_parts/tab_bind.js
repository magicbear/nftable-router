// ---------- bind tab ----------
var ifData=null;
function unbindEntry(b){
 if(!confirm("解绑 "+(b.ip||b.iface)+" (mark "+b.mark+") ?\n只修改配置文件；在状态页『重载主进程』后 nft 打标规则才会撤销。\n注意:ip rule/路由表若为手工段(ext)不会被自动删除。"))return;
 api("/api/unbind",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({mark:b.mark,ip:b.ip||"",iface:b.iface||""})}).then(function(r){
   if(r.ok){if(r.mtime)CFG_MTIME=r.mtime;markDirty();toast("已解绑 "+(b.ip||b.iface)+"(未重载)","good");
    loadCfg(function(){loadBind()})}
   else toast("解绑失败: "+(r.error||""),"bad")}).catch(function(e){toast("请求失败 "+e,"bad")})}
function loadBind(){
 api("/api/interfaces").then(function(d){
  ifData=d;
  var tb=$("tbl-bound");tb.innerHTML="";
  var thead=document.createElement("thead");thead.innerHTML="<tr><th>接口/IP</th><th>类型</th><th>mark</th><th>网关</th><th>状态</th><th>操作</th></tr>";tb.appendChild(thead);
  var body=document.createElement("tbody");(d.bindings||[]).forEach(function(b){
   var tr=el("tr");
   tr.appendChild(el("td","",(b.ip||"")+(b.iface?(" @"+b.iface):"")));
   tr.appendChild(el("td","dim",b.dynamic?"动态":"静态"));
   tr.appendChild(el("td","good","0x"+(b.mark>>>0).toString(16)+" ("+b.mark+")"));
   tr.appendChild(el("td","dim",((b.iprule||{}).gateway)||"未设置"));
   tr.appendChild(el("td","dim","生效由主进程对账"));
   var tdop=el("td");
   var bd=el("button"," bad","解绑");
   bd.onclick=(function(bb){return function(){unbindEntry(bb)}})(b);
   tdop.appendChild(bd);tr.appendChild(tdop);
   body.appendChild(tr)});
  tb.appendChild(body);
  var tc=$("tbl-cand");tc.innerHTML="";
  tc.tHead=tc.tHead||document.createElement("thead");tc.tHead.innerHTML="<tr><th>接口</th><th>地址</th><th>获取方式</th><th>绑定</th><th>操作</th></tr>";
  var cb=document.createElement("tbody");
  (d.candidates||[]).forEach(function(c){
   var tr=el("tr");
   tr.appendChild(el("td","",c.ifname));
   tr.appendChild(el("td","",c.ip?c.ip+"/"+c.prefixlen:""));
   tr.appendChild(el("td","dim",c.method+(c.dynamic?" · 动态":"")));
   tr.appendChild(el("td",c.bound?"good":"warn",c.bound?("已绑定 mark "+c.mark):"未绑定"));
   var td=el("td");
   if(!c.bound){var bt=el("button","good","→ 填表");bt.onclick=function(){bindPrefill(c)};td.appendChild(bt)}
   tr.appendChild(td);cb.appendChild(tr)});
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
function bindPrefill(c){
 var sel=$("b-iface");[].some.call(sel.options,function(o){return o.value===c.ifname})&&(sel.value=c.ifname);
 $("b-ip").value=c.dynamic?"":c.ip;
 $("b-dyn").value=c.dynamic?"1":"0";
 if(c.dynamic)$("b-gw").value=$("b-gw").value||"auto";
 sel.dispatchEvent(new Event("change"));$("b-ip").dispatchEvent(new Event("input"));
 $("b-ip").scrollIntoView({behavior:"smooth",block:"center"})}
function syncIfaceFromIp(){
 var ip=$("b-ip").value.trim();if(!ip||!ifData)return;
 var c=[].find.call(ifData.candidates||[],function(x){return x.ip===ip});
 var hint=$("b-match");
 if(!c){hint.textContent="⚠ 该IP不在扫描到的公网候选里(内网/未起来/输错)";hint.className="warn";return}
 hint.textContent="✓ "+ip+" 位于 "+c.ifname+(c.dynamic?" (动态)":"");hint.className="good";
 var sel=$("b-iface");
 if([].some.call(sel.options,function(o){return o.value===c.ifname})&&sel.value!==c.ifname){
  if(confirm("IP "+ip+" 实际在 "+c.ifname+" 上，接口已从 "+sel.value+" 自动纠正"))sel.value=c.ifname}
 $("b-dyn").value=c.dynamic?"1":"0"}
$("b-ip").addEventListener("input",syncIfaceFromIp);
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
  if(r.ok){markDirty();toast("已绑定: "+body.ifname+" mark 0x"+mark.toString(16)+"(未重载,状态页可重载)","good");
   loadCfg(function(){loadBind()})}
  else toast("拒绝: "+(r.error||JSON.stringify(r.errors||r)),"bad")}).catch(function(e){toast("请求失败 "+e,"bad")})};
onTabSelect("bind",loadBind);
