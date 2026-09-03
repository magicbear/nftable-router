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
  if(!confirm("ip route replace 到表 "+payload.table+" ?\n路由改动直接影响转发/回程，请核对！"))return;
  api("/api/routes",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)})
   .then(function(r){if(r.ok){toast("已生效: "+r.cmd,"good");rtLoad()}else toast("失败: "+(r.out||r.error||"","bad"))}).catch(function(e){toast(""+e,"bad")})})}
function rtDel(dst){
 if(!confirm("删除路由?\nip route del "+dst+" table "+$("rt-table").value+"\n(会立即影响流量，谨慎!)"))return;
 api("/api/routes",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({op:"del",table:$("rt-table").value,dst:dst})}).then(function(r){
   if(r.ok){toast("已删除","good");rtLoad()}else toast("删除失败: "+(r.out||r.error||"","bad"))}).catch(function(e){toast(""+e,"bad")})}
$("rt-refresh").onclick=rtOpts;
$("rt-table").onchange=rtLoad;
$("rt-add").onclick=function(){rtForm("",null,false)};
onTabSelect("rt",rtOpts);
