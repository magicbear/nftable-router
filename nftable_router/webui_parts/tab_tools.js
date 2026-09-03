// ---------- network tools tab (链路MTR/路由表 relocated + ping/dig/whois/ipq) ----------
(function(){
 var body=$("tool-body");
 if(!body)return;
 // relocate the existing top-level sections as first two panes (markup and
 // tab_mtr.js/tab_rt.js untouched; their onTabSelect loaders are reused)
 var mtrS=$("s-mtr"), rtS=$("s-rt");
 if(mtrS)body.insertBefore(mtrS,body.firstChild);
 if(rtS)body.insertBefore(rtS,mtrS?mtrS.nextSibling:body.firstChild);
 var panes={mtr:mtrS,rt:rtS,ping:$("t-ping"),dig:$("t-dig"),whois:$("t-whois"),ipq:$("t-ipq")};
 var curTool="";
 function showTool(k){
  var e=panes[k];if(!e)return;
  Object.keys(panes).forEach(function(x){panes[x]&&panes[x].classList.toggle("sel",x===k)});
  document.querySelectorAll("#tool-tabs button").forEach(function(b){b.classList.toggle("sel",b.dataset.tool===k)});
  if(k!==curTool){curTool=k;var fn=TAB_ON_SELECT[k];if(fn)fn()}
  if(k==="ping"||k==="dig"||k==="ipq")fillLines(k)}
 document.querySelectorAll("#tool-tabs button").forEach(function(b){b.onclick=function(){showTool(b.dataset.tool)}});
 showTool("mtr");
})();
// shared line selector population (same source as the MTR tab)
var toolLines=null;
function fillLines(which){
 var todo=[];
 if(which==="ping"&&!$("p-line").options.length)todo.push(["p-line",$("p-line")]);
 if(which==="dig"&&!$("d-line").options.length)todo.push(["d-line",$("d-line")]);
 if(which==="ipq"&&!$("i-line").options.length)todo.push(["i-line",$("i-line")]);
 if(!todo.length)return;
 function paint(sel){
  sel.innerHTML="";
  var o=el("option","","default (主路由表)");o.value="default";sel.appendChild(o);
  Object.keys(toolLines||{}).sort().forEach(function(k){
   var L=toolLines[k];
   var op=el("option","",(k.split(":")[1])+"  [0x"+((L.mark||0).toString(16))+"]");op.value=k;sel.appendChild(op)})}
 if(toolLines){todo.forEach(function(x){paint(x[1])});return}
 api("/api/mtr/lines").then(function(d){toolLines=d.lines||{};todo.forEach(function(x){paint(x[1])})}).catch(function(){})}

// ---------- ping (live over the existing /ws/stream socket) ----------
var pingId=null;
window.__ping_on=function(m){
 if(!m||String(m.id)!==String(pingId))return;
 var o=$("p-out");
 if(m.line!=null){o.textContent+=m.line+"\n";o.scrollTop=o.scrollHeight}
 if(m.status){
  $("p-run").disabled=false;
  if(m.status==="done"){o.textContent+="\n—— 完成 "+(m.ms||0)+"ms ——\n";$("p-err").textContent=""}
  else $("p-err").textContent="ping "+m.status+(m.error?(": "+m.error):"");
  o.scrollTop=o.scrollHeight}}
$("p-run").onclick=function(){
 var t=$("p-target").value.trim();if(!t)return toast("填写目标 IP / 域名","warn");
 $("p-run").disabled=true;$("p-err").textContent="";
 api("/api/ping",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({target:t,line:$("p-line").value||"default",
   count:parseInt($("p-count").value,10)||20,interval:parseFloat($("p-int").value)||1,
   size:parseInt($("p-size").value,10)||56,family:$("p-fam").value})}).then(function(r){
    if(!r.ok){$("p-run").disabled=false;$("p-err").textContent=r.error;return toast(String(r.error),"bad")}
    pingId=r.id;$("p-out").textContent="";toast("Ping #"+r.id+" 运行中（流式）","good")
  }).catch(function(e){$("p-run").disabled=false;$("p-err").textContent=""+e})};
$("p-target").addEventListener("keydown",function(e){if(e.key==="Enter")$("p-run").click()});
$("p-clear").onclick=function(){$("p-out").textContent=""};

// ---------- dig ----------
$("d-run").onclick=function(){
 var t=$("d-target").value.trim();if(!t)return toast("填写查询域名","warn");
 $("d-run").disabled=true;$("d-err").textContent="";
 api("/api/dig",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({target:t,line:$("d-line").value||"default",type:$("d-type").value,
   server:$("d-server").value.trim(),family:$("d-fam").value})}).then(function(r){
    $("d-run").disabled=false;
    if(!r.ok){$("d-err").textContent=r.error;return}
    $("d-out").textContent=(r.mark?("; mark 0x"+r.mark.toString(16)+" · "+r.ms+"ms\n"):"")+String(r.out||"")+(r.err?("\n[stderr] "+r.err):"")})
   .catch(function(e){$("d-run").disabled=false;$("d-err").textContent=""+e})};
$("d-target").addEventListener("keydown",function(e){if(e.key==="Enter")$("d-run").click()});

// ---------- whois ----------
$("w-run").onclick=function(){
 var t=$("w-target").value.trim();if(!t)return toast("填写域名 / IP","warn");
 $("w-run").disabled=true;$("w-err").textContent="";$("w-out").textContent="查询中（直连注册局，最长 25s）...";
 api("/api/whois",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({target:t})}).then(function(r){
    $("w-run").disabled=false;
    if(!r.ok){$("w-err").textContent=r.error;$("w-out").textContent="";return}
    $("w-out").textContent=String(r.out||"(无输出)")})
   .catch(function(e){$("w-run").disabled=false;$("w-err").textContent=""+e})};
$("w-target").addEventListener("keydown",function(e){if(e.key==="Enter")$("w-run").click()});

// ---------- ip query (route decision + geo) ----------
$("i-run").onclick=function(){
 var t=$("i-ips").value.trim();if(!t)return toast("填写至少一个 IP","warn");
 $("i-run").disabled=true;$("i-err").textContent="";
 api("/api/ipq",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({ips:t,line:$("i-line").value||"default"})}).then(function(r){
    $("i-run").disabled=false;
    if(!r.ok){$("i-err").textContent=r.error;return}
    var rows=(r.rows||[]).map(function(x){
     var g=(r.geo||{})[x.ip];
     var geo=g===undefined?"…":(g===null?"-":((g.cc?flagOf(g.cc)+" ":"")+(g.cn||"")+(g.rg?" "+g.rg:"")+(g.isp?" · "+g.isp:"")+((g.idc)?" [IDC]":"")+((g.ac)?" [任播]":"")));
     return [x.ip,el("span","",String(x.route)),geo]});
    putRows($("i-tbl"),["IP","路由选路"+(r.mark?(" (mark 0x"+r.mark.toString(16)+")"):""),"归属"],rows)})
   .catch(function(e){$("i-run").disabled=false;$("i-err").textContent=""+e})};
