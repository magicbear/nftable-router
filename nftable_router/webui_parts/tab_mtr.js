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
onTabSelect("mtr",function(){loadMtrLines();loadJobs()});
