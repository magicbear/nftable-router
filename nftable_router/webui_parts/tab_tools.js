// ---------- network tools tab (链路MTR/路由表 relocated + ping/dig/whois/ipq) ----------
// panel timer registry: TOOL_HOOK[name]={show,hide}; must be global because
// panel modules (further below, outside the IIFE) register into it.
var TOOL_HOOK={};
(function(){
 var body=$("tool-body");
 if(!body)return;
 // relocate the existing top-level sections as first two panes (markup and
 // tab_mtr.js/tab_rt.js untouched; their onTabSelect loaders are reused)
 var mtrS=$("s-mtr"), rtS=$("s-rt");
 if(mtrS)body.insertBefore(mtrS,body.firstChild);
 if(rtS)body.insertBefore(rtS,mtrS?mtrS.nextSibling:body.firstChild);
 var panes={mtr:mtrS,rt:rtS,ping:$("t-ping"),dig:$("t-dig"),whois:$("t-whois"),ipq:$("t-ipq"),bw:$("t-bw"),ift:$("t-ift")};
 var curTool="";
 function showTool(k){
  var e=panes[k];if(!e)return;
  if(k===curTool)return;
  var prev=curTool;curTool=k;
  Object.keys(panes).forEach(function(x){panes[x]&&panes[x].classList.toggle("sel",x===k)});
  document.querySelectorAll("#tool-tabs button").forEach(function(b){b.classList.toggle("sel",b.dataset.tool===k)});
  var h=prev&&TOOL_HOOK[prev];if(h&&h.hide)try{h.hide()}catch(e){}
  h=TOOL_HOOK[k];if(h&&h.show)try{h.show()}catch(e){}
  var fn=TAB_ON_SELECT[k];if(fn)fn();
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
  var lbl=sel.id=="i-line"?"auto (策略链模拟)":"default (主路由表)";
  var o=el("option","",lbl);o.value=sel.id=="i-line"?"auto":"default";sel.appendChild(o);
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

// ---------- ip query: full router decision-chain replay + mark route + geo fields ----------
function fhz(m){if(m==null)return "?";return "0x"+(Number(m)>>>0).toString(16)}
function elAppend(parent,tag){var e=document.createElement(tag);parent.appendChild(e);return e}
function ipqRender(d){
 var box=$("i-res");box.innerHTML="";
 if(d.geo_err)box.appendChild(el("div","bad","geo库不可用: "+d.geo_err));
 (d.rows||[]).forEach(function(r){
  var c=el("div","card");box.appendChild(c);
  var dec=r.decision||{};
  var hd=el("div","bar");
  hd.innerHTML="<b>"+r.ip+"</b> → "+(dec.line?("<b class=good>"+dec.line+"</b>"):"")+
   " · mark <b>"+fhz(r.mark)+"</b>"+(dec.forced?" <span class=warn>(强制线路)</span>":"")+
   (dec.priority!=null?" · 优先级#"+dec.priority:"")+
   (dec.ecmp?" <span class=warn>ECMP加权分流</span>":"")+
   " · <span class=dim>"+(dec.why||"")+"</span>"+
   (r.seen?" · <span class=dim>实测最近: line="+(r.seen.line||"-")+" mark="+fhz(r.seen.mark)+"</span>":"");
  c.appendChild(hd);
  if((dec.candidates||[]).length){
   putRows(elAppend(c,"table"),["候选线路","mark","权重","占比","命中条件"],
    dec.candidates.map(function(x){return [x.line,fhz(x.mark),String(x.weight),(x.share||0)+"%",x.why]}));}
  if((dec.skips||[]).length)c.appendChild(el("div","dim","门控跳过: "+dec.skips.map(function(x){return x.line+"("+x.skip+")"}).join("， ")));
  var rt=r.route||{}, rl=r.rule||{};
  var rr=el("div","bar");
  rr.innerHTML="路由: <b>"+(rt.table||"?")+"</b> 表 · dev <b>"+(rt.dev||"?")+"</b>"+
   (rt.via?" · via "+rt.via:"")+(rt.src?" · src "+rt.src:"")+
   (rl.pref!=null?" <span class=dim>(ip rule pref "+rl.pref+")</span>":"")+(rl.note?" <span class=dim>"+rl.note+"</span>":"");
  c.appendChild(rr);
  if((r.names||[]).length)c.appendChild(el("div","dim","DNS观测: "+r.names.join(", ")));
  if(r.geo){
   var ks=Object.keys(r.geo).sort();
   var gt=elAppend(c,"table");var trh=document.createElement("tr");
   ks.forEach(function(k){trh.appendChild(el("th","",k))});gt.appendChild(trh);
   var tr=document.createElement("tr");
   ks.forEach(function(k){tr.appendChild(el("td","",String(r.geo[k])))});gt.appendChild(tr);
  }else c.appendChild(el("div","warn","geo 无数据（将走 0x99 直连旁路）"));
  if(rt.raw){var det=document.createElement("details");det.appendChild(el("summary","dim","ip route get 原文"));
   det.appendChild(el("pre","dim",rt.raw));c.appendChild(det)}})}
$("i-run").onclick=function(){
 var t=$("i-ips").value.trim();if(!t)return toast("填写至少一个 IP","warn");
 $("i-run").disabled=true;$("i-err").textContent="";
 api("/api/ipq",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({ips:t,line:$("i-line").value||"auto",src:$("i-src").value.trim(),
   proto:$("i-proto").value,dport:parseInt($("i-port").value,10)||443})}).then(function(r){
    $("i-run").disabled=false;
    if(!r.ok){$("i-err").textContent=r.error;return}
    ipqRender(r)})
   .catch(function(e){$("i-run").disabled=false;$("i-err").textContent=""+e})};
$("i-ips").addEventListener("keydown",function(e){if(e.key==="Enter")$("i-run").click()});
$("i-proto").onchange=function(){var ic=this.value=="1";$("i-port").disabled=ic;
 $("i-port").style.opacity=ic?0.4:1};

// ---------- 带宽趋势 (sampler runs in webadmin forever; WS pushes one point
// every 5s -- first open pulls the 15min snapshot, after that pure push) ----------
var bwData=null,bwSel={},bwCol={},bwVis=false,bwPend=[],bwSig="";
var BW_PAL=["#5b8fd6","#e8b04b","#6fbf73","#d66969","#c586c0","#4ec9b0","#dcdcaa","#b8d1ea"];
function fmtBps(v){v=v||0;
 if(v>=1e9)return (v/1e9).toFixed(2)+" Gb/s";
 if(v>=1e6)return (v/1e6).toFixed(2)+" Mb/s";
 if(v>=1e3)return (v/1e3).toFixed(1)+" Kb/s";
 return Math.round(v)+" b/s"}
function bwFeed(sp){
 if(!bwData){if(bwPend.length<400)bwPend.push(sp);return}
 var S=bwData.samples;
 if(S.length&&S[S.length-1][0]>=sp[0])return;      // older than tail = snapshot overlap
 S.push(sp);
 bwData.now=sp[0];
 var cut=sp[0]-bwData.span;
 while(S.length&&S[0][0]<cut)S.shift();
 bwLegendMaybe();
 if(bwVis)bwDraw()}
window.__bw_on=function(m){if(m&&m.t=="bw")bwFeed([m.ts,m.r||{}])};
function bwLegendMaybe(){
 if(!bwData)return;
 var pk={};
 bwData.samples.forEach(function(sp){for(var k in sp[1]){var v=sp[1][k],a=pk[k]||[0,0];
  if(v[0]>a[0])a[0]=v[0];if(v[1]>a[1])a[1]=v[1];pk[k]=a}});
 var ord=Object.keys(pk).sort(function(x,y){return (pk[y][0]+pk[y][1])-(pk[x][0]+pk[x][1])});
 var sig=ord.join(",");
 if(sig===bwSig)return;                            // iface set unchanged -> keep legend DOM
 bwSig=sig;
 var lg=$("bw-legend");lg.innerHTML="";
 ord.forEach(function(k,i){var col=BW_PAL[i%BW_PAL.length];bwCol[k]=col;
  if(!(k in bwSel))bwSel[k]=i<5||/^(br0|ppp0|bond0|tun|wg|ibs)/.test(k);
  var x=pk[k],b=el("button","bw-lg");b.style.borderColor=col;b.style.color=col;
  b.innerHTML='<i style="background:'+col+'"></i>'+k+' <span class=dim>'+fmtBps(Math.max(x[0],x[1]))+'峰</span>';
  if(!bwSel[k])b.classList.add("off");
  b.onclick=function(){bwSel[k]=!bwSel[k];b.classList.toggle("off",!bwSel[k]);bwDraw()};
  lg.appendChild(b)});
 var mx=0;ord.forEach(function(k){mx=Math.max(mx,pk[k][0],pk[k][1])});
 $("bw-st").textContent=(bwData.samples.length)+" 点 · 窗口峰值 "+fmtBps(mx)}
function bwDraw(){if(!bwVis)return;var cv=$("bw-cv");if(!cv||!bwData)return;
 var g=cv.getContext("2d"),W=cv.width,H=cv.height,L=56,B=22,R=8,T=8;
 g.clearRect(0,0,W,H);
 var span=bwData.span,t1=bwData.now,t0=t1-span;
 var sel=Object.keys(bwSel).filter(function(k){return bwSel[k]});
 var mx=1000;
 bwData.samples.forEach(function(sp){sel.forEach(function(k){var v=sp[1][k];if(v){mx=Math.max(mx,v[0],v[1])}})});
 function yy(f){var v=mx*f;return (v>=1e6?(v/1e6).toFixed(v>=1e7?0:1)+"M":v>=1e3?(v/1e3).toFixed(0)+"K":Math.round(v)+"b")}
 g.font="11px monospace";
 for(var f=0;f<=4;f++){var y=(H-B)-(H-B-T)*f/4;
  g.strokeStyle="#1d2a44";g.beginPath();g.moveTo(L,y);g.lineTo(W-R,y);g.stroke();
  g.fillStyle="#8fa3c0";g.textAlign="right";g.fillText(yy(f/4),L-6,y+4)}
 g.textAlign="center";
 for(var mm=0;mm<=3;mm++){var x=L+(W-L-R)*mm/3;
  g.strokeStyle="#1d2a44";g.beginPath();g.moveTo(x,T);g.lineTo(x,H-B);g.stroke();
  g.fillStyle="#8fa3c0";g.fillText(mm===3?"现在":"-"+(15-5*mm)+"分",x,H-7)}
 if(!sel.length){g.fillStyle="#5a6d8c";g.textAlign="center";g.fillText("点击图例选择接口",W/2,H/2);return}
 sel.forEach(function(k){var col=bwCol[k]||"#5b8fd6";
  [[0,[]],[1,[5,4]]].forEach(function(dd){var idx=dd[0],dash=dd[1];
   g.strokeStyle=col;g.globalAlpha=idx?0.75:1;g.lineWidth=1.3;g.setLineDash(dash);g.beginPath();
   var st=false;
   bwData.samples.forEach(function(sp){var v=sp[1][k];if(!v)return;
    var x=L+(sp[0]-t0)/span*(W-L-R);x=Math.min(W-R,x);
    var y=(H-B)-Math.min(1,v[idx]/mx)*(H-B-T);
    if(!st){g.moveTo(x,y);st=true}else g.lineTo(x,y)});
   g.stroke()});
  g.globalAlpha=1;g.setLineDash([])})}
function bwLoadSnapshot(){api("/api/bw").then(function(d){
 if(!d||!d.ok||bwData)return;
 bwData={interval:d.interval,span:d.span,now:d.now,samples:d.samples||[]};
 var last=bwData.samples.length?bwData.samples[bwData.samples.length-1][0]:0;
 bwPend=bwPend.filter(function(sp){return sp[0]>last});
 bwLegendMaybe();bwPend.forEach(bwFeed);bwPend=[]}).catch(function(){})}
TOOL_HOOK.bw={show:function(){bwVis=true;bwLoadSnapshot();bwLegendMaybe();bwDraw()},
 hide:function(){bwVis=false}};

// ---------- IP流量 (on-demand iftop, live over /ws/stream t=iftop) ----------
var iftOn=false,iftHbTimer=null;
function iftRender(m){
 if(!m)return;
 var run=(m.status==="running");
 if(run)iftOn=true;
 $("f-state").textContent=run?("运行中 · "+m.iface+(m.pairs&&m.pairs.length?(" · "+m.pairs.length+" 对"):" · 等待流量"))
  :(m.running===false?"未运行":(m.status+(m.reason?(" · "+m.reason):"")));
 $("f-start").disabled=run;$("f-stop").disabled=!run;
 var rows=(m.ips||[]).map(function(x){return [x.ip,
  el("span","",("↑ "+fmtBps(x.out[0]))),el("span","dim",fmtBps(x.out[1])+" 10s均"),
  el("span","",("↓ "+fmtBps(x.in[0]))),el("span","dim",fmtBps(x.in[1])+" 10s均")]});
 putRows($("f-ips"),["IP","上行","(10s均)","下行","(10s均)"],rows);
 var pr=(m.pairs||[]).map(function(x){return [x.a,"=>",x.b,fmtBps(x.ab[0])+" | "+fmtBps(x.ab[1]),fmtBps(x.ba[0])+" | "+fmtBps(x.ba[1])]});
 putRows($("f-pairs"),["源","方向","目的","发送 2s|10s","回传 2s|10s"],pr);
 if(m.ifaces&&m.ifaces.length){var sel=$("f-iface");
  if(!sel.dataset.filled){sel.innerHTML="";var ao=el("option","","any (全部接口)");ao.value="any";sel.appendChild(ao);
   m.ifaces.forEach(function(x){var o=el("option","",x);o.value=x;sel.appendChild(o)});
   if(m.recommended&&m.ifaces.indexOf(m.recommended)>=0)sel.value=m.recommended;
   sel.dataset.filled="1"}}
 if(m.status==="stopped"||m.status==="exited"){iftOn=false;if(iftHbTimer){clearInterval(iftHbTimer);iftHbTimer=null}}}
function iftHb(){api("/api/iftop/status").then(iftRender).catch(function(){})}
window.__iftop_on=function(m){iftRender(m)};
$("f-start").onclick=function(){$("f-err").textContent="";
 api("/api/iftop/start",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({iface:$("f-iface").value||"any"})}).then(function(r){
   if(!r.ok){$("f-err").textContent=r.error;return toast(String(r.error),"bad")}
   iftOn=true;if(iftHbTimer)clearInterval(iftHbTimer);iftHbTimer=setInterval(iftHb,8000);
   toast("iftop 启动 ("+r.iface+")","good")}).catch(function(e){$("f-err").textContent=""+e})};
$("f-stop").onclick=function(){iftOn=false;
 if(iftHbTimer){clearInterval(iftHbTimer);iftHbTimer=null}
 api("/api/iftop/stop",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({reason:"按钮停止"})}).then(function(r){$("f-ips").innerHTML="";$("f-pairs").innerHTML="";
  if(r&&r.note)toast(r.note,"warn")}).catch(function(){})};
function iftLeave(){if(!iftOn)return;iftOn=false;
 if(iftHbTimer){clearInterval(iftHbTimer);iftHbTimer=null}
 // sendBeacon: fires reliably during unload; cookie auth rides along
 try{navigator.sendBeacon("/api/iftop/stop",
   new Blob([JSON.stringify({reason:"离开页面"})],{type:"application/json"}))}
 catch(e){try{api("/api/iftop/stop",{method:"POST",headers:{"Content-Type":"application/json"},
   body:JSON.stringify({reason:"离开页面"})})}catch(e2){}}}
window.addEventListener("pagehide",iftLeave);
TOOL_HOOK.ift={show:function(){iftHb();if(iftHbTimer)clearInterval(iftHbTimer);iftHbTimer=setInterval(iftHb,8000)},
 hide:function(){if(iftHbTimer&&!iftOn){clearInterval(iftHbTimer);iftHbTimer=null}}};
