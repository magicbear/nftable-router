// ---------- status tab ----------
function lvl(v){if(v==null||isNaN(v))return"⚫";if(v<0)return"🔴";if(v<=0)return"⚫";
 if(v<=0.1)return"🟢";if(v<=0.2)return"🔵";if(v<=0.4)return"🟣";if(v<=0.6)return"🟡";if(v<=0.8)return"🟠";return"🟤"}
function ago(t){if(t==null)return"-";var s=Math.max(0,Date.now()/1000-t);
 return s<90?Math.round(s)+"s前":s<5400?Math.round(s/60)+"m前":Math.round(s/3600)+"h前"}
function tdTb(tbl,rows){var t=$(tbl);t.innerHTML="";if(t.tHead)t.tHead.remove();return t}
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
  function tb(label,fam,pr){var bt=el("button","dim",label);bt.style.padding="0 6px";bt.style.fontSize="11px";
   bt.onclick=function(){testLine(k,pr,fam,bt)};return bt}
  function fmt(ms){return ms==null||isNaN(ms)?"⚫":(ms<0?"失败":(ms<10?Math.round(ms*1000)+"ms":ms.toFixed(1)+"s"))}
  var caps=(t.caps||{})[k]||{v4:true,v6:!!(v6)};
  var v4cell=!caps.v4?el("span","dim","未启用"):(v4?el("span","",lvl(v4.ms)+" "+fmt(v4.ms)):el("span","","⚫"));
  var v6cell=!caps.v6?el("span","dim","未启用"):(v6?el("span","",lvl(v6.ms)+" "+fmt(v6.ms)):el("span","","⚫"));
  rows.push([k,v4cell,v6cell,
   caps.v4?(((v4&&v4.ip)||"")):"—",
   caps.v6?((v6&&v6.ip)||""):"—",ago(t.round_at),
   (function(){var c=el("td");var any=false;
    if(caps.v4){c.appendChild(tb("v4·T",4,"tcp"));c.appendChild(document.createTextNode(" "));c.appendChild(tb("v4·U",4,"udp"));any=true}
    if(caps.v6){if(any)c.appendChild(document.createTextNode(" "));
     c.appendChild(tb("v6·T",6,"tcp"));c.appendChild(document.createTextNode(" "));c.appendChild(tb("v6·U",6,"udp"))}
    if(!any)c.appendChild(el("span","dim","-"));
    return c})()])});
 if(rows.length)putRows(lt,["线路","IPv4","IPv6","探测IP(v4)","探测IP(v6)","时间","测试"],rows);
 else lt.appendChild(el("div","dim","无测试数据(线路缺少test_url或router未跑过测试轮)"));
 // managed proxies
 var mp=(d.proxies&&d.proxies.managed)||[];
 var pr=$("i-prox");pr.innerHTML="";
 var prows=[];mp.forEach(function(p){
  var its=(p.instances&&p.instances.length)?p.instances:[{tag:"default",state:p.state,pid:p.pid,uptime:p.uptime,cpu:p.cpu,port:p.port}];
  its.forEach(function(e){var st=e.state||"-";
   var stTxt=st+(p.instances?(" ("+ (p.running||"?") +")"):"");
   var key=(e.tag==="default")?p.managed:(p.managed+"#"+e.tag);
   var op=el("td");
   var lb=el("button","dim","日志");lb.style.padding="0 8px";lb.onclick=function(){logView(key)};op.appendChild(lb);
   if(e.why)op.appendChild(el("span","bad"," "+e.why));
   prows.push([key,p.daemon||"",
    (e.port?(":"+e.port):"ip-rule"),p.upstream?("→ "+p.upstream):"",
    el("span",st.indexOf("running")>=0?"good":(st==="not running"?"bad":"dim"),stTxt),
    e.pid||"",e.uptime!=null?Math.round(e.uptime/60)+"m":"",e.cpu!=null?e.cpu+"%":"",op]);});});
 if(prows.length)putRows(pr,["线路","daemon","端口","上游","状态","pid","运行","cpu","操作"],prows);
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
 if(ext.length)putRows($("i-ext"),["pid","父进程","user","cmd"],
  ext.map(function(e){return[e.pid,(e.ppid!=null?("ppid "+e.ppid+(e.ppname?" ("+e.ppname+")":"")):""),e.user,e.cmd]}));
 else $("i-ext").innerHTML="";
 if(d.error){var er=el("div","bad","health: "+d.error);$("i-master").appendChild(er)}
 }).catch(function(e){$("i-round").textContent="health 加载失败: "+e})}
function testLine(name,proto,family,btn){
 var old=btn?btn.textContent:"";
 if(btn){btn.disabled=true;btn.textContent="⋯"}
 var done=function(fn){return function(x){if(btn){btn.disabled=false;btn.textContent=old}return fn(x)}};
 api("/api/test_line",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({line:name,proto:proto,family:family})})
 .then(done(function(r){
   var det=(r.steps||[]).map(function(s){return s.name+" "+(s.ok?("✓ "+s.ms+"ms"):"✗")}).join(" · ");
   if(r.error)toast(name+" "+proto+" ✗ "+r.error,"bad");
   else toast((r.ok?"✓ ":"✗ ")+name+" v"+family+" "+proto.toUpperCase()+": "+det+(r.note?("　"+r.note):""),r.ok?"good":"bad");
   loadInfo()})).catch(done(function(e){toast(name+" 请求失败 "+e,"bad")})); }
var logTimer=null;
function logView(key){
 openModal("日志: "+key,function(body){
  var bar=el("div","bar");
  var en=document.createElement("label");var cb=document.createElement("input");cb.type="checkbox";cb.id="lg_auto";cb.checked=true;
  en.appendChild(cb);en.appendChild(document.createTextNode(" 自动刷新(2s)"));bar.appendChild(en);body.appendChild(bar);
  var pre=el("pre","dim");pre.style.cssText="max-height:60vh;overflow:auto;white-space:pre-wrap;margin:6px 0;font-size:12px";pre.id="lg_pre";body.appendChild(pre);
  function fetchLog(){
   api("/api/proxy_log?line="+encodeURIComponent(key)+"&tail=32768").then(function(r){
    var box=document.getElementById("lg_pre");if(!box)return;
    box.textContent=r.ok?((r.size>r.text.length?("...(截断,全文件 "+r.size+" 字节)\n"):"")+r.text):("(无日志文件: "+(r.error||"")+")");
    box.scrollTop=box.scrollHeight;
    var a=document.getElementById("lg_auto");
    if(logTimer&&(!a||!a.checked)){clearInterval(logTimer);logTimer=null}})}
  fetchLog();
  if(logTimer)clearInterval(logTimer);
  logTimer=setInterval(function(){var a=document.getElementById("lg_auto");
   if(!a){clearInterval(logTimer);logTimer=null;return}if(a.checked)fetchLog();},2000);
 },"关闭",function(){if(logTimer){clearInterval(logTimer);logTimer=null}});}
$("i-refresh").onclick=loadInfo;
$("i-reload").onclick=function(){
 if(!confirm("向主进程发送 SIGUSR1 执行完整重载？\n(重读配置:egress/链/规则/worker全部重启)"))return;
 api("/api/reload",{method:"POST"}).then(function(r){
  if(r.ok){toast("已重载 (pid "+r.pid+")","good");localStorage.removeItem("nft_dirty");updateDirtyUI();loadInfo()}
  else toast("重载失败: "+(r.error||""),"bad")}).catch(function(e){toast(""+e,"bad")})};
$("i-testnow").onclick=function(){
 api("/api/test_now",{method:"POST"}).then(function(r){
  toast(r.ok?"已请求立即测试线路（轮询周期1s，稍候看结果）":"触发失败: "+(r.error||""),r.ok?"good":"bad");
  setTimeout(loadInfo,5000);setTimeout(loadInfo,12000);
 }).catch(function(e){toast("请求失败 "+e,"bad")})};
onTabSelect("info",loadInfo);
