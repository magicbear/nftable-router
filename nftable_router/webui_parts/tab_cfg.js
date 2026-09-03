// ---------- config tab ----------
// loadCfg() itself (shared CFG/CFG_MTIME state) lives in common.js -- it's
// called by the proxy/rules tabs too. This file only owns the raw-JSON
// tab's own controls.
$("c-reload").onclick=loadCfg;
$("c-fmt").onclick=function(){try{$("c-box").value=JSON.stringify(JSON.parse($("c-box").value),null,3);$("c-msg").innerHTML="<span class=good>已格式化</span>"}catch(e){$("c-msg").innerHTML="<span class=bad>"+e+"</span>"}};
$("c-check").onclick=function(){var cfg;try{cfg=JSON.parse($("c-box").value)}catch(e){return $("c-msg").innerHTML="<span class=bad>JSON 错误: "+e+"</span>"}
 api("/api/validate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({config:cfg})}).then(function(r){
  $("c-msg").innerHTML=r.ok?"<span class=good>校验通过</span>":("<span class=bad>错误:</span><br>"+r.errors.map(function(x){return "· "+x}).join("<br>"))})};
$("c-save").onclick=function(){var cfg;try{cfg=JSON.parse($("c-box").value)}catch(e){return toast("JSON 错误: "+e,"bad")}
 if(!confirm("保存整份配置到 nft_route.json？(仅写文件，不通知主进程)"))return;
 api("/api/config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({config:cfg,reload:false,base_mtime:CFG_MTIME,ui_ver:(typeof UI_VER!=="undefined"?UI_VER:"")})}).then(function(r){
  if(r.stale){toast("配置已被外部修改，请先点『读取配置』重新加载","bad");return}
  if(r.outdated_ui){toast(String(r.error),"bad");return}
  if(r.ok){if(r.mtime)CFG_MTIME=r.mtime;toast("已保存(未重载) — 到 状态 页点『重载主进程』生效","good");markDirty();loadCfg()}
  else{var msg=(r.errors||[r.error||JSON.stringify(r)]).join("\n");toast("拒绝保存:\n"+msg,"bad");$("c-msg").innerHTML="<span class=bad>"+msg.replace(/\n/g,"<br>")+"</span>"}})};
loadCfg();
