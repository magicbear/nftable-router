// ---------- proxy lines ----------
var PROXY_COLS=["mark","weight","port","upstream","daemon","uid","server","server_port","cipher",
 "password","password_file","plugin","plugin_opts","bind_addr","obfs","obfs_param","protocol","protocol_param","mode","binary","config","instances",
 "bind","proxy_ip","test_dns","test_url","ipv4","ipv6","udp_v4","udp_v6","fullcone","autostart","restart"];
function proxyReferrers(name){
 var refs=[];
 Object.keys(CFG.proxy||{}).forEach(function(k){if(CFG.proxy[k]&&CFG.proxy[k].upstream==name)refs.push("proxy:"+k)});
 (CFG.rules||[]).forEach(function(rr,i){if(rr&&Object.prototype.hasOwnProperty.call(rr,name))refs.push("rules#"+i)});
 return refs}
function renderProxy(){
 var box=$("ptable");box.innerHTML="";if(!CFG)return;
 var t=el("table");t.innerHTML="<thead><tr><th>线路</th><th>mark</th><th>端口/ip-rule</th><th>托管</th><th>上游链</th><th>能力</th><th>测试</th><th>引用</th><th></th></tr></thead>";
 var tb=document.createElement("tbody");
 Object.keys(CFG.proxy||{}).forEach(function(name){
  var c=CFG.proxy[name]||{};var tr=el("tr");
  tr.appendChild(el("td","good",name));
  tr.appendChild(el("td","",c.mark!=null?("0x"+(c.mark>>>0).toString(16)+" ("+c.mark+")"):"-"));
  tr.appendChild(el("td","",c.port?("tproxy :"+c.port):"ip-rule"));
  tr.appendChild(el("td",c.daemon?"line":"dim",c.daemon||"-"));
  tr.appendChild(el("td","dim",c.upstream?("→ "+c.upstream):""));
  var caps=[];["ipv4","ipv6","udp_v4","udp_v6","fullcone"].forEach(function(k){if(c[k])caps.push(k.replace("_"," "))});
  tr.appendChild(el("td","dim",caps.join(" ")));

  tr.appendChild(el("td","dim",c.test_url?"ok":"-"));
  var refs=proxyReferrers(name);
  tr.appendChild(el("td","dim",refs.length+"" ));
  var td=el("td");
  var be=el("button","","编辑");be.onclick=function(){editProxy(name)};td.appendChild(be);
  var bd=el("button"," bad"," 删");bd.onclick=function(){delProxy(name)};td.appendChild(bd);
  tr.appendChild(td);tb.appendChild(tr)});
 t.appendChild(tb);box.appendChild(t)}
function editProxy(name){
 var isNew=!name;
 var src=(CFG.proxy||{})[name]||{mark:nextMark(),weight:1,ipv4:true,ipv6:false};
 var c=JSON.parse(JSON.stringify(src));
 var cur={name:name||"",mark:c.mark,weight:c.weight,port:c.port,upstream:c.upstream,daemon:c.daemon,
  uid:c.uid,server:c.server||c.proxy_ip,server_port:c.server_port,cipher:c.cipher,password:c.password,
  password_file:c.password_file,plugin:c.plugin,plugin_opts:c.plugin_opts,bind_addr:c.bind_addr,
  mode:c.mode,test_url:c.test_url,
  test_dns:(c.test_dns instanceof Array)?c.test_dns.join(", "):(c.test_dns||""),
  restart_max:(c.restart||{}).max,restart_window:(c.restart||{}).window};
   // upstream = inherit that line's skuid identity -> only lines that HAVE a
   // run-user are chainable; a uid-less line offers nothing to inherit (mfields
   // still keeps the CURRENT value visible if it predates this rule).
   var lines=Object.keys(CFG.proxy||{}).filter(function(x){return x!=name && ((CFG.proxy[x].uid||"")+"").trim()!==""});
  cur.autostart_x=String(c.autostart!==false);
  var CAP_LABELS={ipv4:"IPv4",ipv6:"IPv6",udp_v4:"UDP v4",udp_v6:"UDP v6",fullcone:"FullCone"};
  // ---- instances: SOLE source of connection params (默认线路页已移除) ----
  // legacy line-level protocol fields are flattened into self-contained
  // instances ONCE at modal load (backend INSTANCE_SCOPED_FIELDS would not
  // inherit them anyway once instances exist); on save the line keeps none.
  var line_srv={mode:c.mode||"",plugin:c.plugin||"",plugin_opts:c.plugin_opts||"",
   bind_addr:c.bind_addr||"",server:c.server||c.proxy_ip||"",
   server_port:c.server_port!=null?String(c.server_port):"",
   cipher:c.cipher||c.method||"",password:c.password||"",password_file:c.password_file||""};
  var raw_insts=(c.instances instanceof Array)?JSON.parse(JSON.stringify(c.instances)):[];
  // Line-level (legacy) protocol fields may ONLY seed a line that has no
  // instances at all. Once instances exist they are the single source of
  // truth -- the line mirror (proxy_ip=inst[0].server, single-main flatten)
  // must NOT backfill empty fields of other instances (bug: switching to
  // instance #2 showed instance #1's values in every empty field).
  var legacy_fallback=(raw_insts.length===0);
  function materialize(o,i){
   var r={name:String(o.name||("i"+i))};
   if(o.port!=null&&o.port!=="")r.port=parseInt(o.port,10);
   ["mode","plugin","plugin_opts","bind_addr","server","cipher","password","password_file"].forEach(function(k){
    var v=(o[k]!=null&&String(o[k])!=="")?String(o[k]):(legacy_fallback?(line_srv[k]||""):"");
    if(v!=="")r[k]=v});
   var sp=(o.server_port!=null&&String(o.server_port)!=="")?String(o.server_port):(legacy_fallback?(line_srv.server_port||""):"");
   if(sp!=="")r.server_port=parseInt(sp,10);
   if(!r.mode)r.mode="tcp";
   return r}
  var insts=raw_insts.map(materialize);
  if(!insts.length){insts=[materialize({},0)];insts[0].name="main"}
  var cur_inst={i:0};
  var itabs=null, ipane=null;
  var IF=[["iname","实例名","text"],["imode","模式","select",["tcp","tcp_and_udp","udp"]],
   ["iplugin","传输插件(plugin)","text",null,"如 v2ray-plugin"],
   ["iopts","插件参数(plugin-opts)","text",null,"mode=websocket;tls;host=x;path=/dev"],
   ["ibind","监听地址(-b)","text",null,"默认0.0.0.0, IPv6用 ::0"],
   ["iserver","服务器地址","text"],["isp","服务器端口","num"],
   ["icipher","加密算法","text"],
   ["ipw","密码(内联,ps可见慎用)","text"],["ipwf","密码文件","text"],
   ["iport","透明端口覆盖(留空=用线路端口)","num"]];
  function gv(k){var e=ipane&&ipane.querySelector('[data-fk="'+k+'"]');return e?(e.value||"").trim():""}
  function inst_commit(){
   if(!ipane||cur_inst.i<0||!insts[cur_inst.i])return;
   var KEYMAP={imode:"mode",iplugin:"plugin",iopts:"plugin_opts",ibind:"bind_addr",
    iserver:"server",icipher:"cipher",ipw:"password",ipwf:"password_file"};
   var o={name:gv("iname")||insts[cur_inst.i].name};
   if(gv("iport"))o.port=parseInt(gv("iport"),10);
   Object.keys(KEYMAP).forEach(function(k){var v=gv(k);if(v!=="")o[KEYMAP[k]]=v});
   var sp=gv("isp");if(sp!=="")o.server_port=parseInt(sp,10);
   if(!o.mode)o.mode="tcp";
   insts[cur_inst.i]=o}
  function itabs_render(){
   if(!itabs)return;
   itabs.innerHTML="";ipane.innerHTML="";
   insts.forEach(function(o,i){
    var tb=el("button","itab"+(i===cur_inst.i?" sel":""),String(o.name||("i"+i)));
    tb.onclick=function(){if(i===cur_inst.i)return;inst_commit();cur_inst.i=i;itabs_render()};
    itabs.appendChild(tb)});
   var ba=el("button","itab","+ 实例");
   ba.onclick=function(){inst_commit();var n=1;
    while(insts.some(function(o){return String(o.name)==="i"+n}))n++;
    var copy=JSON.parse(JSON.stringify(insts[cur_inst.i]||{}));copy.name="i"+n;
    insts.push(copy);cur_inst.i=insts.length-1;itabs_render()};
   itabs.appendChild(ba);
   if(insts.length===1&&insts[0].name==="main"){
    var qp=el("button","itab","+ TCP/UDP 双实例(常用)");
    qp.title="TCP插件 + UDP裸连 常用组合，参数从当前配置各自复制";
    qp.onclick=function(){inst_commit();var b=insts[0];
     insts=[Object.assign(JSON.parse(JSON.stringify(b)),{name:"tcp",mode:"tcp"}),
            Object.assign(JSON.parse(JSON.stringify(b)),{name:"udp",mode:"udp",plugin:"",plugin_opts:""})];
     cur_inst.i=0;itabs_render()};
    itabs.appendChild(qp)}
   if(insts.length>1){
    var bd=el("button","itab bad","× 删除本实例");
    bd.onclick=function(){if(!confirm("删除实例 "+((insts[cur_inst.i]||{}).name||"")+" ?"))return;
     insts.splice(cur_inst.i,1);cur_inst.i=Math.min(cur_inst.i,insts.length-1);itabs_render()};
    itabs.appendChild(bd)}
   var o=insts[cur_inst.i]||{};
   mfields(ipane,IF,{iname:o.name||"",imode:o.mode||"tcp",iplugin:o.plugin||"",iopts:o.plugin_opts||"",
    ibind:o.bind_addr||"",iserver:o.server||"",isp:o.server_port!=null?o.server_port:"",
    icipher:o.cipher||"",ipw:o.password||"",ipwf:o.password_file||"",
    iport:o.port!=null?o.port:""});
   var iname=ipane.querySelector('[data-fk="iname"]');
   iname&&(iname.onchange=function(){inst_commit();itabs_render()});
  }
  openModal(isNew?"新增线路":"编辑线路: "+name,function(body){
    var g=mgrid(mgroup(body,"基本信息"));
    mfields(g,[
     ["name","线路名","text"],["mark","fwmark","num"],["weight","权重","num"],
     ["port","透明端口(空=ip-rule)","num"],
     ["upstream","上游线路(继承其skuid)","select",lines],
     ["uid","运行用户(skuid)","text",null,"选填，线路级全局身份；创建: useradd -rs /bin/false 用户名。留空=进程按当前用户运行、不生成 skuid 规则。两条线路不能用同一用户"]],cur);
    g=mgrid(mgroup(body,"托管进程"));
    mfields(g,[
     ["daemon","托管进程","select",["ss-redir","v2ray","sing-box","custom"]],
     ["autostart_x","自动启动","select",["true","false"]]],cur);
    (function(){
     var dsel=g.querySelector('[data-fk="daemon"]');
     var hint=el("div","dim","  托管进程绑定上游线路时：若上游是 ip-rule(mark) 线路并设有运行用户，本进程即『以上游用户身份运行』，其出站被上游线路的 skuid 规则路由出该线路（无需本线路再填运行用户）；若上游是透明端口(port)线路，则靠本线路自身的运行用户生成 redirect 规则。");
     hint.style.display="none";g.parentNode.appendChild(hint);
     function upd(){hint.style.display=dsel.value?"block":"none"}
     dsel.onchange=upd;upd()})();
   g=mgroup(body,"能力 / 探测");
   mbools(g,["ipv4","ipv6","udp_v4","udp_v6","fullcone"],c,CAP_LABELS);
   mfields(mgrid(g),[
    ["test_url","探测 URL (test_url)","text",null,"http://connectivitycheck.../generate_204"],
    ["test_dns","探测 DNS (逗号分隔)","text",null,"116.228.111.118, 223.5.5.5"]],cur);
   g=mgrid(mgroup(body,"重启抑制"));
   mfields(g,[["restart_max","重启上限","num"],["restart_window","重启窗口(秒)","num"]],cur);
   var ig=mgroup(body,"连接参数（实例制：每实例=一个进程，参数自包含；线路级不再保留协议字段）");
   itabs=el("div","itabs");ipane=el("div","ipane");ig.appendChild(itabs);ig.appendChild(ipane);
   itabs_render();
   var adv=document.createElement("details");adv.style.marginTop="14px";
   adv.appendChild(el("summary","dim","高级字段(其余键保留，可直接编辑JSON)"));
   var ta=document.createElement("textarea");ta.className="padv";
   ta.value=JSON.stringify(knownOnly(c,PROXY_COLS),null,2);ta.style.height="150px";
   adv.appendChild(ta);body.appendChild(adv)},
 isNew?"创建":"保存线路",function(body){
  function g(k){var x=body.querySelector('[data-fk="'+k+'"]');return x?(x.value||"").trim():""}
  function gi(k){var v=g(k);return v===""?null:parseInt(v,10)}
  // MERGE onto the existing entry: keys the form does not own (ipv4/ipv6/
  // udp_*/owner extras/anything hand-added) survive untouched. Only fields
  // bound to controls are overwritten.
  var out=isNew?{}:JSON.parse(JSON.stringify(c));
  out.mark=gi("mark");out.weight=gi("weight");
  var p=gi("port");if(p!=null)out.port=p;else delete out.port;
  if(g("upstream"))out.upstream=g("upstream");else delete out.upstream;
   var dn=g("daemon");
   if(dn)out.daemon=dn;else delete out.daemon;
   ["uid","test_url"].forEach(function(f){var v=g(f);if(v)out[f]=v;else delete out[f]});
   var upn=g("upstream"),upl=upn?((CFG.proxy||{})[upn]||{}):null;
   if(dn&&upl&&(upl.port!=null)&&!g("uid"))
     toast("提示: 上游 "+upn+" 是透明端口线路，本线路需填运行用户才能生成 skuid redirect，否则主进程会拒绝托管","bad");
  delete out.bind;   // legacy alive-check bind ip:port -- dead since SO_MARK probes
  if(g("test_dns"))out.test_dns=g("test_dns").split(/[,，\s]+/).filter(function(x){return x.length});
  else if("test_dns" in out&&!g("test_dns"))delete out.test_dns;
  ["ipv4","ipv6","udp_v4","udp_v6","fullcone"].forEach(function(f){
   var e=body.querySelector('[data-fk="'+f+'"]');if(e)out[f]=!!e.checked});
  var rmx=gi("restart_max"),rmw=gi("restart_window");
  if(rmx!=null||rmw!=null)out.restart={max:rmx==null?5:rmx,window:rmw==null?300:rmw};
  if(dn){
   // ---- instances / protocol fields: managed lines ONLY ----
   inst_commit();
   var inames={};
   for(var ii=0;ii<insts.length;ii++){
    var it0=insts[ii];
    if(!it0.name)return toast("实例缺少名字","bad");
    if(inames[it0.name])return toast("实例名重复: "+it0.name,"bad");
    inames[it0.name]=1;
    if(dn==="ss-redir"&&(!it0.server||(!it0.password&&!it0.password_file)))
     return toast("实例 "+it0.name+": ss-redir 需要 server 和 password(或 password_file)","bad")}
   out.instances=insts;
   out.autostart=g("autostart_x")==="true";
   if(insts[0].server)out.proxy_ip=insts[0].server;
   if(insts.length===1&&insts[0].name==="main"){
    ["mode","plugin","plugin_opts","bind_addr","server","cipher","password","password_file"].forEach(function(k){
     if(insts[0][k]!=null&&insts[0][k]!=="")out[k]=insts[0][k]});
    if(insts[0].server_port!=null)out.server_port=insts[0].server_port;
    if(insts[0].port!=null)out.port=insts[0].port}
  }else{
   // unmanaged (ip-rule / external process) line: never write instances,
   // never mirror protocol fields, never autostart/restart semantics
   delete out.instances;
  }
  var adv;try{adv=JSON.parse(body.querySelector(".padv").value||"{}")}catch(e){return toast("高级字段不是合法JSON","bad")}
  for(var ak in adv)out[ak]=adv[ak];
  if(out.mark==null)return toast("mark 必填","bad");
  var newName=g("name")||name;
  if(!newName)return toast("线路名必填","bad");
  if(newName!=name&&CFG.proxy[newName])return toast("线路名已存在","bad");
  if(newName!=name)delete CFG.proxy[name];
  CFG.proxy=CFG.proxy||{};CFG.proxy[newName]=out;
  closeModal();
  pushCfg(function(){renderProxy();renderRules()})})}

function nextMark(){var used={};Object.keys(CFG.proxy||{}).forEach(function(k){used[(CFG.proxy[k]||{}).mark]=1});
 var m=1005;while(used[m]||m===0x99||m===0x100)m++;return m}
function delProxy(name){
 var refs=proxyReferrers(name);
 if(refs.length)return toast("无法删除: 被 "+refs.join(", ")+" 引用（先改上游/规则）","bad");
 if(!confirm("删除线路 "+name+" 并重载?"))return;
 delete CFG.proxy[name];
 pushCfg(function(){renderProxy();renderRules()})}
$("p-refresh").onclick=function(){loadCfg(renderProxy)};
$("p-add").onclick=function(){editProxy(null)};
onTabSelect("proxy",function(){if(!CFG)loadCfg(renderProxy);else renderProxy()});
