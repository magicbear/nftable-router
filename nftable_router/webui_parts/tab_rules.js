// ---------- rules ----------
var GEO_KEYS=["any","from","resolve","cidr","country_name","region_name","city_name","owner_domain",
 "isp_domain","country_code","anycast","idc","base_station"];
var VAL_KEYS={anycast:["","ANYCAST"],idc:["","IDC"],base_station:["","基站"]};
function ruleLabel(cond){
 if(cond===true)return "any";
 if(typeof cond!="object")return "?";
 var parts=[];Object.keys(cond).forEach(function(k){
  var v=cond[k];
  if(k=="any"&&v){parts.push("any");return}
  if(v instanceof Array)parts.push(k+"="+v.length+"项");
  else parts.push(k+"="+String(v))});
 return parts.join(" · ")}
function renderRules(){
 var box=$("rtable");box.innerHTML="";if(!CFG)return;
 CFG.rules=CFG.rules||[];
 CFG.rules.forEach(function(prio,pi){
  var card=el("div","card");
  var head=el("div","bar");
  head.appendChild(el("b","","优先级 "+pi));
  var up=el("button","dim","↑");up.onclick=function(){if(pi>0){var a=CFG.rules;var x=a.splice(pi,1)[0];a.splice(pi-1,0,x);pushCfg(renderRules)}};
  var dn=el("button","dim","↓");dn.onclick=function(){if(pi<CFG.rules.length-1){var a=CFG.rules;var x=a.splice(pi,1)[0];a.splice(pi+1,0,x);pushCfg(renderRules)}};
  var rm=el("button"," bad","删除优先级");rm.onclick=function(){if(!confirm("删除优先级 "+pi+"?"))return;CFG.rules.splice(pi,1);pushCfg(renderRules)};
  head.appendChild(up);head.appendChild(dn);head.appendChild(rm);card.appendChild(head);
  Object.keys(prio||{}).forEach(function(line){
   var row=el("div");row.style.cssText="display:flex;gap:8px;align-items:center;margin:4px 0";
   var sel=document.createElement("select");
   Object.keys(CFG.proxy||{}).forEach(function(pn){var op=el("option","",pn);op.value=pn;if(pn==line)op.selected=true;sel.appendChild(op)});
   sel.onchange=function(){var v=prio[line];delete prio[line];prio[sel.value]=v;pushCfg(renderRules)};
   row.appendChild(sel);
   var cond=prio[line];
   var txt=el("span","dim",ruleLabel(cond));row.appendChild(txt);
   var ed=el("button","dim","编辑条件");ed.onclick=function(){editCond(pi,line)};row.appendChild(ed);
   var dl=el("button"," bad","移除");dl.onclick=function(){if(!confirm("从优先级 "+pi+" 移除 "+line+"?"))return;delete prio[line];pushCfg(renderRules)};
   row.appendChild(dl);card.appendChild(row)});
  var addl=el("button","dim","+ 本优先级加线路");
  addl.onclick=function(){
   var name=prompt("线路名 (必须已在线路管理中存在)","");
   if(!name)return;if(!CFG.proxy[name])return toast("线路不存在: "+name,"bad");
   if(prio[name])return toast("已存在","warn");
   prio[name]={any:true};pushCfg(renderRules)};
  card.appendChild(addl);
  box.appendChild(card)})}
function editCond(pi,line){
 var prio=CFG.rules[pi];var cur=prio[line];
 if(cur===true)cur={any:true};
 if(typeof cur!="object"||!cur)cur={};
 var LIST=["from","cidr","resolve","country_code","country_name","region_name","city_name","owner_domain","isp_domain"];
 var COND_LABELS={from:"源地址/网段 (from)",cidr:"目的网段 (cidr)",resolve:"域名 (resolve)",
  country_code:"国家代码",country_name:"国家名",region_name:"省份/地区",city_name:"城市",
  owner_domain:"归属域",isp_domain:"运营商域"};
 var lists={};LIST.forEach(function(k){lists[k]=(cur[k]||[]).slice()});
 var disp={};
 function summary(arr){return arr.length?(arr.length+"项: "+arr.join(", ")):"（空）"}
 function listField(g,k){
  var row=el("div","mfield");
  row.appendChild(el("label","dim",COND_LABELS[k]||k));
  var line=el("div");line.style.cssText="display:flex;gap:6px;align-items:center";
  var sp=el("span","dim");sp.textContent=summary(lists[k]);disp[k]=sp;
  sp.style.cssText="flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis";
  var b=el("button","dim","编辑");
  b.onclick=function(){openListEditor((COND_LABELS[k]||k)+" — "+k,lists[k],function(arr){
   lists[k]=arr;sp.textContent=summary(arr)})};
  line.appendChild(sp);line.appendChild(b);row.appendChild(line);g.appendChild(row)}
 openModal("条件编辑: 优先级 "+pi+" · "+line,function(body){
  var g=mgrid(mgroup(body,"总控"));
  mfields(g,[["any","any(匹配全部)","select",["true"]]],{any:cur.any?"true":""});
  g=mgrid(mgroup(body,"地理匹配"));LIST.slice(0,4).forEach(function(k){listField(g,k)});
  g=mgrid(mgroup(body,"网络匹配"));LIST.slice(4,7).forEach(function(k){listField(g,k)});
  g=mgrid(mgroup(body,"域名匹配"));LIST.slice(7,9).forEach(function(k){listField(g,k)});
  g=mgroup(body,"节点标签");var trow=el("div","mchips");
  [["anycast","ANYCAST"],["idc","IDC"],["base_station","基站"]].forEach(function(t){
   var lb=el("label");
   var cb=document.createElement("input");cb.type="checkbox";cb.dataset.key=t[0];
   cb.checked=!!(cur[t[0]]&&cur[t[0]].length);
   lb.appendChild(cb);lb.appendChild(document.createTextNode(" "+t[0]+" ("+t[1]+")"));trow.appendChild(lb)});
  g.appendChild(trow)},
 "保存条件",function(body){
  var out={};
  var anySel=body.querySelector('[data-fk="any"]');
  if(anySel&&anySel.value==="true")out.any=true;
  LIST.forEach(function(k){
   var arr=(lists[k]||[]).map(function(s){return (s||"").trim()}).filter(Boolean);
   if(arr.length)out[k]=arr});
  body.querySelectorAll("input[data-key]").forEach(function(cb){
   if(cb.checked)out[cb.dataset.key]=[VAL_KEYS[cb.dataset.key][1]]});
  if(!Object.keys(out).length)return toast("至少设置一个条件","bad");
  if(out.any&&Object.keys(out).length>1)delete out.any;
  prio[line]=out;
  closeModal();
  pushCfg(function(){renderRules()})})}
$("r-refresh").onclick=function(){loadCfg(renderRules)};
$("r-add").onclick=function(){if(!Object.keys(CFG.proxy||{}).length)return toast("先创建线路","bad");
 CFG.rules.push({});pushCfg(renderRules)};
onTabSelect("rules",function(){if(!CFG)loadCfg(renderRules);else renderRules()});
