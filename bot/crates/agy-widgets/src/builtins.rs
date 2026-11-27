//! Built-in Apple-HIG Profile-1 interactive widgets, inline query builder, and standalone preview.

use agy_core::error::{BridgeError, Result};
use agy_core::tg::{
    InlineQueryResultArticle, InputSharedWidgetMessageContent, InputWidgetMessageContent,
};
use agy_render::esc_attr;
use serde_json::{json, Value};

use crate::spec::{
    count_widget_size, encode_widget_data, validate_widget_spec, WidgetData, WidgetSpec,
    WIDGET_HTML_RAW_LIMIT, WIDGET_HTML_ZLIB_LIMIT,
};

const HIG_BASE_CSS: &str = concat!(
    ":root{color-scheme:light dark;--bg:var(--tg-theme-bg-color,light-dark(#fff,#1c1c1e));",
    "--fg:var(--tg-theme-text-color,light-dark(#000,#fff));",
    "--mut:var(--tg-theme-hint-color,light-dark(#8e8e93,#98989d));",
    "--acc:var(--tg-theme-button-color,light-dark(#007aff,#0a84ff));",
    "--btnfg:var(--tg-theme-button-text-color,#fff);",
    "--sec:var(--tg-theme-secondary-bg-color,light-dark(#f2f2f7,#2c2c2e));",
    "--sep:var(--tg-theme-section-separator-color,light-dark(rgba(60,60,67,.16),rgba(255,255,255,.16)));",
    "--bad:var(--tg-theme-destructive-text-color,light-dark(#ff3b30,#ff453a))}",
    "*{box-sizing:border-box}",
    "body{margin:0;padding:14px 16px calc(14px + env(safe-area-inset-bottom,0px));",
    "font:13.5px/1.4 -apple-system,system-ui,sans-serif;",
    "background:var(--bg);color:var(--fg)}",
    "button{font-family:inherit}",
    ".hd{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}",
    ".ttl{font-size:15.5px;font-weight:600;letter-spacing:-.25px;line-height:1.25}",
    ".sub{font-size:11.5px;color:var(--mut);margin-top:1px}",
    ".btn{border:0;border-radius:10px;padding:7px 13px;font-size:12.5px;font-weight:600;line-height:1.15;",
    "background:var(--acc);color:var(--btnfg);cursor:pointer;",
    "box-shadow:inset 0 1px 0 rgba(255,255,255,.18),0 1px 0 rgba(0,0,0,.08)}",
    ".btn:active{transform:scale(.97)}",
    ".card{background:var(--sec);border:1px solid var(--sep);border-radius:13px;padding:2px 12px}",
    ".row{display:flex;justify-content:space-between;align-items:center;padding:9px 0;",
    "border-bottom:1px solid var(--sep);gap:10px}",
    ".row:last-child{border-bottom:0}",
    ".k{color:var(--mut);font-size:12px}",
    ".v{font-weight:600;font-size:12px;font-family:ui-monospace,monospace;",
    "text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:65%}",
    ".err{margin-top:8px;font-size:11.5px;color:var(--bad)}",
    ".err:empty{display:none}"
);

const HIG_UI_CSS: &str = concat!(
    ".card.pad{padding:12px}",
    ".seg{display:flex;background:var(--sec);border:1px solid var(--sep);border-radius:10px;",
    "padding:3px;margin-bottom:10px;gap:3px}",
    ".tab{flex:1;border:0;background:transparent;color:var(--mut);font-size:12px;",
    "font-weight:600;padding:5px 6px;border-radius:7px;cursor:pointer}",
    ".tab.on{background:var(--bg);color:var(--fg);box-shadow:0 1px 0 rgba(0,0,0,.08)}",
    ".pills{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}",
    ".pill{border:1px solid var(--sep);border-radius:999px;padding:5px 11px;font-size:12px;",
    "font-weight:600;background:var(--sec);color:var(--fg);cursor:pointer;box-shadow:0 1px 0 rgba(0,0,0,.04)}",
    ".pill:active{transform:scale(.97)}",
    ".pill.on{background:var(--acc);color:var(--btnfg);border-color:var(--acc);",
    "box-shadow:inset 0 1px 0 rgba(255,255,255,.18),0 1px 0 rgba(0,0,0,.08)}",
    ".btn.sm{padding:5px 10px;font-size:11.5px;border-radius:8px;flex-shrink:0}",
    ".btn.sec,.btn.bad{background:var(--bg);border:1px solid var(--sep);box-shadow:0 1px 0 rgba(0,0,0,.05)}",
    ".btn.sec{color:var(--fg)}",
    ".btn.bad{color:var(--bad)}",
    ".btn[disabled]{opacity:.45;cursor:default}",
    ".inp[contenteditable=true]{flex:1;min-width:0;min-height:32px;padding:7px 10px;",
    "border-radius:10px;border:1px solid var(--sep);background:var(--bg);color:var(--fg);",
    "font:inherit;outline:none;word-break:break-word;white-space:pre-wrap}",
    ".bar .inp[contenteditable=true]{background:var(--sec)}",
    ".inp[contenteditable=true]:empty::before{content:attr(data-ph);color:var(--mut);pointer-events:none}",
    ".bar{display:flex;gap:7px;align-items:center;margin-bottom:10px}",
    ".acts{display:flex;gap:6px;align-items:center;flex-shrink:0}",
    ".bdg{font-size:10.5px;font-weight:600;padding:2px 7px;border-radius:999px;",
    "background:var(--bg);color:var(--mut);border:1px solid var(--sep);white-space:nowrap;flex-shrink:0}",
    ".lbl{font-size:11px;font-weight:600;color:var(--mut);letter-spacing:.03em;margin:10px 2px 5px;text-transform:uppercase}",
    ".meta{min-width:0;flex:1}",
    ".nmr{display:flex;align-items:center;gap:6px;min-width:0}",
    ".nm{font-weight:600;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}",
    ".ds{font-size:11.5px;color:var(--mut);margin-top:2px;overflow:hidden;text-overflow:ellipsis;",
    "display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}",
    ".empty{padding:14px 4px;text-align:center;color:var(--mut);font-size:12px}",
    ".mt{margin-top:10px}.mb{margin-bottom:8px}",
    ".mono{font-family:ui-monospace,monospace;font-size:12px}.ta{min-height:54px}",
    ".hide{display:none}"
);

const JS_ERR_MAP: &str = concat!(
    "var W=window.TelegramWidget||{},EM={",
    "NOT_ALLOWED:'Tap required',BUSY:'Busy',RATE_LIMITED:'Rate limited',",
    "TIMEOUT:'Timed out',FAILED:'Failed',INVALID_ANSWER:'Invalid reply',",
    "REJECTED:'Rejected',BAD_REQUEST:'Bad request'};",
    "function em(e){var c=e&&(e.code||e.name);return EM[c]||(e&&e.message)||'Error';}",
    "function res(r){return (r&&typeof r==='object'&&'result' in r)?r.result:r;}",
    "function pj(s){try{var v=res(s);return v?(typeof v==='string'?JSON.parse(v):v):null;}catch(_){return null;}}"
);

const JS_UI_CORE: &str = concat!(
    "function $(i){return document.getElementById(i);}",
    "function val(el){return String((el.innerText!=null?el.innerText:el.textContent)||'').trim();}",
    r#"function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}"#,
    "function rst(){var r=W.richState;if(typeof r==='string')r=pj(r);return (r&&typeof r==='object')?r:(pj(W.chatData)||pj(W.publicData)||{});}",
    "function act(a,p,fb){if(typeof W.callAction==='function')return W.callAction(a,p||{});if(typeof W.request==='function'&&fb)return W.request(fb);return Promise.reject({code:'NOT_ALLOWED',message:'Open WebApp for action'});}",
    "function hap(k){try{W.HapticFeedback&&(k==='sel'?W.HapticFeedback.selectionChanged():W.HapticFeedback.impactOccurred(k||'light'));}catch(_){}}",
    "function applyResp(r,cur){var nx=(r&&r.richState)||W.richState;if(typeof nx==='string')nx=pj(nx);if(nx&&typeof nx==='object')return nx;var p=pj(W.chatData)||pj(W.publicData)||pj(r);return (p&&typeof p==='object'&&!p.echo)?Object.assign({},cur,p):cur;}",
    "function bindSt(fn){if(W.onEvent){W.onEvent('chatDataChanged',fn);W.onEvent('richStateChanged',fn);W.onEvent('publicDataChanged',fn);}}"
);

fn wrap_widget_html(body: &str, js: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><style>{HIG_BASE_CSS}{HIG_UI_CSS}</style></head><body>{body}<div id='err' class='err'></div><script>{JS_ERR_MAP}{JS_UI_CORE}{js}</script></body></html>"
    )
}

fn skills_widget_html() -> String {
    let body = concat!(
        "<div class='hd'><div><div class='ttl'>Skills Manager</div><div id='sub' class='sub'>Ready</div></div>",
        "<div class='acts'><span id='grd' class='bdg'></span>",
        "<button id='ref' class='btn sm sec' type='button'>Refresh</button></div></div>",
        "<div id='tabs' class='seg'>",
        "<button data-t='inst' class='tab on' type='button'>Installed</button>",
        "<button data-t='sp' class='tab' type='button'>SkillPort</button>",
        "<button data-t='cat' class='tab' type='button'>Catalog</button></div>",
        "<div class='bar'><div id='q' class='inp' contenteditable='true' role='textbox' data-ph='Search skills...'></div>",
        "<button id='go' class='btn sm' type='button'>Search</button></div>",
        "<div id='list' class='card'></div>"
    );
    let js = r#"var st=rst(),qEl=$('q'),list=$('list'),sub=$('sub'),grd=$('grd'),err=$('err'),tabs=$('tabs').querySelectorAll('.tab');function nt(t){t=String(t||'inst').toLowerCase();return t==='installed'?'inst':(t==='skillport'?'sp':(t==='catalog'?'cat':(t==='sp'||t==='cat'?t:'inst')));}var curTab=nt(st.tab);if(st.q)qEl.textContent=st.q;function curItems(){if(Array.isArray(st.items))return st.items;if(curTab==='inst'&&Array.isArray(st.installed))return st.installed;if(curTab!=='inst'&&Array.isArray(st.results))return st.results;return [];}function draw(){for(var i=0;i<tabs.length;i++){var tb=tabs[i];tb.className='tab'+(tb.getAttribute('data-t')===curTab?' on':'');}var can=st.can_manage!==false;grd.textContent=st.can_manage===false?'Read-only':(st.can_manage===true?'Manage':'Ready');var items=curItems();sub.textContent=items.length+' skill'+(items.length===1?'':'s');var h='';for(var j=0;j<items.length;j++){var it=items[j]||{};var nm=typeof it==='string'?it:(it.name||it.slug||it.id||'unnamed');var ds=typeof it==='string'?'':(it.desc||it.description||it.summary||'');var isIn=typeof it==='object'&&it.installed!=null?!!it.installed:(curTab==='inst');var dis=can?'':' disabled';h+="<div class='row'><div class='meta'><div class='nm'>"+esc(nm)+"</div>"+(ds?"<div class='ds'>"+esc(ds)+"</div>":'')+"</div>"+(isIn?"<button class='btn sm bad' type='button' data-a='del' data-i='"+j+"'"+dis+">Delete</button>":"<button class='btn sm' type='button' data-a='in' data-i='"+j+"'"+dis+">Install</button>")+"</div>";}list.innerHTML=h||"<div class='empty'>No skills found.</div>";W.ready&&W.ready();}function run(a,p,fb){err.textContent='';sub.textContent='Working...';act(a,p,fb).then(function(r){st=applyResp(r,st);if(st.tab)curTab=nt(st.tab);draw();},function(e){err.textContent=em(e);draw();});}function search(){run('sk_search',{q:val(qEl),tab:curTab},'sk:t:'+curTab);}$('tabs').addEventListener('click',function(e){var t=e.target.getAttribute('data-t');if(!t)return;hap('sel');curTab=nt(t);draw();search();});$('go').addEventListener('click',function(){hap('light');search();});$('ref').addEventListener('click',function(){hap('light');search();});qEl.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();search();}});list.addEventListener('click',function(e){var a=e.target.getAttribute('data-a');if(!a)return;if(st.can_manage===false){err.textContent='Permission denied';return;}var idx=+e.target.getAttribute('data-i'),it=curItems()[idx];if(!it)return;hap('light');var nm=typeof it==='string'?it:(it.name||it.slug||it.id||'');if(a==='del')run('sk_delete',{name:nm},'sk:del:'+idx);else{var src=(typeof it==='object'&&it.source)||(curTab==='sp'?'skillport':'catalog');var id=(typeof it==='object'&&(it.id||it.slug||it.name))||nm,sl=(typeof it==='object'&&(it.slug||it.id||it.name))||id;run('sk_install',{source:src,id:id,slug:sl},'sk:in:'+idx);}});bindSt(function(){st=rst();if(st.tab)curTab=nt(st.tab);draw();});draw();W.ready&&W.ready();"#;
    wrap_widget_html(body, js)
}

fn mcp_widget_html() -> String {
    let body = concat!(
        "<div class='hd'><div><div class='ttl'>MCP Servers</div><div id='sub' class='sub'>0/0 enabled</div></div>",
        "<button id='ref' class='btn sm sec' type='button'>Refresh</button></div>",
        "<div class='bar'><div id='ais' class='inp' contenteditable='true' role='textbox' data-ph='URL, npx/uvx, or describe MCP...'></div>",
        "<button id='aib' class='btn sm' type='button'>AI Install</button></div>",
        "<div id='list' class='card'></div>",
        "<div id='ed' class='card pad hide'>",
        "<div class='hd mb'><div class='meta nm'>Config: <span id='ed-nm'></span></div>",
        "<button id='ed-x' class='btn sm sec' type='button'>Close</button></div>",
        "<div class='lbl'>Command / URL</div>",
        "<div id='ed-cmd' class='inp' contenteditable='true' role='textbox' data-ph='npx or https://...'></div>",
        "<div class='lbl'>Args (space-separated)</div>",
        "<div id='ed-args' class='inp' contenteditable='true' role='textbox' data-ph='-y @pkg/server'></div>",
        "<div class='lbl'>Env (KEY=VAL or -KEY)</div>",
        "<div id='ed-env' class='inp mono ta' contenteditable='true' role='textbox' data-ph='API_KEY=...&#10;-OLD_KEY'></div>",
        "<div class='acts mt'><button id='ed-sv' class='btn sm' type='button'>Save</button></div>",
        "</div>"
    );
    let js = r#"var st=rst(),editName='',list=$('list'),sub=$('sub'),err=$('err'),ais=$('ais'),ed=$('ed'),edNm=$('ed-nm'),edCmd=$('ed-cmd'),edArgs=$('ed-args'),edEnv=$('ed-env');function srvs(){return Array.isArray(st.servers)?st.servers:(Array.isArray(st.items)?st.items:[]);}function draw(){var arr=srvs(),on=0,h='';for(var i=0;i<arr.length;i++){var s=arr[i]||{};var isOn=('enabled' in s)?!!s.enabled:(String(s.status||'').toLowerCase()==='enabled');if(isOn)on++;h+="<div class='row'><div class='meta'><div class='nmr'><span class='nm'>"+esc(s.name||'mcp')+"</span><span class='bdg'>"+esc(s.type||'stdio')+"</span></div></div><div class='acts'><button class='btn sm sec' type='button' data-ed='"+i+"'>Edit</button><button class='btn sm"+(isOn?'':' sec')+"' type='button' data-tg='"+i+"'>"+(isOn?'On':'Off')+"</button></div></div>";}sub.textContent=on+'/'+arr.length+' enabled';list.innerHTML=h||"<div class='empty'>No MCP servers.</div>";W.ready&&W.ready();}function openEd(i){var s=srvs()[i];if(!s)return;var c=(st.configs&&st.configs[s.name])||s;editName=s.name||'';edNm.textContent=editName;edCmd.textContent=c.url||c.command||'';edArgs.textContent=Array.isArray(c.args)?c.args.join(' '):(c.args||'');var ev=c.env_masked||c.env,el=[];if(ev&&typeof ev==='object'&&!Array.isArray(ev)){for(var k in ev){if(Object.prototype.hasOwnProperty.call(ev,k))el.push(k+'=••••••••');}}else if(Array.isArray(c.env_keys)){for(var j=0;j<c.env_keys.length;j++)el.push(c.env_keys[j]+'=••••••••');}edEnv.textContent=el.join('\n');ed.className='card pad mt';W.ready&&W.ready();}function run(a,p,fb,cb){err.textContent='';act(a,p,fb).then(function(r){st=applyResp(r,st);cb&&cb();draw();},function(e){err.textContent=em(e);});}function doAi(){var sp=val(ais);if(!sp){err.textContent='Enter MCP spec';return;}hap('light');run('mcp_ai_install',{spec:sp},null,function(){ais.textContent='';});}list.addEventListener('click',function(e){var ei=e.target.getAttribute('data-ed'),ti=e.target.getAttribute('data-tg');if(ei!==null){hap('sel');openEd(+ei);return;}if(ti!==null){var s=srvs()[+ti];if(!s)return;hap('light');run('mcp_toggle',{name:s.name},'mcp:t:'+(+ti));}});$('ed-x').addEventListener('click',function(){editName='';ed.className='card pad hide';W.ready&&W.ready();});$('ed-sv').addEventListener('click',function(){if(!editName)return;hap('light');var cu=val(edCmd),isU=/^https?:\/\//i.test(cu),ar=val(edArgs);var args=ar?ar.split(/\s+/):[],env_set={},env_unset=[],lns=val(edEnv).split(/\r?\n/);for(var i=0;i<lns.length;i++){var ln=lns[i].trim();if(!ln)continue;if(ln.charAt(0)==='-'){var uk=ln.slice(1).trim();if(uk)env_unset.push(uk);}else{var eq=ln.indexOf('=');if(eq>0){var ek=ln.slice(0,eq).trim(),evv=ln.slice(eq+1).trim();if(ek&&evv!=='••••••••')env_set[ek]=evv;}}}run('mcp_update',{name:editName,command:isU?'':cu,args:args,url:isU?cu:'',env_set:env_set,env_unset:env_unset},null,function(){editName='';ed.className='card pad hide';});});$('aib').addEventListener('click',doAi);ais.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();doAi();}});$('ref').addEventListener('click',function(){hap('light');run('mcp_refresh',{},'mcp:ref');});bindSt(function(){st=rst();draw();});draw();W.ready&&W.ready();"#;
    wrap_widget_html(body, js)
}

fn models_widget_html() -> String {
    let body = concat!(
        "<div class='hd'><div><div class='ttl'>Models & Reasoning</div><div id='sub' class='sub'>Default</div></div>",
        "<button id='ref' class='btn sm sec' type='button'>Refresh</button></div>",
        "<div class='lbl'>Effort</div><div id='ge' class='pills'></div>",
        "<div class='lbl'>Mode</div><div id='gm' class='pills'></div>",
        "<div class='lbl'>Stream</div><div id='gs' class='pills'></div>",
        "<div class='lbl'>Model</div><div id='ml' class='card'></div>"
    );
    let js = r#"var st=rst(),sub=$('sub'),ge=$('ge'),gm=$('gm'),gs=$('gs'),ml=$('ml'),err=$('err');var EFF=['default','low','medium','high','xhigh','max'],MOD=['auto','accept-edits','plan'],STR=['semi','live','off'];function pills(el,vals,cur,k,fbp){var h='';for(var i=0;i<vals.length;i++){var v=vals[i];h+="<button type='button' class='pill"+(cur===v?' on':'')+"' data-k='"+k+"' data-v='"+v+"' data-fb='"+fbp+v+"'>"+v+"</button>";}el.innerHTML=h;}function draw(){var curM=st.model||'';sub.textContent=st.model_name||curM||'Default';pills(ge,EFF,st.effort||'default','effort','mdl:eff:');pills(gm,MOD,st.mode||'auto','mode','mdl:m:');pills(gs,STR,st.stream_mode||st.stream||'semi','stream_mode','mdl:st:');var arr=Array.isArray(st.models)?st.models:[];var h="<div class='row'><span class='meta nm'>Default</span><button type='button' class='btn sm"+(!curM?'':' sec')+"' data-id=''>"+(!curM?'Active':'Use')+"</button></div>";for(var i=0;i<arr.length;i++){var m=arr[i],id=typeof m==='string'?m:(m.id||m.name||''),nm=typeof m==='string'?m:(m.name||id),on=curM===id&&!!id;h+="<div class='row'><span class='meta nm'>"+esc(nm)+"</span><button type='button' class='btn sm"+(on?'':' sec')+"' data-idx='"+i+"' data-id='"+esc(id)+"'>"+(on?'Active':'Use')+"</button></div>";}ml.innerHTML=h;W.ready&&W.ready();}function send(p,fb){err.textContent='';act('mdl_set',p,fb).then(function(r){st=applyResp(r,st);draw();},function(e){err.textContent=em(e);});}function onPill(e){var k=e.target.getAttribute('data-k');if(!k)return;hap('sel');var p={};p[k]=e.target.getAttribute('data-v');send(p,e.target.getAttribute('data-fb'));}ge.addEventListener('click',onPill);gm.addEventListener('click',onPill);gs.addEventListener('click',onPill);ml.addEventListener('click',function(e){var id=e.target.getAttribute('data-id');if(id===null)return;hap('sel');var idx=e.target.getAttribute('data-idx');send({id:id},idx===null?'mdl:def':'mdl:s:'+idx);});$('ref').addEventListener('click',function(){hap('light');err.textContent='';act('mdl_refresh',{},'mdl:ref').then(function(r){st=applyResp(r,st);draw();},function(e){err.textContent=em(e);});});bindSt(function(){st=rst();draw();});draw();W.ready&&W.ready();"#;
    wrap_widget_html(body, js)
}

fn memory_widget_html() -> String {
    let body = concat!(
        "<div class='hd'><div><div class='ttl'>AI Memory</div><div id='sub' class='sub'>Total: 0 · 24h: 0</div></div>",
        "<div class='acts'><button id='newb' class='btn sm' type='button'>+ New</button>",
        "<button id='ref' class='btn sm sec' type='button'>Refresh</button></div></div>",
        "<div id='comp' class='card pad hide'>",
        "<div id='ntypes' class='pills'></div>",
        "<div id='nttl' class='inp mb' contenteditable='true' role='textbox' data-ph='Title...'></div>",
        "<div id='nsum' class='inp ta mb' contenteditable='true' role='textbox' data-ph='Summary...'></div>",
        "<button id='nsv' class='btn sm' type='button'>Save</button></div>",
        "<div id='ftypes' class='pills'></div>",
        "<div class='bar'><div id='q' class='inp' contenteditable='true' role='textbox' data-ph='Search memories...'></div>",
        "<button id='go' class='btn sm' type='button'>Search</button></div>",
        "<div id='list' class='card'></div>"
    );
    let js = r#"var st=rst(),sub=$('sub'),newb=$('newb'),comp=$('comp'),ntypes=$('ntypes'),ftypes=$('ftypes'),nttl=$('nttl'),nsum=$('nsum'),qEl=$('q'),list=$('list'),err=$('err');var FTYPES=['all','decision','preference','fact','insight'],NTYPES=['decision','preference','fact','insight'];var curType=String(st.type||st.filter||'all').toLowerCase(),newType='decision',openComp=false;if(FTYPES.indexOf(curType)<0)curType='all';if(st.q)qEl.textContent=st.q;function items(){return Array.isArray(st.items)?st.items:(Array.isArray(st.memories)?st.memories:[]);}function pills(el,vals,cur){var h='';for(var i=0;i<vals.length;i++){var v=vals[i];h+="<button type='button' class='pill"+(cur===v?' on':'')+"' data-t='"+v+"'>"+v+"</button>";}el.innerHTML=h;}function draw(){var arr=items(),tot=st.total!=null?st.total:arr.length,h24=st.recent_24h!=null?st.recent_24h:(st.last_24h!=null?st.last_24h:(st.h24||0));sub.textContent='Total: '+tot+' · 24h: '+h24;newb.textContent=openComp?'Close':'+ New';comp.className=openComp?'card pad mb':'card pad hide';pills(ntypes,NTYPES,newType);pills(ftypes,FTYPES,curType);var h='';for(var i=0;i<arr.length;i++){var it=arr[i]||{},c=it.content||{};var tp=it.type||'fact',tl=it.title||c.title||'(untitled)',sm=it.summary||c.summary||'';h+="<div class='row'><div class='meta'><div class='nmr'><span class='bdg'>"+esc(tp)+"</span><span class='nm'>"+esc(tl)+"</span></div>"+(sm?"<div class='ds'>"+esc(sm)+"</div>":'')+"</div><button class='btn sm bad' type='button' data-del='"+i+"'>Delete</button></div>";}list.innerHTML=h||"<div class='empty'>No memories found.</div>";W.ready&&W.ready();}function run(a,p,fb,cb){err.textContent='';act(a,p,fb).then(function(r){st=applyResp(r,st);cb&&cb();draw();},function(e){err.textContent=em(e);});}function search(){run('mem_search',{q:val(qEl),type:curType},'mem:f:'+curType);}newb.addEventListener('click',function(){hap('sel');openComp=!openComp;draw();});ntypes.addEventListener('click',function(e){var t=e.target.getAttribute('data-t');if(!t)return;hap('sel');newType=t;draw();});ftypes.addEventListener('click',function(e){var t=e.target.getAttribute('data-t');if(!t)return;hap('sel');curType=t;draw();search();});$('go').addEventListener('click',function(){hap('light');search();});$('ref').addEventListener('click',function(){hap('light');run('mem_search',{q:val(qEl),type:curType},'mem:ref');});nttl.addEventListener('keydown',function(e){if(e.key==='Enter')e.preventDefault();});qEl.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();search();}});$('nsv').addEventListener('click',function(){var tl=val(nttl),sm=val(nsum);if(!tl||!sm){err.textContent='Title and summary required';return;}hap('light');run('mem_add',{title:tl,summary:sm,type:newType},null,function(){nttl.textContent='';nsum.textContent='';openComp=false;});});list.addEventListener('click',function(e){var di=e.target.getAttribute('data-del');if(di===null)return;var it=items()[+di];if(!it)return;hap('light');run('mem_delete',{id:it.id},'mem:d:'+(+di));});bindSt(function(){st=rst();if(st.type||st.filter)curType=String(st.type||st.filter).toLowerCase();draw();});draw();W.ready&&W.ready();"#;
    wrap_widget_html(body, js)
}

fn telemetry_widget_html() -> String {
    let body = concat!(
        "<div class='hd'><div><div class='ttl'>Quota &amp; Telemetry</div><div id='sub' class='sub'>Loading…</div></div>",
        "<div class='acts'><span id='md' class='bdg'></span>",
        "<button id='ref' class='btn sm sec' type='button'>Refresh</button></div></div>",
        "<div id='sw' class='pills'></div>",
        "<div class='lbl'>Pools (5h / 7d)</div><div id='pools' class='card'></div>",
        "<div class='lbl'>Burn Advisor</div><div id='adv' class='card'></div>"
    );
    let js = r#"var st=rst(),sub=$('sub'),md=$('md'),sw=$('sw'),pools=$('pools'),adv=$('adv'),err=$('err');var ENGS=[['agy','Antigravity'],['grok','Grok'],['gemini_web','Gemini Web'],['uncensored','Venice']];function stIcon(s){return s==='ready'?'OK':(s==='reserved'?'1% RES':(s==='cooldown'?'WAIT':(s==='disabled'?'OFF':'NONE')));}function draw(){var actv=st.act!=null?st.act:0,mx=st.max!=null?st.max:4,st24=st.st24;sub.textContent=(st.why||'Ready')+' · Slots '+actv+'/'+mx+(st24!=null?' · 24h '+st24+' steps':'');md.textContent=st.mlbl||st.mode||'balanced';var cur=st.eng||'agy',sh='';for(var i=0;i<ENGS.length;i++){var e=ENGS[i];sh+="<button type='button' class='pill"+(cur===e[0]?' on':'')+"' data-e='"+e[0]+"'>"+e[1]+"</button>";}sw.innerHTML=sh;var arr=Array.isArray(st.pools)?st.pools:[],ph='';for(var j=0;j<arr.length;j++){var p=arr[j]||{};var meta=(p.w5||'—')+' / '+(p.w7||'—')+(p.inf?' · '+p.inf+' active':'')+(p.px===false?' · PX BLK':'');ph+="<div class='row'><div class='meta'><div class='nmr'><span class='nm'>"+esc(p.lbl||p.id||'pool')+"</span><span class='bdg'>"+esc(stIcon(p.st))+"</span></div><div class='ds mono'>"+esc(meta)+"</div></div></div>";}pools.innerHTML=ph||"<div class='empty'>No pools available.</div>";var al=Array.isArray(st.adv)?st.adv:[],ah='';for(var k=0;k<al.length;k++){var a=al[k]||{};ah+="<div class='row'><div class='meta'><div class='nm'>"+esc(a.t||'Tip')+"</div><div class='ds'>"+esc(a.d||'')+"</div></div></div>";}adv.innerHTML=ah||"<div class='empty'>All pools healthy.</div>";W.ready&&W.ready();}function run(a,p,fb){err.textContent='';act(a,p,fb).then(function(r){st=applyResp(r,st);draw();},function(e){err.textContent=em(e);});}$('ref').addEventListener('click',function(){hap('light');run('tel_refresh',{force:true},'tel:ref');});sw.addEventListener('click',function(e){var en=e.target.getAttribute('data-e');if(!en)return;hap('sel');run('tel_switch',{engine:en},'tel:sw:'+en);});bindSt(function(){st=rst();draw();});draw();W.ready&&W.ready();"#;
    wrap_widget_html(body, js)
}

/// Build one of the 5 official Apple-HIG built-in interactive widgets (`skills`, `mcp`, `models`, `memory`, `telemetry`).
pub fn builtin_widget(kind: &str, initial_state: Option<&Value>) -> Result<WidgetSpec> {
    let k = kind.trim().to_ascii_lowercase();
    let cd = match initial_state {
        Some(v) => encode_widget_data(Some(WidgetData::Value(v)), false)?,
        None => None,
    };

    let (html, caption, slug, handler) = match k.as_str() {
        "skills" => (skills_widget_html(), "Skills Manager", "skills_hub", "skills"),
        "mcp" => (mcp_widget_html(), "MCP Servers", "mcp_hub", "mcp"),
        "models" => (
            models_widget_html(),
            "Models & Reasoning",
            "models_hub",
            "models",
        ),
        "memory" => (memory_widget_html(), "AI Memory", "memory_hub", "memory"),
        "telemetry" => (
            telemetry_widget_html(),
            "Quota & Telemetry",
            "telemetry_hub",
            "telemetry",
        ),
        _ => {
            return Err(BridgeError::Validation(format!(
                "Unknown built-in widget kind: {kind:?}"
            )));
        }
    };

    Ok(WidgetSpec {
        html: Some(html),
        caption: Some(caption.to_string()),
        chat_data: cd,
        allow_queries: Some(true),
        slug: Some(slug.to_string()),
        handler: Some(handler.to_string()),
        ..Default::default()
    })
}

/// Validate `spec` and wrap it into a Bot API 10.4 `InlineQueryResultArticle`.
pub fn build_inline_widget_article(
    result_id: &str,
    title: &str,
    spec: &WidgetSpec,
    description: Option<&str>,
) -> Result<InlineQueryResultArticle> {
    let (norm, _) = validate_widget_spec(spec)?;

    let mut content_val: Value = if let (Some(wid), None) = (&norm.widget_id, &norm.html) {
        if wid.is_empty() {
            return Err(BridgeError::Validation(
                "Inline widget article requires html or resolved widget_id".to_string(),
            ));
        }
        let shared = InputSharedWidgetMessageContent {
            widget_id: wid.clone(),
            chat_data: norm.chat_data.clone(),
            caption: norm.caption.clone(),
            parse_mode: norm.parse_mode.clone(),
        };
        serde_json::to_value(shared)
            .map_err(|e| BridgeError::json("serialize InputSharedWidgetMessageContent", e))?
    } else if let Some(html) = norm.html {
        let direct = InputWidgetMessageContent {
            html,
            width: norm.width,
            height: norm.height,
            public_data: norm.public_data.clone(),
            chat_data: norm.chat_data.clone(),
            caption: norm.caption.clone(),
            parse_mode: norm.parse_mode.clone(),
            allow_queries: norm.allow_queries,
            is_shared: norm.is_shared,
        };
        serde_json::to_value(direct)
            .map_err(|e| BridgeError::json("serialize InputWidgetMessageContent", e))?
    } else {
        return Err(BridgeError::Validation(
            "Inline widget article requires html or resolved widget_id".to_string(),
        ));
    };

    if let Some(obj) = content_val.as_object_mut() {
        if let Some(entities) = norm.caption_entities {
            let ents_val = serde_json::to_value(entities)
                .map_err(|e| BridgeError::json("serialize caption_entities", e))?;
            obj.insert("caption_entities".to_string(), ents_val);
        }
        if let Some(above) = norm.show_caption_above_media {
            obj.insert("show_caption_above_media".to_string(), Value::Bool(above));
        }
    }

    Ok(InlineQueryResultArticle {
        kind: "article".to_string(),
        id: result_id.to_string(),
        title: title.to_string(),
        description: description.map(str::to_string),
        input_message_content: content_val,
        reply_markup: norm.reply_markup,
    })
}

fn safe_json_for_script(obj: &Value) -> Result<String> {
    let raw =
        serde_json::to_string(obj).map_err(|e| BridgeError::json("safe_json_for_script", e))?;
    Ok(raw.replace("</", "<\\/"))
}

/// Format a concise human-readable summary of a widget spec and its size telemetry.
pub fn preview_summary_text(spec: &WidgetSpec) -> String {
    let title = spec
        .caption
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| spec.slug.as_deref().filter(|s| !s.is_empty()))
        .or_else(|| spec.handler.as_deref().filter(|s| !s.is_empty()))
        .unwrap_or("Widget");

    if let Some(ref html) = spec.html {
        let sz = count_widget_size(html);
        format!(
            "{title} · raw {}/{WIDGET_HTML_RAW_LIMIT} B · zlib-9 {}/{WIDGET_HTML_ZLIB_LIMIT} B · {}",
            sz.raw_bytes,
            sz.zlib_bytes,
            if sz.ok { "OK" } else { "OVER LIMIT" }
        )
    } else if let Some(ref wid) = spec.widget_id {
        format!("{title} · shared widget {wid}")
    } else if let Some(ref slug) = spec.slug {
        format!("{title} · slug {slug}")
    } else {
        title.to_string()
    }
}

/// Render a self-contained HTML5 mobile preview shell with a `window.TelegramWidget` polyfill.
pub fn render_standalone_preview_html(spec: &WidgetSpec) -> Result<String> {
    let (norm, _) = validate_widget_spec(spec)?;
    let title_raw = norm
        .caption
        .as_deref()
        .or(norm.slug.as_deref())
        .unwrap_or("Widget Preview");
    let title_text = esc_attr(title_raw);

    let widget_body = match norm.html {
        Some(ref html) => html.clone(),
        None => {
            let shared_ref = norm
                .widget_id
                .as_deref()
                .or(norm.slug.as_deref())
                .unwrap_or("");
            format!(
                r#"<div style="padding:14px;font-family:-apple-system,system-ui,sans-serif;color:var(--tg-theme-text-color)">Shared widget: {}</div>"#,
                esc_attr(shared_ref)
            )
        }
    };

    let frame_w = norm
        .width
        .map_or_else(|| "100%".to_string(), |w| format!("{w}px"));
    let frame_h = norm
        .height
        .map_or_else(|| "240px".to_string(), |h| format!("{h}px"));
    let auto_h = if norm.height.is_some() {
        "false"
    } else {
        "true"
    };

    let payload_obj = json!({
        "html": widget_body,
        "publicData": norm.public_data,
        "chatData": norm.chat_data,
        "isShared": norm.is_shared.unwrap_or(false),
        "allowQueries": norm.allow_queries.unwrap_or(false),
        "autoHeight": norm.height.is_none(),
        "slug": norm.slug,
        "handler": norm.handler,
    });
    let payload_json = safe_json_for_script(&payload_obj)?;

    // Replace structural placeholders first, then __PAYLOAD_JSON__ last to avoid
    // accidental placeholder expansion inside widget HTML or user data.
    let out = PREVIEW_TEMPLATE
        .replace("__TITLE__", &title_text)
        .replace("__FRAME_W__", &frame_w)
        .replace("__FRAME_H__", &frame_h)
        .replace("__AUTO_H__", auto_h)
        .replace("__PAYLOAD_JSON__", &payload_json);
    Ok(out)
}

const PREVIEW_TEMPLATE: &str = r####"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>__TITLE__</title>
<style>
:root {
  color-scheme: light dark;
  --tg-theme-bg-color: #ffffff;
  --tg-theme-text-color: #000000;
  --tg-theme-hint-color: #8e8e93;
  --tg-theme-link-color: #007aff;
  --tg-theme-button-color: #007aff;
  --tg-theme-button-text-color: #ffffff;
  --tg-theme-secondary-bg-color: #f2f2f7;
  --tg-theme-header-bg-color: #f9f9fb;
  --tg-theme-section-bg-color: #ffffff;
  --tg-theme-section-header-text-color: #6d6d72;
  --tg-theme-subtitle-text-color: #8e8e93;
  --tg-theme-destructive-text-color: #ff3b30;
  --tg-theme-accent-text-color: #007aff;
  --tg-theme-section-separator-color: rgba(60,60,67,0.18);
}
html[data-theme="dark"] {
  --tg-theme-bg-color: #1c1c1e;
  --tg-theme-text-color: #ffffff;
  --tg-theme-hint-color: #98989d;
  --tg-theme-link-color: #0a84ff;
  --tg-theme-button-color: #0a84ff;
  --tg-theme-button-text-color: #ffffff;
  --tg-theme-secondary-bg-color: #000000;
  --tg-theme-header-bg-color: #2c2c2e;
  --tg-theme-section-bg-color: #2c2c2e;
  --tg-theme-section-header-text-color: #98989d;
  --tg-theme-subtitle-text-color: #98989d;
  --tg-theme-destructive-text-color: #ff453a;
  --tg-theme-accent-text-color: #0a84ff;
  --tg-theme-section-separator-color: rgba(255,255,255,0.14);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 16px 12px calc(16px + env(safe-area-inset-bottom, 0px));
  background: var(--tg-theme-secondary-bg-color);
  color: var(--tg-theme-text-color);
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif;
}
.shell {
  max-width: 420px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  border-radius: 14px;
  background: var(--tg-theme-section-bg-color);
  border: 1px solid var(--tg-theme-section-separator-color);
}
.topbar h1 {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
}
.topbar small {
  color: var(--tg-theme-hint-color);
  font-size: 11px;
}
.theme-btn {
  border: 0;
  border-radius: 999px;
  padding: 6px 12px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  background: var(--tg-theme-button-color);
  color: var(--tg-theme-button-text-color);
}
.bubble {
  background: var(--tg-theme-bg-color);
  border-radius: 16px;
  overflow: hidden;
  border: 1px solid var(--tg-theme-section-separator-color);
  width: __FRAME_W__;
  max-width: 100%;
}
#tg-preview-frame {
  display: block;
  width: 100%;
  height: __FRAME_H__;
  border: 0;
  background: transparent;
}
.statusbar {
  background: var(--tg-theme-section-bg-color);
  border: 1px solid var(--tg-theme-section-separator-color);
  border-radius: 14px;
  padding: 10px 12px;
  font-size: 11px;
}
.statusbar-hdr {
  display: flex;
  justify-content: space-between;
  color: var(--tg-theme-hint-color);
  margin-bottom: 6px;
  font-weight: 600;
}
#tg-log {
  margin: 0;
  padding: 0;
  list-style: none;
  font-family: "SF Mono", ui-monospace, Menlo, monospace;
  font-size: 11px;
  max-height: 150px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 3px;
}
#tg-log li {
  color: var(--tg-theme-text-color);
  word-break: break-word;
}
</style>
</head>
<body>
<div class="shell">
  <div class="topbar">
    <div>
      <h1>__TITLE__</h1>
      <small>Telegram Widget Profile-1 Preview</small>
    </div>
    <button id="theme-toggle" class="theme-btn" type="button">Dark / Light</button>
  </div>
  <div class="bubble">
    <iframe id="tg-preview-frame" title="Widget Preview"></iframe>
  </div>
  <div class="statusbar">
    <div class="statusbar-hdr"><span>TelegramWidget Bridge Log</span><span id="tg-status-state">Ready</span></div>
    <ul id="tg-log"></ul>
  </div>
</div>
<script id="tg-preview-payload" type="application/json">__PAYLOAD_JSON__</script>
<script>
(function() {
  var payload = JSON.parse(document.getElementById("tg-preview-payload").textContent);
  var logEl = document.getElementById("tg-log");
  var statusEl = document.getElementById("tg-status-state");
  var frame = document.getElementById("tg-preview-frame");
  var listeners = {};
  var watchActive = false;

  var THEMES = {
    light: {
      bg_color: "#ffffff", text_color: "#000000", hint_color: "#8e8e93",
      link_color: "#007aff", button_color: "#007aff", button_text_color: "#ffffff",
      secondary_bg_color: "#f2f2f7", header_bg_color: "#f9f9fb",
      section_bg_color: "#ffffff", section_header_text_color: "#6d6d72",
      subtitle_text_color: "#8e8e93", destructive_text_color: "#ff3b30",
      accent_text_color: "#007aff", section_separator_color: "rgba(60,60,67,0.18)"
    },
    dark: {
      bg_color: "#1c1c1e", text_color: "#ffffff", hint_color: "#98989d",
      link_color: "#0a84ff", button_color: "#0a84ff", button_text_color: "#ffffff",
      secondary_bg_color: "#000000", header_bg_color: "#2c2c2e",
      section_bg_color: "#2c2c2e", section_header_text_color: "#98989d",
      subtitle_text_color: "#98989d", destructive_text_color: "#ff453a",
      accent_text_color: "#0a84ff", section_separator_color: "rgba(255,255,255,0.14)"
    }
  };

  function logCall(kind, detail) {
    var li = document.createElement("li");
    var ts = new Date().toLocaleTimeString();
    li.textContent = "[" + ts + "] " + kind + (detail ? ": " + detail : "");
    logEl.prepend(li);
    statusEl.textContent = kind;
  }

  function emit(ev, data) {
    var arr = listeners[ev] || [];
    for (var i = 0; i < arr.length; i++) {
      try { arr[i](data); } catch (e) {}
    }
  }

  var scheme = (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", scheme);

  var api = {
    profile: 1,
    isProfileAtLeast: function(n) { return 1 >= Number(n || 0); },
    colorScheme: scheme,
    themeParams: Object.assign({}, THEMES[scheme]),
    isActive: true,
    isPreview: false,
    isForward: false,
    chatType: "private",
    viewer: { id: 0, first_name: "Preview", username: "preview_user" },
    publicData: payload.publicData,
    chatData: payload.chatData,
    contentSafeAreaInset: { top: 0, right: 0, bottom: 0, left: 0, cornerLeft: 0, cornerRight: 0 },
    HapticFeedback: {
      impactOccurred: function(s) { logCall("HapticFeedback.impact", s || "light"); return this; },
      notificationOccurred: function(t) { logCall("HapticFeedback.notify", t || "success"); return this; },
      selectionChanged: function() { logCall("HapticFeedback.selection", "changed"); return this; }
    },
    wallet: null,
    watchPublicData: function() {
      watchActive = true;
      logCall("watchPublicData", "active");
    },
    unwatchPublicData: function() {
      watchActive = false;
      logCall("unwatchPublicData", "stopped");
    },
    request: function(data, opts) {
      logCall("request", String(data) + (opts ? " " + JSON.stringify(opts) : ""));
      if (String(data).indexOf("poll:vote:") === 0 && api.publicData) {
        try {
          var idx = parseInt(String(data).split(":")[2], 10);
          var st = JSON.parse(api.publicData);
          if (Array.isArray(st.v) && idx >= 0 && idx < st.v.length) {
            st.v[idx] = (st.v[idx] || 0) + 1;
            st.r = (st.r || 0) + 1;
            api.publicData = JSON.stringify(st);
            if (watchActive) emit("publicDataChanged");
            return Promise.resolve({ result: api.publicData });
          }
        } catch (e) {}
      }
      if (data === "sys:snap") {
        return Promise.resolve({ result: JSON.stringify({
          host: "preview", uptime: "12d 4h", load: "0.24 0.19 0.15",
          cpu_pct: 12, ram_pct: 41, disk_pct: 28, service: "active",
          polling: { updates: 142, errors: 0, latency_ms: 38, mode: "long-poll" }
        }) });
      }
      return Promise.resolve({ result: JSON.stringify({ ok: true, echo: data }) });
    },
    copyText: function(text) {
      logCall("copyText", String(text));
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(String(text)).catch(function() {});
      }
    },
    openLink: function(url) { logCall("openLink", String(url)); },
    openTelegramLink: function(url) { logCall("openTelegramLink", String(url)); },
    setResizeAnchor: function(a) { logCall("setResizeAnchor", String(a)); },
    ready: function() { logCall("ready", "widget ready"); },
    onEvent: function(ev, cb) {
      if (!listeners[ev]) listeners[ev] = [];
      listeners[ev].push(cb);
    },
    offEvent: function(ev, cb) {
      if (!listeners[ev]) return;
      listeners[ev] = listeners[ev].filter(function(f) { return f !== cb; });
    }
  };
  window.TelegramWidget = api;

  function applyThemeToDoc(doc, s) {
    if (!doc || !doc.documentElement) return;
    doc.documentElement.style.colorScheme = s;
    var p = THEMES[s];
    for (var k in p) {
      doc.documentElement.style.setProperty("--tg-theme-" + k.replace(/_/g, "-"), p[k]);
    }
  }

  function syncSize() {
    if (!__AUTO_H__) return;
    try {
      var b = frame.contentDocument && frame.contentDocument.body;
      if (b) {
        var h = Math.max(50, Math.min(600, b.scrollHeight || 160));
        frame.style.height = h + "px";
      }
    } catch (e) {}
  }

  document.getElementById("theme-toggle").addEventListener("click", function() {
    scheme = scheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", scheme);
    api.colorScheme = scheme;
    api.themeParams = Object.assign({}, THEMES[scheme]);
    applyThemeToDoc(frame.contentDocument, scheme);
    emit("themeChanged", { colorScheme: scheme, themeParams: api.themeParams });
    logCall("themeChanged", scheme);
  });

  var fdoc = frame.contentDocument || frame.contentWindow.document;
  var inject = "<style>html,body{margin:0;padding:0;background:transparent;}</style>" +
    "<script>window.TelegramWidget=window.parent.TelegramWidget;<\/script>";
  var docHtml = /<head\b[^>]*>/i.test(payload.html)
    ? payload.html.replace(/<head\b[^>]*>/i, function(m) { return m + inject; })
    : "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" + inject + "</head><body>" + payload.html + "</body></html>";
  fdoc.open();
  fdoc.write(docHtml);
  fdoc.close();
  applyThemeToDoc(fdoc, scheme);
  setTimeout(syncSize, 40);
  setTimeout(syncSize, 250);
})();
</script>
</body>
</html>"####;

/// Alias for [`render_standalone_preview_html`].
pub fn render_preview_html(spec: &WidgetSpec) -> Result<String> {
    render_standalone_preview_html(spec)
}
