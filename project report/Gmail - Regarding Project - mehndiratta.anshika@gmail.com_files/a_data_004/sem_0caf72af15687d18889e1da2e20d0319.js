(function(){try{var h=true,j=null,k=false;window.gbar.tev&&window.gbar.tev(3,"m");var aa=this,ba=function(a){var b=typeof a;if(b=="object")if(a){if(a instanceof Array)return"array";else if(a instanceof Object)return b;var c=Object.prototype.toString.call(a);if(c=="[object Window]")return"object";if(c=="[object Array]"||typeof a.length=="number"&&typeof a.splice!="undefined"&&typeof a.propertyIsEnumerable!="undefined"&&!a.propertyIsEnumerable("splice"))return"array";if(c=="[object Function]"||typeof a.call!="undefined"&&typeof a.propertyIsEnumerable!="undefined"&&!a.propertyIsEnumerable("call"))return"function"}else return"null";
else if(b=="function"&&typeof a.call=="undefined")return"object";return b},fa=function(a){return a.call.apply(a.bind,arguments)},ga=function(a,b){if(!a)throw Error();if(arguments.length>2){var c=Array.prototype.slice.call(arguments,2);return function(){var d=Array.prototype.slice.call(arguments);Array.prototype.unshift.apply(d,c);return a.apply(b,d)}}else return function(){return a.apply(b,arguments)}},l=function(){l=Function.prototype.bind&&Function.prototype.bind.toString().indexOf("native code")!=
-1?fa:ga;return l.apply(j,arguments)},m=function(a){var b=Array.prototype.slice.call(arguments,1);return function(){var c=Array.prototype.slice.call(arguments);c.unshift.apply(c,b);return a.apply(this,c)}},o=function(a,b){var c=a.split("."),d=aa;!(c[0]in d)&&d.execScript&&d.execScript("var "+c[0]);for(var e;c.length&&(e=c.shift());)if(!c.length&&b!==undefined)d[e]=b;else d=d[e]?d[e]:d[e]={}};var ha=function(){};(function(a){a.N=function(){return a.O||(a.O=new a)}})(ha);var p=j;var r={$:1,ca:2,ma:3,W:4,G:5,D:6,aa:7,F:8,qa:9,la:10,ea:11,ka:12,ja:13,fa:14,ia:15,ha:16,oa:17,Y:18,ga:19,pa:20,na:21,X:22,ba:23,sa:24,ta:25,ra:26,Z:27,da:500};var s=window.gbar;var t={v:1,V:2,U:3,A:4,z:5,C:6,B:7,w:8};var w=[],B=j,C=function(a,b){var c=j;if(b)c={m:b};s.tev&&s.tev(a,"m",c)};var E=function(a){E[" "](a);return a};E[" "]=function(){};var F=function(a,b,c){var d={};d._sn=["m",b,c].join(".");s.logger.ml(a,d)};var G,oa=function(){G=/MSIE (\d+)\.(\d+);/.exec(navigator.userAgent);ia();o("gbar.addHover",ja);o("gbar.close",ka);o("gbar.cls",la);o("gbar.tg",ma);s.adh("gbd4",function(){na(r.G,!H)});s.adh("gbd5",function(){na(r.D,!H)})},J="",H=undefined,K=undefined,L=undefined,pa=undefined,qa=k,M=undefined,ra=["gbzt","gbgt","gbg0l","gbmt","gbml1","gbqfb","gbqfqw"],N=function(a,b,c,d){var e="on"+b;if(a.addEventListener)a.addEventListener(b,c,!!d);else if(a.attachEvent)a.attachEvent(e,c);else{var f=a[e];a[e]=function(){var g=
f.apply(this,arguments),i=c.apply(this,arguments);return g==undefined?i:i==undefined?g:i&&g}}},O=function(a){return document.getElementById(a)},sa=function(a){var b={};if(a.style.display!="none"){b.width=a.offsetWidth;b.height=a.offsetHeight;return b}var c=a.style,d=c.display,e=c.visibility,f=c.position;c.visibility="hidden";c.position="absolute";c.display="inline";var g;g=a.offsetWidth;a=a.offsetHeight;c.display=d;c.position=f;c.visibility=e;b.width=g;b.height=a;return b},ta=function(a){if(L===undefined){var b=
document.body.style;L=!(b.WebkitBoxShadow!==undefined||b.MozBoxShadow!==undefined||b.boxShadow!==undefined||b.BoxShadow!==undefined)}if(L){b=a.id+"-gbxms";var c=O(b);if(!c){c=document.createElement("span");c.id=b;c.className="gbxms";a.appendChild(c)}if(pa===undefined)pa=c.offsetHeight<a.offsetHeight/2;if(pa){c.style.height=a.offsetHeight-5+"px";c.style.width=a.offsetWidth-3+"px"}}},ua=function(a,b){if(a){var c=a.style,d=b||O(J);if(d){a.parentNode&&a.parentNode.appendChild(d);d=d.style;d.width=a.offsetWidth+
"px";d.height=a.offsetHeight+"px";d.top="32px";d.left=c.left;d.right=c.right}}},Q=function(){try{if(H){var a=O(J);if(a)a.style.visibility="hidden";var b=O(H);if(b){b.style.visibility="hidden";var c=b.getAttribute("aria-owner"),d=c?O(c):j;if(d){P(d.parentNode,"gbto");d.blur()}}if(K){K();K=undefined}var e=s.ch[H];if(e){a=0;for(var f;f=e[a];a++)try{f()}catch(g){F(g,"sb","cdd1")}}H=undefined}}catch(i){F(i,"sb","cdd2")}},na=function(a,b){var c={s:b?"o":"c"};a!=-1&&s.logger.il(a,c)},U=function(a,b){var c=
a.className;T(a,b)||(a.className+=(c!=""?" ":"")+b)},P=function(a,b){var c=a.className,d=RegExp("\\s?\\b"+b+"\\b");if(c&&c.match(d))a.className=c.replace(d,"")},T=function(a,b){var c=a.className;return!!(c&&c.match(RegExp("\\b"+b+"\\b")))},ma=function(a,b,c){try{a=a||window.event;c=c||k;if(!J){var d=document.createElement("iframe");d.frameBorder="0";J=d.id="gbs";d.src="javascript:''";O("gbw").appendChild(d)}if(!qa){N(document,"click",ka);N(document,"keyup",va);qa=h}if(!c){a.preventDefault&&a.preventDefault();
a.returnValue=k;a.cancelBubble=h}if(!b){b=a.target||a.srcElement;for(var e=b.parentNode.id;!T(b.parentNode,"gbt");){if(e=="gb")return;b=b.parentNode;e=b.parentNode.id}}var f=b.getAttribute("aria-owns");if(f.length){b.focus();if(H==f)la(f);else{var g=b.offsetWidth;a=0;do a+=b.offsetLeft||0;while(b=b.offsetParent);if(M===undefined){var i=document.body,u,D=document.defaultView;if(D&&D.getComputedStyle){var v=D.getComputedStyle(i,"");if(v)u=v.direction}else u=i.currentStyle?i.currentStyle.direction:i.style.direction;
M=u=="rtl"}b=M?k:h;i=M?k:h;if(f=="gbd")i=!i;var q=O("gb");q&&M&&U(q,"gbrtl");H&&Q();var n=s.bh[f];if(n)for(var y=0,z;z=n[y];y++)try{z()}catch(ca){F(ca,"sb","t1")}q=a;n=i;var x=O(f);if(x){var A=x.style,R=x.offsetWidth;if(R<g){A.width=g+"px";R=g;var xa=x.offsetWidth;if(xa!=g)A.width=g-(xa-g)+"px"}var S,I,da=document.documentElement&&document.documentElement.clientWidth?document.documentElement.clientWidth:document.body.clientWidth;if(n){S=b?Math.max(da-q-R,5):da-q-g;I=-(da-q-g-S);if(G&&G.length>1){var ya=
new Number(G[1]);if(ya==6||ya==7&&document.compatMode=="BackCompat")I-=2}}else{S=b?q:Math.max(q+g-R,5);I=S-q}var za=O("gbw"),Aa=O("gb");if(za&&Aa){var Ba=za.offsetLeft;if(Ba!=Aa.offsetLeft)I-=Ba}ta(x);A.top="32px";A.right=n?I+"px":"auto";A.left=n?"auto":I+"px";A.visibility="visible";var Ca=x.getAttribute("aria-owner"),Da=Ca?O(Ca):j;Da&&U(Da.parentNode,"gbto");var ea=O(J);if(ea){ua(x,ea);ea.style.visibility="visible"}H=f}var Ea=s.dh[f];if(Ea)for(y=0;z=Ea[y];y++)try{z()}catch(ab){F(ab,"sb","t2")}}}}catch(bb){F(bb,
"sb","t3")}},va=function(a){if(H)try{a=a||window.event;var b=a.target||a.srcElement;if(a.keyCode&&b)if(a.keyCode&&a.keyCode==27)Q();else if(b.tagName.toLowerCase()=="a"&&b.className.indexOf("gbgt")!=-1&&(a.keyCode==13||a.keyCode==3)){var c=document.getElementById(H);if(c){var d=c.getElementsByTagName("a");d&&d.length&&d[0].focus&&d[0].focus()}}}catch(e){F(e,"sb","kuh")}},ia=function(){var a=O("gb");if(a){P(a,"gbpdjs");var b=a.getElementsByTagName("a");a=[];for(var c=O("gbqfw"),d=0,e;e=b[d];d++)a.push(e);
if(c){b=O("gbqfqw");d=c.getElementsByTagName("button");c=[];b&&c.push(b);if(d&&d.length>0)for(b=0;e=d[b];b++)c.push(e);for(d=0;b=c[d];d++)a.push(b)}for(d=0;c=a[d];d++)(b=wa(c))&&Fa(c,m(Ga,b))}},ja=function(a){var b=wa(a);b&&Fa(a,m(Ga,b))},wa=function(a){for(var b=0,c;c=ra[b];b++)if(T(a,c))return c},Fa=function(a,b){var c=function(d,e){return function(f){try{f=f||window.event;var g;var i=f.relatedTarget,u;b:{try{E(i.parentNode);u=h;break b}catch(D){}u=k}g=u?i:j;var v;if(!(v=d===g))if(d===g)v=k;else{for(;g&&
g!==d;)g=g.parentNode;v=g===d}v||e(f,d)}catch(q){F(q,"sb","bhe")}}}(a,b);N(a,"mouseover",c);N(a,"mouseout",c)},Ga=function(a,b,c){try{a+="-hvr";if(b.type=="mouseover"){U(c,a);var d=document.activeElement;if(d){var e=T(d,"gbgt")||T(d,"gbzt"),f=T(c,"gbgt")||T(c,"gbzt");e&&f&&d.blur()}}else b.type=="mouseout"&&P(c,a)}catch(g){F(g,"sb","moaoh")}},V=function(a){for(;a&&a.hasChildNodes();)a.removeChild(a.firstChild)},ka=function(){Q()},la=function(a){a==H&&Q()},W=function(a,b){var c=document.createElement(a);
c.className=b;return c},Ha=function(a){if(a&&a.style.visibility=="visible"){ta(a);ua(a)}};w.push(["base",{init:function(a){oa(a)}}]);var X=function(a){o("gbar.pcm",l(this.I,this));o("gbar.paa",l(this.H,this));o("gbar.prm",l(this.R,this));o("gbar.pge",l(this.k,this));o("gbar.ppe",l(this.o,this));o("gbar.spn",l(this.S,this));o("gbar.spp",l(this.T,this));this.t=this.c=this.h=k;this.K=a.mg||"%1$s";this.J=a.md||"%1$s";this.M=a.g;this.ua=a.d;this.a=a.e;this.b=a.p;this.L=a.m;var b=O("gbmpn");if(b&&(b.firstChild&&b.firstChild.nodeValue?b.firstChild.nodeValue:"")==this.a){b=this.a.indexOf("@");b>=0&&Ia(this,this.a.substring(0,b))}(b=O("gbi4i"))&&
b.loadError&&this.k();(b=O("gbmpi"))&&b.loadError&&this.o();if(!this.h){b=O("gbd4");var c=O("gbmp2"),d=O("gbmpsb");b&&N(b,"click",l(this.P,this),h);if(c&&d){N(c,"click",l(this.u,this));N(d,"click",l(this.u,this))}this.h=h}if(this.M){b=O("gbpm");c=O("gbpms");if(b&&c){var e=c.innerHTML.split("%1$s");if(e.length==2){d=document.createTextNode(e[0]);e=document.createTextNode(e[1]);var f=W("span","gbpms2"),g=document.createTextNode(this.L);V(c);f.appendChild(g);c.appendChild(d);c.appendChild(f);c.appendChild(e);
b.style.display=""}}}if(a.xp){a=O("gbg4");b=O("gbg6");a&&N(a,"mouseover",l(this.r,this));b&&N(b,"mouseover",l(this.r,this))}};X.prototype.P=function(a){try{if(H)for(var b=a.target||a.srcElement;b.tagName.toLowerCase()!="a";){if(b.id=="gbd4"){a.cancelBubble=h;return b}b=b.parentNode}}catch(c){F(c,"sp","kdo")}return j};
X.prototype.u=function(a){try{a=a||window.event;a.cancelBubble=h;a.stopPropagation&&a.stopPropagation();a.preventDefault&&a.preventDefault();var b=O("gbmps");if(b){var c=b.style.display=="none";try{var d=O("gbd4"),e=O("gbmps"),f=O("gbmpdv");if(d&&e&&f){f.style.display=c?"none":"";e.style.display=c?"":"none";Ha(d)}}catch(g){F(g,"sp","tav")}}}catch(i){F(i,"sp","tave")}return k};X.prototype.I=function(){try{var a=O("gbmpas");a&&V(a);this.c=k}catch(b){F(b,"sp","cam")}};
X.prototype.R=function(){var a=O("gbmpdv"),b=O("gbmps");if(a&&b){a.style.display="";b.style.display="none";if(!this.c){var c=O("gbmpal"),d=O("gbpm");if(c){a.style.width="";b.style.width="";c.style.width="";if(d)d.style.width="1px";var e=sa(a).width,f=sa(b).width;e=e>f?e:f;if(f=O("gbg4")){f=sa(f).width;if(f>e)e=f}if(G&&G.length>1){f=new Number(G[1]);if(f==6||f==7&&document.compatMode=="BackCompat")e+=2}e+="px";a.style.width=e;b.style.width=e;c.style.width=e;if(d)d.style.width=e;this.c=h}}}};
X.prototype.H=function(a,b,c,d,e,f,g,i){try{var u=O("gbmpas");if(u){var D="gbmtc";if(a)D+=" gbmpmta";var v=W("div",D),q=W("div","gbmpph");v.appendChild(q);var n=W(f?"a":"span","gbmpl");U(n,"gbmt");if(f){if(i)for(var y in i)n.setAttribute(y,i[y]);n.href=g;Fa(n,m(Ga,"gbmt"))}v.appendChild(n);var z=W("span","gbmpmn");n.appendChild(z);z.appendChild(document.createTextNode(d||e));if(a){var ca=W("span","gbmpmtc");z.appendChild(ca)}var x=W("span","gbmpme");n.appendChild(x);a=e;if(b)a=this.J.replace("%1$s",
e);else if(c)a=this.K.replace("%1$s",e);x.appendChild(document.createTextNode(a));u.appendChild(v)}}catch(A){F(A,"sp","aa")}};var Ia=function(a,b){var c=O("gbd4"),d=O("gbmpn");if(c&&d){V(d);d.appendChild(document.createTextNode(b));Ha(c)}};X.prototype.k=function(){try{Ja(this,"gbi4i","gbi4id")}catch(a){F(a,"sp","gbpe")}};X.prototype.o=function(){try{Ja(this,"gbmpi","gbmpid")}catch(a){F(a,"sp","ppe")}};var Ja=function(a,b,c){if(a=O(b))a.style.display="none";if(c=O(c))c.style.display=""};
X.prototype.r=function(){try{if(!this.t){this.t=h;var a=O("gbmpi");if(a&&this.b)a.src=this.b}}catch(b){F(b,"sp","spp")}};X.prototype.S=function(a){try{var b=O("gbi4t");(O("gbmpn").firstChild&&O("gbmpn").firstChild.nodeValue?O("gbmpn").firstChild.nodeValue:"")==this.a||Ia(this,a);if((b.firstChild&&b.firstChild.nodeValue?b.firstChild.nodeValue:"")!=this.a){V(b);b.appendChild(document.createTextNode(a))}}catch(c){F(c,"sp","spn")}};
X.prototype.T=function(a){try{var b=O("gbmpi"),c=O("gbi4i");this.b=a(96);if(b)b.src=a(96);if(c)c.src=a(24)}catch(d){F(d,"sp","spp")}};w.push(["prf",{init:function(a){new X(a)}}]);w.push(["il",{init:function(){ha.N();var a=r.F,b;if(!p){a:{b="gbar.logger".split(".");for(var c=aa,d;d=b.shift();)if(c[d]!=j)c=c[d];else{b=j;break a}b=c}p=b||{}}b=p;ba(b.il)=="function"&&b.il(a,void 0)}}]);var Na=function(a,b){if(window.gbar.logger._itl(b))return b;var c=a.stack;if(c){c=c.replace(/\s*$/,"").split("\n");for(var d=[],e=0;e<c.length;e++)d.push(Ka(c[e]));c=d}else c=La();d=c;e=0;for(var f=d.length-1,g=0;g<=f;g++)if(d[g]&&d[g].name.indexOf("_mlToken")>=0){e=g+1;break}e==0&&f--;c=[];for(g=e;g<=f;g++)d[g]&&!(d[g].name.indexOf("_onErrorToken")>=0)&&c.push("> "+Ma(d[g]));d=[b,"&jsst=",c.join("")];e=d.join("");if(!window.gbar.logger._itl(e))return e;if(c.length>2){d[2]=c[0]+"..."+c[c.length-1];
e=d.join("");if(!window.gbar.logger._itl(e))return e}return b};w.push(["er",{init:function(){window.gbar.logger._aem=Na}}]);var Ka=function(a){var b=a.match(Oa);if(b)return new Pa(b[1]||"",b[2]||"",b[3]||"","",b[4]||b[5]||"");if(b=a.match(Qa))return new Pa("",b[1]||"","",b[2]||"",b[3]||"");return j},Oa=RegExp("^    at(?: (?:(.*?)\\.)?((?:new )?(?:[a-zA-Z_$][\\w$]*|<anonymous>))(?: \\[as ([a-zA-Z_$][\\w$]*)\\])?)? (?:\\(unknown source\\)|\\(native\\)|\\((?:eval at )?((?:http|https|file)://[^\\s)]+|javascript:.*)\\)|((?:http|https|file)://[^\\s)]+|javascript:.*))$"),Qa=/^([a-zA-Z_$][\w$]*)?(\(.*\))?@(?::0|((?:http|https|file):\/\/[^\s)]+|javascript:.*))$/,
La=function(){for(var a=[],b=arguments.callee.caller,c=0;b&&c<20;){var d;d=(d=Function.prototype.toString.call(b).match(Ra))?d[1]:"";var e=b,f=["("];if(e.arguments)for(var g=0;g<e.arguments.length;g++){var i=e.arguments[g];g>0&&f.push(", ");typeof i=="string"?f.push('"',i,'"'):f.push(String(i))}else f.push("unknown");f.push(")");a.push(new Pa("",d,"",f.join(""),""));try{if(b==b.caller)break;b=b.caller}catch(u){break}c++}return a},Ra=/^function ([a-zA-Z_$][\w$]*)/,Pa=function(a,b,c,d,e){this.i=a;this.name=
b;this.f=c;this.Q=d;this.n=e},Ma=function(a){var b=[a.i?a.i+".":"",a.name?a.name:"anonymous",a.Q,a.f?" [as "+a.f+"]":""];if(a.n){b.push(" at ");b.push(a.n)}a=b.join("");for(b=window.location.href.replace(/#.*/,"");a.indexOf(b)>=0;)a=a.replace(b,"[page]");return a=a.replace(/http.*?extern_js.*?\.js/g,"[xjs]")};var Ua=function(){this.j=k;var a=document.getElementById("gbqfq");if(a&&!this.j){N(a,"focus",Sa);N(a,"blur",Ta);this.j=h}},Sa=function(){var a=document.getElementById("gbqfqw");a&&U(a,"gbqfqwf")},Ta=function(){var a=document.getElementById("gbqfqw");a&&P(a,"gbqfqwf")};w.push(["sf",{init:function(a){new Ua(a)}}]);C(t.w);C(t.A);var Va,Y;for(Va=0;Y=s.bnc[Va];++Va)if(Y[0]=="m")break;
if(Y&&!Y[1].l){for(var Wa=s.mdc,Xa=s.mdi||{},Ya=0,Za;Za=w[Ya];++Ya){var Z=Za[0],$a=Wa[Z],cb=Xa[Z],db;if(db=$a){var eb;if(eb=!cb){var fb;a:{var gb=Z,hb=s.mdd;if(hb)try{if(!B){B={};for(var ib=hb.split(/;/),jb=0;jb<ib.length;++jb)B[ib[jb]]=h}fb=B[gb];break a}catch(kb){s.logger&&s.logger.ml(kb)}fb=k}eb=!fb}db=eb}if(db){C(t.C,Z);try{Za[1].init($a);Xa[Z]=h}catch(lb){s.logger&&s.logger.ml(lb)}C(t.B,Z)}}var mb=s.qd.m;if(mb){s.qd.m=[];for(var nb=0,ob;ob=mb[nb];++nb)try{ob()}catch(pb){s.logger&&s.logger.ml(pb)}}Y[1].l=
h;C(t.z);var qb;a:{for(var rb=0,$;$=s.bnc[rb];++rb)if(($[1].auto||$[0]=="m")&&!$[1].l){qb=k;break a}qb=h}qb&&C(t.v)};}catch(e){window.gbar&&gbar.logger&&gbar.logger.ml(e,{"_sn":"m.init"});}})();
