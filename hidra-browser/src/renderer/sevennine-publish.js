// Injected into the SevenNine page (127.0.0.1:8084) by the HidraNet browser.
// Adds a "Publicar na rede" button to each site, encrypting + storing the site
// on the public relay (MQTT retained) so it's reachable from any network by its
// secret .hidra address. Runs in the trusted browser process — no engine rebuild.
(function(){
  if (window.__hnetPub) return; window.__hnetPub = true;
  var enc = new TextEncoder();
  var BROKER = 'wss://broker.emqx.io:8084/mqtt';
  var client = null, ready = false;

  // ── crypto (mesmo esquema do visualizador de sites) ──
  function b32(bytes){ var A='abcdefghijklmnopqrstuvwxyz234567',o='',bits=0,v=0; for(var i=0;i<bytes.length;i++){ v=(v<<8)|bytes[i]; bits+=8; while(bits>=5){ o+=A[(v>>>(bits-5))&31]; bits-=5; } } if(bits>0) o+=A[(v<<(5-bits))&31]; return o; }
  function newAddr(){ return b32(crypto.getRandomValues(new Uint8Array(16)))+'.hidra'; }
  async function deriveKey(a){ var km=await crypto.subtle.importKey('raw',enc.encode(a),'PBKDF2',false,['deriveKey']); return crypto.subtle.deriveKey({name:'PBKDF2',salt:enc.encode('hidra-site-v1'),iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['encrypt','decrypt']); }
  async function siteTopic(a){ var b=await crypto.subtle.digest('SHA-256',enc.encode('hidra-site-topic:'+a)); var u=new Uint8Array(b),h=''; for(var i=0;i<16;i++) h+=u[i].toString(16).padStart(2,'0'); return 'hsite/'+h; }
  async function E(k,t){ var iv=crypto.getRandomValues(new Uint8Array(12)); var c=await crypto.subtle.encrypt({name:'AES-GCM',iv:iv},k,enc.encode(t)); var o=new Uint8Array(12+c.byteLength); o.set(iv); o.set(new Uint8Array(c),12); var s=''; for(var i=0;i<o.length;i++) s+=String.fromCharCode(o[i]); return btoa(s); }

  function loadMqtt(cb){ if(window.mqtt) return cb(); var s=document.createElement('script'); s.src='https://unpkg.com/mqtt@5/dist/mqtt.min.js'; s.onload=cb; s.onerror=function(){ var s2=document.createElement('script'); s2.src='https://cdn.jsdelivr.net/npm/mqtt@5/dist/mqtt.min.js'; s2.onload=cb; document.head.appendChild(s2); }; document.head.appendChild(s); }
  function mqttConnect(){ try{ client=mqtt.connect(BROKER,{clientId:'hnetsn_'+Math.floor(Math.random()*1e9),clean:true,reconnectPeriod:4000,keepalive:30}); client.on('connect',function(){ ready=true; republishAll(); }); }catch(e){} }

  function getAddrs(){ try{ return JSON.parse(localStorage.getItem('hnet_site_addrs')||'{}'); }catch(e){ return {}; } }
  function setAddr(name,addr){ var m=getAddrs(); m[name]=addr; try{ localStorage.setItem('hnet_site_addrs',JSON.stringify(m)); }catch(e){} }

  async function fetchBundle(name){
    var bundle={};
    bundle['index.html']=await fetch('/sites/'+name+'/').then(function(r){return r.text();});
    try{
      var d=await fetch('/api/sites').then(function(r){return r.json();});
      if(d&&d.ok&&d.sites){ var s=d.sites.filter(function(x){return x.name===name;})[0];
        if(s&&s.files){ for(var i=0;i<s.files.length;i++){ var f=s.files[i]; if(f!=='index.html'&&/\.html$/i.test(f)){ try{ bundle[f]=await fetch('/sites/'+name+'/'+f).then(function(r){return r.text();}); }catch(e){} } } } }
    }catch(e){}
    return bundle;
  }
  async function publish(name){
    if(!ready){ showResult(null,'Conectando à rede… aguarde alguns segundos e tente de novo.'); return; }
    var addrs=getAddrs(); var addr=addrs[name]||newAddr();
    var bundle=await fetchBundle(name);
    var key=await deriveKey(addr), top=await siteTopic(addr);
    var ct=await E(key, JSON.stringify(bundle));
    if(ct.length>900000){ showResult(null,'Este site é grande demais para a rede pública (máx ~600 KB). Reduza imagens/conteúdo.'); return; }
    client.publish(top, ct, {qos:0, retain:true});
    setAddr(name, addr);
    showResult(addr, null);
  }
  async function republishAll(){
    var addrs=getAddrs();
    for(var name in addrs){ try{ var bundle=await fetchBundle(name); var key=await deriveKey(addrs[name]), top=await siteTopic(addrs[name]); var ct=await E(key, JSON.stringify(bundle)); if(ct.length<=900000) client.publish(top, ct, {qos:0, retain:true}); }catch(e){} }
  }
  setInterval(function(){ if(ready) republishAll(); }, 60000);

  // ── injeta o botão por site ──
  function siteNameOf(item){
    var b=item.querySelector('[onclick^="openEditor"]');
    if(b){ var m=/openEditor\(['"]([^'"]+)['"]/.exec(b.getAttribute('onclick')); if(m) return m[1]; }
    var n=item.querySelector('.site-name'); return n?n.textContent.replace('.hidra','').trim():null;
  }
  function addButtons(){
    var items=document.querySelectorAll('#sites-list .site-item');
    for(var i=0;i<items.length;i++){
      var item=items[i]; var actions=item.querySelector('.site-actions');
      if(!actions||actions.querySelector('.hnet-pub')) continue;
      var name=siteNameOf(item); if(!name) continue;
      (function(name){
        var btn=document.createElement('button');
        btn.className='btn btn-primary btn-sm hnet-pub'; btn.type='button';
        btn.textContent='🌐 Publicar na rede';
        btn.onclick=function(e){ e.preventDefault(); btn.disabled=true; var t=btn.textContent; btn.textContent='⏳ Publicando…';
          Promise.resolve(publish(name)).catch(function(){}).then(function(){ btn.disabled=false; btn.textContent=t; }); };
        actions.insertBefore(btn, actions.firstChild);
      })(name);
    }
  }
  var mo=new MutationObserver(function(){ addButtons(); });
  mo.observe(document.documentElement,{childList:true,subtree:true});

  function showResult(addr, errMsg){
    var old=document.getElementById('hnet-modal'); if(old) old.remove();
    var m=document.createElement('div'); m.id='hnet-modal';
    m.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:99999;display:flex;align-items:center;justify-content:center;font-family:-apple-system,sans-serif';
    var inner;
    if(addr){
      var url='http://127.0.0.1:8090/site?addr='+encodeURIComponent(addr);
      inner='<div style="font-size:1.15em;font-weight:800;color:#00d4aa;margin-bottom:8px">🌐 Site publicado na rede!</div>'+
        '<div style="color:#9aa3bd;font-size:.88em;margin-bottom:14px;line-height:1.5">Compartilhe este endereço secreto. Qualquer pessoa, em qualquer rede, acessa digitando ele na barra do HidraNet. O conteúdo vai criptografado.</div>'+
        '<div style="display:flex;gap:8px;align-items:center;background:#0a0d16;border:1px solid #1c2133;border-radius:9px;padding:12px 14px;margin-bottom:14px"><code id="hnet-addr" style="flex:1;color:#00d4aa;word-break:break-all;font-size:.95em;font-family:monospace">'+addr+'</code><button id="hnet-copy" style="background:none;border:none;color:#9aa3bd;cursor:pointer;font-size:1.15em">⧉</button></div>'+
        '<div style="display:flex;gap:8px"><a href="'+url+'" target="_blank" style="flex:1;text-align:center;background:#00d4aa;color:#04120e;padding:11px;border-radius:9px;text-decoration:none;font-weight:700">Abrir o site</a><button id="hnet-close" style="background:#161a2b;color:#e9ecf5;border:1px solid #1c2133;padding:11px 20px;border-radius:9px;cursor:pointer">Fechar</button></div>'+
        '<div style="color:#5b6480;font-size:.75em;margin-top:13px;line-height:1.5">⚠️ Deixe o HidraNet aberto pra manter o site no ar — ele é re-publicado sozinho a cada minuto.</div>';
    } else {
      inner='<div style="font-size:1.05em;font-weight:700;color:#ff5c6c;margin-bottom:10px">Atenção</div><div style="color:#9aa3bd;font-size:.9em;margin-bottom:16px;line-height:1.5">'+(errMsg||'Erro ao publicar.')+'</div><div style="text-align:right"><button id="hnet-close" style="background:#161a2b;color:#e9ecf5;border:1px solid #1c2133;padding:10px 18px;border-radius:8px;cursor:pointer">Fechar</button></div>';
    }
    var box=document.createElement('div'); box.style.cssText='background:#10131f;border:1px solid #1c2133;border-radius:16px;padding:26px;max-width:470px;width:90%;box-shadow:0 24px 70px rgba(0,0,0,.55)'; box.innerHTML=inner;
    m.appendChild(box); document.body.appendChild(m);
    var close=function(){ m.remove(); };
    m.addEventListener('click',function(e){ if(e.target===m) close(); });
    var c=document.getElementById('hnet-close'); if(c) c.onclick=close;
    var cp=document.getElementById('hnet-copy'); if(cp) cp.onclick=function(){ if(navigator.clipboard) navigator.clipboard.writeText(addr); cp.textContent='✓'; setTimeout(function(){cp.textContent='⧉';},1500); };
  }

  loadMqtt(function(){ mqttConnect(); addButtons(); });
})();
