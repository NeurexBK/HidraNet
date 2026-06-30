const { app, BrowserWindow } = require('electron');
const fs=require('fs'), path=require('path');
app.commandLine.appendSwitch('disable-gpu');
const OUT=path.join(process.cwd(),'forum.out'); const w=s=>{try{fs.appendFileSync(OUT,s+'\n')}catch(e){}};
fs.writeFileSync(OUT,'inicio\n');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const RUN=Math.floor(Math.random()*1e6);
const file=path.join('src','ui','forum.html');
app.on('window-all-closed', e=>{ e.preventDefault(); });
function mk(part){ return new BrowserWindow({show:false,webPreferences:{nodeIntegration:false,contextIsolation:true,partition:'persist:'+part}}); }
app.whenReady().then(async()=>{
 const keep=new BrowserWindow({show:false});
 try{
  // Alice abre, escolhe apelido, cria topico + resposta
  var A=mk('fa'+RUN);
  A.webContents.on('render-process-gone',(e,d)=>w('A_RENDER_GONE:'+JSON.stringify(d)));
  A.webContents.on('console-message',(e,lvl,msg)=>{ if(lvl>=2)w('A_console:'+msg); });
  await A.loadFile(file); w('A_loaded'); await sleep(8000);
  var aconn=await A.webContents.executeJavaScript("document.getElementById('ctxt').textContent"); w('A_conn='+aconn);
  var ares=await A.webContents.executeJavaScript("(async()=>{ await setNick('Alice'); await postTopic('Tecnologia','Ola mundo HidraNet TST','Primeiro **topico** do forum!'); var tid=Object.keys(state.topics).filter(function(k){return state.topics[k].title.indexOf('Ola mundo HidraNet TST')===0;})[0]; await postReply(tid,'Resposta de teste da Alice TST'); return JSON.stringify({tid:tid,topics:Object.keys(state.topics).length,replies:Object.keys(state.replies).length}); })()");
  w('A_post='+ares);
  await sleep(3000); A.close(); await sleep(1500);
  // Bob abre depois (outra particao) -> deve receber topico+resposta retidos do relay
  var B=mk('fb'+RUN); await B.loadFile(file); await sleep(9000);
  var bres=await B.webContents.executeJavaScript("JSON.stringify({ tinha:Object.values(state.topics).some(function(t){return t.title.indexOf('Ola mundo HidraNet TST')===0;}), repl:Object.values(state.replies).some(function(r){return (r.body||'').indexOf('Resposta de teste da Alice TST')===0;}) })");
  w('B_view='+bres);
  // limpeza: remove os artefatos de teste do relay (publica retido vazio)
  var cl=await B.webContents.executeJavaScript("(async()=>{ var n=0; for(var k in state.topics){ var t=state.topics[k]; if(t.title&&t.title.indexOf('Ola mundo HidraNet TST')===0){ client.publish('hforum/t/'+t.id,'',{qos:1,retain:true}); n++; } } for(var r in state.replies){ var rr=state.replies[r]; if(rr.body&&rr.body.indexOf('Resposta de teste da Alice TST')===0){ client.publish('hforum/r/'+rr.topicId+'/'+rr.id,'',{qos:1,retain:true}); n++; } } return n; })()");
  w('limpou='+cl); await sleep(2500);
  w('FIM_OK');
 }catch(e){ w('ERRO:'+e.message); }
 app.exit(0);
});
setTimeout(()=>{w('TIMEOUT');app.exit(0)},60000);
