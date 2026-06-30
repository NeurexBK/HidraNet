const { app, BrowserWindow } = require('electron');
const fs=require('fs'), path=require('path');
app.commandLine.appendSwitch('disable-gpu');
const OUT=path.join(process.cwd(),'forumclean.out'); const w=s=>{try{fs.appendFileSync(OUT,s+'\n')}catch(e){}};
fs.writeFileSync(OUT,'inicio\n');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
app.on('window-all-closed', e=>{ e.preventDefault(); });
app.whenReady().then(async()=>{
 const keep=new BrowserWindow({show:false});
 try{
  var W=new BrowserWindow({show:false,webPreferences:{nodeIntegration:false,contextIsolation:true,partition:'persist:clean'+Math.random()}});
  await W.loadFile(path.join('src','ui','forum.html')); await sleep(15000);
  var titles=await W.webContents.executeJavaScript("JSON.stringify(Object.values(state.topics).map(function(t){return t.title;}))");
  w('titulos_no_relay='+titles);
  // remove qualquer artefato de teste retido no relay (titulos/respostas de teste)
  var cl=await W.webContents.executeJavaScript("(async()=>{ var n=0; for(var k in state.topics){ var t=state.topics[k]; if(t.title&&(t.title.indexOf('Ola mundo HidraNet')===0)){ client.publish('hforum/t/'+t.id,'',{qos:1,retain:true}); n++; } } for(var r in state.replies){ var rr=state.replies[r]; if(rr.body&&rr.body.indexOf('Resposta de teste da Alice')===0){ client.publish('hforum/r/'+rr.topicId+'/'+rr.id,'',{qos:1,retain:true}); n++; } } return n; })()");
  w('removidos='+cl); await sleep(3500);
  w('FIM_OK');
 }catch(e){ w('ERRO:'+e.message); }
 app.exit(0);
});
setTimeout(()=>{w('TIMEOUT');app.exit(0)},40000);
