const { app, BrowserWindow } = require('electron');
const fs=require('fs'), path=require('path');
app.commandLine.appendSwitch('disable-gpu');
const OUT=path.join(process.cwd(),'mail.out'); const w=s=>{try{fs.appendFileSync(OUT,s+'\n')}catch(e){}};
fs.writeFileSync(OUT,'inicio\n');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const RUN=Math.floor(Math.random()*1e6);
const file=path.join('src','ui','hidramail.html');
// IMPORTANT: do not let Electron quit when a window closes (we simulate "offline")
app.on('window-all-closed', e=>{ e.preventDefault(); });
function mk(part){ return new BrowserWindow({show:false,webPreferences:{nodeIntegration:false,contextIsolation:true,partition:'persist:'+part}}); }
app.whenReady().then(async()=>{
 // a keepalive window makes sure the app never drops to 0 windows
 const keep=new BrowserWindow({show:false});
 try{
  // B opens (creates identity, publishes RETAINED directory, subscribes) and THEN closes = offline
  var B1=mk('pb'+RUN); await B1.loadFile(file); await sleep(8000);
  var Baddr=await B1.webContents.executeJavaScript("state.ids[0].addr");
  var Bconn=await B1.webContents.executeJavaScript("document.getElementById('ctxt').textContent");
  w('B_addr='+Baddr+' conn='+Bconn);
  B1.close(); await sleep(2000); w('B_fechou_(offline)');
  // A opens and sends to B (B is offline; the message stays RETAINED on the relay)
  var A=mk('pa'+RUN); await A.loadFile(file); await sleep(8000);
  var Aaddr=await A.webContents.executeJavaScript("state.ids[0].addr");
  w('A_addr='+Aaddr);
  var res=await A.webContents.executeJavaScript("(async()=>{return JSON.stringify(await sendMail("+JSON.stringify(Baddr)+",'Reuniao amanha','Oi! Esse e um email criptografado de ponta a ponta. Confirma?'));})()");
  w('A_envio='+res);
  A.close(); await sleep(2000);
  // B reopens (same partition = same identity/key) -> receives the retained message
  var B2=mk('pb'+RUN); await B2.loadFile(file); await sleep(9000);
  var inbox=await B2.webContents.executeJavaScript("JSON.stringify({n:state.box.inbox.length, subj:(state.box.inbox[0]||{}).subject, body:(state.box.inbox[0]||{}).body, from:(state.box.inbox[0]||{}).from})");
  w('B_inbox='+inbox);
  w('FIM_OK');
 }catch(e){ w('ERROR:'+e.message); }
 app.exit(0);
});
setTimeout(()=>{w('TIMEOUT');app.exit(0)},60000);
