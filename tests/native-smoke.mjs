import {fileURLToPath} from 'node:url';
process.chdir(fileURLToPath(new URL('..', import.meta.url)));
// Run under nix-shell for the helper's GUI libraries; isolated X display.
import {spawn, execFileSync} from 'node:child_process';
import {mkdir} from 'node:fs/promises';
import {chromium} from 'playwright';
import {serve} from '../demo/serve.mjs';
await mkdir('tests/artifacts/native-smoke', {recursive:true});
const xvfb=spawn(process.env.XVFB || 'Xvfb', ['-displayfd','3','-screen','0','850x750x24'], {stdio:['ignore','ignore','pipe','pipe']});
let app,browser,server;
try {
  const display=await new Promise((resolve,reject)=>{xvfb.stdio[3].once('data',d=>resolve(':'+d.toString().trim()));xvfb.once('error',reject);});
  app=spawn('helper/target/debug/chatgpt-login-helper', [], {env:{...process.env,DISPLAY:display,WINIT_UNIX_BACKEND:'x11'},stdio:['ignore','ignore','pipe']});
  let error='';app.stderr.on('data',d=>error+=d);
  server=await serve('demo',0);
  browser=await chromium.launch({executablePath:process.env.CHROMIUM,headless:true,args:['--no-sandbox']});
  const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.waitForTimeout(1500);
  if(app.exitCode!==null)throw Error(error);
  execFileSync('import',['-display',display,'-window','root','tests/artifacts/native-smoke/idle.png']);
  await page.click('#connect');await page.waitForFunction(()=>document.querySelector('#status').textContent.includes('Enter the four-digit PIN'));
  await page.waitForTimeout(700);
  execFileSync('import',['-display',display,'-window','root','tests/artifacts/native-smoke/pairing.png']);
  const second = await browser.newPage();
  await second.goto(`http://127.0.0.1:${server.address().port}`);
  await second.click('#connect');
  await second.waitForFunction(()=>document.querySelector('#status').textContent.includes('Enter the four-digit PIN'));
  await second.waitForTimeout(700);
  execFileSync('import',['-display',display,'-window','root','tests/artifacts/native-smoke/requests.png']);
  await second.close();
  // Never approve real OAuth during this smoke test.
  await page.close();await new Promise(resolve=>setTimeout(resolve,500));
  execFileSync('import',['-display',display,'-window','root','tests/artifacts/native-smoke/cancelled.png']);
  if(app.exitCode!==null)throw Error(error);
  console.log('Native GUI + real browser WebSocket pairing and disconnect smoke passed.');
}finally{await browser?.close();app?.kill();xvfb.kill();if(server)await new Promise(resolve=>server.close(resolve));}
