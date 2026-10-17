import {chromium} from 'playwright';
import assert from 'node:assert/strict';
import {mkdir, readFile} from 'node:fs/promises';
import {unzip} from '../web/zip.js';
import {execFileSync} from 'node:child_process';
import {resolve} from 'node:path';
import {serve} from '../tools/serve.mjs';
const dir = resolve('target/browser-test'); await mkdir(dir, {recursive:true});
const server = await serve(process.env.WEB_ROOT || 'web', 0), origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({executablePath:process.env.CHROMIUM || undefined, headless:true, args:['--no-sandbox']});
const context = await browser.newContext({acceptDownloads:true, viewport:{width:1000,height:900}});
let refreshes = 0;
await context.route('https://api.openai.com/v1/models', route => route.fulfill({json:{models:[{visibility:'list', slug:'test-model', display_name:'Test model'}]}}));
await context.route('https://api.openai.com/v1/responses', async route => {
  const body = route.request().postDataJSON(); assert.equal(body.store, false); assert.equal(body.stream, true); assert.equal(body.model, 'test-model');
  await route.fulfill({contentType:'text/event-stream', body:'data: {"type":"response.output_text.delta","delta":"Hello from the fixture."}\n\ndata: {"type":"response.completed","response":{"status":"completed"}}\n\n'});
});
await context.route('https://auth.openai.com/api/accounts/oauth/token', async route => {
  const form = new URLSearchParams(route.request().postData());
  assert.equal(form.get('grant_type'), 'refresh_token'); assert.equal(form.get('refresh_token'), 'synthetic-refresh'); assert.equal(form.get('client_id'), 'oaiapp_test');
  refreshes++;
  await route.fulfill({json:{access_token:'renewed-access', refresh_token:'renewed-refresh', token_type:'Bearer', expires_in:3600, scope:'openid resource.invoke chatgpt.tokens.use.direct offline_access'}});
});
await context.route('https://auth.openai.com/api/accounts/oauth/revoke', route => route.fulfill({status:200, body:''}));
try {
  const page = await context.newPage(); const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin); await page.locator('details').evaluate(e => e.open = true);
  const downloadEvent = page.waitForEvent('download'); await page.click('#request');
  const download = await downloadEvent; await download.saveAs(`${dir}/request.zip`);
  execFileSync(resolve('target/debug/examples/interop'), [`${dir}/request.zip`, `${dir}/response.zip`]);
  // Private key must survive reload but must not be exportable.
  await page.reload();
  const keyFlags = await page.evaluate(async () => {
    const db = await new Promise((resolve,reject) => {const r=indexedDB.open('chatgpt-helper-demo-v1');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
    const pending = await new Promise(resolve => {const r=db.transaction('kv').objectStore('kv').get('pending');r.onsuccess=()=>resolve(r.result);});
    return {extractable:pending.privateKey.extractable, type:pending.privateKey.type};
  });
  assert.deepEqual(keyFlags, {extractable:false,type:'private'});
  const envelope=JSON.parse(unzip(new Uint8Array(await readFile(`${dir}/response.zip`)), 'response.json'));
  assert.equal(await page.evaluate(async envelope => {
    const {acceptResponse}=await import('./client.js');
    const wrong={...envelope,request_hash:'incorrect'};
    try{await acceptResponse(wrong);return false;}catch{}
    const changed={...envelope,ciphertext:(envelope.ciphertext[0]==='A'?'B':'A')+envelope.ciphertext.slice(1)};
    try{await acceptResponse(changed);return false;}catch{}
    return true;
  },envelope),true,'binding and AEAD tampering must fail without consuming the request');
  await page.locator('details').evaluate(e => e.open = true);
  await page.setInputFiles('#response', `${dir}/response.zip`);
  await page.waitForFunction(() => document.querySelector('#status').textContent.includes('Connected.'));
  await page.fill('#prompt', 'Hello'); await page.click('#send');
  await page.waitForFunction(() => document.querySelector('#status').textContent === 'Complete.');
  assert.equal(await page.locator('#output').textContent(), 'Hello from the fixture.');
  await page.screenshot({path:`${dir}/desktop.png`});
  await page.setViewportSize({width:390,height:844}); await page.screenshot({path:`${dir}/mobile.png`});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  // Consume-once and ciphertext binding: importing again cannot replace the session.
  await page.setInputFiles('#response', `${dir}/response.zip`);
  await page.waitForFunction(() => document.querySelector('#status').textContent.includes('No pending request'));
  const stored = await page.evaluate(async () => {
    const db=await new Promise(resolve=>{const r=indexedDB.open('chatgpt-helper-demo-v1');r.onsuccess=()=>resolve(r.result);});
    const get=k=>new Promise(resolve=>{const r=db.transaction('kv').objectStore('kv').get(k);r.onsuccess=()=>resolve(r.result);});
    const key=await get('key'), record=await get('session');
    const payload=JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:record.iv,additionalData:new TextEncoder().encode('session:v1')},key,record.data)));
    payload.expires_at=0;
    const data=await crypto.subtle.encrypt({name:'AES-GCM',iv:crypto.getRandomValues(record.iv),additionalData:new TextEncoder().encode('session:v1')},key,new TextEncoder().encode(JSON.stringify(payload)));
    await new Promise(resolve=>{const tx=db.transaction('kv','readwrite');tx.objectStore('kv').put({iv:record.iv,data},'session');tx.oncomplete=resolve;});
    return {extractable:key.extractable, encrypted:record.data instanceof ArrayBuffer};
  });
  assert.deepEqual(stored,{extractable:false,encrypted:true});
  const second=await context.newPage(); await Promise.all([page.reload(),second.goto(origin)]);
  await Promise.all([page.waitForFunction(()=>document.querySelector('#status').textContent==='Restored saved connection.'), second.waitForFunction(()=>document.querySelector('#status').textContent==='Restored saved connection.')]);
  assert.equal(refreshes,1,'refresh rotation must serialize across tabs');
  await page.click('#disconnect'); await page.waitForFunction(()=>document.querySelector('#status').textContent==='Disconnected.');
  assert.deepEqual(errors,[]);
  console.log('Browser: Rust/WebCrypto ZIP interoperability, non-extractable keys, reload, replay rejection, refresh rotation, inference and layouts passed.');
} finally { await browser.close(); await new Promise(resolve=>server.close(resolve)); }
