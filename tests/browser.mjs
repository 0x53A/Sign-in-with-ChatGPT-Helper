import {fileURLToPath} from 'node:url';
process.chdir(fileURLToPath(new URL('..', import.meta.url)));
import {chromium} from 'playwright';
import assert from 'node:assert/strict';
import {mkdir, readFile} from 'node:fs/promises';
import {unzip} from '../demo/zip.js';
import {execFileSync} from 'node:child_process';
import {resolve} from 'node:path';
import {serve} from '../demo/serve.mjs';
const dir = resolve('tests/artifacts/browser-test'); await mkdir(dir, {recursive:true});
const server = await serve(process.env.WEB_ROOT || 'demo', 0), origin = `http://127.0.0.1:${server.address().port}`;
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
  await page.goto(origin);
  await page.waitForFunction(()=>!document.querySelector('#request').disabled);
  assert.equal(await page.locator('#login').isVisible(), true);
  assert.equal(await page.locator('#inference').isVisible(), false);
  assert.equal(await page.locator('#success').isVisible(), false);
  await page.screenshot({path:dir+'/signed-out.png'});
  // Cancel while RSA generation is still pending: no socket may open afterward.
  await page.evaluate(() => {
    const generate = crypto.subtle.generateKey.bind(crypto.subtle);
    crypto.subtle.generateKey = async (...args) => {
      await new Promise(resolve => { globalThis.resumeKey = resolve; });
      return generate(...args);
    };
    globalThis.socketOpened = false;
    globalThis.WebSocket = class { constructor() { globalThis.socketOpened = true; throw Error('Unexpected socket'); } };
  });
  await page.click('#connect');
  await page.waitForFunction(()=>typeof globalThis.resumeKey === 'function');
  await page.click('#cancel'); await page.evaluate(()=>globalThis.resumeKey());
  await page.waitForFunction(()=>document.querySelector('#status').textContent === 'Pairing cancelled.');
  assert.equal(await page.evaluate(()=>globalThis.socketOpened), false);
  await page.reload();
  const downloadEvent = page.waitForEvent('download'); await page.click('#request');
  const download = await downloadEvent; await download.saveAs(`${dir}/request.zip`);
  execFileSync(resolve('helper/target/debug/examples/interop'), [`${dir}/request.zip`, `${dir}/response.zip`]);
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
  await page.waitForFunction(()=>!document.querySelector('#offline').hidden);
  await page.screenshot({path:dir+'/offline.png'});
  await page.setInputFiles('#response', `${dir}/response.zip`);
  await page.waitForFunction(() => !document.querySelector('#success').hidden && !document.querySelector('#send').disabled);
  assert.equal(await page.locator('#login').isVisible(), false);
  await page.fill('#prompt', 'Hello'); await page.click('#send');
  await page.waitForFunction(() => document.querySelector('#status').textContent === 'Complete.');
  assert.equal(await page.locator('#output').textContent(), 'Hello from the fixture.');
  // A blocked catalog must still allow testing the inference endpoint.
  await page.route('https://api.openai.com/v1/models', route => route.abort());
  await page.route('https://api.openai.com/v1/responses', async route => {
    assert.equal(route.request().postDataJSON().model, 'gpt-6.1-sol');
    await route.fulfill({contentType:'text/event-stream', body:'data: {"type":"response.completed","response":{"status":"completed"}}\n\n'});
  });
  await page.click('#reload');
  await page.waitForFunction(()=>!document.querySelector('#send').disabled && document.querySelector('#model').value === 'gpt-6.1-sol');
  await page.click('#send');
  await page.waitForFunction(()=>document.querySelector('#status').textContent === 'Complete.');
  await page.unroute('https://api.openai.com/v1/models');
  await page.unroute('https://api.openai.com/v1/responses');
  await page.click('#reload');
  await page.waitForFunction(()=>document.querySelector('#status').textContent === 'Models loaded.');
  await page.screenshot({path:`${dir}/desktop.png`});
  await page.setViewportSize({width:390,height:844}); await page.screenshot({path:`${dir}/mobile.png`});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  // Consume-once and ciphertext binding: importing again cannot replace the session.
  assert.equal(await page.evaluate(async envelope => {
    try { await (await import('./client.js')).acceptResponse(envelope); return false; }
    catch(e) { return e.message.includes('No pending request'); }
  }, envelope), true);
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
  await Promise.all([page.waitForFunction(()=>!document.querySelector('#success').hidden && !document.querySelector('#send').disabled), second.waitForFunction(()=>!document.querySelector('#success').hidden && !document.querySelector('#send').disabled)]);
  assert.equal(refreshes,1,'refresh rotation must serialize across tabs');
  // An ambiguous refresh must never retry the rotated token.
  assert.equal(await page.evaluate(async () => {
    const db=await new Promise(resolve=>{const r=indexedDB.open('chatgpt-helper-demo-v1');r.onsuccess=()=>resolve(r.result);});
    await new Promise(resolve=>{const tx=db.transaction('kv','readwrite');tx.objectStore('kv').put(true,'refresh-pending');tx.oncomplete=resolve;});
    try { await (await import('./client.js')).models(); return false; }
    catch(e) { return e.message.includes('previous refresh'); }
  }), true);
  assert.equal(refreshes, 1);
  await page.click('#disconnect'); await page.waitForFunction(()=>!document.querySelector('#login').hidden && !document.querySelector('#connect').disabled);
  assert.equal(await page.locator('#inference').isVisible(), false);
  assert.equal(await page.locator('#output').textContent(), '');
  // Corrupt storage must have a reachable UI recovery path, without claiming success.
  await page.evaluate(async () => {
    const db=await new Promise(resolve=>{const r=indexedDB.open('chatgpt-helper-demo-v1');r.onsuccess=()=>resolve(r.result);});
    await new Promise(resolve=>{const tx=db.transaction('kv','readwrite');tx.objectStore('kv').put({iv:new Uint8Array(12),data:new ArrayBuffer(1)},'session');tx.oncomplete=resolve;});
  });
  await page.reload();
  await page.waitForFunction(()=>!document.querySelector('#disconnect').disabled);
  assert.equal(await page.locator('#disconnect').isVisible(), true);
  assert.equal(await page.locator('#login-state').textContent(), 'Saved login unreadable');
  assert.equal(await page.locator('#inference').isVisible(), false);
  await page.click('#disconnect');
  await page.waitForFunction(()=>!document.querySelector('#login').hidden);
  assert.match(await page.locator('#status').textContent(), /Remote revocation was not confirmed/);
  assert.equal(await page.evaluate(async () => {
    const db=await new Promise(resolve=>{const r=indexedDB.open('chatgpt-helper-demo-v1');r.onsuccess=()=>resolve(r.result);});
    return await new Promise(resolve=>{const r=db.transaction('kv').objectStore('kv').get('session');r.onsuccess=()=>resolve(r.result === undefined);});
  }), true);
  assert.deepEqual(errors,[]);
  console.log('Browser: Rust/WebCrypto ZIP interoperability, non-extractable keys, reload, replay rejection, refresh rotation, inference and layouts passed.');
} finally { await browser.close(); await new Promise(resolve=>server.close(resolve)); }
