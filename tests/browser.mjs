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
let refreshes = 0, fixtureCredentials, catalogFails = false, proxySessions = 0;
await context.route('https://**', () => { throw Error('Browser must never send credentials directly to OpenAI'); });
await context.routeWebSocket(/ws:\/\/127\.0\.0\.1:\d+\/proxy$/, ws => {
  proxySessions++;
  ws.send(JSON.stringify({type:'ready',protocol:1}));
  const reply = (id, body, status = 200) => {
    ws.send(JSON.stringify({id,type:'headers',status,content_type:'application/json'}));
    const prefix = Buffer.alloc(4); prefix.writeUInt32BE(id);
    ws.send(Buffer.concat([prefix, Buffer.from(body)])); ws.send(JSON.stringify({id,type:'end'}));
  };
  ws.onMessage(raw => {
    const {type, id, request} = JSON.parse(raw);
    if (type === 'cancel') return;
    assert.equal(type, 'request');
    assert.equal(request.credentials.version, 2);
    assert.equal('token' in request, false);
    assert.equal(raw.includes('synthetic-access') || raw.includes('synthetic-refresh'), false);
    if (request.endpoint === 'models') reply(id, JSON.stringify(catalogFails ? {error:{code:'test_catalog_unavailable'}} : {models:[{visibility:'list',slug:'test-model',display_name:'Test model'}]}), catalogFails ? 503 : 200);
    else if (request.endpoint === 'responses') {
      assert.equal(request.body.store, false); assert.equal(request.body.stream, true);
      assert.equal(request.body.model, catalogFails ? 'gpt-6.1-sol' : 'test-model');
      reply(id, 'data: {"type":"response.output_text.delta","delta":"Hello from the fixture."}\n\ndata: {"type":"response.completed","response":{"status":"completed"}}\n\n');
    } else if (request.endpoint === 'refresh') {
      refreshes++;
      ws.send(JSON.stringify({id,type:'credentials',credentials:{...fixtureCredentials,expires_at:Math.floor(Date.now()/1000)+3600}}));
    } else if (request.endpoint === 'revoke') ws.send(JSON.stringify({id,type:'revoked'}));
    else throw Error('Unexpected proxy operation');
  });
});
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
  await page.waitForFunction(() => !document.querySelector('#success').hidden && !document.querySelector('#proxy-connect').disabled);
  await page.click('#proxy-connect');
  await page.waitForFunction(() => !document.querySelector('#send').disabled);
  assert.equal(await page.locator('#login').isVisible(), false);
  await page.fill('#prompt', 'Hello'); await page.click('#send');
  await page.waitForFunction(() => document.querySelector('#status').textContent === 'Complete.');
  assert.equal(await page.locator('#output').textContent(), 'Hello from the fixture.');
  // A blocked catalog must still allow testing the inference endpoint.
  catalogFails = true;
  await page.click('#reload');
  await page.waitForFunction(()=>!document.querySelector('#send').disabled && document.querySelector('#model').value === 'gpt-6.1-sol');
  await page.click('#send');
  await page.waitForFunction(()=>document.querySelector('#status').textContent === 'Complete.');
  catalogFails = false;
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
  fixtureCredentials = await page.evaluate(async () => {
    const db=await new Promise(resolve=>{const r=indexedDB.open('chatgpt-helper-demo-v1');r.onsuccess=()=>resolve(r.result);});
    const credentials=await new Promise(resolve=>{const r=db.transaction('kv').objectStore('kv').get('session');r.onsuccess=()=>resolve(r.result);});
    await new Promise(resolve=>{const tx=db.transaction('kv','readwrite');tx.objectStore('kv').put({...credentials,expires_at:0},'session');tx.oncomplete=resolve;});
    return credentials;
  });
  assert.equal(fixtureCredentials.bundle.version, 2);
  assert.equal(JSON.stringify(fixtureCredentials).includes('synthetic'), false, 'JS never receives bearer credentials');
  const second=await context.newPage(); await Promise.all([page.reload(),second.goto(origin)]);
  for (const tab of [page,second]) await tab.waitForFunction(()=>!document.querySelector('#proxy-connect').disabled);
  await Promise.all([page.click('#proxy-connect'),second.click('#proxy-connect')]);
  await Promise.all([page.waitForFunction(()=>!document.querySelector('#send').disabled), second.waitForFunction(()=>!document.querySelector('#send').disabled)]);
  assert.equal(refreshes,1,'refresh rotation must serialize across tabs');
  assert.equal(proxySessions,3,'reload and each tab require a new approval');
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
  // An old v1 tab must explain a blocked upgrade, then discard old raw tokens.
  const upgradeContext = await browser.newContext();
  await upgradeContext.route(origin + '/upgrade-fixture', route => route.fulfill({contentType:'text/html',body:'<title>Storage fixture</title>'}));
  const oldTab = await upgradeContext.newPage(); await oldTab.goto(origin + '/upgrade-fixture');
  await oldTab.evaluate(async () => {
    const db = await new Promise(resolve => { const r = indexedDB.open('chatgpt-helper-demo-v1',1); r.onupgradeneeded=()=>r.result.createObjectStore('kv'); r.onsuccess=()=>resolve(r.result); });
    globalThis.heldDatabase = db;
    await new Promise(resolve=>{const tx=db.transaction('kv','readwrite');tx.objectStore('kv').put({access_token:'legacy-secret'},'session');tx.oncomplete=resolve;});
  });
  const upgraded = await upgradeContext.newPage(); await upgraded.goto(origin);
  await upgraded.waitForFunction(()=>document.querySelector('#status').textContent.includes('Close other demo tabs'));
  await oldTab.close(); await upgraded.reload();
  await upgraded.waitForFunction(()=>!document.querySelector('#connect').disabled);
  assert.equal(await upgraded.locator('#login').isVisible(),true);
  assert.equal(await upgraded.evaluate(async()=>{
    const db=await new Promise(resolve=>{const r=indexedDB.open('chatgpt-helper-demo-v1');r.onsuccess=()=>resolve(r.result);});
    return await new Promise(resolve=>{const r=db.transaction('kv').objectStore('kv').get('session');r.onsuccess=()=>resolve(r.result===undefined);});
  }), true);
  await upgradeContext.close();
  assert.deepEqual(errors,[]);
  console.log('Browser: Rust/WebCrypto ZIP interoperability, non-extractable keys, reload, replay rejection, refresh rotation, inference and layouts passed.');
} finally { await browser.close(); await new Promise(resolve=>server.close(resolve)); }
