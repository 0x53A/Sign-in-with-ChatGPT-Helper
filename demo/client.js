// Reusable browser client. Tokens never appear in URLs, logs or download controls.
export const scopes = ['openid', 'resource.invoke', 'chatgpt.tokens.use.direct', 'offline_access'];
const resource = 'https://api.openai.com/v1', auth = 'https://auth.openai.com/api/accounts/oauth';
const enc = new TextEncoder(), dec = new TextDecoder('utf-8', {fatal: true});
export const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
export const unb64 = text => Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
const random = () => b64(crypto.getRandomValues(new Uint8Array(32)));
const now = () => Math.floor(Date.now() / 1000);
const digest = async text => b64(await crypto.subtle.digest('SHA-256', enc.encode(text)));
const locked = fn => navigator.locks.request('chatgpt-helper-demo-session', fn);
let database;
async function db() {
  if (!database) database = await new Promise((resolve, reject) => {
    const req = indexedDB.open('chatgpt-helper-demo-v1', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('kv');
    req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error);
  });
  return database;
}
async function read(key) {
  const database = await db();
  return new Promise((resolve, reject) => {
    const tx = database.transaction('kv'), req = tx.objectStore('kv').get(key);
    req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error);
  });
}
async function write(entries) {
  const database = await db();
  return new Promise((resolve, reject) => {
    const tx = database.transaction('kv', 'readwrite'), store = tx.objectStore('kv');
    for (const [key, value] of entries) value === undefined ? store.delete(key) : store.put(value, key);
    tx.oncomplete = resolve; tx.onabort = tx.onerror = () => reject(tx.error || Error('Storage write failed.'));
  });
}
async function storageKey() {
  let key = await read('key');
  if (!key) { key = await crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']); await write([['key', key]]); }
  return key;
}
async function saved() {
  const record = await read('session');
  if (!record) return null;
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({name: 'AES-GCM', iv: record.iv, additionalData: enc.encode('session:v1')}, await storageKey(), record.data)));
}
async function persist(tokens, extra = []) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: enc.encode('session:v1')}, await storageKey(), enc.encode(JSON.stringify(tokens)));
  await write([['session', {iv, data}], ...extra]);
}
function grant(value) {
  const actual = typeof value.scope === 'string' ? value.scope.trim().split(/\s+/) : [];
  if (actual.length !== scopes.length || !scopes.every(s => actual.filter(x => x === s).length === 1) ||
      (typeof value.token_type === 'string' ? value.token_type.toLowerCase() : '') !== 'bearer' || !value.access_token || !value.refresh_token ||
      typeof value.access_token !== 'string' || typeof value.refresh_token !== 'string' ||
      value.access_token.length >= 32000 || value.refresh_token.length >= 32000) throw Error('Missing or unexpected granted permissions or tokens.');
}
export async function createRequest(offline = false) {
  if (!isSecureContext || !navigator.locks || !crypto.subtle) throw Error('Use a current browser over HTTPS or localhost.');
  const pair = await crypto.subtle.generateKey({name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256'}, false, ['encrypt', 'decrypt']);
  return locked(async () => {
    let host = await read('host');
    if (!host) { host = `urn:uuid:${crypto.randomUUID()}`; await write([['host', host]]); }
    const key = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const request = {version: 1, request_id: random(), app_name: 'ChatGPT Helper Demo', origin: location.origin,
      host_id: host, client_id: (await read('registration'))?.client_id || null, expires_at: now() + 86400,
      scopes, public_key: {kty: key.kty, n: key.n, e: key.e}};
    const raw = JSON.stringify(request);
    // One outstanding request per demo: replacing it deliberately invalidates old files.
    await write([['pending', {raw, privateKey: pair.privateKey, offline}]]);
    return raw;
  });
}
export async function acceptResponse(envelope) {
  return locked(async () => {
    const pending = await read('pending'); if (!pending) throw Error('No pending request in this browser.');
    const request = JSON.parse(pending.raw), hash = await digest(pending.raw);
    if (!envelope || typeof envelope !== 'object') throw Error('Invalid helper response.');
    if (envelope.version !== 1 || envelope.request_id !== request.request_id || envelope.request_hash !== hash || request.expires_at <= now()) throw Error('Response belongs to a different or expired request.');
    if (unb64(envelope.iv).length !== 12) throw Error('Invalid response nonce.');
    const rawKey = await crypto.subtle.decrypt({name: 'RSA-OAEP'}, pending.privateKey, unb64(envelope.wrapped_key));
    if (rawKey.byteLength !== 32) throw Error('Invalid response key.');
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    const tokens = JSON.parse(dec.decode(await crypto.subtle.decrypt({name: 'AES-GCM', iv: unb64(envelope.iv),
      additionalData: enc.encode(`chatgpt-helper-v1:${request.request_id}:${hash}`)}, key, unb64(envelope.ciphertext))));
    grant(tokens);
    if (!Number.isSafeInteger(tokens.expires_at) || tokens.expires_at <= now() || tokens.expires_at > now() + 86400 ||
        tokens.host_id !== request.host_id || typeof tokens.subject !== 'string' || !tokens.subject || typeof tokens.client_id !== 'string' || !/^[\w-]{1,200}$/.test(tokens.client_id) ||
        tokens.client_id === 'dynamic_agent_client' || (request.client_id && tokens.client_id !== request.client_id)) throw Error('Invalid credential binding or expiry.');
    const old = await read('registration');
    if (old && (old.client_id !== tokens.client_id || old.subject !== tokens.subject)) throw Error('Returning registration identity changed.');
    await persist(tokens, [['registration', {client_id: tokens.client_id, subject: tokens.subject}], ['pending', undefined], ['refresh-pending', undefined]]);
  });
}
async function http(url, options = {}) {
  let response;
  try { response = await fetch(url, {credentials: 'omit', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(90000), ...options}); }
  catch { throw Error('Request unavailable: network failure, timeout or browser CORS restriction.'); }
  if (!response.ok) {
    let body; try { body = await response.json(); } catch {}
    const code = body?.error?.code || body?.error;
    throw Error(`OpenAI HTTP ${response.status}${typeof code === 'string' && /^[\w.-]{1,100}$/.test(code) ? ` (${code})` : ''}.`);
  }
  return response;
}
async function access() {
  return locked(async () => {
    let tokens = await saved(); if (!tokens) throw Error('Sign in first.');
    grant(tokens);
    if (await read('refresh-pending')) throw Error('A previous refresh did not finish safely. Sign in again.');
    if (tokens.expires_at <= now() + 60) {
      // If the process dies or the reply is lost after rotation, don't reuse an old token.
      await write([['refresh-pending', true]]);
      const response = await http(`${auth}/token`, {method: 'POST', body: new URLSearchParams({grant_type: 'refresh_token', client_id: tokens.client_id, refresh_token: tokens.refresh_token, resource})});
      const next = await response.json(); grant(next);
      if (!Number.isSafeInteger(next.expires_in) || next.expires_in <= 0 || next.expires_in > 86400) throw Error('Invalid refreshed expiry.');
      tokens = {...tokens, access_token: next.access_token, refresh_token: next.refresh_token, scope: next.scope, expires_at: now() + next.expires_in};
      // Persist before using the replacement; never retry a rotating token automatically.
      await persist(tokens, [['refresh-pending', undefined]]);
    }
    return tokens.access_token;
  });
}
export async function offlinePending() {
  const pending = await read('pending');
  return !!(pending?.offline && JSON.parse(pending.raw).expires_at > now());
}
export async function connected() { return locked(async () => !!await saved()); }
export async function models() {
  const response = await http(`${resource}/models`, {headers: {Authorization: `Bearer ${await access()}`}});
  const value = await response.json(); if (!Array.isArray(value.models)) throw Error('Unexpected model catalog.');
  return value.models.filter(m => m.visibility === 'list' && typeof m.slug === 'string');
}
export async function inference(model, input, onText) {
  const response = await http(`${resource}/responses`, {method: 'POST', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${await access()}`},
    body: JSON.stringify({model, input: [{role: 'user', content: input}], store: false, stream: true})});
  await streamText(response.body, onText);
}
export async function streamText(body, onText) {
  const reader = body.getReader(), decoder = new TextDecoder(); let buffer = '', complete = false, count = 0;
  function consume(final = false) {
    const blocks = buffer.split(/\r?\n\r?\n/); buffer = blocks.pop(); if (final && buffer.trim()) { blocks.push(buffer); buffer = ''; }
    for (const block of blocks) {
      const data = block.split(/\r?\n/).filter(l => l.startsWith('data:')).map(l => l.slice(5).trimStart()).join('\n');
      if (!data || data === '[DONE]') continue;
      const event = JSON.parse(data);
      if (['response.failed', 'response.incomplete', 'error'].includes(event.type)) throw Error('Inference failed or was incomplete.');
      if (event.type === 'response.output_text.delta') { if (typeof event.delta !== 'string') throw Error('Invalid response text.'); onText(event.delta); }
      if (event.type === 'response.completed' && event.response?.status === 'completed') complete = true;
    }
  }
  try {
    while (true) { const {value, done} = await reader.read(); if (done) break; count += value.length; if (count > 4 * 1024 * 1024) throw Error('Response exceeded demo limit.'); buffer += decoder.decode(value, {stream: true}); consume(); }
    buffer += decoder.decode(); consume(true); if (!complete) throw Error('Stream ended before completion.');
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
export async function disconnect() {
  return locked(async () => {
    let tokens, revoked = true;
    try { tokens = await saved(); } catch { revoked = false; }
    // Clear locally before the network request, including when stored data is corrupt.
    await write([['session', undefined], ['pending', undefined], ['refresh-pending', undefined]]);
    if (tokens) try { await http(`${auth}/revoke`, {method: 'POST', body: new URLSearchParams({token: tokens.refresh_token, token_type_hint: 'refresh_token', client_id: tokens.client_id})}); } catch { revoked = false; }
    return revoked;
  });
}
