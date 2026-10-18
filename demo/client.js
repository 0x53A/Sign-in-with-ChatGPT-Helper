// The browser owns opaque bundles; bearer credentials never reach JavaScript.
import {proxyRequest, closeProxy} from './proxy.js';
export const scopes = ['openid', 'resource.invoke', 'chatgpt.tokens.use.direct', 'offline_access'];
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
    const req = indexedDB.open('chatgpt-helper-demo-v1', 2);
    let blocked = false;
    req.onblocked = () => { blocked = true; reject(Error('Close other demo tabs, then reload to upgrade credential storage.')); };
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains('kv')) req.result.createObjectStore('kv');
      else {
        // v1 stored browser-decryptable bearer credentials. Require a fresh login.
        for (const key of ['session','key','pending','refresh-pending']) req.transaction.objectStore('kv').delete(key);
      }
    };
    req.onsuccess = () => {
      if (blocked) { req.result.close(); return; }
      req.result.onversionchange = () => { req.result.close(); database = undefined; closeProxy(); };
      resolve(req.result);
    }; req.onerror = () => reject(req.error);
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
async function saved() {
  const credentials = await read('session');
  if (credentials) validate(credentials);
  return credentials;
}
async function persist(credentials, extra = []) { await write([['session', credentials], ...extra]); }
function validate(value) {
  const bundle = value?.bundle;
  if (!bundle || bundle.version !== 2 || typeof bundle.helper_id !== 'string' ||
      !['wrapped_key','iv','ciphertext'].every(k => typeof bundle[k] === 'string' && bundle[k].length > 0 && bundle[k].length < 131072) ||
      typeof value.client_id !== 'string' || !/^[\w-]{1,200}$/.test(value.client_id) || value.client_id === 'dynamic_agent_client' ||
      typeof value.subject !== 'string' || !value.subject || typeof value.host_id !== 'string' ||
      !Number.isSafeInteger(value.expires_at) || 'access_token' in value || 'refresh_token' in value) throw Error('Invalid sealed credentials.');
}
export async function createRequest(offline = false) {
  if (!isSecureContext || !navigator.locks || !crypto.subtle) throw Error('Use a current browser over HTTPS or localhost.');
  const pair = await crypto.subtle.generateKey({name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256'}, false, ['encrypt', 'decrypt']);
  return locked(async () => {
    let host = await read('host');
    if (!host) { host = `urn:uuid:${crypto.randomUUID()}`; await write([['host', host]]); }
    const key = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const request = {version: 2, request_id: random(), app_name: 'ChatGPT Helper Demo', origin: location.origin,
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
    if (envelope.version !== 2 || envelope.request_id !== request.request_id || envelope.request_hash !== hash || request.expires_at <= now()) throw Error('Response belongs to a different or expired request.');
    if (unb64(envelope.iv).length !== 12) throw Error('Invalid response nonce.');
    const rawKey = await crypto.subtle.decrypt({name: 'RSA-OAEP'}, pending.privateKey, unb64(envelope.wrapped_key));
    if (rawKey.byteLength !== 32) throw Error('Invalid response key.');
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    const tokens = JSON.parse(dec.decode(await crypto.subtle.decrypt({name: 'AES-GCM', iv: unb64(envelope.iv),
      additionalData: enc.encode(`chatgpt-helper-v2:${request.request_id}:${hash}`)}, key, unb64(envelope.ciphertext))));
    validate(tokens);
    if (!Number.isSafeInteger(tokens.expires_at) || tokens.expires_at <= now() || tokens.expires_at > now() + 86400 ||
        tokens.host_id !== request.host_id || typeof tokens.subject !== 'string' || !tokens.subject || typeof tokens.client_id !== 'string' || !/^[\w-]{1,200}$/.test(tokens.client_id) ||
        tokens.client_id === 'dynamic_agent_client' || (request.client_id && tokens.client_id !== request.client_id)) throw Error('Invalid credential binding or expiry.');
    const old = await read('registration');
    if (old && (old.client_id !== tokens.client_id || old.subject !== tokens.subject)) throw Error('Returning registration identity changed.');
    await persist(tokens, [['registration', {client_id: tokens.client_id, subject: tokens.subject}], ['pending', undefined], ['refresh-pending', undefined]]);
  });
}
async function checked(response) {
  if (!response.ok) {
    let body; try { body = await response.json(); } catch {}
    const code = body?.error?.code || body?.error;
    throw Error(`OpenAI HTTP ${response.status}${typeof code === 'string' && /^[\w.-]{1,100}$/.test(code) ? ` (${code})` : ''}.`);
  }
  return response;
}
async function access() {
  return locked(async () => {
    let credentials = await saved(); if (!credentials) throw Error('Sign in first.');
    if (await read('refresh-pending')) throw Error('A previous refresh did not finish safely. Sign in again.');
    if (credentials.expires_at <= now() + 60) {
      await write([['refresh-pending', true]]);
      const next = await proxyRequest('refresh', credentials.bundle);
      validate(next);
      if (next.client_id !== credentials.client_id || next.subject !== credentials.subject || next.host_id !== credentials.host_id ||
          next.expires_at <= now() || next.expires_at > now() + 86400) throw Error('Invalid refreshed credential binding.');
      await persist(next, [['refresh-pending', undefined]]);
      credentials = next;
    }
    return credentials.bundle;
  });
}
export async function offlinePending() {
  const pending = await read('pending');
  return !!(pending?.offline && JSON.parse(pending.raw).expires_at > now());
}
export async function connected() { return locked(async () => !!await saved()); }
export async function models() {
  const response = await checked(await proxyRequest('models', await access()));
  const value = await response.json(); if (!Array.isArray(value.models)) throw Error('Unexpected model catalog.');
  return value.models.filter(m => m.visibility === 'list' && typeof m.slug === 'string');
}
export async function inference(model, input, onText) {
  const response = await checked(await proxyRequest('responses', await access(), {model, input: [{role: 'user', content: input}], store: false, stream: true}));
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
    if (tokens) try { await proxyRequest('revoke', tokens.bundle); } catch { revoked = false; }
    closeProxy();
    return revoked;
  });
}
