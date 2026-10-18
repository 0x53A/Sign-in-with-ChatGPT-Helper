import {connectProxy, closeProxy, proxyConnected, proxyConnecting, onProxyChange} from './proxy.js';
import {createRequest, acceptResponse, connected, offlinePending, models, inference, disconnect} from './client.js';
import {zip, unzip} from './zip.js';
const $ = id => document.getElementById(id);
let pairing, busy = false, signedIn = false, unreadable = false, flow = null;
const status = text => { $('status').textContent = text; $('status').hidden = !text; };
function draw() {
  $('login').hidden = signedIn || unreadable;
  $('success').hidden = !signedIn && !unreadable;
  $('inference').hidden = !signedIn;
  $('login-state').textContent = unreadable ? 'Saved login unreadable' : 'Login Success';
  $('online').hidden = flow !== 'online';
  $('offline').hidden = flow !== 'offline';
  $('cancel').hidden = !pairing;
  for (const id of ['connect', 'request', 'response', 'port']) $(id).disabled = busy;
  $('disconnect').disabled = busy || (!signedIn && !unreadable);
  $('proxy-connect').disabled = busy || proxyConnected();
  $('proxy-stop').hidden = !proxyConnected() && !proxyConnecting();
  $('proxy-port').disabled = busy || proxyConnected();
  $('reload').disabled = $('model').disabled = busy || !signedIn || !proxyConnected();
  $('send').disabled = busy || !signedIn || !proxyConnected() || !$('model').value;
}
async function run(fn) { if (busy) return; busy = true; draw(); try { await fn(); } catch (e) { status(e.message); } finally { busy = false; draw(); } }
async function catalog() {
  $('model').replaceChildren(new Option('Loading models…', ''));
  let list;
  try { list = await models(); }
  catch (error) {
    $('model').replaceChildren(new Option('GPT-6.1 Sol (test fallback)', 'gpt-6.1-sol'));
    throw Error(`Model list unavailable. Using GPT-6.1 Sol for testing. ${error.message}`);
  }
  $('model').replaceChildren(...list.map(m => new Option(m.display_name || m.slug, m.slug)));
  if (!list.length) $('model').add(new Option('No available models', ''));
}
async function received(value) {
  if (!value || typeof value !== 'object') throw Error('Invalid helper response.');
  if (value.error) throw Error('Login did not complete. Check the helper.');
  await acceptResponse(value);
  if (flow === 'online') $('proxy-port').value = $('port').value;
  signedIn = true; flow = null; $('pair').hidden = true; draw();
  status('Connect the proxy to load models and send messages.');
}
$('connect').onclick = () => run(async () => {
  flow = 'online'; pairing = new AbortController(); draw();
  const signal = pairing.signal;
  try {
    const port = Number($('port').value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error('Enter a port from 1 to 65535.');
    const raw = await createRequest(); signal.throwIfAborted();
    // Rejection sampling avoids modulo bias, including leading-zero PINs.
    let n; do { n = crypto.getRandomValues(new Uint16Array(1))[0]; } while (n >= 60000);
    const pin = String(n % 10000).padStart(4, '0'); $('pin').textContent = pin; $('pair').hidden = false;
    status('Connecting to the helper…');
    const value = await new Promise((resolve, reject) => {
      const socket = new WebSocket('ws://127.0.0.1:' + port + '/pair');
      const timer = setTimeout(() => finish(Error('Pairing timed out. Start again.')), 12 * 60 * 1000);
      const abort = () => finish(signal.reason);
      function finish(error, value) {
        clearTimeout(timer); signal.removeEventListener('abort', abort);
        socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null;
        socket.close(); error ? reject(error) : resolve(value);
      }
      signal.addEventListener('abort', abort, {once:true});
      socket.onopen = () => { socket.send(JSON.stringify({request:raw, pin})); status('Enter the four-digit PIN in the helper.'); };
      socket.onmessage = e => {
        try {
          if (typeof e.data !== 'string' || e.data.length > 262144) throw Error('Invalid helper response.');
          finish(null, JSON.parse(e.data));
        } catch (error) { finish(error); }
      };
      socket.onerror = () => finish(Error('Cannot reach helper. Check its port and browser local-network permission, or use request files.'));
      socket.onclose = () => finish(Error('Helper connection closed before completing login.'));
    });
    signal.throwIfAborted();
    pairing = null; draw();
    await received(value);
  } finally { pairing = null; $('pair').hidden = true; }
});
$('request').onclick = () => run(async () => {
  const raw = await createRequest(true), url = URL.createObjectURL(new Blob([zip('request.json', raw)], {type: 'application/zip'}));
  const link = document.createElement('a'); link.href = url; link.download = 'chatgpt-request.zip'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  flow = 'offline'; status('');
});
$('cancel').onclick = () => pairing?.abort(Error('Pairing cancelled.'));
$('response').onchange = () => run(async () => {
  const file = $('response').files[0]; $('response').value = ''; if (!file) return;
  if (file.size > 262144) throw Error('Response file is too large.');
  await received(JSON.parse(unzip(new Uint8Array(await file.arrayBuffer()), 'response.json')));
});
onProxyChange(connected => {
  if (!connected && !proxyConnecting() && signedIn) status('Proxy disconnected. Connect and approve a new session.');
  draw();
});
$('proxy-connect').onclick = () => run(async () => {
  status('Approve this proxy session in the helper. Close the login result first if needed.');
  await connectProxy(Number($('proxy-port').value));
  await catalog(); status('Proxy connected.');
});
$('proxy-stop').onclick = closeProxy;
$('model').onchange = draw;
$('reload').onclick = () => run(async () => { await catalog(); status('Models loaded.'); });
$('send').onclick = () => run(async () => {
  const prompt = $('prompt').value.trim(); if (!prompt) throw Error('Enter a message.');
  $('output').textContent = ''; status('Generating…');
  await inference($('model').value, prompt, text => { $('output').textContent += text; }); status('Complete.');
});
$('disconnect').onclick = () => run(async () => {
  const revoked = await disconnect(); signedIn = false; unreadable = false; flow = null; $('prompt').value = ''; $('output').textContent = ''; $('model').replaceChildren(new Option('Sign in to load models', ''));
  status(revoked ? '' : 'Removed local credentials. Remote revocation was not confirmed; disconnect this app in ChatGPT settings.');
});
await run(async () => {
  try { signedIn = await connected(); }
  catch (error) {
    if (error.message.includes('Close other demo tabs')) throw error;
    unreadable = true; throw Error('Saved login could not be read. Log out to clear it.');
  }
  if (!signedIn && await offlinePending()) flow = 'offline';
  draw();
  if (signedIn) status('Connect the proxy to load models and send messages.');
});
