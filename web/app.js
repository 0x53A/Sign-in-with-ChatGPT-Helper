import {createRequest, acceptResponse, connected, models, inference, disconnect} from './client.js';
import {zip, unzip} from './zip.js';
const $ = id => document.getElementById(id);
let socket, busy = false, signedIn = false;
const status = text => { $('status').textContent = text; };
function draw() {
  for (const id of ['connect', 'request', 'response', 'port']) $(id).disabled = busy;
  $('disconnect').disabled = busy || !signedIn;
  $('reload').disabled = $('model').disabled = busy || !signedIn;
  $('send').disabled = busy || !signedIn || !$('model').value || $('model').options[0]?.value === '';
}
async function run(fn) { if (busy) return; busy = true; draw(); try { await fn(); } catch (e) { status(e.message); } finally { busy = false; draw(); } }
async function catalog() {
  $('model').replaceChildren(new Option('Loading models…', ''));
  const list = await models(); $('model').replaceChildren(...list.map(m => new Option(m.display_name || m.slug, m.slug)));
  if (!list.length) $('model').add(new Option('No available models', ''));
}
async function received(value) {
  if (value.error) throw Error('Login did not complete. Check the helper.');
  await acceptResponse(value); signedIn = true; $('pair').hidden = true;
  status('Signed in. Loading models…'); await catalog(); status('Connected. The helper can now be closed.');
}
$('connect').onclick = () => run(async () => {
  const port = Number($('port').value); if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error('Enter a port from 1 to 65535.');
  const raw = await createRequest();
  // Rejection sampling avoids modulo bias, including leading-zero PINs.
  let n; do { n = crypto.getRandomValues(new Uint16Array(1))[0]; } while (n >= 60000);
  const pin = String(n % 10000).padStart(4, '0'); $('pin').textContent = pin; $('pair').hidden = false;
  status('Connecting to the helper…');
  try {
    const value = await new Promise((resolve, reject) => {
      socket = new WebSocket(`ws://127.0.0.1:${port}/pair`);
      const timer = setTimeout(() => { socket.close(); reject(Error('Pairing timed out. Start again.')); }, 12 * 60 * 1000);
      socket.onopen = () => { socket.send(JSON.stringify({request: raw, pin})); status('Enter the four-digit PIN in the helper.'); };
      socket.onmessage = e => { clearTimeout(timer); try { if (typeof e.data !== 'string' || e.data.length > 262144) throw Error('Invalid helper response.'); resolve(JSON.parse(e.data)); } catch (error) { reject(error); } socket.close(); };
      socket.onerror = () => { clearTimeout(timer); reject(Error('Cannot reach helper. Check its port and browser local-network permission, or use request files.')); };
      socket.onclose = () => { clearTimeout(timer); reject(Error('Helper connection closed before completing login.')); };
    });
    await received(value);
  } finally { socket?.close(); socket = null; $('pair').hidden = true; }
});
$('request').onclick = () => run(async () => {
  const raw = await createRequest(), url = URL.createObjectURL(new Blob([zip('request.json', raw)], {type: 'application/zip'}));
  const link = document.createElement('a'); link.href = url; link.download = 'chatgpt-request.zip'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  status('Open the request ZIP in the helper. Keep this browser profile to import its response. Creating a new request replaces the old one.');
});
$('response').onchange = () => run(async () => {
  const file = $('response').files[0]; $('response').value = ''; if (!file) return;
  if (file.size > 262144) throw Error('Response file is too large.');
  await received(JSON.parse(unzip(new Uint8Array(await file.arrayBuffer()), 'response.json')));
});
$('reload').onclick = () => run(async () => { await catalog(); status('Models loaded.'); });
$('send').onclick = () => run(async () => {
  const prompt = $('prompt').value.trim(); if (!prompt) throw Error('Enter a message.');
  $('output').textContent = ''; status('Generating…');
  await inference($('model').value, prompt, text => { $('output').textContent += text; }); status('Complete.');
});
$('disconnect').onclick = () => run(async () => {
  const revoked = await disconnect(); signedIn = false; $('output').textContent = ''; $('model').replaceChildren(new Option('Sign in to load models', ''));
  status(revoked ? 'Disconnected.' : 'Removed local credentials. Remote revocation was not confirmed; disconnect this app in ChatGPT settings.');
});
await run(async () => { signedIn = await connected(); if (signedIn) { await catalog(); status('Restored saved connection.'); } });
