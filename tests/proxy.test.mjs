import {test} from 'node:test';
import assert from 'node:assert/strict';

// Exercise the real client transport without credentials or an upstream service.
test('multiplexed streams, scoped errors/cancellation, and session shutdown', async () => {
  const original = globalThis.WebSocket;
  let socket;
  globalThis.WebSocket = class {
    static OPEN = 1;
    readyState = 1;
    sent = [];
    constructor() { socket = this; queueMicrotask(() => this.json({type:'ready',protocol:1})); }
    send(raw) { this.sent.push(JSON.parse(raw)); }
    close() { this.readyState = 3; }
    json(data) { this.onmessage?.({data:JSON.stringify(data)}); }
    chunk(id, text) {
      const bytes = new TextEncoder().encode(text), data = new ArrayBuffer(bytes.length + 4);
      new DataView(data).setUint32(0, id); new Uint8Array(data, 4).set(bytes);
      this.onmessage?.({data});
    }
  };
  const proxy = await import('../demo/proxy.js');
  const headers = id => socket.json({id,type:'headers',status:200,content_type:'text/plain'});
  const end = id => socket.json({id,type:'end'});
  try {
    await proxy.connectProxy(17653);
    const first = proxy.proxyRequest('responses', {}), second = proxy.proxyRequest('responses', {});
    assert.deepEqual(socket.sent.map(m => [m.type,m.id]), [['request',1],['request',2]]);
    headers(2); headers(1);
    const firstText = (await first).text(), secondText = (await second).text();
    socket.chunk(2, 'second '); socket.chunk(1, 'first ');
    socket.chunk(2, 'reply'); end(2); socket.chunk(1, 'reply'); end(1);
    assert.deepEqual(await Promise.all([firstText,secondText]), ['first reply','second reply']);

    const failed = proxy.proxyRequest('models', {}), unaffected = proxy.proxyRequest('models', {});
    const failure = assert.rejects(failed, /limit/);
    socket.json({id:3,type:'error',message:'Session limit reached'});
    headers(4); socket.chunk(4, 'ok'); end(4);
    await failure; assert.equal(await (await unaffected).text(), 'ok');
    assert.equal(proxy.proxyConnected(), true);

    const abort = new AbortController();
    const cancelled = proxy.proxyRequest('models', {}, undefined, {signal:abort.signal});
    const cancellation = assert.rejects(cancelled, {name:'AbortError'});
    abort.abort(); await cancellation;
    assert.deepEqual(socket.sent.at(-1), {type:'cancel',id:5});
    // Late frames after cancellation must not break another stream.
    headers(5); socket.chunk(5, 'discard'); end(5);
    const streaming = proxy.proxyRequest('responses', {});
    headers(6); const response = await streaming;
    await response.body.cancel();
    assert.deepEqual(socket.sent.at(-1), {type:'cancel',id:6});
    assert.equal(proxy.proxyConnected(), true);

    const active = proxy.proxyRequest('models', {}), waiting = proxy.proxyRequest('models', {});
    headers(7);
    const text = (await active).text();
    const stopped = Promise.all([assert.rejects(text, /stopped/), assert.rejects(waiting, /stopped/)]);
    socket.onclose(); await stopped;
    assert.equal(proxy.proxyConnected(), false);

    // An already-aborted request must never be sent.
    await proxy.connectProxy(17653);
    await assert.rejects(proxy.proxyRequest('models', {}, undefined, {signal:abort.signal}), {name:'AbortError'});
    assert.equal(socket.sent.length, 0);
  } finally { proxy.closeProxy(); globalThis.WebSocket = original; }
});
