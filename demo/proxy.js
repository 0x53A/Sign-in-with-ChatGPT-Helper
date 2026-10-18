// Click-approved, multiplexed connection. Request errors never trigger retries.
let socket, opening, timer, nextId = 0, changed = () => {};
const pending = new Map();
export const proxyConnected = () => socket?.readyState === WebSocket.OPEN && !opening;
export const proxyConnecting = () => !!opening;
export function onProxyChange(fn) { changed = fn; }
export function closeProxy() { fail(Error('Proxy disconnected. Connect and approve a new session.')); }
function remove(id) {
  const request = pending.get(id);
  if (!request) return;
  pending.delete(id); clearTimeout(request.timer); request.cleanup?.();
  return request;
}
function rejectRequest(id, error) {
  const request = remove(id);
  request?.controller?.error(error); request?.reject(error);
}
function cancel(id, error) {
  if (!pending.has(id)) return;
  rejectRequest(id, error);
  try { socket?.send(JSON.stringify({type:'cancel', id})); }
  catch { fail(Error('Proxy connection closed.')); }
}
function fail(error) {
  clearTimeout(timer);
  const old = socket; socket = null;
  if (old) { old.onmessage = old.onerror = old.onclose = null; old.close(); }
  opening?.reject(error); opening = null;
  for (const id of pending.keys()) rejectRequest(id, error);
  changed(false);
}
function reply(id) {
  if (!Number.isInteger(id) || id < 1 || id > nextId) throw Error('Invalid proxy request ID.');
  // Replies already in transit after cancellation/timeout are harmless. IDs are
  // never reused on this connection, so they cannot reach a later request.
  return pending.get(id);
}
export async function connectProxy(port) {
  if (socket) throw Error('A proxy connection already exists.');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error('Enter a helper port from 1 to 65535.');
  return new Promise((resolve, reject) => {
    opening = {resolve, reject}; nextId = 0;
    changed(false);
    try { socket = new WebSocket(`ws://127.0.0.1:${port}/proxy`); }
    catch { fail(Error('Cannot connect to helper.')); return; }
    socket.binaryType = 'arraybuffer';
    timer = setTimeout(() => fail(Error('Proxy approval timed out.')), 125000);
    socket.onerror = () => fail(Error('Cannot reach helper. Check its port and local-network permission.'));
    socket.onclose = () => fail(Error('Helper stopped or closed the proxy session.'));
    socket.onmessage = ({data}) => {
      try {
        if (data instanceof ArrayBuffer) {
          if (data.byteLength < 4) throw Error('Invalid proxy data.');
          const id = new DataView(data).getUint32(0), request = reply(id);
          if (!request) return;
          if (!request.controller) throw Error('Unexpected proxy data.');
          request.bytes += data.byteLength - 4;
          if (request.bytes > 8 * 1024 * 1024) {
            cancel(id, Error('Proxy response exceeds demo limit.')); return;
          }
          request.controller.enqueue(new Uint8Array(data, 4)); return;
        }
        if (typeof data !== 'string' || data.length > 262144) throw Error('Invalid proxy message.');
        const message = JSON.parse(data);
        if (message.type === 'ready' && message.protocol === 1 && opening) {
          clearTimeout(timer); const ready = opening; opening = null; changed(true); ready.resolve(); return;
        }
        const request = reply(message.id);
        if (!request) return;
        if (message.type === 'error') {
          rejectRequest(message.id, Error(typeof message.message === 'string' ? message.message : 'Proxy request failed.')); return;
        }
        if (message.type === 'headers' && !request.controller && ['models','responses'].includes(request.endpoint)) {
          const body = new ReadableStream({
            start(controller) { request.controller = controller; },
            cancel() { cancel(message.id, new DOMException('Request cancelled.', 'AbortError')); },
          });
          request.resolve(new Response([204,205,304].includes(message.status) ? null : body, {
            status: message.status, headers: {'Content-Type':message.content_type},
          }));
        } else if (message.type === 'end' && request.controller) {
          request.controller.close(); remove(message.id);
        } else if ((message.type === 'credentials' && request.endpoint === 'refresh') ||
                   (message.type === 'revoked' && request.endpoint === 'revoke')) {
          request.resolve(message.credentials); remove(message.id);
        } else throw Error('Unexpected proxy reply.');
      } catch (error) { fail(error); }
    };
  });
}
export function proxyRequest(endpoint, credentials, body, {signal} = {}) {
  if (!proxyConnected()) return Promise.reject(Error('Connect to the proxy and approve it in the helper.'));
  if (signal?.aborted) return Promise.reject(signal.reason);
  if (nextId === 0xffffffff) return Promise.reject(Error('Request IDs exhausted; reconnect the proxy.'));
  const id = ++nextId;
  const message = JSON.stringify({type:'request', id, request:{endpoint, credentials, ...(body === undefined ? {} : {body})}});
  if (new TextEncoder().encode(message).length > 1024 * 1024) return Promise.reject(Error('Request exceeds 1 MiB limit.'));
  return new Promise((resolve, reject) => {
    const abort = () => cancel(id, signal.reason);
    pending.set(id, {resolve, reject, endpoint, bytes:0,
      timer:setTimeout(() => cancel(id, Error('Proxy request timed out. It was not retried.')), 135000),
      cleanup:() => signal?.removeEventListener('abort', abort),
    });
    signal?.addEventListener('abort', abort, {once:true});
    try { socket.send(message); } catch { fail(Error('Proxy connection closed.')); }
  });
}
