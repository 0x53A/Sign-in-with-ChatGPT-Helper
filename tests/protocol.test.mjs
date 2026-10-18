import {test} from 'node:test';
import assert from 'node:assert/strict';
import {zip, unzip} from '../demo/zip.js';
import {streamText} from '../demo/client.js';
test('ZIP transport round trip and tampering', () => {
  const value = zip('request.json', '{"origin":"https://example.com","name":"水"}');
  assert.match(unzip(value, 'request.json'), /水/);
  assert.throws(() => unzip(value, 'response.json'));
  const damaged = value.slice(); damaged[45] ^= 1; assert.throws(() => unzip(damaged, 'request.json'));
  assert.throws(() => unzip(value.slice(0, -1), 'request.json'));
});
function body(events) {
  const bytes = new TextEncoder().encode(events.map(e => 'data: ' + JSON.stringify(e) + '\r\n\r\n').join(''));
  return new ReadableStream({start(c) { for (let i = 0; i < bytes.length; i += 3) c.enqueue(bytes.slice(i, i + 3)); c.close(); }});
}
test('stream handles UTF-8 boundaries and requires completion', async () => {
  let text = '';
  await streamText(body([{type:'response.output_text.delta', delta:'水 🌊'}, {type:'response.completed', response:{status:'completed'}}]), s => text += s);
  assert.equal(text, '水 🌊');
  await assert.rejects(streamText(body([{type:'response.output_text.delta', delta:'partial'}]), () => {}), /before completion/);
  await assert.rejects(streamText(body([{type:'response.failed'}]), () => {}), /failed/);
});
