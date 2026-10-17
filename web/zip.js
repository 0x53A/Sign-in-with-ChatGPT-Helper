// One stored entry, ZIP32. No dependency, compression or filesystem extraction.
const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', {fatal: true});
function crc(bytes) {
  let n = 0xffffffff;
  for (const b of bytes) { n ^= b; for (let i = 0; i < 8; i++) n = (n >>> 1) ^ (0xedb88320 & -(n & 1)); }
  return (n ^ 0xffffffff) >>> 0;
}
export function zip(name, text) {
  const filename = encoder.encode(name), data = encoder.encode(text), size = data.length, sum = crc(data);
  const bytes = new Uint8Array(30 + filename.length + size + 46 + filename.length + 22), v = new DataView(bytes.buffer);
  const local = 30 + filename.length + size, end = local + 46 + filename.length;
  const u16 = (at, n) => v.setUint16(at, n, true), u32 = (at, n) => v.setUint32(at, n, true);
  u32(0, 0x04034b50); u16(4, 20); u32(14, sum); u32(18, size); u32(22, size); u16(26, filename.length);
  bytes.set(filename, 30); bytes.set(data, 30 + filename.length);
  u32(local, 0x02014b50); u16(local + 4, 20); u16(local + 6, 20); u32(local + 16, sum);
  u32(local + 20, size); u32(local + 24, size); u16(local + 28, filename.length); bytes.set(filename, local + 46);
  u32(end, 0x06054b50); u16(end + 8, 1); u16(end + 10, 1); u32(end + 12, 46 + filename.length); u32(end + 16, local);
  return bytes;
}
export function unzip(bytes, name) {
  if (bytes.length < 98 || bytes.length > 262144) throw Error('Invalid package size.');
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = at => v.getUint16(at, true), u32 = at => v.getUint32(at, true);
  const end = bytes.length - 22, central = u32(end + 16), len = u16(26), extra = u16(28), size = u32(18);
  if (u32(0) !== 0x04034b50 || u16(6) !== 0 || u16(8) !== 0 || size !== u32(22) ||
      u32(end) !== 0x06054b50 || u16(end + 4) || u16(end + 6) || u16(end + 8) !== 1 || u16(end + 10) !== 1 || u16(end + 20) ||
      central !== 30 + len + extra + size || central + 46 > end || u32(central) !== 0x02014b50 ||
      u32(central + 42) !== 0 || u16(central + 8) !== 0 || u16(central + 10) !== 0 ||
      u32(central + 20) !== size || u32(central + 24) !== size || u32(central + 16) !== u32(14) ||
      central + 46 + u16(central + 28) + u16(central + 30) + u16(central + 32) !== end || u32(end + 12) !== end - central ||
      decoder.decode(bytes.slice(30, 30 + len)) !== name || decoder.decode(bytes.slice(central + 46, central + 46 + u16(central + 28))) !== name) throw Error('Expected a single stored JSON file.');
  const data = bytes.slice(30 + len + extra, central);
  if (crc(data) !== u32(14)) throw Error('Package checksum mismatch.');
  return decoder.decode(data);
}
