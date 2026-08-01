const textEncoder = new TextEncoder();

export function utf8ToBytes(str) {
  return textEncoder.encode(String(str));
}

export function bytesToHex(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = '';
  for (let i = 0; i < u8.length; i++) out += u8[i].toString(16).padStart(2, '0');
  return out.toUpperCase();
}

export function bytesToBase64Url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// Standard base64 (with +/ and padding)
export function bytesToBase64(bytes) {
  let b64 = bytesToBase64Url(bytes).replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return b64;
}

export function base64UrlToBytes(b64u) {
  const s = String(b64u || '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const b64 = s + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Accepts either standard base64 or base64url and returns bytes.
export function base64ToBytes(b64) {
  return base64UrlToBytes(normalizeBase64Url(b64));
}

export function normalizeBase64Url(b64u) {
  let s = String(b64u || '').trim();
  s = s.replace(/\+/g, '-').replace(/\//g, '_');
  s = s.replace(/=+$/g, '');
  return s;
}

export function jsonToBase64Url(obj) {
  return bytesToBase64Url(utf8ToBytes(JSON.stringify(obj)));
}

export function base64UrlToJson(b64u) {
  const bytes = base64UrlToBytes(b64u);
  const str = new TextDecoder().decode(bytes);
  return JSON.parse(str);
}
