import { utf8ToBytes, bytesToBase64Url } from './base64.js';

export async function sha256Bytes(dataBytes) {
  const digest = await crypto.subtle.digest('SHA-256', dataBytes);
  return new Uint8Array(digest);
}

export async function sha256Utf8(str) {
  return sha256Bytes(utf8ToBytes(str));
}

export async function hmacSha256Base64Url(secret, dataBytes) {
  const key = await crypto.subtle.importKey(
    'raw',
    utf8ToBytes(String(secret)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, dataBytes);
  return bytesToBase64Url(new Uint8Array(sig));
}

export function timingSafeEqual(a, b) {
  const aa = String(a);
  const bb = String(b);
  if (aa.length !== bb.length) return false;
  let out = 0;
  for (let i = 0; i < aa.length; i++) out |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  return out === 0;
}
