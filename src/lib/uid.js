import { sha256Utf8, hmacSha256Base64Url } from './crypto.js';
import { bytesToHex, utf8ToBytes, base64UrlToBytes } from './base64.js';

export function normalizeUsername(username) {
  return String(username || '').trim().toLowerCase();
}

export async function hashUsername(username, uidHashSecret) {
  const normalized = normalizeUsername(username);
  if (uidHashSecret && String(uidHashSecret).length > 0) {
    // hex(HMAC-SHA256(secret, normalized))
    const sigB64u = await hmacSha256Base64Url(String(uidHashSecret), utf8ToBytes(normalized));
    // Convert base64url signature bytes to hex
    const bytes = base64UrlToBytes(sigB64u);
    return bytesToHex(bytes);
  }
  const digest = await sha256Utf8(normalized);
  return bytesToHex(digest);
}
