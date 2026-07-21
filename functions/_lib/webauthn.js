import { decode as cborDecode, decodeMultiple as cborDecodeMultiple, encode as cborEncode } from 'cbor-x';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  base64UrlToBytes,
  base64ToBytes,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  normalizeBase64Url,
  utf8ToBytes,
  jsonToBase64Url,
  base64UrlToJson,
} from './base64.js';
import { sha256Utf8, sha256Bytes, hmacSha256Base64Url, timingSafeEqual } from './crypto.js';

const CHALLENGE_COOKIE = 'webauthn_chal';
const CHALLENGE_EXPIRY_MS = 5 * 60 * 1000;

function randomChallengeBase64Url() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

function formatUuidFromBytes(u8) {
  const b = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8);
  const hex = Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
  return (
    hex.slice(0, 8) + '-' +
    hex.slice(8, 12) + '-' +
    hex.slice(12, 16) + '-' +
    hex.slice(16, 20) + '-' +
    hex.slice(20)
  ).toUpperCase();
}

function coseToJwk(coseKeyBytes) {
  // COSE_Key is a CBOR map. Depending on decoder/runtime it may decode to a Map
  // or to a plain object with stringified integer keys.
  // Use decodeMultiple to handle cases where extra bytes (e.g., extension data) follow the COSE key
  const decoded = cborDecodeMultiple(coseKeyBytes);
  const key = decoded && decoded.length > 0 ? decoded[0] : cborDecode(coseKeyBytes);

  const get = (label) => {
    if (key && typeof key.get === 'function') return key.get(label);
    if (key && typeof key === 'object') return key[label] ?? key[String(label)];
    return undefined;
  };
  // Expected map keys:
  // 1: kty (2=EC2, 3=RSA, 1=OKP)
  // 3: alg
  // -1: crv
  // -2: x
  // -3: y
  const kty = get(1);
  const alg = get(3);

  // EC2
  if (alg === -7 || alg === -35 || alg === -36) {
    const crv = get(-1);
    const x = get(-2);
    const y = get(-3);
    const namedCurve = crv === 1 ? 'P-256' : crv === 2 ? 'P-384' : crv === 3 ? 'P-521' : null;
    if (!namedCurve) throw new Error('Unknown EC curve');
    return {
      kty: 'EC',
      crv: namedCurve,
      x: bytesToBase64Url(new Uint8Array(x)),
      y: bytesToBase64Url(new Uint8Array(y)),
    };
  }

  // RSA
  if (alg === -257) {
    const n = get(-1);
    const e = get(-2);
    return {
      kty: 'RSA',
      n: bytesToBase64Url(new Uint8Array(n)),
      e: bytesToBase64Url(new Uint8Array(e)),
    };
  }

  // OKP (Ed25519)
  if (alg === -8 || kty === 1) {
    const crv = get(-1);
    const x = get(-2);
    const crvName = crv === 6 ? 'Ed25519' : null;
    if (!crvName) throw new Error('Unknown OKP curve');
    return {
      key: {
        kty: 'OKP',
        crv: crvName,
        x: bytesToBase64Url(new Uint8Array(x)).replace(/-/g, '+').replace(/_/g, '/'),
      },
      format: 'jwk',
    };
  }

  // AKP (ML-DSA / post-quantum). Public key is stored at COSE label -1.
  if (alg === -48 || alg === -49 || alg === -50) {
    const pub = get(-1);
    const algName = alg === -48 ? 'ML-DSA-44' : alg === -49 ? 'ML-DSA-65' : 'ML-DSA-87';
    return {
      kty: 'AKP',
      alg: algName,
      pub: bytesToBase64Url(new Uint8Array(pub)),
    };
  }

  throw new Error('Unknown public key algorithm');
}

function coseToHex(coseKeyBytes) {
  return bytesToHex(coseKeyBytes);
}

function parseAuthenticatorData(authDataBytes) {
  const authData = authDataBytes instanceof Uint8Array ? authDataBytes : new Uint8Array(authDataBytes);
  if (authData.length < 37) throw new Error('authData too short');

  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];

  const out = {
    rpIdHash,
    flags,
    signCount,
    attestedCredentialData: undefined,
    extensionDataHex: undefined,
  };

  if (flags & 64) {
    const aaguidBytes = authData.slice(37, 53);
    const aaguid = formatUuidFromBytes(aaguidBytes);
    const credentialIdLength = (authData[53] << 8) | authData[54];
    const credentialId = authData.slice(55, 55 + credentialIdLength);
    const publicKeyBytes = authData.slice(55 + credentialIdLength);
    const publicKeyHex = coseToHex(publicKeyBytes);
    const publicKey = coseToJwk(publicKeyBytes);

    out.attestedCredentialData = {
      aaguid,
      credentialId,
      credentialIdLength,
      publicKeyHex,
      publicKey,
    };
  }

  // Extension parsing is optional in this playground; keep hex if present.
  if (flags & 128) {
    try {
      const extensionData = cborDecode(authData.slice(37));
      const encoded = new TextEncoder().encode(JSON.stringify(extensionData));
      out.extensionDataHex = bytesToHex(encoded);
    } catch {
      out.extensionDataHex = 'No extension data';
    }
  } else {
    out.extensionDataHex = 'No extension data';
  }

  return out;
}

function summarizeAuthenticatorData(authenticatorData) {
  const f = authenticatorData.flags;
  return `UP=${(f & 1) ? '1' : '0'}, UV=${(f & 4) ? '1' : '0'}, BE=${(f & 8) ? '1' : '0'}, BS=${(f & 16) ? '1' : '0'}, AT=${(f & 64) ? '1' : '0'}, ED=${(f & 128) ? '1' : '0'}, SignCount=${authenticatorData.signCount}`;
}

async function importVerifyKey(publicKey) {
  if (publicKey.kty === 'RSA') {
    return crypto.subtle.importKey(
      'jwk',
      publicKey,
      { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
      false,
      ['verify']
    );
  }

  if (publicKey.kty === 'EC') {
    const namedCurve = publicKey.crv;
    return crypto.subtle.importKey(
      'jwk',
      publicKey,
      { name: 'ECDSA', namedCurve },
      false,
      ['verify']
    );
  }

  // Ed25519 support varies by runtime; try if available.
  if (publicKey.key && publicKey.key.kty === 'OKP') {
    return crypto.subtle.importKey(
      'jwk',
      publicKey.key,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
  }

  throw new Error('Unsupported key type');
}

async function verifySignature(publicKey, dataBytes, sigBytes) {
  // AKP (ML-DSA / post-quantum): the Workers WebCrypto runtime does not support
  // ML-DSA, so verification is performed with the pure-JS @noble/post-quantum
  // implementation (FIPS-204). The COSE key stores the raw public key at label
  // -1, exposed here as publicKey.pub (base64url).
  if (publicKey.kty === 'AKP') {
    const mldsa = publicKey.alg === 'ML-DSA-44' ? ml_dsa44
      : publicKey.alg === 'ML-DSA-65' ? ml_dsa65
      : publicKey.alg === 'ML-DSA-87' ? ml_dsa87
      : null;
    if (!mldsa) throw new Error(`Unsupported AKP algorithm ${publicKey.alg}`);
    const pub = base64UrlToBytes(publicKey.pub);
    const msg = dataBytes instanceof Uint8Array ? dataBytes : new Uint8Array(dataBytes);
    const s = sigBytes instanceof Uint8Array ? sigBytes : new Uint8Array(sigBytes);
    return mldsa.verify(s, msg, pub);
  }

  const key = await importVerifyKey(publicKey);

  if (publicKey.kty === 'RSA') {
    return crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      sigBytes,
      dataBytes
    );
  }

  if (publicKey.kty === 'EC') {
    const hashName = publicKey.crv === 'P-384' ? 'SHA-384' : publicKey.crv === 'P-521' ? 'SHA-512' : 'SHA-256';

    const verify = (signatureBytes) =>
      crypto.subtle.verify(
        { name: 'ECDSA', hash: { name: hashName } },
        key,
        signatureBytes,
        dataBytes
      );

    // Cloudflare Workers WebCrypto has historically differed in whether it expects
    // ECDSA signatures as ASN.1 DER (WebAuthn standard) vs raw P-1363 (r||s).
    // Try both encodings for compatibility.
    const size = publicKey.crv === 'P-384' ? 48 : publicKey.crv === 'P-521' ? 66 : 32;

    const u8 = sigBytes instanceof Uint8Array ? sigBytes : new Uint8Array(sigBytes);
    let ok = await verify(u8);
    if (ok) return true;

    const asn1Len = (len) => {
      if (len < 0x80) return new Uint8Array([len]);
      // Long form
      const bytes = [];
      let n = len;
      while (n > 0) {
        bytes.unshift(n & 0xff);
        n >>= 8;
      }
      return new Uint8Array([0x80 | bytes.length, ...bytes]);
    };

    const derToRaw = (der, partLen) => {
      const d = der instanceof Uint8Array ? der : new Uint8Array(der);
      let offset = 0;
      if (d[offset++] !== 0x30) throw new Error('Not a DER sequence');

      let seqLen = d[offset++];
      if (seqLen & 0x80) {
        const n = seqLen & 0x7f;
        seqLen = 0;
        for (let i = 0; i < n; i++) seqLen = (seqLen << 8) | d[offset++];
      }

      if (d[offset++] !== 0x02) throw new Error('Expected INTEGER (r)');
      let rLen = d[offset++];
      if (rLen & 0x80) {
        const n = rLen & 0x7f;
        rLen = 0;
        for (let i = 0; i < n; i++) rLen = (rLen << 8) | d[offset++];
      }
      let r = d.slice(offset, offset + rLen);
      offset += rLen;

      if (d[offset++] !== 0x02) throw new Error('Expected INTEGER (s)');
      let sLen = d[offset++];
      if (sLen & 0x80) {
        const n = sLen & 0x7f;
        sLen = 0;
        for (let i = 0; i < n; i++) sLen = (sLen << 8) | d[offset++];
      }
      let s = d.slice(offset, offset + sLen);

      // Strip leading zero padding
      while (r.length > 1 && r[0] === 0x00) r = r.slice(1);
      while (s.length > 1 && s[0] === 0x00) s = s.slice(1);

      if (r.length > partLen || s.length > partLen) throw new Error('Invalid DER integer length');
      const out = new Uint8Array(partLen * 2);
      out.set(r, partLen - r.length);
      out.set(s, partLen * 2 - s.length);
      return out;
    };

    const rawToDer = (raw, partLen) => {
      const r0 = raw.slice(0, partLen);
      const s0 = raw.slice(partLen);

      const trimInt = (bytes) => {
        let b = bytes;
        while (b.length > 1 && b[0] === 0x00) b = b.slice(1);
        // If high bit set, prefix 0x00 to keep it positive.
        if (b[0] & 0x80) {
          const prefixed = new Uint8Array(b.length + 1);
          prefixed[0] = 0x00;
          prefixed.set(b, 1);
          b = prefixed;
        }
        return b;
      };

      const r = trimInt(r0);
      const s = trimInt(s0);

      const rLen = asn1Len(r.length);
      const sLen = asn1Len(s.length);
      const seqBodyLen = 2 + rLen.length + r.length + 2 + sLen.length + s.length;
      const seqLen = asn1Len(seqBodyLen);

      const out = new Uint8Array(1 + seqLen.length + seqBodyLen);
      let o = 0;
      out[o++] = 0x30;
      out.set(seqLen, o);
      o += seqLen.length;

      out[o++] = 0x02;
      out.set(rLen, o);
      o += rLen.length;
      out.set(r, o);
      o += r.length;

      out[o++] = 0x02;
      out.set(sLen, o);
      o += sLen.length;
      out.set(s, o);
      return out;
    };

    // Try DER->raw if signature looks DER.
    try {
      if (u8.length > 8 && u8[0] === 0x30) {
        ok = await verify(derToRaw(u8, size));
        if (ok) return true;
      }
    } catch {
      // ignore
    }

    // Try raw->DER if signature looks raw.
    try {
      if (u8.length === size * 2) {
        ok = await verify(rawToDer(u8, size));
        if (ok) return true;
      }
    } catch {
      // ignore
    }

    return false;
  }

  if (publicKey.key && publicKey.key.kty === 'OKP') {
    return crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      sigBytes,
      dataBytes
    );
  }

  throw new Error('Unsupported key type');
}

export function getValidHostname(request, env, clientHostname) {
  const reqHost = new URL(request.url).hostname;
  const valid = [env?.CUSTOM_DOMAIN, env?.HOSTNAME, reqHost, 'localhost'].filter(Boolean);

  if (clientHostname && clientHostname !== reqHost) {
    // Only allow the caller to use the actual request hostname.
    throw new Error('Invalid clientHostname');
  }

  // For Pages/Workers, the request hostname is the only safe default.
  return valid.includes(reqHost) ? reqHost : reqHost;
}

export async function issueChallenge(uid, hostname, type, env) {
  const challenge = randomChallengeBase64Url();
  const expiresAt = Date.now() + CHALLENGE_EXPIRY_MS;

  const payload = { c: challenge, u: uid, h: hostname, t: type, e: expiresAt };
  const payloadB64u = jsonToBase64Url(payload);

  const secret = env?.CHALLENGE_HMAC_SECRET;
  if (!secret) throw new Error('CHALLENGE_HMAC_SECRET is not configured');

  const sigB64u = await hmacSha256Base64Url(secret, utf8ToBytes(payloadB64u));
  const token = `${payloadB64u}.${sigB64u}`;

  return { challenge, token, expiresAt };
}

export async function verifyChallengeFromCookie(cookieValue, clientChallenge, uid, hostname, type, env) {
  if (!cookieValue) throw new Error('No challenge stored');

  const parts = String(cookieValue).split('.');
  if (parts.length !== 2) throw new Error('Invalid challenge token');

  const [payloadB64u, sigB64u] = parts;
  const secret = env?.CHALLENGE_HMAC_SECRET;
  if (!secret) throw new Error('CHALLENGE_HMAC_SECRET is not configured');

  const expectedSig = await hmacSha256Base64Url(secret, utf8ToBytes(payloadB64u));
  if (!timingSafeEqual(expectedSig, sigB64u)) throw new Error('Invalid challenge token');

  const payload = base64UrlToJson(payloadB64u);
  if (!payload || typeof payload !== 'object') throw new Error('Invalid challenge token');

  if (payload.u !== uid) throw new Error('Invalid challenge token');
  if (payload.h !== hostname) throw new Error('Invalid challenge token');
  if (payload.t !== type) throw new Error('Invalid challenge token');
  if (!payload.e || Date.now() > payload.e) throw new Error('Challenge expired');

  const clientB64u = normalizeBase64Url(clientChallenge);
  if (payload.c !== clientB64u) throw new Error('Invalid challenge in collectedClientData');

  return true;
}

function concatBytes(a, b) {
  const aa = a instanceof Uint8Array ? a : new Uint8Array(a);
  const bb = b instanceof Uint8Array ? b : new Uint8Array(b);
  const out = new Uint8Array(aa.length + bb.length);
  out.set(aa, 0);
  out.set(bb, aa.length);
  return out;
}

// Maps a parsed COSE public key (as produced by coseToJwk) to the COSE
// algorithm identifier it implies. Used to check self-attestation alg matches.
function expectedCoseAlgForKey(publicKey) {
  if (!publicKey) return null;
  if (publicKey.kty === 'EC') {
    return publicKey.crv === 'P-256' ? -7
      : publicKey.crv === 'P-384' ? -35
      : publicKey.crv === 'P-521' ? -36
      : null;
  }
  if (publicKey.kty === 'RSA') return -257;
  if (publicKey.key && publicKey.key.kty === 'OKP') {
    return publicKey.key.crv === 'Ed25519' ? -8 : null;
  }
  if (publicKey.kty === 'AKP') {
    return publicKey.alg === 'ML-DSA-44' ? -48
      : publicKey.alg === 'ML-DSA-65' ? -49
      : publicKey.alg === 'ML-DSA-87' ? -50
      : null;
  }
  return null;
}

// Maps a COSE algorithm identifier to its human-readable name, including the
// numeric COSE identifier, e.g. "ES384 (-35)". Falls back to "alg <n>" when the
// name is unknown.
function coseAlgName(alg) {
  const names = {
    [-7]: 'ES256', [-35]: 'ES384', [-36]: 'ES512',
    [-257]: 'RS256', [-258]: 'RS384', [-259]: 'RS512',
    [-37]: 'PS256', [-38]: 'PS384', [-39]: 'PS512',
    [-8]: 'EdDSA',
    [-65535]: 'RS1',
    [-48]: 'ML-DSA-44', [-49]: 'ML-DSA-65', [-50]: 'ML-DSA-87',
  };
  const name = names[alg];
  return name ? `${name} (${alg})` : `alg ${alg}`;
}

// Verifies a "packed" attestation statement (WebAuthn §8.2).
// - Self attestation (no x5c): fully verified with Workers WebCrypto using the
//   credential public key over authData || clientDataHash.
// - Full attestation (x5c present): the leaf certificate's public key is used to
//   verify the attestation signature. This proves possession of the attestation
//   private key, but the certificate chain is NOT validated to a trusted root
//   (FIDO MDS roots are not available on the edge yet).

// Minimal ASN.1 DER TLV reader.
function asn1ReadTlv(bytes, offset) {
  const tag = bytes[offset];
  let p = offset + 1;
  let len = bytes[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | bytes[p++];
  }
  return { tag, valueStart: p, length: len, end: p + len };
}

// Extracts the SubjectPublicKeyInfo (DER) from an X.509 certificate. Within a
// TBSCertificate the SPKI is the 5th SEQUENCE child (signature, issuer,
// validity, subject, subjectPublicKeyInfo); the optional version/serial fields
// are not SEQUENCEs so they do not affect the count.
function extractSpkiFromCert(certBytes) {
  const cert = asn1ReadTlv(certBytes, 0);               // Certificate SEQUENCE
  const tbs = asn1ReadTlv(certBytes, cert.valueStart);  // TBSCertificate SEQUENCE
  let p = tbs.valueStart;
  let seqCount = 0;
  while (p < tbs.end) {
    const child = asn1ReadTlv(certBytes, p);
    if (child.tag === 0x30) {
      seqCount++;
      if (seqCount === 5) return certBytes.slice(p, child.end);
    }
    p = child.end;
  }
  throw new Error('SubjectPublicKeyInfo not found in certificate');
}

// Extracts the raw public key bytes from a SubjectPublicKeyInfo DER structure:
//   SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
// Returns the BIT STRING contents with the leading "unused bits" byte removed.
// Used for algorithms (e.g. ML-DSA) whose verifier needs the raw key rather
// than a WebCrypto-importable SPKI.
function extractRawPublicKeyFromSpki(spki) {
  const seq = asn1ReadTlv(spki, 0);                 // SubjectPublicKeyInfo SEQUENCE
  const algId = asn1ReadTlv(spki, seq.valueStart);  // AlgorithmIdentifier SEQUENCE
  const bitStr = asn1ReadTlv(spki, algId.end);      // subjectPublicKey BIT STRING
  if (bitStr.tag !== 0x03) throw new Error('Expected BIT STRING in SubjectPublicKeyInfo');
  // First content byte is the count of unused bits (0 for byte-aligned keys).
  return spki.slice(bitStr.valueStart + 1, bitStr.end);
}

// Decodes a DER OBJECT IDENTIFIER value (content bytes) to a dotted string.
function decodeOid(bytes) {
  const out = [];
  const first = bytes[0];
  if (first < 40) out.push(0, first);
  else if (first < 80) out.push(1, first - 40);
  else out.push(2, first - 80);
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) { out.push(value); value = 0; }
  }
  return out.join('.');
}

// OID -> public key algorithm. For RSA the COSE alg is null because
// rsaEncryption does not encode the signature scheme (RS*/PS* + hash come from
// the attestation statement). For EC the COSE alg is resolved from the curve.
const SPKI_OID_ALG = {
  '1.2.840.113549.1.1.1': { name: 'RSA', coseAlg: null },
  '1.2.840.10045.2.1': { name: 'EC', coseAlg: null },
  '1.3.101.112': { name: 'Ed25519', coseAlg: -8 },
  '2.16.840.1.101.3.4.3.17': { name: 'ML-DSA-44', coseAlg: -48 },
  '2.16.840.1.101.3.4.3.18': { name: 'ML-DSA-65', coseAlg: -49 },
  '2.16.840.1.101.3.4.3.19': { name: 'ML-DSA-87', coseAlg: -50 },
};
const EC_CURVE_OID_ALG = {
  '1.2.840.10045.3.1.7': { curve: 'P-256', coseAlg: -7 },
  '1.3.132.0.34': { curve: 'P-384', coseAlg: -35 },
  '1.3.132.0.35': { curve: 'P-521', coseAlg: -36 },
};

// Identifies the public key algorithm (name, COSE identifier, OID) of a cert
// from its SubjectPublicKeyInfo AlgorithmIdentifier OID. For EC keys the named
// curve is read from the algorithm parameters to resolve the exact COSE alg.
function certPublicKeyAlgorithm(spki) {
  const seq = asn1ReadTlv(spki, 0);                    // SubjectPublicKeyInfo SEQUENCE
  const algId = asn1ReadTlv(spki, seq.valueStart);     // AlgorithmIdentifier SEQUENCE
  const oidTlv = asn1ReadTlv(spki, algId.valueStart);  // OBJECT IDENTIFIER
  if (oidTlv.tag !== 0x06) throw new Error('Expected OID in AlgorithmIdentifier');
  const oid = decodeOid(spki.slice(oidTlv.valueStart, oidTlv.end));
  const base = SPKI_OID_ALG[oid];
  if (!base) return { oid, name: `unknown (${oid})`, coseAlg: null };

  if (base.name === 'EC') {
    const curveTlv = asn1ReadTlv(spki, oidTlv.end);    // named-curve OID (parameters)
    if (curveTlv.tag === 0x06) {
      const curveOid = decodeOid(spki.slice(curveTlv.valueStart, curveTlv.end));
      const c = EC_CURVE_OID_ALG[curveOid];
      if (c) return { oid, curveOid, name: `EC ${c.curve}`, coseAlg: c.coseAlg };
    }
    return { oid, name: 'EC', coseAlg: null };
  }
  return { oid, name: base.name, coseAlg: base.coseAlg };
}

// Converts a DER-encoded ECDSA signature (SEQUENCE of two INTEGERs) to the raw
// r||s form expected by WebCrypto, left-padding each integer to partLen bytes.
function ecdsaDerToRaw(der, partLen) {
  const d = der instanceof Uint8Array ? der : new Uint8Array(der);
  let offset = 0;
  if (d[offset++] !== 0x30) throw new Error('Not a DER sequence');
  let seqLen = d[offset++];
  if (seqLen & 0x80) { const n = seqLen & 0x7f; seqLen = 0; for (let i = 0; i < n; i++) seqLen = (seqLen << 8) | d[offset++]; }
  if (d[offset++] !== 0x02) throw new Error('Expected INTEGER (r)');
  let rLen = d[offset++];
  let r = d.slice(offset, offset + rLen); offset += rLen;
  if (d[offset++] !== 0x02) throw new Error('Expected INTEGER (s)');
  let sLen = d[offset++];
  let s = d.slice(offset, offset + sLen); offset += sLen;
  while (r.length > partLen && r[0] === 0x00) r = r.slice(1);
  while (s.length > partLen && s[0] === 0x00) s = s.slice(1);
  const out = new Uint8Array(partLen * 2);
  out.set(r, partLen - r.length);
  out.set(s, partLen * 2 - s.length);
  return out;
}

// Verifies the packed attestation signature using the leaf certificate's public
// key. Supports ECDSA (ES256/384/512), RSASSA-PKCS1-v1_5 (RS256/384/512) and
// RSA-PSS (PS256/384/512) — all available in the Workers WebCrypto runtime.
async function verifyX5cLeafSignature(certBytes, alg, sigBytes, signedData) {
  const spki = extractSpkiFromCert(certBytes);

  const ecParams = {
    [-7]: { curve: 'P-256', hash: 'SHA-256', size: 32 },
    [-35]: { curve: 'P-384', hash: 'SHA-384', size: 48 },
    [-36]: { curve: 'P-521', hash: 'SHA-512', size: 66 },
  };
  const rsaPkcs1 = { [-257]: 'SHA-256', [-258]: 'SHA-384', [-259]: 'SHA-512', [-65535]: 'SHA-1' };
  const rsaPss = { [-37]: ['SHA-256', 32], [-38]: ['SHA-384', 48], [-39]: ['SHA-512', 64] };
  const mldsaAlg = { [-48]: ml_dsa44, [-49]: ml_dsa65, [-50]: ml_dsa87 };

  if (mldsaAlg[alg]) {
    // ML-DSA (post-quantum): verified with @noble/post-quantum using the raw
    // public key extracted from the leaf certificate's SubjectPublicKeyInfo.
    const mldsa = mldsaAlg[alg];
    const rawPub = extractRawPublicKeyFromSpki(spki);
    const s = sigBytes instanceof Uint8Array ? sigBytes : new Uint8Array(sigBytes);
    const msg = signedData instanceof Uint8Array ? signedData : new Uint8Array(signedData);
    return mldsa.verify(s, msg, rawPub);
  }

  if (ecParams[alg]) {
    const { curve, hash, size } = ecParams[alg];
    const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
    const u8 = sigBytes instanceof Uint8Array ? sigBytes : new Uint8Array(sigBytes);
    const doVerify = (s) => crypto.subtle.verify({ name: 'ECDSA', hash: { name: hash } }, key, s, signedData);
    // WebAuthn/X.509 ECDSA signatures are DER-encoded; TPM ECDSA signatures are
    // raw r||s. Accept both encodings.
    if (u8.length > 8 && u8[0] === 0x30) {
      try { if (await doVerify(ecdsaDerToRaw(u8, size))) return true; } catch { /* not DER; try raw */ }
    }
    if (u8.length === size * 2) {
      if (await doVerify(u8)) return true;
    }
    return false;
  }
  if (rsaPkcs1[alg]) {
    const hash = rsaPkcs1[alg];
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: { name: hash } }, false, ['verify']);
    return crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sigBytes, signedData);
  }
  if (rsaPss[alg]) {
    const [hash, saltLength] = rsaPss[alg];
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSA-PSS', hash: { name: hash } }, false, ['verify']);
    return crypto.subtle.verify({ name: 'RSA-PSS', saltLength }, key, sigBytes, signedData);
  }
  throw new Error(`unsupported x5c alg ${alg}`);
}

// --- TPM attestation (WebAuthn §8.3) ---------------------------------------

const TPM_ALG_RSA = 0x0001;
const TPM_ALG_ECC = 0x0023;
const TPM_GENERATED_VALUE = 0xff544347;
const TPM_ST_ATTEST_CERTIFY = 0x8017;
const TPM_HASH_NAME = { 0x0004: 'SHA-1', 0x000b: 'SHA-256', 0x000c: 'SHA-384', 0x000d: 'SHA-512' };
const TPM_ECC_CURVE = { 0x0003: 'P-256', 0x0004: 'P-384', 0x0005: 'P-521' };

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function stripLeadingZeros(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  return bytes.slice(i);
}

function bytesToInt(bytes) {
  let v = 0;
  for (let i = 0; i < bytes.length; i++) v = (v * 256) + bytes[i];
  return v;
}

// Maps a COSE signature algorithm to the WebCrypto digest name.
function coseAlgHash(alg) {
  if (alg === -65535) return 'SHA-1';   // RS1 (used by Windows TPM attestation)
  if (alg === -7 || alg === -257 || alg === -37) return 'SHA-256';
  if (alg === -35 || alg === -258 || alg === -38) return 'SHA-384';
  if (alg === -36 || alg === -259 || alg === -39) return 'SHA-512';
  return 'SHA-256';
}

// Big-endian TPM structure reader.
function tpmReader(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let o = 0;
  return {
    u16() { const v = (b[o] << 8) | b[o + 1]; o += 2; return v; },
    u32() { const v = ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; o += 4; return v; },
    skip(n) { o += n; },
    sized16() { const n = (b[o] << 8) | b[o + 1]; o += 2; const v = b.slice(o, o + n); o += n; return v; },
  };
}

// Parses a TPMT_PUBLIC (pubArea) structure into { type, nameAlg, rsa|ecc }.
function parseTpmPubArea(pubAreaBytes) {
  const r = tpmReader(pubAreaBytes);
  const type = r.u16();
  const nameAlg = r.u16();
  r.u32();      // objectAttributes
  r.sized16();  // authPolicy
  const out = { type, nameAlg };
  if (type === TPM_ALG_RSA) {
    r.u16();    // symmetric
    r.u16();    // scheme
    const keyBits = r.u16();
    let exponent = r.u32();
    if (exponent === 0) exponent = 65537;
    const modulus = r.sized16();
    out.rsa = { keyBits, exponent, modulus };
  } else if (type === TPM_ALG_ECC) {
    r.u16();    // symmetric
    r.u16();    // scheme
    const curveId = r.u16();
    r.u16();    // kdf
    const x = r.sized16();
    const y = r.sized16();
    out.ecc = { curve: TPM_ECC_CURVE[curveId] || null, x, y };
  } else {
    throw new Error(`unsupported TPM key type 0x${type.toString(16)}`);
  }
  return out;
}

// Parses a TPMS_ATTEST (certInfo) structure for the fields we validate.
function parseTpmCertInfo(certInfoBytes) {
  const r = tpmReader(certInfoBytes);
  const magic = r.u32();
  const type = r.u16();
  r.sized16();                 // qualifiedSigner (TPM2B_NAME)
  const extraData = r.sized16(); // TPM2B_DATA
  r.skip(17);                  // clockInfo: UINT64 + UINT32 + UINT32 + BYTE
  r.skip(8);                   // firmwareVersion (UINT64)
  const attestedName = r.sized16(); // TPMS_CERTIFY_INFO.name (TPM2B_NAME)
  return { magic, type, extraData, attestedName };
}

// Checks that the TPM pubArea key equals the attested credential public key.
function tpmPubMatchesCredential(pub, credentialPublicKey) {
  if (!credentialPublicKey) return false;
  if (credentialPublicKey.kty === 'RSA' && pub.rsa) {
    const n = base64UrlToBytes(credentialPublicKey.n);
    if (!bytesEqual(stripLeadingZeros(pub.rsa.modulus), stripLeadingZeros(n))) return false;
    return pub.rsa.exponent === bytesToInt(base64UrlToBytes(credentialPublicKey.e));
  }
  if (credentialPublicKey.kty === 'EC' && pub.ecc) {
    if (pub.ecc.curve !== credentialPublicKey.crv) return false;
    const x = base64UrlToBytes(credentialPublicKey.x);
    const y = base64UrlToBytes(credentialPublicKey.y);
    return bytesEqual(stripLeadingZeros(pub.ecc.x), stripLeadingZeros(x))
      && bytesEqual(stripLeadingZeros(pub.ecc.y), stripLeadingZeros(y));
  }
  return false;
}

// Verifies a "tpm" attestation statement (WebAuthn §8.3). The AIK certificate
// chain is not validated to a trusted root (FIDO MDS roots are unavailable on
// the edge yet); the attestation signature and all structural bindings are.
async function verifyTpmAttestation(attStmt, authDataBytes, clientDataHash, credentialPublicKey) {
  const get = (k) => (attStmt && typeof attStmt.get === 'function') ? attStmt.get(k) : (attStmt ? attStmt[k] : undefined);
  const alg = get('alg');
  const sig = get('sig');
  const x5c = get('x5c');
  const certInfo = get('certInfo');
  const pubArea = get('pubArea');
  const ver = get('ver');

  if (ver && String(ver) !== '2.0') return { verified: false, detail: `TPM: unsupported ver ${ver}` };
  if (!sig || !x5c || !x5c.length || !certInfo || !pubArea) return { verified: false, detail: 'TPM: missing attestation fields' };

  const toU8 = (v) => (v instanceof Uint8Array ? v : new Uint8Array(v));
  const sigBytes = toU8(sig);
  const certInfoBytes = toU8(certInfo);
  const pubAreaBytes = toU8(pubArea);
  const algName = coseAlgName(alg);

  try {
    // 1. pubArea public key must match the attested credential public key.
    const pub = parseTpmPubArea(pubAreaBytes);
    if (!tpmPubMatchesCredential(pub, credentialPublicKey)) {
      return { verified: false, detail: 'TPM: pubArea does not match credential public key' };
    }

    // 2. certInfo structural checks.
    const ci = parseTpmCertInfo(certInfoBytes);
    if (ci.magic !== TPM_GENERATED_VALUE) return { verified: false, detail: 'TPM: invalid magic in certInfo' };
    if (ci.type !== TPM_ST_ATTEST_CERTIFY) return { verified: false, detail: 'TPM: certInfo is not TPM_ST_ATTEST_CERTIFY' };

    // extraData must equal hash(authData || clientDataHash) using the sig hash.
    const attToBeSigned = concatBytes(authDataBytes, clientDataHash);
    const extraExpected = new Uint8Array(await crypto.subtle.digest(coseAlgHash(alg), attToBeSigned));
    if (!bytesEqual(ci.extraData, extraExpected)) return { verified: false, detail: 'TPM: certInfo extraData mismatch' };

    // attested name must equal nameAlg id (2 bytes) || Hash(pubArea) with nameAlg.
    const nameHash = TPM_HASH_NAME[pub.nameAlg];
    if (!nameHash) return { verified: false, detail: `TPM: unsupported nameAlg 0x${pub.nameAlg.toString(16)}` };
    const pubAreaHash = new Uint8Array(await crypto.subtle.digest(nameHash, pubAreaBytes));
    const expectedName = concatBytes(new Uint8Array([(pub.nameAlg >> 8) & 0xff, pub.nameAlg & 0xff]), pubAreaHash);
    if (!bytesEqual(ci.attestedName, expectedName)) return { verified: false, detail: 'TPM: attested name mismatch' };

    // 3. Verify the signature over certInfo with the AIK leaf certificate.
    const leaf = toU8(x5c[0]);
    const ok = await verifyX5cLeafSignature(leaf, alg, sigBytes, certInfoBytes);
    return ok
      ? { verified: true, detail: `TPM: Attestation verified using ${algName}` }
      : { verified: false, detail: `TPM: Signature invalid (${algName})` };
  } catch (e) {
    return { verified: false, detail: `TPM: ${e?.message || e}` };
  }
}

async function verifyPackedAttestation(attStmt, authDataBytes, clientDataHash, credentialPublicKey) {
  const get = (k) => (attStmt && typeof attStmt.get === 'function')
    ? attStmt.get(k)
    : (attStmt ? attStmt[k] : undefined);
  const alg = get('alg');
  const sig = get('sig');
  const x5c = get('x5c');

  if (typeof sig === 'undefined' || sig === null) {
    return { verified: false, detail: 'packed: missing signature' };
  }
  const sigBytes = sig instanceof Uint8Array ? sig : new Uint8Array(sig);
  const signedData = concatBytes(authDataBytes, clientDataHash);

  if (x5c && x5c.length) {
    const leaf = x5c[0];
    const certBytes = leaf instanceof Uint8Array ? leaf : new Uint8Array(leaf);
    const algName = coseAlgName(alg);
    try {
      const ok = await verifyX5cLeafSignature(certBytes, alg, sigBytes, signedData);
      return ok
        ? { verified: true, detail: `Packed (x5c): Attestation signature verified using ${algName}` }
        : { verified: false, detail: `Packed (x5c): Attestation signature invalid (${algName})` };
    } catch (e) {
      return { verified: false, detail: `Packed (x5c): ${e?.message || e}` };
    }
  }

  // Self attestation: alg must match the credential public key's algorithm.
  const expectedAlg = expectedCoseAlgForKey(credentialPublicKey);
  if (typeof alg !== 'undefined' && expectedAlg !== null && alg !== expectedAlg) {
    return { verified: false, detail: `Packed (self): alg ${alg} does not match credential key alg ${expectedAlg}` };
  }

  try {
    const ok = await verifySignature(credentialPublicKey, signedData, sigBytes);
    const algName = coseAlgName(typeof alg !== 'undefined' ? alg : expectedAlg);
    return ok
      ? { verified: true, detail: `Packed (self) Verified using ${algName}` }
      : { verified: false, detail: `Packed (self): Signature invalid (${algName})` };
  } catch (e) {
    return { verified: false, detail: `Packed (self): ${e?.message || e}` };
  }
}

export async function makeCredential(uid, attestation, hostname) {
  if (!attestation?.id) throw new Error('id is missing');
  if (!attestation?.attestationObject) throw new Error('attestationObject is missing');
  if (!attestation?.clientDataJSON) throw new Error('clientDataJSON is missing');

  let clientData;
  try {
    clientData = JSON.parse(attestation.clientDataJSON);
  } catch {
    throw new Error('clientDataJSON could not be parsed');
  }

  let origin;
  try {
    origin = new URL(clientData.origin);
  } catch {
    throw new Error('Invalid origin in collectedClientData');
  }

  if (origin.hostname !== hostname) throw new Error(`Invalid origin in collectedClientData. Expected hostname ${hostname}`);
  if (hostname !== 'localhost' && origin.protocol !== 'https:') throw new Error('Invalid origin in collectedClientData. Expected HTTPS protocol.');

  const clientDataHash = await sha256Utf8(attestation.clientDataJSON);

  const attObjBytes = base64ToBytes(attestation.attestationObject);
  const attestationObject = cborDecode(attObjBytes);

  const authDataBytes = new Uint8Array(attestationObject.authData);
  const authenticatorData = parseAuthenticatorData(authDataBytes);
  if (!authenticatorData.attestedCredentialData) throw new Error('Did not see AD flag in authenticatorData');

  const expectedRpId = (attestation && attestation.metadata && typeof attestation.metadata.rpId !== 'undefined')
    ? attestation.metadata.rpId
    : hostname;
  const expectedRpIdHash = await sha256Utf8(expectedRpId);
  if (bytesToHex(authenticatorData.rpIdHash) !== bytesToHex(expectedRpIdHash)) {
    throw new Error(`RPID hash does not match expected value: sha256(${expectedRpId})`);
  }

  if ((authenticatorData.flags & 1) === 0) throw new Error('User Present bit was not set.');

  // Edge-native attestation handling: "packed" self-attestation signatures are
  // verified with Workers WebCrypto. Certificate-chain formats (x5c, tpm,
  // android-key, apple, etc.) are not verified on the edge yet.
  const fmt = String(attestationObject.fmt || 'unknown');
  let attStmtHex = 'UNVERIFIED';
  try {
    if (typeof attestationObject.attStmt !== 'undefined') {
      attStmtHex = bytesToHex(new Uint8Array(cborEncode(attestationObject.attStmt)));
    }
  } catch {
    attStmtHex = 'UNVERIFIED';
  }

  let attestationVerified = false;
  let attestationVerification = `Verification Skipped`;
  if (fmt === 'none') {
    attestationVerification = 'None (no attestation)';
  } else if (fmt === 'packed') {
    const result = await verifyPackedAttestation(
      attestationObject.attStmt,
      authDataBytes,
      clientDataHash,
      authenticatorData.attestedCredentialData.publicKey,
    );
    attestationVerified = result.verified;
    attestationVerification = result.detail;
  } else if (fmt === 'tpm') {
    const result = await verifyTpmAttestation(
      attestationObject.attStmt,
      authDataBytes,
      clientDataHash,
      authenticatorData.attestedCredentialData.publicKey,
    );
    attestationVerified = result.verified;
    attestationVerification = result.detail;
  }

  const credential = {
    uid,
    id: bytesToBase64(authenticatorData.attestedCredentialData.credentialId),
    idHex: bytesToHex(authenticatorData.attestedCredentialData.credentialId),
    transports: attestation.transports,
    enabled: true,
    metadata: {
      rpId: expectedRpId,
      userName: attestation?.metadata?.userName,
      residentKey: !!attestation?.metadata?.residentKey,
    },
    creationData: {
      publicKey: JSON.stringify(authenticatorData.attestedCredentialData.publicKey),
      publicKeySummary: authenticatorData.attestedCredentialData.publicKey.kty,
      publicKeyHex: authenticatorData.attestedCredentialData.publicKeyHex,
      aaguid: authenticatorData.attestedCredentialData.aaguid,
      attestationStatementHex: attStmtHex || 'UNAVAILABLE',
      attestationStatementSummary: fmt,
      attestationVerified,
      attestationVerification,
      attestationStatementChainJSON: 'none',
      authenticatorDataSummary: summarizeAuthenticatorData(authenticatorData),
      authenticatorDataHex: bytesToHex(authDataBytes),
      extensionDataHex: authenticatorData.extensionDataHex,
      authenticatorData: attestation.authenticatorData,
      attestationObject: attestation.attestationObjectHex,
      clientDataJSON: attestation.clientDataJSON,
      clientDataJSONHex: bytesToHex(utf8ToBytes(attestation.clientDataJSON)),
      publicKey2: attestation.publicKey,
      publicKeyAlgorithm: attestation.publicKeyAlgorithm,
      authenticatorAttachment: attestation.authenticatorAttachment,
      prfEnabled: attestation.prfEnabled,
      prfFirst: attestation.prfFirst,
      prfSecond: attestation.prfSecond,
    },
    authenticationData: {
      authenticatorDataSummary: 'No authentications',
      signCount: authenticatorData.signCount,
      userHandleHex: 'none',
      authenticatorDataHex: 'none',
      clientDataJSON: 'none',
      clientDataJSONHex: 'none',
      signatureHex: 'none',
      extensionDataHex: 'No extension data',
      authenticatorAttachment: 'none',
      prfFirst: 'none',
      prfSecond: 'none',
    },
  };

  return credential;
}

export async function verifyAssertion(credential, assertion, hostname) {
  if (!credential) throw new Error('Credential not found');

  let clientData;
  try {
    clientData = JSON.parse(assertion.clientDataJSON);
  } catch {
    throw new Error('clientDataJSON could not be parsed');
  }

  let origin;
  try {
    origin = new URL(clientData.origin);
  } catch {
    throw new Error('Invalid origin in collectedClientData');
  }

  if (origin.hostname !== hostname) throw new Error(`Invalid origin in collectedClientData. Expected hostname ${hostname}`);
  if (hostname !== 'localhost' && origin.protocol !== 'https:') throw new Error('Invalid origin in collectedClientData. Expected HTTPS protocol.');

  const authData = base64ToBytes(assertion.authenticatorData);
  const sig = base64ToBytes(assertion.signature);

  const authenticatorData = parseAuthenticatorData(authData);

  const expectedRpId = (assertion && assertion.metadata && typeof assertion.metadata.rpId !== 'undefined')
    ? assertion.metadata.rpId
    : hostname;
  const expectedRpIdHash = await sha256Utf8(expectedRpId);
  if (bytesToHex(authenticatorData.rpIdHash) !== bytesToHex(expectedRpIdHash)) {
    throw new Error(`RPID hash does not match expected value: sha256(${expectedRpId})`);
  }

  if ((authenticatorData.flags & 1) === 0) throw new Error('User Present bit was not set.');

  const clientHash = await sha256Utf8(assertion.clientDataJSON);
  const data = new Uint8Array(authData.length + clientHash.length);
  data.set(authData, 0);
  data.set(clientHash, authData.length);

  const publicKey = JSON.parse(credential.creationData.publicKey);
  const ok = await verifySignature(publicKey, data, sig);
  if (!ok) throw new Error('Could not verify signature');

  const prevSignCount = credential?.authenticationData?.signCount ?? 0;
  if (authenticatorData.signCount !== 0 && authenticatorData.signCount < prevSignCount) {
    throw new Error(`Received signCount of ${authenticatorData.signCount} expected signCount > ${prevSignCount}`);
  }

  credential.authenticationData = {
    authenticatorDataSummary: summarizeAuthenticatorData(authenticatorData),
    signCount: authenticatorData.signCount,
    userHandleHex: assertion.userHandle ? bytesToHex(base64ToBytes(assertion.userHandle)) : 'none',
    authenticatorDataHex: bytesToHex(authData),
    clientDataJSON: assertion.clientDataJSON,
    clientDataJSONHex: bytesToHex(utf8ToBytes(assertion.clientDataJSON)),
    signatureHex: bytesToHex(sig),
    extensionDataHex: authenticatorData.extensionDataHex,
    authenticatorAttachment: assertion.authenticatorAttachment,
    prfFirst: assertion.prfFirst,
    prfSecond: assertion.prfSecond,
  };

  return credential;
}

export async function validateClientDataFromCookie(clientData, uid, hostname, type, cookies, env) {
  if (clientData.type !== type) throw new Error(`collectedClientData type was expected to be ${type}`);
  const token = cookies[CHALLENGE_COOKIE];
  await verifyChallengeFromCookie(token, clientData.challenge, uid, hostname, type, env);
}

export function challengeCookieName() {
  return CHALLENGE_COOKIE;
}
