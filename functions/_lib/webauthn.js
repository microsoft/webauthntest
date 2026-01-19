import { decode as cborDecode, encode as cborEncode } from 'cbor-x';
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
  const key = cborDecode(coseKeyBytes);

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

  // AKP etc not supported in edge version yet
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

  // Edge-native: keep attestation statement hex/summary but do not verify certificate chains.
  const fmt = String(attestationObject.fmt || 'unknown');
  let attStmtHex = 'UNVERIFIED';
  try {
    if (typeof attestationObject.attStmt !== 'undefined') {
      attStmtHex = bytesToHex(new Uint8Array(cborEncode(attestationObject.attStmt)));
    }
  } catch {
    attStmtHex = 'UNVERIFIED';
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
