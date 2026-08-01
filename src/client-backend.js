import { bytesToBase64Url, normalizeBase64Url } from './lib/base64.js';
import { hashUsername, normalizeUsername } from './lib/uid.js';
import { makeCredential, verifyAssertion } from './lib/webauthn.js';

const DB_NAME = 'passkey-playground';
const DB_VERSION = 1;
const STORE_NAME = 'credentials';
const CHALLENGES_KEY = 'passkey.pendingChallenges';
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB request failed'));
  });
}

function transactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error || new Error('IndexedDB transaction aborted'));
    transaction.onerror = () => reject(transaction.error || new Error('IndexedDB transaction failed'));
  });
}

function openDatabase() {
  if (!globalThis.indexedDB) {
    return Promise.reject(new Error('IndexedDB is not available in this browser'));
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      const store = db.createObjectStore(STORE_NAME, { keyPath: 'key' });
      store.createIndex('uidRpId', ['uid', 'rpId'], { unique: false });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Unable to open IndexedDB'));
  });
}

async function userId(username) {
  const normalized = normalizeUsername(username);
  if (!normalized || normalized.length < 3 || normalized.includes(' ')) {
    throw new Error('Invalid username. Please sign out and sign back in.');
  }
  return hashUsername(normalized);
}

function credentialKey(uid, id) {
  return `${uid}:${id}`;
}

function loadPendingChallenges() {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(CHALLENGES_KEY) || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function savePendingChallenges(challenges) {
  sessionStorage.setItem(CHALLENGES_KEY, JSON.stringify(challenges));
}

function prunePendingChallenges(challenges, now = Date.now()) {
  return challenges.filter((entry) => entry && entry.challenge && entry.expiresAt > now);
}

function validateClientData(payload, expectedType) {
  let clientData;
  try {
    clientData = JSON.parse(payload?.clientDataJSON);
  } catch {
    throw new Error('clientDataJSON could not be parsed');
  }

  if (clientData.type !== expectedType) {
    throw new Error(`collectedClientData type was expected to be ${expectedType}`);
  }

  const challenge = normalizeBase64Url(clientData.challenge);
  const now = Date.now();
  const pending = prunePendingChallenges(loadPendingChallenges(), now);
  const matchIndex = pending.findIndex(
    (entry) => entry.challenge === challenge && entry.type === expectedType
  );

  if (matchIndex < 0) {
    savePendingChallenges(pending);
    throw new Error('Challenge is missing, expired, or has already been used');
  }

  return pending[matchIndex].challenge;
}

function consumeChallenge(challenge) {
  const pending = prunePendingChallenges(loadPendingChallenges());
  const matchIndex = pending.findIndex((entry) => entry.challenge === challenge);
  if (matchIndex >= 0) pending.splice(matchIndex, 1);
  savePendingChallenges(pending);
}

async function getRecord(uid, id) {
  const db = await openDatabase();
  try {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    return await requestResult(transaction.objectStore(STORE_NAME).get(credentialKey(uid, id)));
  } finally {
    db.close();
  }
}

async function putCredential(credential, createdAt = Date.now()) {
  const db = await openDatabase();
  try {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    transaction.objectStore(STORE_NAME).put({
      key: credentialKey(credential.uid, credential.id),
      uid: credential.uid,
      rpId: credential.metadata.rpId,
      createdAt,
      data: credential,
    });
    await transactionDone(transaction);
  } finally {
    db.close();
  }
  return credential;
}

export function createChallenge(type = 'webauthn.get') {
  if (type !== 'webauthn.get' && type !== 'webauthn.create') {
    throw new Error('Invalid challenge type');
  }

  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const challenge = bytesToBase64Url(bytes);
  const pending = prunePendingChallenges(loadPendingChallenges());
  pending.push({ challenge, type, expiresAt: Date.now() + CHALLENGE_TTL_MS });
  savePendingChallenges(pending);
  return bytes.buffer;
}

export async function listCredentials(username, rpId) {
  const uid = await userId(username);
  const db = await openDatabase();
  try {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const index = transaction.objectStore(STORE_NAME).index('uidRpId');
    const records = await requestResult(index.getAll(IDBKeyRange.only([uid, rpId])));
    return records
      .sort((a, b) => b.createdAt - a.createdAt)
      .map((record) => record.data);
  } finally {
    db.close();
  }
}

export async function saveRegistration(username, attestation, hostname) {
  const challenge = validateClientData(attestation, 'webauthn.create');
  const uid = await userId(username);
  const credential = await makeCredential(uid, attestation, hostname);
  await putCredential(credential);
  consumeChallenge(challenge);
  return { id: credential.id };
}

export async function saveAssertion(username, assertion, hostname) {
  const challenge = validateClientData(assertion, 'webauthn.get');
  const uid = await userId(username);
  const record = await getRecord(uid, assertion.id);
  if (!record) throw new Error('Credential not found in this browser');
  if (record.data.enabled === false) throw new Error('Credential is disabled');

  const credential = await verifyAssertion(record.data, assertion, hostname);
  await putCredential(credential, record.createdAt);
  consumeChallenge(challenge);
  return credential;
}

export async function deleteCredential(username, id) {
  const uid = await userId(username);
  const db = await openDatabase();
  try {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    transaction.objectStore(STORE_NAME).delete(credentialKey(uid, id));
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

export async function updateCredentialTransports(username, id, transports) {
  const allowed = new Set(['internal', 'usb', 'nfc', 'ble', 'hybrid']);
  const clean = Array.isArray(transports)
    ? transports.filter((transport, index) => allowed.has(transport) && transports.indexOf(transport) === index)
    : [];
  const uid = await userId(username);
  const record = await getRecord(uid, id);
  if (!record) throw new Error('Credential not found in this browser');

  record.data.transports = clean;
  await putCredential(record.data, record.createdAt);
  return { id, transports: clean };
}

export async function updateCredentialEnabled(username, id, enabled) {
  if (typeof enabled !== 'boolean') throw new Error('enabled must be boolean');
  const uid = await userId(username);
  const record = await getRecord(uid, id);
  if (!record) throw new Error('Credential not found in this browser');

  record.data.enabled = enabled;
  await putCredential(record.data, record.createdAt);
  return { id, enabled };
}
