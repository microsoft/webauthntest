import { json } from '../_lib/http.js';
import { parseCookies } from '../_lib/cookies.js';
import { normalizeUsername, hashUsername } from '../_lib/uid.js';
import { updateCredentialFields } from '../_lib/storage_d1.js';

function getAllowedTransports(transports) {
  const allowed = new Set(['internal', 'usb', 'nfc', 'ble', 'hybrid']);
  const clean = [];
  if (!Array.isArray(transports)) return clean;
  for (const t of transports) if (allowed.has(t) && !clean.includes(t)) clean.push(t);
  return clean;
}

async function getUserIdFromRequest(request, env) {
  const cookies = parseCookies(request.headers.get('cookie'));
  if (!cookies.uid) throw new Error('You need to sign out and sign back in again.');

  const normalized = normalizeUsername(cookies.uid);
  if (!normalized || normalized.length < 3 || normalized.includes(' ')) {
    throw new Error('Invalid username. Please sign out and sign back in.');
  }

  return hashUsername(normalized, env?.UID_HASH_SECRET);
}

export async function onRequestPatch(context) {
  try {
    const { request, env } = context;
    const db = env.DB;
    if (!db) throw new Error('D1 binding DB is not configured');

    const uid = await getUserIdFromRequest(request, env);
    const body = await request.json();

    const { id, transports } = body || {};
    if (!id) throw new Error('id is required');

    const clean = getAllowedTransports(transports);
    const updated = await updateCredentialFields(db, uid, id, async (c) => {
      c.transports = clean;
      return c;
    });

    if (!updated) throw new Error('Credential not found');
    return json({ result: { id: updated.id, transports: updated.transports } });
  } catch (e) {
    return json({ error: e?.message || String(e) });
  }
}
