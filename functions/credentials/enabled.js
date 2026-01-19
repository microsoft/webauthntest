import { json } from '../_lib/http.js';
import { parseCookies } from '../_lib/cookies.js';
import { normalizeUsername, hashUsername } from '../_lib/uid.js';
import { updateCredentialFields } from '../_lib/storage_d1.js';

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

    const { id, enabled } = body || {};
    if (!id) throw new Error('id is required');
    if (typeof id !== 'string') throw new Error('id must be a string');
    if (typeof enabled !== 'boolean') throw new Error('enabled must be boolean');

    const updated = await updateCredentialFields(db, uid, id, async (c) => {
      c.enabled = enabled;
      return c;
    });

    if (!updated) throw new Error('Credential not found');
    return json({ result: { id: updated.id, enabled: updated.enabled } });
  } catch (e) {
    return json({ error: e?.message || String(e) });
  }
}
