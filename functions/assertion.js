import { json } from './_lib/http.js';
import { parseCookies, makeSetCookie } from './_lib/cookies.js';
import { normalizeUsername, hashUsername } from './_lib/uid.js';
import { getValidHostname, validateClientDataFromCookie, challengeCookieName, verifyAssertion } from './_lib/webauthn.js';
import { getCredential, updateCredentialFields } from './_lib/storage_d1.js';

async function getUserIdFromRequest(request, env) {
  const cookies = parseCookies(request.headers.get('cookie'));
  if (!cookies.uid) throw new Error('You need to sign out and sign back in again.');

  const normalized = normalizeUsername(cookies.uid);
  if (!normalized || normalized.length < 3 || normalized.includes(' ')) {
    throw new Error('Invalid username. Please sign out and sign back in.');
  }

  return hashUsername(normalized, env?.UID_HASH_SECRET);
}

export async function onRequestPut(context) {
  try {
    const { request, env } = context;
    const db = env.DB;
    if (!db) throw new Error('D1 binding DB is not configured');

    const uid = await getUserIdFromRequest(request, env);

    const url = new URL(request.url);
    const clientHostname = url.searchParams.get('clientHostname') || undefined;
    const hostname = getValidHostname(request, env, clientHostname);

    const cookies = parseCookies(request.headers.get('cookie'));
    const body = await request.json();

    let clientData;
    try { clientData = JSON.parse(body.clientDataJSON); } catch { throw new Error('clientDataJSON could not be parsed'); }
    await validateClientDataFromCookie(clientData, uid, hostname, 'webauthn.get', cookies, env);

    const isHttps = new URL(request.url).protocol === 'https:';

    // One-time cookie: clear it
    const clearCookie = makeSetCookie(challengeCookieName(), '', { httpOnly: true, secure: isHttps, sameSite: 'Lax', path: '/', maxAge: 0 });

    const credential = await getCredential(db, uid, body.id);
    if (!credential) throw new Error('Credential not found');

    const updated = await verifyAssertion(credential, body, hostname);

    const saved = await updateCredentialFields(db, uid, body.id, async () => updated);

    const headers = new Headers();
    headers.append('Set-Cookie', clearCookie);

    return json({ result: saved }, { headers });
  } catch (e) {
    return json({ error: e?.message || String(e) });
  }
}
