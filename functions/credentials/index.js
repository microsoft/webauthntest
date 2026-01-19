import { json } from '../_lib/http.js';
import { parseCookies, makeSetCookie } from '../_lib/cookies.js';
import { normalizeUsername, hashUsername } from '../_lib/uid.js';
import { getValidHostname, validateClientDataFromCookie, challengeCookieName, makeCredential } from '../_lib/webauthn.js';
import { getCredentialsForRp, upsertCredential, deleteCredential } from '../_lib/storage_d1.js';

async function getUserIdFromRequest(request, env) {
  const cookies = parseCookies(request.headers.get('cookie'));
  if (!cookies.uid) throw new Error('You need to sign out and sign back in again.');

  const normalized = normalizeUsername(cookies.uid);
  if (!normalized || normalized.length < 3 || normalized.includes(' ')) {
    throw new Error('Invalid username. Please sign out and sign back in.');
  }

  return hashUsername(normalized, env?.UID_HASH_SECRET);
}

export async function onRequest(context) {
  try {
    const { request, env } = context;
    const db = env.DB;
    if (!db) throw new Error('D1 binding DB is not configured');

    const uid = await getUserIdFromRequest(request, env);

    const url = new URL(request.url);
    const clientHostname = url.searchParams.get('clientHostname') || undefined;
    const hostname = getValidHostname(request, env, clientHostname);

    if (request.method === 'GET') {
      const credentials = await getCredentialsForRp(db, uid, hostname);
      return json({ result: credentials });
    }

    if (request.method === 'PUT') {
      const cookies = parseCookies(request.headers.get('cookie'));
      const body = await request.json();

      const isHttps = new URL(request.url).protocol === 'https:';

      let clientData;
      try {
        clientData = JSON.parse(body.clientDataJSON);
      } catch {
        throw new Error('clientDataJSON could not be parsed');
      }

      await validateClientDataFromCookie(clientData, uid, hostname, 'webauthn.create', cookies, env);

      // One-time cookie: clear it
      const clearCookie = makeSetCookie(challengeCookieName(), '', {
        httpOnly: true,
        secure: isHttps,
        sameSite: 'Lax',
        path: '/',
        maxAge: 0,
      });

      const credential = await makeCredential(uid, body, hostname);
      await upsertCredential(db, credential);

      const headers = new Headers();
      headers.append('Set-Cookie', clearCookie);
      return json({ result: { id: credential.id } }, { headers });
    }

    if (request.method === 'DELETE') {
      const body = await request.json();
      await deleteCredential(db, uid, body.id);
      return json({});
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204 });
    }

    return json({ error: 'Method not supported' }, { status: 405 });
  } catch (e) {
    return json({ error: e?.message || String(e) });
  }
}
