import { json } from './_lib/http.js';
import { parseCookies, makeSetCookie } from './_lib/cookies.js';
import { normalizeUsername, hashUsername } from './_lib/uid.js';
import { getValidHostname, issueChallenge, challengeCookieName } from './_lib/webauthn.js';

export async function onRequestGet(context) {
  try {
    const { request, env } = context;
    const cookies = parseCookies(request.headers.get('cookie'));
    const rawUid = cookies.uid;
    if (!rawUid) throw new Error('You need to sign out and sign back in again.');

    const normalized = normalizeUsername(rawUid);
    if (!normalized || normalized.length < 3 || normalized.includes(' ')) {
      throw new Error('Invalid username. Please sign out and sign back in.');
    }

    const uid = await hashUsername(normalized, env?.UID_HASH_SECRET);

    const url = new URL(request.url);
    const clientHostname = url.searchParams.get('clientHostname') || undefined;
    const type = url.searchParams.get('type') || 'webauthn.get';
    if (type !== 'webauthn.get' && type !== 'webauthn.create') {
      throw new Error('Invalid challenge type');
    }
    const hostname = getValidHostname(request, env, clientHostname);

    const { challenge, token } = await issueChallenge(uid, hostname, type, env);

    const isHttps = new URL(request.url).protocol === 'https:';

    const headers = new Headers();
    headers.append(
      'Set-Cookie',
      makeSetCookie(challengeCookieName(), token, {
        httpOnly: true,
        secure: isHttps,
        sameSite: 'Lax',
        path: '/',
        maxAge: 300,
      })
    );

    return json({ result: challenge }, { headers });
  } catch (e) {
    return json({ error: e?.message || String(e) });
  }
}
