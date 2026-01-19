export function parseCookies(cookieHeader) {
  const out = Object.create(null);
  if (!cookieHeader) return out;
  const parts = String(cookieHeader).split(/;\s*/);
  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!name) continue;
    out[name] = value;
  }
  return out;
}

export function makeSetCookie(name, value, opts = {}) {
  const {
    httpOnly = true,
    secure = true,
    sameSite = 'Lax',
    path = '/',
    maxAge,
    expires,
  } = opts;

  let cookie = `${name}=${value}`;
  if (path) cookie += `; Path=${path}`;
  if (typeof maxAge === 'number') cookie += `; Max-Age=${Math.floor(maxAge)}`;
  if (expires instanceof Date) cookie += `; Expires=${expires.toUTCString()}`;
  if (secure) cookie += `; Secure`;
  if (httpOnly) cookie += `; HttpOnly`;
  if (sameSite) cookie += `; SameSite=${sameSite}`;
  return cookie;
}
