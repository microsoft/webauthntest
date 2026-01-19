export function json(data, init = {}) {
  const headers = new Headers(init.headers || {});
  if (!headers.has('content-type')) headers.set('content-type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(data), { ...init, headers });
}

export function badRequest(message) {
  return json({ error: message }, { status: 400 });
}

export function internalError(message) {
  return json({ error: message }, { status: 500 });
}
