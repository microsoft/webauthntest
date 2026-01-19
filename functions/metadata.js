import { json } from './_lib/http.js';

export async function onRequestGet(context) {
  const appVersion = context?.env?.APP_VERSION || 'unknown';
  return json({ appVersion });
}
