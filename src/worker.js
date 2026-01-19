import * as metadata from '../functions/metadata.js';
import * as challenge from '../functions/challenge.js';
import * as credentials from '../functions/credentials/index.js';
import * as credentialTransports from '../functions/credentials/transports.js';
import * as credentialEnabled from '../functions/credentials/enabled.js';
import * as assertion from '../functions/assertion.js';

function isApiPath(pathname) {
  return (
    pathname === '/metadata' ||
    pathname === '/challenge' ||
    pathname === '/credentials' ||
    pathname === '/credentials/transports' ||
    pathname === '/credentials/enabled' ||
    pathname === '/assertion'
  );
}

function handlerNotFound() {
  return new Response('Not found', { status: 404 });
}

function handlerMethodNotAllowed() {
  return new Response('Method not allowed', { status: 405 });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // API routes (previously Pages Functions)
    if (pathname === '/metadata') {
      if (request.method !== 'GET') return handlerMethodNotAllowed();
      return metadata.onRequestGet({ request, env, ctx });
    }

    if (pathname === '/challenge') {
      if (request.method !== 'GET') return handlerMethodNotAllowed();
      return challenge.onRequestGet({ request, env, ctx });
    }

    if (pathname === '/credentials') {
      return credentials.onRequest({ request, env, ctx });
    }

    if (pathname === '/credentials/transports') {
      if (request.method !== 'PATCH') return handlerMethodNotAllowed();
      return credentialTransports.onRequestPatch({ request, env, ctx });
    }

    if (pathname === '/credentials/enabled') {
      if (request.method !== 'PATCH') return handlerMethodNotAllowed();
      return credentialEnabled.onRequestPatch({ request, env, ctx });
    }

    if (pathname === '/assertion') {
      if (request.method !== 'PUT') return handlerMethodNotAllowed();
      return assertion.onRequestPut({ request, env, ctx });
    }

    // Everything else: static assets from ./public via Workers Assets.
    // If ASSETS isn't configured (misconfig), return a helpful 404 for non-API routes.
    if (!env?.ASSETS) {
      if (isApiPath(pathname)) return handlerNotFound();
      return new Response('Static assets are not configured (missing ASSETS binding).', { status: 500 });
    }

    return env.ASSETS.fetch(request);
  },
};
