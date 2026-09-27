// The HTTP transport behind NetworkGate: Chromium's network stack instead of Node's fetch, so
// Blazma behaves like the browser on corporate and home networks — system proxy settings
// (including PAC/WPAD) and the Windows certificate store are honoured. The session is in-memory
// and separate from the UI, requests carry no cookies and nothing is cached on disk.

import { net, session, type Session } from 'electron';
import type { FetchLike } from '../../core/network-gate';

let ses: Session | null = null;
const getSession = () => (ses ??= session.fromPartition('blazma-network', { cache: false }));

export const systemFetch: FetchLike = (url, init = {}) => {
  // Electron's fetch cancels a redirect in 'manual' mode instead of returning it, but NetworkGate
  // callers need the 3xx + Location to follow each hop through the gate themselves.
  if (init.redirect === 'manual') return manualRedirectFetch(url, init);
  return getSession().fetch(url, { ...init, credentials: 'omit', cache: 'no-store', bypassCustomProtocolHandlers: true });
};

/** The in-memory limit for one response on the manual-redirect path. */
const MAX_MANUAL_BODY = 16 * 1024 * 1024;

function manualRedirectFetch(url: string, init: RequestInit): Promise<Response> {
  return new Promise((resolve, reject) => {
    if (init.signal?.aborted) return reject(new DOMException('Aborted', 'AbortError'));
    const req = net.request({ url, method: init.method ?? 'GET', session: getSession(), redirect: 'manual', useSessionCookies: false, cache: 'no-store' });
    for (const [k, v] of new Headers(init.headers).entries()) req.setHeader(k, v);
    const onAbort = () => {
      req.abort();
      reject(new DOMException('Aborted', 'AbortError'));
    };
    init.signal?.addEventListener('abort', onAbort, { once: true });
    const done = () => init.signal?.removeEventListener('abort', onAbort);
    req.on('redirect', (status, _method, location) => {
      done();
      req.abort();
      resolve(new Response(null, { status, headers: { location } }));
    });
    req.on('response', (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_MANUAL_BODY) {
          done();
          req.abort();
          reject(Object.assign(new Error('response_too_large'), { code: 'response_too_large' }));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        done();
        const headers = new Headers();
        for (const [k, v] of Object.entries(res.headers)) headers.set(k, Array.isArray(v) ? v.join(', ') : v);
        const body = res.statusCode === 204 || res.statusCode === 304 ? null : Buffer.concat(chunks);
        resolve(new Response(body, { status: res.statusCode, headers }));
      });
      res.on('error', (e: Error) => {
        done();
        reject(e);
      });
    });
    req.on('error', (e) => {
      done();
      reject(e);
    });
    if (typeof init.body === 'string') req.write(init.body);
    req.end();
  });
}
