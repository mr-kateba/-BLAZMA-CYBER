// Response headers from Electron's net module arrive as JS strings decoded as UTF-8, but the WHATWG
// Headers class only accepts byte strings (every char ≤ 0xFF) and throws otherwise — one server
// sending an emoji or Arabic text in a header must not crash the app. Pure helpers.

/** Re-encodes a UTF-8-decoded header value to the byte string that came over the wire (lossless). */
export function toByteString(v: string): string {
  // eslint-disable-next-line no-control-regex
  return /^[\u0000-ÿ]*$/.test(v) ? v : Buffer.from(v, 'utf8').toString('latin1');
}

/** Builds a Headers object from raw response headers; invalid names/values are skipped, never thrown. */
export function safeHeaders(raw: Record<string, string | string[] | undefined>): Headers {
  const headers = new Headers();
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue;
    try {
      const value = Array.isArray(v) ? v.join(', ') : v;
      // A redirect target is a URL: non-ASCII becomes %XX (UTF-8), as browsers do, so it can be followed.
      headers.append(k, k.toLowerCase() === 'location' ? value.replace(/[^\u0000-\u007f]+/g, (m) => encodeURIComponent(m)) : toByteString(value));
    } catch {
      /* invalid header name or value (e.g. control characters): leave it out */
    }
  }
  return headers;
}
