/**
 * Single source of truth for the Content-Security-Policy.
 *
 * Consumed by:
 *   - vite.config.js        → injects the meta-tag form into built HTML
 *   - scripts/gen-headers.mjs → regenerates netlify.toml + vercel.json (`npm run headers`)
 *
 * Keeping one list means the meta tag and the HTTP headers cannot drift apart.
 */

/** The only host the app contacts without the user asking: the CISA KEV catalog. */
export const KEV_ORIGIN = "https://raw.githubusercontent.com";

/**
 * @param {string} proxyUrl  VITE_CLAUDE_PROXY_URL, or "" when the AI features are off.
 * @param {{ forMeta?: boolean }} opts
 *   forMeta drops `frame-ancestors`, which browsers ignore in a <meta> tag and warn
 *   about in the console. Clickjacking protection comes from the real headers instead
 *   (frame-ancestors + X-Frame-Options in netlify.toml / vercel.json).
 */
export function buildCsp(proxyUrl = "", { forMeta = false } = {}) {
  const connect = ["'self'", KEV_ORIGIN];
  const url = String(proxyUrl || "").trim();
  if (url) {
    let origin;
    try { origin = new URL(url).origin; }
    catch { throw new Error(`VITE_CLAUDE_PROXY_URL is not a valid absolute URL: ${url}`); }
    connect.push(origin);
  }

  const directives = [
    "default-src 'none'",
    "script-src 'self'",
    // 'unsafe-inline' is required and deliberate: the component ships its stylesheet
    // as a React <style> element and uses inline style attributes for severity
    // colours. Dropping it means extracting the CSS to a real stylesheet — recorded
    // in docs/security-audit.md as an accepted, documented limitation.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    `connect-src ${connect.join(" ")}`,
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "manifest-src 'self'",
    "upgrade-insecure-requests",
  ];

  return directives
    .filter((d) => !(forMeta && d.startsWith("frame-ancestors")))
    .join("; ");
}

/** Security headers applied to every response by the host configs. */
export const SECURITY_HEADERS = (csp) => ({
  "Content-Security-Policy": csp,
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy":
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
});
