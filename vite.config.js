import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { buildCsp } from "./csp.config.js";

// Minimal dev/preview config. This is a runnable harness around the single-file
// Otter Shell component — NOT the full TypeScript/Vitest port described in
// migration/02_ARCHITECTURE.md. See README for what runs locally and what doesn't.

/**
 * Inject the CSP as a meta tag so the policy travels with the bundle to any static
 * host, including `npm run preview` and a plain file server. The HTTP headers in
 * netlify.toml / vercel.json are the stronger form; this is the floor, not the ceiling.
 */
function cspPlugin(env) {
  const csp = buildCsp(env.VITE_CLAUDE_PROXY_URL, { forMeta: true });
  return {
    name: "otter-shell-csp",
    // Build only. The dev server injects an INLINE React Refresh preamble, which a
    // strict `script-src 'self'` blocks — that breaks HMR and leaves the page dead.
    // Rather than weaken the policy with 'unsafe-inline' just to satisfy dev (which
    // would mean dev never exercises the policy you actually ship), the CSP applies
    // to built output only. Use `npm run preview` to exercise the real policy — it
    // serves dist/, so the shipped CSP is fully in force there.
    apply: "build",
    transformIndexHtml(html) {
      // Promote relative social-card URLs to absolute when the deploy URL is known.
      // Open Graph specifies absolute URLs; most scrapers resolve relative paths, but
      // not all of them do.
      const site = (env.VITE_SITE_URL || "").trim().replace(/\/+$/, "");
      if (site) {
        html = html.replace(
          /(<meta (?:property|name)="(?:og:image|twitter:image|og:url)" content=")\//g,
          `$1${site}/`,
        );
      }
      return {
        html,
        tags: [{
          tag: "meta",
          attrs: { "http-equiv": "Content-Security-Policy", content: csp },
          injectTo: "head-prepend",
        }],
      };
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    plugins: [react(), cspPlugin(env)],
    server: { port: 5173, open: true },
  };
});
