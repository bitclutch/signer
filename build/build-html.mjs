// build/build-html.mjs — Generate single-file bitclutch-signer.html
// Inlines lib/bundle.js and app.js into index.html for offline desktop use.
// Removes Service Worker registration, manifest, and PWA-specific meta tags.
import { readFileSync, writeFileSync } from 'fs';
import { createHash } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

const indexHtml = readFileSync(join(root, 'index.html'), 'utf-8');
const bundleJs = readFileSync(join(root, 'lib', 'bundle.js'), 'utf-8');
const appJs = readFileSync(join(root, 'app.js'), 'utf-8');

// Compute SHA-256 hashes
const appHash = createHash('sha256').update(appJs).digest('hex');
const libHash = createHash('sha256').update(bundleJs).digest('hex');

// Modify app.js for standalone mode:
// - Replace fetch-based source loading with inline display
// - Skip service worker registration (no SW in file:// mode)
const appJsStandalone = appJs
  .replace(
    "navigator.serviceWorker.register('/sw.js').catch(() => {});",
    "// Service Worker disabled in standalone mode"
  );

// Build the standalone HTML
let html = indexHtml;

// Remove manifest link (not needed offline)
html = html.replace(/<link rel="manifest"[^>]*>\n?/i, '');

// Remove apple-mobile-web-app meta tags
html = html.replace(/<meta name="apple-mobile-web-app[^>]*>\n?/gi, '');

// Adjust CSP for inline scripts; no network allowed in standalone mode
html = html.replace(
  /content="default-src[^"]*"/,
  `content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src data: blob:; media-src blob:;"`
);

// Replace external script tags with inline scripts
// NOTE: Cannot use .replace() with bundleJs/appJs in replacement string because
// they contain $& and $' which are special replacement patterns in String.replace().
// Instead, use indexOf + slice to manually splice the content.
const scriptTagPattern = /<script src="lib\/bundle\.js"><\/script>\s*\n?\s*<script src="app\.js"><\/script>/;
const scriptMatch = html.match(scriptTagPattern);
if (!scriptMatch) throw new Error('Could not find script tags to replace');
const scriptIdx = html.indexOf(scriptMatch[0]);
const inlineScripts = `<script>\n// ── lib/bundle.js (SHA-256: ${libHash}) ──\n${bundleJs}\n</script>\n<script>\n// ── app.js (SHA-256: ${appHash}) ──\n${appJsStandalone}\n</script>`;
html = html.slice(0, scriptIdx) + inlineScripts + html.slice(scriptIdx + scriptMatch[0].length);

// Add a comment at the top
html = html.replace(
  '<!DOCTYPE html>',
  `<!DOCTYPE html>
<!-- BitClutch Signer — Standalone offline signing tool -->
<!-- SHA-256 app.js: ${appHash} -->
<!-- SHA-256 lib/bundle.js: ${libHash} -->
<!-- Generated: ${new Date().toISOString()} -->`
);

const outPath = join(root, 'bitclutch-signer.html');
writeFileSync(outPath, html, 'utf-8');

const sizeKB = Math.round(Buffer.byteLength(html) / 1024);
console.log(`bitclutch-signer.html created (${sizeKB} KB)`);
console.log(`  app.js SHA-256: ${appHash}`);
console.log(`  lib/bundle.js SHA-256: ${libHash}`);
