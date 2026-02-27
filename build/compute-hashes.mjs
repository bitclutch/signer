// build/compute-hashes.mjs — Compute SHA256 hashes and embed lib hash into app.js
// NOTE: app.js cannot embed its own hash (circular). Its hash is only in hashes.json
// and the standalone HTML header comment.
import { createHash } from 'crypto';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

function sha256(filePath) {
  if (!existsSync(filePath)) return 'FILE_NOT_FOUND';
  const data = readFileSync(filePath);
  return createHash('sha256').update(data).digest('hex');
}

const libHash = sha256(join(root, 'lib', 'bundle.js'));

// Embed lib hash into app.js (this is safe — it's a different file)
const appPath = join(root, 'app.js');
let appJs = readFileSync(appPath, 'utf-8');
appJs = appJs.replace(
  /const BUILD_LIB_HASH = '[^']*';/,
  `const BUILD_LIB_HASH = '${libHash}';`
);
writeFileSync(appPath, appJs, 'utf-8');

// Compute final app.js hash (after lib hash is embedded)
const appHash = sha256(appPath);

// Compute standalone HTML hash (built by build-html step before this)
const standaloneHash = sha256(join(root, 'bitclutch-signer.html'));

// Auto-update SW cache name with content hash (app.js + bundle.js)
const swPath = join(root, 'sw.js');
const contentHash = createHash('sha256').update(appHash + libHash).digest('hex').slice(0, 8);
let swJs = readFileSync(swPath, 'utf-8');
swJs = swJs.replace(
  /const CACHE_NAME = '[^']*';/,
  `const CACHE_NAME = 'bitclutch-signer-${contentHash}';`
);
writeFileSync(swPath, swJs, 'utf-8');
console.log(`sw.js       cache:  bitclutch-signer-${contentHash}`);

// Write hashes.json for external verification
const hashesPath = join(root, 'hashes.json');
const version = appJs.match(/const APP_VERSION = '([^']+)'/)?.[1] || 'unknown';
const hashes = {
  version,
  generated: new Date().toISOString(),
  files: {
    'bitclutch-signer.html': standaloneHash,
    'app.js': appHash,
    'lib/bundle.js': libHash,
  },
};
writeFileSync(hashesPath, JSON.stringify(hashes, null, 2) + '\n', 'utf-8');

console.log(`standalone  SHA256: ${standaloneHash}`);
console.log(`app.js      SHA256: ${appHash}`);
console.log(`bundle.js   SHA256: ${libHash}`);
console.log(`hashes.json written (v${version})`);
