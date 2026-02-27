// build/bundle-libs.mjs — Bundle crypto libraries into lib/bundle.js
import { build } from 'esbuild';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

await build({
  entryPoints: [join(root, 'lib-entry.js')],
  bundle: true,
  minify: false,       // Keep readable for auditability
  outfile: join(root, 'lib', 'bundle.js'),
  format: 'iife',
  globalName: 'SignerLib',
  platform: 'browser',
  target: ['es2020'],
  inject: [join(__dirname, 'buffer-shim.js')],  // Provide Buffer to bc-ur without global pollution
  define: {
    'process.env.NODE_ENV': '"production"',
    'process.env.NODE_DEBUG': 'undefined',
    'process.env': '{}',
    'global': 'globalThis',
  },
  logLevel: 'info',
});

console.log('✅ lib/bundle.js created');
