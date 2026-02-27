// buffer-shim.js — esbuild inject shim
// Provides Buffer to any module that references it (e.g. @ngraveio/bc-ur)
// without polluting globalThis. esbuild's inject replaces bare `Buffer`
// references with this import automatically.
import { Buffer } from 'buffer';
export { Buffer };
