// lib-entry.js — esbuild bundle entry point
// Bundled into lib/bundle.js as IIFE → window.SignerLib
// App logic (app.js) accesses these via window.SignerLib

// Bitcoin transaction signing (PSBT, Miniscript)
export { Transaction, p2wsh, p2wpkh, p2sh } from '@scure/btc-signer';

// Elliptic curve (ECDSA sign/verify, BMS)
export { secp256k1 } from '@noble/curves/secp256k1';

// HD key derivation (BIP-32)
export { HDKey } from '@scure/bip32';

// Mnemonic ↔ entropy (BIP-39)
export {
  mnemonicToSeedSync,
  entropyToMnemonic,
  validateMnemonic,
  mnemonicToEntropy,
} from '@scure/bip39';
export { wordlist as englishWordlist } from '@scure/bip39/wordlists/english';
export { wordlist as koreanWordlist } from '@scure/bip39/wordlists/korean';
export { wordlist as japaneseWordlist } from '@scure/bip39/wordlists/japanese';
export { wordlist as spanishWordlist } from '@scure/bip39/wordlists/spanish';
export { wordlist as frenchWordlist } from '@scure/bip39/wordlists/french';
export { wordlist as italianWordlist } from '@scure/bip39/wordlists/italian';
export { wordlist as portugueseWordlist } from '@scure/bip39/wordlists/portuguese';
export { wordlist as czechWordlist } from '@scure/bip39/wordlists/czech';
export { wordlist as simplifiedChineseWordlist } from '@scure/bip39/wordlists/simplified-chinese';
export { wordlist as traditionalChineseWordlist } from '@scure/bip39/wordlists/traditional-chinese';

// Hashing (SHA256, RIPEMD160, HMAC, PBKDF2)
export { sha256 } from '@noble/hashes/sha256';
export { ripemd160 } from '@noble/hashes/ripemd160';
export { hmac } from '@noble/hashes/hmac';
export { concatBytes, bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

// BC-UR (fountain codes for QR)
export { UR, UREncoder, URDecoder } from '@ngraveio/bc-ur';

// QR code generation
import qrgen from 'qrcode-generator';
export { qrgen };

// QR code scanning
import jsQR from 'jsqr';
export { jsQR };
