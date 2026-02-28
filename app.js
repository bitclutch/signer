// app.js — BitClutch Signer PWA
// This is the auditable app logic. All crypto in lib/bundle.js (hash-verified).
// All crypto operations are delegated to lib/bundle.js (SignerLib).
// SHA256 of this file: [computed at build time]
'use strict';

const {
  Transaction, p2wsh, p2wpkh,
  secp256k1,
  HDKey,
  mnemonicToSeedSync, entropyToMnemonic, validateMnemonic, mnemonicToEntropy,
  englishWordlist, koreanWordlist, japaneseWordlist,
  spanishWordlist, frenchWordlist, italianWordlist, portugueseWordlist,
  czechWordlist, simplifiedChineseWordlist, traditionalChineseWordlist,
  sha256, ripemd160, hmac,
  concatBytes, bytesToHex, hexToBytes, utf8ToBytes,
  UR, UREncoder, URDecoder,
  qrgen, jsQR,
} = SignerLib;

// ── State ──────────────────────────────────────────
const S = {
  tab: 'key',            // key | sign | settings
  screen: 'loading',     // loading | setup | home | dice | coin | mnemonic | set-pass | import | scan | confirm-tx | enter-pass | show-qr | confirm-bms | bms-result | view-source | security | guide | settings-main
  xprv: null,            // decrypted account xprv (in memory only, cleared after signing)
  signingKeyId: null,          // set per-signing session (auto-detected or user-selected)
  network: localStorage.getItem('signer-network') || 'main',
  lang: localStorage.getItem('signer-lang') || (navigator.language.startsWith('ko') ? 'ko' : 'en'),
  seedLang: localStorage.getItem('signer-seed-lang') || 'en', // seed phrase wordlist language
  diceEntropy: [],       // collected dice values
  coinEntropy: [],       // collected coin flips
  tempMnemonic: null,    // shown during keygen only, then cleared
  tempEntropy: null,     // raw 256-bit entropy (kept until passphrase set, for language switch)
  tempKeyResult: null,   // {mnemonic, xprv, xpub, fingerprint} pending passphrase
  lastActivity: Date.now(),
  scanStream: null,      // active camera stream
  scanAnimId: null,      // requestAnimationFrame ID
  urDecoder: null,       // BC-UR multi-part decoder
  urProgress: '',        // scan progress text
  parsedTx: null,        // {psbtBytes, inputs[], outputs[], fee, inputTotal, outputTotal}
  signedPsbtBytes: null, // signed PSBT after user confirms
  qrEncoder: null,       // BC-UR fountain encoder for animated QR
  qrAnimId: null,        // setInterval ID for fountain animation
  bmsRequest: null,      // {message, index} from scanned BMS QR
  bmsResult: null,       // {message, signature, address} after BMS signing
  importWordCount: 12,   // 12 or 24 for import screen
  theme: localStorage.getItem('signer-theme') || 'auto', // auto | light | dark
  pendingAction: null,   // 'sign-tx' | 'sign-bms' — set before enter-pass screen
  expandedKeyId: null,   // which key card has xpub expanded
};

const DICE_REQUIRED = 99;
const COIN_REQUIRED = 256;
const LOCK_TIMEOUT = 5 * 60 * 1000; // 5 min
const PBKDF2_ITERATIONS = 600000;
// Build-time SHA-256 hash for lib/bundle.js (inserted by compute-hashes.mjs)
// NOTE: app.js cannot contain its own hash (circular). Its hash is in hashes.json.
const BUILD_LIB_HASH = '08f1fa5b879902b6be2ed088ea269f87bbd7a84f2eacbf988e5cff34d3afbe50';
const APP_VERSION = '0.2.0';
const $ = (id) => document.getElementById(id);
const $screen = () => $('screen');

// ── i18n ─────────────────────────────────────────
const I18N = {
  en: {
    // Lock badge
    unlocked: 'Unlocked',
    locked: 'Locked',
    // Tabs
    tabKey: 'Key',
    tabSign: 'Sign',
    tabSettings: 'Settings',
    // Setup
    createKeys: 'Create Your Key',
    setupDesc: 'Generate a new key using physical entropy,<br>or import an existing seed phrase.',
    diceBtn: 'Dice (99 rolls)',
    coinBtn: 'Coin flip (256 flips)',
    importBtn: 'Import seed phrase',
    restoreBackup: 'Restore encrypted backup',
    backup: 'Backup',
    exportBackup: 'Export Encrypted Backup',
    importBackup: 'Import Encrypted Backup',
    backupSaved: 'Encrypted backup saved. Store this file in a safe place — it lets you restore your key if browser data is cleared.',
    invalidBackup: 'Invalid backup file.',
    backupRestored: 'Backup restored. Enter your passphrase to unlock.',
    backupExists: 'A key already exists. Delete it first to restore from backup.',
    // Unlock
    enterPassphrase: 'Enter passphrase to unlock',
    passphrase: 'Passphrase',
    unlock: 'Unlock',
    wrongPassphrase: 'Wrong passphrase.',
    // Home
    yourKey: 'Your Key',
    network: 'Network',
    fingerprint: 'Fingerprint',
    keyCreated: 'Created',
    lastOnline: 'Last Online',
    neverOnline: 'Never (safe)',
    onlineAfterKey: 'Key may be compromised! Generate a new key on a clean device.',
    accountXpub: 'Account xpub',
    showXpubQR: 'Show xpub QR',
    lockBtn: 'Lock',
    mainnet: 'Mainnet',
    testnet: 'Testnet',
    // Dice
    diceTitle: 'Dice Key Generation',
    diceDesc: 'Roll a real physical die and tap the result.',
    progress: 'Progress',
    undoLast: 'Undo last',
    cancel: 'Cancel',
    ok: 'OK',
    // Coin
    coinTitle: 'Coin Flip Key Generation',
    coinDesc: 'Flip a real physical coin and tap the result.',
    entropyWarning: 'Use a real physical die/coin \u2014 never make up numbers. Human choices are predictable and weaken your key. No cameras or microphones nearby \u2014 anyone who sees your rolls can steal your Bitcoin.',
    heads: 'H (Heads)',
    tails: 'T (Tails)',
    // Mnemonic
    writeDown: 'Write these words down!',
    mnemonicDesc: 'This is your seed phrase. Store it safely offline. It will NOT be shown again.',
    stolenVsLost: 'Stolen vs. Lost — know the difference',
    theft: 'Theft:',
    theftDesc: 'If someone finds your seed phrase, they can steal your Bitcoin immediately. No one can reverse this.',
    loss: 'Loss:',
    lossDesc: 'If you lose your seed phrase and your device breaks, your Bitcoin is gone forever — unless you have a recovery plan.',
    bitclutchPromo: '<strong>BitClutch</strong> protects against loss and death, not theft. Create a <strong>Protected Wallet</strong> with a timelock — your Bitcoin stays yours, but can be recovered by your heirs if something happens to you.',
    visitBitclutch: 'Visit <strong>bitclutch.app</strong> on an online device to create a Protected Wallet.',
    confirmedWritten: "I've written it down",
    // Import
    importTitle: 'Import Seed Phrase',
    importDesc: 'Select word count and language, then enter each word.',
    importPlaceholder: 'word1 word2 word3 ...',
    importAction: 'Import',
    words: 'words',
    fillAllWords: 'Please fill in all words.',
    needWords: 'Need 12 or 24 words',
    invalidMnemonic: 'Invalid mnemonic',
    // Set passphrase
    setPassTitle: 'Set Passphrase',
    setPassDesc: "Choose a strong passphrase to encrypt your private key. You'll need it every time you unlock.",
    confirmPass: 'Confirm passphrase',
    enterPass: 'Enter passphrase',
    passRequired: 'Passphrase is required.',
    passTooShort: 'Passphrase too short (min 4 chars).',
    passNoMatch: 'Passphrases do not match.',
    noKeyToSave: 'No key to save. Start over.',
    encryptSave: 'Encrypt & Save',
    encryptFailed: 'Encryption failed: ',
    // Scan
    scanTitle: 'Scan QR',
    scanDesc: 'Point camera at the QR code from your BitClutch app.',
    startingCamera: 'Starting camera...',
    scanning: 'Scanning... Point at QR code.',
    cameraError: 'Camera error: ',
    receivingFountain: 'Receiving fountain code...',
    urFailed: 'UR decoding failed. Try again.',
    psbtParseError: 'PSBT parse error: ',
    // Confirm TX
    confirmTx: 'Confirm Transaction',
    reviewBeforeSign: 'Review carefully before signing.',
    inputs: 'Inputs',
    output: 'Output',
    change: '(change)',
    fee: 'Fee',
    reject: 'Reject',
    sign: 'Sign',
    signingFailed: 'Signing failed: ',
    // Show QR
    signedPsbt: 'Signed PSBT',
    showQRDesc: 'Let your BitClutch app scan this QR code to broadcast the transaction.',
    scanComplete: 'Scan Complete',
    scanSignatureDesc: 'Let your BitClutch app scan this QR code to submit the signature.',
    singleQR: 'single QR',
    fountainKeepShowing: 'fountain code — keep showing',
    frame: 'Frame',
    // BMS
    confirmBms: 'Confirm Message Signing',
    reviewMessage: 'Review the message before signing.',
    type: 'Type',
    bmsType: 'BMS (Bitcoin Message)',
    index: 'Index',
    address: 'Address',
    message: 'Message',
    bmsSignature: 'BMS Signature',
    sigBase64: 'Signature (base64)',
    tapToCopy: 'Tap to copy',
    copySig: 'Copy signature',
    sha256: 'SHA-256',
    // Settings
    settings: 'Settings',
    version: 'Version',
    language: 'Language',
    seedLanguage: 'Seed Language',
    theme: 'Theme',
    themeAuto: 'Auto',
    themeLight: 'Light',
    themeDark: 'Dark',
    testnetWarningTitle: 'Switch to Testnet?',
    testnetWarningBody: 'Testnet is for developers only. Testnet coins have no real value. A key generated on testnet cannot be used on mainnet.',
    switchTestnet: 'Switch to Testnet',
    onlineKeygenTitle: 'Network Connected!',
    onlineKeygenBody: 'Your device is connected to the internet. A key generated while online can be intercepted by malware. Disconnect ALL networks (WiFi, cellular, Bluetooth, USB) before proceeding.',
    proceedAnyway: 'Proceed anyway (unsafe)',
    installGuide: 'Installation Guide',
    viewSource: 'Verify Source Integrity',
    securityInfo: 'Security Info',
    deleteKey: 'Delete Key',
    deleteConfirm1: 'Delete your key? This cannot be undone.\nMake sure you have your seed phrase backed up!',
    deleteConfirm2: 'Are you absolutely sure? Your Bitcoin will be LOST if you have no backup.',
    // View Source
    verifyIntegrity: 'Verify Integrity',
    verifyDesc: 'Compare SHA-256 hashes against the official release on GitHub.',
    computing: 'Computing...',
    fetchFailed: '(fetch failed)',
    verifyFile: 'Verify this file',
    verifyFileDesc: 'Tap here and select the <strong>bitclutch-signer.html</strong> file you downloaded.<br>Its SHA-256 hash will be computed locally so you can compare it with the official hash on GitHub.',
    tapToSelect: 'Tap to select file',
    compareGithub: 'Compare with <code>hashes.json</code> from the GitHub release.',
    auditableSource: 'Auditable Source',
    auditableDesc: "This app's entire logic is in a single auditable file. Source code and official hashes are published on GitHub.",
    back: 'Back',
    // Security
    securityTitle: 'Security Information',
    securityLevel: 'Security Level: Software Air-Gap',
    whatProvides: 'What this provides:',
    secProvide1: 'Private key never touches the internet (after setup)',
    secProvide2: 'Code is auditable (single app.js file, no build obfuscation)',
    secProvide3: 'Entropy from physical sources only (dice/coins)',
    secProvide4: 'AES-256-GCM encryption with 600K PBKDF2 iterations',
    whatNot: 'What this does NOT provide:',
    secNot1: 'Secure Element (hardware wallets have this)',
    secNot2: 'Hardware-level air gap (WiFi chip still exists)',
    secNot3: 'Side-channel attack resistance',
    keyStorage: 'Key Storage',
    encryption: 'Encryption:',
    encryptionDesc: 'AES-256-GCM + PBKDF2 (600,000 iterations) + random salt/IV',
    warning: 'Warning:',
    clearDataWarning: 'Clearing browser data will permanently delete your encrypted key. Always keep your seed phrase backed up offline.',
    autoLock: 'Auto-lock:',
    autoLockDesc: 'Key is wiped from memory after 5 minutes of inactivity.',
    // Key storage descriptions
    storageEncKey: 'Encrypted private key (AES-256-GCM)',
    storageXpub: 'Account extended public key',
    storageFp: 'BIP-32 fingerprint',
    storageNet: 'Network setting (main/test)',
    storageLang: 'UI language',
    storageSeedLang: 'Seed phrase language',
    storageKeyCreated: 'Key creation timestamp',
    storageLastOnline: 'Last network detection timestamp',
    // Guide
    guideTitle: 'Installation Guide',
    guideDesc: 'Install BitClutch Signer as an offline app, then enable airplane mode before use.',
    detected: 'Detected',
    guideIosSafari: '<strong>Install as offline app:</strong><ol><li>Open this page in <strong>Safari</strong></li><li>Tap the <strong>Share</strong> button (box with arrow)</li><li>Scroll down and tap <strong>"Add to Home Screen"</strong></li><li>Tap <strong>"Add"</strong> in the top right</li></ol><strong>Enable Airplane Mode:</strong><ol><li>Swipe down from top-right corner (or up from bottom on older iPhones)</li><li>Tap the <strong>airplane icon</strong> to enable</li><li>Make sure Wi-Fi and Bluetooth are also OFF</li></ol>',
    guideIosChrome: '<strong>Important:</strong> Chrome on iOS cannot install offline apps. Use <strong>Safari</strong> instead.<ol><li>Copy this page URL</li><li>Open <strong>Safari</strong> and paste the URL</li><li>Follow the <strong>iOS Safari</strong> instructions above</li></ol><strong>Enable Airplane Mode:</strong><ol><li>Swipe down from top-right corner</li><li>Tap the <strong>airplane icon</strong></li></ol>',
    guideAndroidChrome: '<strong>Install as offline app:</strong><ol><li>Open this page in <strong>Chrome</strong></li><li>Tap the <strong>three-dot menu</strong> (top right)</li><li>Tap <strong>"Install app"</strong> or <strong>"Add to Home screen"</strong></li><li>Confirm by tapping <strong>"Install"</strong></li></ol><strong>Enable Airplane Mode:</strong><ol><li>Swipe down from the top of the screen</li><li>Tap <strong>"Airplane mode"</strong></li><li>Verify Wi-Fi and mobile data are OFF</li></ol>',
    guideAndroidSamsung: '<strong>Install as offline app:</strong><ol><li>Open this page in <strong>Samsung Internet</strong></li><li>Tap the <strong>menu icon</strong> (three lines, bottom right)</li><li>Tap <strong>"Add page to"</strong> then <strong>"Home screen"</strong></li></ol><strong>Enable Airplane Mode:</strong><ol><li>Swipe down from the top twice to open Quick Settings</li><li>Tap <strong>"Airplane mode"</strong></li></ol>',
    guideMacosSafari: '<strong>Install as offline app (macOS Sonoma+):</strong><ol><li>Open this page in <strong>Safari</strong></li><li>Click <strong>File</strong> menu then <strong>"Add to Dock"</strong></li><li>Click <strong>"Add"</strong></li></ol><strong>Disable Network:</strong><ol><li>Click the <strong>Wi-Fi icon</strong> in the menu bar</li><li>Click to <strong>turn Wi-Fi off</strong></li><li>Unplug any Ethernet cables</li></ol>',
    guideMacosChrome: '<strong>Install as offline app:</strong><ol><li>Open this page in <strong>Chrome</strong></li><li>Click the <strong>install icon</strong> in the address bar (or three-dot menu &rarr; "Install BitClutch Signer")</li><li>Click <strong>"Install"</strong></li></ol><strong>Disable Network:</strong><ol><li>Click the <strong>Wi-Fi icon</strong> in the menu bar</li><li>Click to <strong>turn Wi-Fi off</strong></li><li>Unplug any Ethernet cables</li></ol>',
    guideWindowsChrome: '<strong>Install as offline app:</strong><ol><li>Open this page in <strong>Chrome</strong></li><li>Click the <strong>install icon</strong> in the address bar (or three-dot menu &rarr; "Install BitClutch Signer")</li><li>Click <strong>"Install"</strong></li></ol><strong>Disable Network:</strong><ol><li>Click the <strong>Wi-Fi icon</strong> in the taskbar (bottom right)</li><li>Click to <strong>disconnect Wi-Fi</strong></li><li>Unplug any Ethernet cables</li></ol>',
    guideWindowsEdge: '<strong>Install as offline app:</strong><ol><li>Open this page in <strong>Edge</strong></li><li>Click the <strong>install icon</strong> in the address bar (or three-dot menu &rarr; "Apps" &rarr; "Install BitClutch Signer")</li><li>Click <strong>"Install"</strong></li></ol><strong>Disable Network:</strong><ol><li>Click the <strong>Wi-Fi icon</strong> in the taskbar (bottom right)</li><li>Click to <strong>disconnect Wi-Fi</strong></li><li>Unplug any Ethernet cables</li></ol>',
    // xpub QR
    accountXpubTitle: 'Account xpub',
    noMnemonic: 'No mnemonic available.',
    noTxData: 'No transaction data.',
    noSignedData: 'No signed data.',
    noBmsRequest: 'No BMS request.',
    noSignature: 'No signature.',
    loading: 'Loading...',
    bannerWarn: 'NETWORK DETECTED \u2014 Disconnect all networks before generating keys.',
    bannerOnline: 'NETWORK CONNECTED \u2014 Disconnect NOW and NEVER reconnect this device. Your key may already be exposed.',
    bannerOffline: 'No wireless network detected. Verify Bluetooth, NFC, and USB data cables are also disconnected.',
    // Multi-key
    addNewKey: '+ Add New Key',
    noKeysYet: 'No keys yet. Create or import one to get started.',
    enterPassToSign: 'Enter passphrase to sign',
    passCorrect: 'Passphrase is correct!',
    passWrong: 'Wrong passphrase.',
    signFailed: 'Signing failed',
    verifyPass: 'Verify Passphrase',
    keyAlreadyExists: 'A key with this fingerprint already exists.',
    keyN: 'Key #',
    storageKeys: 'Encrypted key array (AES-256-GCM)',
    deleteKeyConfirm1: 'Delete this key? This cannot be undone.\nMake sure you have your seed phrase backed up!',
    deleteKeyConfirm2: 'Are you absolutely sure? Your Bitcoin will be LOST if you have no backup.',
    selectKeyForBms: 'Select key to sign with',
    selectKeyAtSign: '(key will be selected at signing)',
    renameKeyTitle: 'Rename Key',
    save: 'Save',
  },
  ko: {
    unlocked: '잠금 해제',
    locked: '잠김',
    tabKey: '키',
    tabSign: '서명',
    tabSettings: '설정',
    createKeys: '키 생성',
    setupDesc: '물리적 엔트로피로 새 키를 생성하거나,<br>기존 시드 구문을 가져옵니다.',
    diceBtn: '주사위 (99회)',
    coinBtn: '동전 던지기 (256회)',
    importBtn: '시드 구문 가져오기',
    restoreBackup: '암호화 백업 복원',
    backup: '백업',
    exportBackup: '암호화 백업 내보내기',
    importBackup: '암호화 백업 가져오기',
    backupSaved: '암호화 백업이 저장되었습니다. 안전한 곳에 보관하세요 — 브라우저 데이터가 삭제되어도 이 파일로 키를 복원할 수 있습니다.',
    invalidBackup: '유효하지 않은 백업 파일입니다.',
    backupRestored: '백업이 복원되었습니다. 비밀번호를 입력하여 잠금을 해제하세요.',
    backupExists: '이미 키가 존재합니다. 백업을 복원하려면 기존 키를 먼저 삭제하세요.',
    enterPassphrase: '잠금 해제 비밀번호를 입력하세요',
    passphrase: '비밀번호',
    unlock: '잠금 해제',
    wrongPassphrase: '비밀번호가 틀렸습니다.',
    yourKey: '내 키',
    network: '네트워크',
    fingerprint: '지문',
    keyCreated: '생성일',
    lastOnline: '마지막 온라인',
    neverOnline: '없음 (안전)',
    onlineAfterKey: '키가 노출되었을 수 있습니다! 안전한 기기에서 새 키를 생성하세요.',
    accountXpub: '계정 xpub',
    showXpubQR: 'xpub QR 보기',
    lockBtn: '잠금',
    mainnet: '메인넷',
    testnet: '테스트넷',
    diceTitle: '주사위 키 생성',
    diceDesc: '\uc2e4\uc81c 6\uba74 \uc8fc\uc0ac\uc704\ub97c \uad74\ub9ac\uace0 \uacb0\uacfc\ub97c \ud0ed\ud558\uc138\uc694.',
    progress: '\uc9c4\ud589\ub960',
    undoLast: '\ub9c8\uc9c0\ub9c9 \ucde8\uc18c',
    cancel: '\ucde8\uc18c',
    ok: '\ud655\uc778',
    coinTitle: '\ub3d9\uc804 \ub358\uc9c0\uae30 \ud0a4 \uc0dd\uc131',
    coinDesc: '\uc2e4\uc81c \ub3d9\uc804\uc744 \ub358\uc9c0\uace0 \uacb0\uacfc\ub97c \ud0ed\ud558\uc138\uc694.',
    entropyWarning: '\ubc18\ub4dc\uc2dc \uc2e4\uc81c \uc8fc\uc0ac\uc704/\ub3d9\uc804\uc744 \uc0ac\uc6a9\ud558\uc138\uc694 \u2014 \uc784\uc758\ub85c \uc22b\uc790\ub97c \ub9cc\ub4e4\uc9c0 \ub9c8\uc138\uc694. \uc0ac\ub78c\uc758 \uc120\ud0dd\uc740 \uc608\uce21 \uac00\ub2a5\ud558\uc5ec \ud0a4\ub97c \uc57d\ud654\uc2dc\ud0b5\ub2c8\ub2e4. \uc8fc\ubcc0\uc5d0 \uce74\uba54\ub77c\ub098 \ub9c8\uc774\ud06c\uac00 \uc5c6\ub294\uc9c0 \ud655\uc778\ud558\uc138\uc694 \u2014 \uad74\ub9bc \uacb0\uacfc\ub97c \ubcf8 \uc0ac\ub78c\uc740 \ube44\ud2b8\ucf54\uc778\uc744 \ud6d4\uce60 \uc218 \uc788\uc2b5\ub2c8\ub2e4.',
    heads: 'H (\uc55e\uba74)',
    tails: 'T (\ub4b7\uba74)',
    writeDown: '이 단어들을 적어두세요!',
    mnemonicDesc: '이것은 시드 구문입니다. 오프라인에 안전하게 보관하세요. 다시 표시되지 않습니다.',
    stolenVsLost: '도난 vs. 분실 — 차이를 아세요',
    theft: '도난:',
    theftDesc: '누군가 시드 구문을 발견하면 즉시 비트코인을 탈취할 수 있습니다. 누구도 이를 되돌릴 수 없습니다.',
    loss: '분실:',
    lossDesc: '시드 구문을 잃고 기기가 고장나면 비트코인은 영원히 사라집니다 — 복구 계획이 없다면.',
    bitclutchPromo: '<strong>BitClutch</strong>는 분실과 사망으로부터 보호합니다. 도난은 아닙니다. 타임락이 있는 <strong>보호 지갑</strong>을 만드세요 — 비트코인은 당신의 것이지만, 만일의 경우 상속인이 복구할 수 있습니다.',
    visitBitclutch: '온라인 기기에서 <strong>bitclutch.app</strong>을 방문하여 보호 지갑을 만드세요.',
    confirmedWritten: '적어두었습니다',
    importTitle: '시드 구문 가져오기',
    importDesc: '단어 수와 언어를 선택한 후, 각 단어를 입력하세요.',
    importPlaceholder: '단어1 단어2 단어3 ...',
    importAction: '가져오기',
    words: '단어',
    fillAllWords: '모든 단어를 입력해주세요.',
    needWords: '12개 또는 24개 단어가 필요합니다',
    invalidMnemonic: '유효하지 않은 시드 구문',
    setPassTitle: '비밀번호 설정',
    setPassDesc: '개인키를 암호화할 강력한 비밀번호를 선택하세요. 잠금 해제 시 매번 필요합니다.',
    confirmPass: '비밀번호 확인',
    enterPass: '비밀번호 입력',
    passRequired: '비밀번호는 필수입니다.',
    passTooShort: '비밀번호가 너무 짧습니다 (최소 4자).',
    passNoMatch: '비밀번호가 일치하지 않습니다.',
    noKeyToSave: '저장할 키가 없습니다. 처음부터 다시 시작하세요.',
    encryptSave: '암호화 및 저장',
    encryptFailed: '암호화 실패: ',
    scanTitle: 'QR 스캔',
    scanDesc: 'BitClutch 앱의 QR 코드를 카메라로 비추세요.',
    startingCamera: '카메라 시작 중...',
    scanning: '스캔 중... QR 코드를 비추세요.',
    cameraError: '카메라 오류: ',
    receivingFountain: '파운틴 코드 수신 중...',
    urFailed: 'UR 디코딩 실패. 다시 시도하세요.',
    psbtParseError: 'PSBT 파싱 오류: ',
    confirmTx: '거래 확인',
    reviewBeforeSign: '서명 전에 신중히 확인하세요.',
    inputs: '입력',
    output: '출력',
    change: '(잔돈)',
    fee: '수수료',
    reject: '거부',
    sign: '서명',
    signingFailed: '서명 실패: ',
    signedPsbt: '서명된 PSBT',
    showQRDesc: 'BitClutch 앱으로 이 QR 코드를 스캔하여 거래를 브로드캐스트하세요.',
    scanComplete: '스캔 완료',
    scanSignatureDesc: 'BitClutch 앱으로 이 QR 코드를 스캔하여 서명을 제출하세요.',
    singleQR: '단일 QR',
    fountainKeepShowing: '파운틴 코드 — 계속 보여주세요',
    frame: '프레임',
    confirmBms: '메시지 서명 확인',
    reviewMessage: '서명 전에 메시지를 확인하세요.',
    type: '유형',
    bmsType: 'BMS (비트코인 메시지)',
    index: '인덱스',
    address: '주소',
    message: '메시지',
    bmsSignature: 'BMS 서명',
    sigBase64: '서명 (base64)',
    tapToCopy: '탭하여 복사',
    copySig: '서명 복사',
    sha256: 'SHA-256',
    settings: '설정',
    version: '버전',
    language: '언어',
    seedLanguage: '시드 언어',
    theme: '테마',
    themeAuto: '자동',
    themeLight: '라이트',
    themeDark: '다크',
    testnetWarningTitle: '테스트넷으로 전환하시겠습니까?',
    testnetWarningBody: '테스트넷은 개발자 전용입니다. 테스트넷 코인은 실제 가치가 없습니다. 테스트넷에서 생성된 키는 메인넷에서 사용할 수 없습니다.',
    switchTestnet: '테스트넷으로 전환',
    onlineKeygenTitle: '네트워크 연결됨!',
    onlineKeygenBody: '기기가 인터넷에 연결되어 있습니다. 온라인 상태에서 생성된 키는 악성코드에 의해 탈취될 수 있습니다. 진행하기 전에 모든 네트워크(WiFi, 셀룰러, 블루투스, USB)를 끊으세요.',
    proceedAnyway: '그래도 진행 (위험)',
    installGuide: '설치 가이드',
    viewSource: '소스 무결성 검증',
    securityInfo: '보안 정보',
    deleteKey: '키 삭제',
    deleteConfirm1: '키를 삭제하시겠습니까? 되돌릴 수 없습니다.\n시드 구문 백업을 확인하세요!',
    deleteConfirm2: '정말 확실합니까? 백업이 없으면 비트코인을 잃게 됩니다.',
    verifyIntegrity: '무결성 검증',
    verifyDesc: 'SHA-256 해시를 GitHub 공식 릴리스와 비교하세요.',
    computing: '계산 중...',
    fetchFailed: '(가져오기 실패)',
    verifyFile: '이 파일 검증',
    verifyFileDesc: '여기를 탭하고 다운로드한 <strong>bitclutch-signer.html</strong> 파일을 선택하세요.<br>SHA-256 해시가 로컬에서 계산되어 GitHub의 공식 해시와 비교할 수 있습니다.',
    tapToSelect: '탭하여 파일 선택',
    compareGithub: 'GitHub 릴리스의 <code>hashes.json</code>과 비교하세요.',
    auditableSource: '감사 가능한 소스',
    auditableDesc: '이 앱의 전체 로직은 하나의 감사 가능한 파일에 있습니다. 소스 코드와 공식 해시는 GitHub에 공개되어 있습니다.',
    back: '뒤로',
    securityTitle: '보안 정보',
    securityLevel: '보안 수준: 소프트웨어 에어갭',
    whatProvides: '제공하는 것:',
    secProvide1: '개인키가 인터넷에 접속하지 않음 (설정 후)',
    secProvide2: '코드가 감사 가능 (단일 app.js, 빌드 난독화 없음)',
    secProvide3: '물리적 소스의 엔트로피만 사용 (주사위/동전)',
    secProvide4: 'AES-256-GCM 암호화 + 600K PBKDF2 반복',
    whatNot: '제공하지 않는 것:',
    secNot1: 'Secure Element (하드웨어 지갑에 있음)',
    secNot2: '하드웨어 수준 에어갭 (WiFi 칩은 여전히 존재)',
    secNot3: '부채널 공격 저항성',
    keyStorage: '키 저장소',
    encryption: '암호화:',
    encryptionDesc: 'AES-256-GCM + PBKDF2 (600,000 반복) + 랜덤 솔트/IV',
    warning: '경고:',
    clearDataWarning: '브라우저 데이터를 삭제하면 암호화된 키가 영구적으로 삭제됩니다. 항상 시드 구문을 오프라인에 백업하세요.',
    autoLock: '자동 잠금:',
    autoLockDesc: '5분간 비활성 시 메모리에서 키가 삭제됩니다.',
    storageEncKey: '암호화된 개인키 (AES-256-GCM)',
    storageXpub: '계정 확장 공개키',
    storageFp: 'BIP-32 지문',
    storageNet: '네트워크 설정 (main/test)',
    storageLang: 'UI 언어',
    storageSeedLang: '시드 구문 언어',
    storageKeyCreated: '키 생성 타임스탬프',
    storageLastOnline: '네트워크 감지 타임스탬프',
    guideTitle: '설치 가이드',
    guideDesc: 'BitClutch Signer를 오프라인 앱으로 설치한 후, 사용 전에 비행기 모드를 활성화하세요.',
    detected: '감지됨',
    guideIosSafari: '<strong>오프라인 앱으로 설치:</strong><ol><li><strong>Safari</strong>에서 이 페이지를 여세요</li><li><strong>공유</strong> 버튼(화살표가 있는 상자)을 탭하세요</li><li>아래로 스크롤하여 <strong>"홈 화면에 추가"</strong>를 탭하세요</li><li>오른쪽 상단의 <strong>"추가"</strong>를 탭하세요</li></ol><strong>비행기 모드 활성화:</strong><ol><li>오른쪽 상단에서 아래로 스와이프하세요 (구형 iPhone은 아래에서 위로)</li><li><strong>비행기 아이콘</strong>을 탭하여 활성화하세요</li><li>Wi-Fi와 블루투스도 꺼져 있는지 확인하세요</li></ol>',
    guideIosChrome: '<strong>중요:</strong> iOS의 Chrome은 오프라인 앱을 설치할 수 없습니다. <strong>Safari</strong>를 사용하세요.<ol><li>이 페이지의 URL을 복사하세요</li><li><strong>Safari</strong>를 열고 URL을 붙여넣으세요</li><li>위의 <strong>iOS Safari</strong> 안내를 따르세요</li></ol><strong>비행기 모드 활성화:</strong><ol><li>오른쪽 상단에서 아래로 스와이프하세요</li><li><strong>비행기 아이콘</strong>을 탭하세요</li></ol>',
    guideAndroidChrome: '<strong>오프라인 앱으로 설치:</strong><ol><li><strong>Chrome</strong>에서 이 페이지를 여세요</li><li>오른쪽 상단의 <strong>점 세 개 메뉴</strong>를 탭하세요</li><li><strong>"앱 설치"</strong> 또는 <strong>"홈 화면에 추가"</strong>를 탭하세요</li><li><strong>"설치"</strong>를 탭하여 확인하세요</li></ol><strong>비행기 모드 활성화:</strong><ol><li>화면 상단에서 아래로 스와이프하세요</li><li><strong>"비행기 모드"</strong>를 탭하세요</li><li>Wi-Fi와 모바일 데이터가 꺼져 있는지 확인하세요</li></ol>',
    guideAndroidSamsung: '<strong>오프라인 앱으로 설치:</strong><ol><li><strong>삼성 인터넷</strong>에서 이 페이지를 여세요</li><li>오른쪽 하단의 <strong>메뉴 아이콘</strong>(세 줄)을 탭하세요</li><li><strong>"페이지 추가"</strong>에서 <strong>"홈 화면"</strong>을 탭하세요</li></ol><strong>비행기 모드 활성화:</strong><ol><li>상단에서 두 번 아래로 스와이프하여 빠른 설정을 여세요</li><li><strong>"비행기 모드"</strong>를 탭하세요</li></ol>',
    guideMacosSafari: '<strong>오프라인 앱으로 설치 (macOS Sonoma+):</strong><ol><li><strong>Safari</strong>에서 이 페이지를 여세요</li><li><strong>파일</strong> 메뉴에서 <strong>"Dock에 추가"</strong>를 클릭하세요</li><li><strong>"추가"</strong>를 클릭하세요</li></ol><strong>네트워크 비활성화:</strong><ol><li>메뉴 바의 <strong>Wi-Fi 아이콘</strong>을 클릭하세요</li><li>클릭하여 <strong>Wi-Fi를 끄세요</strong></li><li>이더넷 케이블이 있다면 분리하세요</li></ol>',
    guideMacosChrome: '<strong>오프라인 앱으로 설치:</strong><ol><li><strong>Chrome</strong>에서 이 페이지를 여세요</li><li>주소 표시줄의 <strong>설치 아이콘</strong>을 클릭하세요 (또는 점 세 개 메뉴 &rarr; "BitClutch Signer 설치")</li><li><strong>"설치"</strong>를 클릭하세요</li></ol><strong>네트워크 비활성화:</strong><ol><li>메뉴 바의 <strong>Wi-Fi 아이콘</strong>을 클릭하세요</li><li>클릭하여 <strong>Wi-Fi를 끄세요</strong></li><li>이더넷 케이블이 있다면 분리하세요</li></ol>',
    guideWindowsChrome: '<strong>오프라인 앱으로 설치:</strong><ol><li><strong>Chrome</strong>에서 이 페이지를 엽니다</li><li>주소창의 <strong>설치 아이콘</strong>을 클릭합니다 (또는 점 3개 메뉴 &rarr; "BitClutch Signer 설치")</li><li><strong>"설치"</strong>를 클릭합니다</li></ol><strong>네트워크 비활성화:</strong><ol><li>작업 표시줄 오른쪽 하단의 <strong>Wi-Fi 아이콘</strong>을 클릭합니다</li><li><strong>Wi-Fi 연결 해제</strong>를 클릭합니다</li><li>이더넷 케이블이 있다면 분리합니다</li></ol>',
    guideWindowsEdge: '<strong>오프라인 앱으로 설치:</strong><ol><li><strong>Edge</strong>에서 이 페이지를 엽니다</li><li>주소창의 <strong>설치 아이콘</strong>을 클릭합니다 (또는 점 3개 메뉴 &rarr; "앱" &rarr; "BitClutch Signer 설치")</li><li><strong>"설치"</strong>를 클릭합니다</li></ol><strong>네트워크 비활성화:</strong><ol><li>작업 표시줄 오른쪽 하단의 <strong>Wi-Fi 아이콘</strong>을 클릭합니다</li><li><strong>Wi-Fi 연결 해제</strong>를 클릭합니다</li><li>이더넷 케이블이 있다면 분리합니다</li></ol>',
    accountXpubTitle: '계정 xpub',
    noMnemonic: '니모닉이 없습니다.',
    noTxData: '거래 데이터가 없습니다.',
    noSignedData: '서명된 데이터가 없습니다.',
    noBmsRequest: 'BMS 요청이 없습니다.',
    noSignature: '서명이 없습니다.',
    loading: '로딩 중...',
    bannerWarn: '\ub124\ud2b8\uc6cc\ud06c \uac10\uc9c0\ub428 \u2014 \ud0a4 \uc0dd\uc131 \uc804\uc5d0 \ubaa8\ub4e0 \ub124\ud2b8\uc6cc\ud06c\ub97c \ub04a\uc73c\uc138\uc694.',
    bannerOnline: '\ub124\ud2b8\uc6cc\ud06c \uc5f0\uacb0\ub428 \u2014 \uc9c0\uae08 \uc989\uc2dc \ub04a\uace0 \uc774 \uae30\uae30\ub97c \uc808\ub300 \ub2e4\uc2dc \uc5f0\uacb0\ud558\uc9c0 \ub9c8\uc138\uc694. \ud0a4\uac00 \uc774\ubbf8 \ub178\ucd9c\ub418\uc5c8\uc744 \uc218 \uc788\uc2b5\ub2c8\ub2e4.',
    bannerOffline: '\ubb34\uc120 \ub124\ud2b8\uc6cc\ud06c \uac10\uc9c0\ub418\uc9c0 \uc54a\uc74c. \ube14\ub8e8\ud22c\uc2a4, NFC, USB \ub370\uc774\ud130 \ucf00\uc774\ube14\ub3c4 \ubd84\ub9ac\ub418\uc5c8\ub294\uc9c0 \ud655\uc778\ud558\uc138\uc694.',
    addNewKey: '+ 새 키 추가',
    noKeysYet: '키가 없습니다. 새로 생성하거나 가져오세요.',
    enterPassToSign: '서명을 위해 비밀번호를 입력하세요',
    passCorrect: '비밀번호가 올바릅니다!',
    passWrong: '비밀번호가 틀렸습니다.',
    signFailed: '서명 실패',
    verifyPass: '비밀번호 확인',
    keyAlreadyExists: '이 지문의 키가 이미 존재합니다.',
    keyN: '키 #',
    storageKeys: '암호화된 키 배열 (AES-256-GCM)',
    deleteKeyConfirm1: '이 키를 삭제하시겠습니까? 되돌릴 수 없습니다.\n시드 구문 백업을 확인하세요!',
    deleteKeyConfirm2: '정말 확실합니까? 백업이 없으면 비트코인을 잃게 됩니다.',
    selectKeyForBms: '서명에 사용할 키를 선택하세요',
    selectKeyAtSign: '(서명 시 키를 선택합니다)',
    renameKeyTitle: '키 이름 변경',
    save: '저장',
  },
  es: {
    unlocked: 'Desbloqueado', locked: 'Bloqueado',
    tabKey: 'Clave', tabSign: 'Firmar', tabSettings: 'Ajustes',
    createKeys: 'Crea tu clave',
    setupDesc: 'Genera una nueva clave con entrop\u00eda f\u00edsica,<br>o importa una frase semilla existente.',
    diceBtn: 'Dado (99 lanzamientos)', coinBtn: 'Moneda (256 lanzamientos)', importBtn: 'Importar frase semilla',
    enterPassphrase: 'Introduce la contrase\u00f1a para desbloquear', passphrase: 'Contrase\u00f1a', unlock: 'Desbloquear', wrongPassphrase: 'Contrase\u00f1a incorrecta.',
    yourKey: 'Tu clave', network: 'Red', fingerprint: 'Huella digital', keyCreated: 'Creada', lastOnline: '\u00dalt. en l\u00ednea', neverOnline: 'Nunca (seguro)', onlineAfterKey: 'La clave puede estar comprometida. Genera una nueva en un dispositivo limpio.', accountXpub: 'xpub de cuenta',
    showXpubQR: 'Mostrar QR xpub', lockBtn: 'Bloquear', mainnet: 'Mainnet', testnet: 'Testnet',
    diceTitle: 'Generaci\u00f3n con dado', diceDesc: 'Lanza un dado f\u00edsico real y toca el resultado.',
    progress: 'Progreso', undoLast: 'Deshacer', cancel: 'Cancelar', ok: 'OK',
    coinTitle: 'Generaci\u00f3n con moneda', coinDesc: 'Lanza una moneda f\u00edsica real y toca el resultado.',
    entropyWarning: 'Usa un dado/moneda f\u00edsico real \u2014 nunca inventes n\u00fameros. Las elecciones humanas son predecibles y debilitan tu clave. Sin c\u00e1maras ni micr\u00f3fonos cerca \u2014 quien vea tus lanzamientos puede robar tu Bitcoin.',
    heads: 'H (Cara)', tails: 'T (Cruz)',
    writeDown: '\u00a1Anota estas palabras!',
    mnemonicDesc: 'Esta es tu frase semilla. Gu\u00e1rdala de forma segura sin conexi\u00f3n. NO se mostrar\u00e1 de nuevo.',
    stolenVsLost: 'Robado vs. Perdido \u2014 conoce la diferencia',
    theft: 'Robo:', theftDesc: 'Si alguien encuentra tu frase semilla, puede robar tus Bitcoin de inmediato. Nadie puede revertirlo.',
    loss: 'P\u00e9rdida:', lossDesc: 'Si pierdes tu frase semilla y tu dispositivo se rompe, tus Bitcoin se pierden para siempre \u2014 a menos que tengas un plan de recuperaci\u00f3n.',
    bitclutchPromo: '<strong>BitClutch</strong> protege contra p\u00e9rdida y fallecimiento, no contra robo. Crea una <strong>Billetera Protegida</strong> con timelock \u2014 tus Bitcoin siguen siendo tuyos, pero tus herederos pueden recuperarlos si algo te sucede.',
    visitBitclutch: 'Visita <strong>bitclutch.app</strong> en un dispositivo con conexi\u00f3n para crear una Billetera Protegida.',
    confirmedWritten: 'Lo he anotado',
    importTitle: 'Importar frase semilla', importDesc: 'Selecciona el n\u00famero de palabras y el idioma, luego ingresa cada palabra.',
    importPlaceholder: 'palabra1 palabra2 palabra3 ...', importAction: 'Importar', words: 'palabras',
    fillAllWords: 'Por favor completa todas las palabras.', needWords: 'Se necesitan 12 o 24 palabras', invalidMnemonic: 'Mnemot\u00e9cnico inv\u00e1lido',
    setPassTitle: 'Establecer contrase\u00f1a', setPassDesc: 'Elige una contrase\u00f1a fuerte para cifrar tu clave privada. La necesitar\u00e1s cada vez que desbloquees.',
    confirmPass: 'Confirmar contrase\u00f1a', enterPass: 'Introducir contrase\u00f1a',
    passRequired: 'La contrase\u00f1a es obligatoria.', passTooShort: 'Contrase\u00f1a demasiado corta (m\u00edn. 4 caracteres).', passNoMatch: 'Las contrase\u00f1as no coinciden.',
    noKeyToSave: 'No hay clave para guardar. Empieza de nuevo.', encryptSave: 'Cifrar y guardar', encryptFailed: 'Error de cifrado: ',
    scanTitle: 'Escanear QR', scanDesc: 'Apunta la c\u00e1mara al c\u00f3digo QR de tu app BitClutch.',
    startingCamera: 'Iniciando c\u00e1mara...', scanning: 'Escaneando... Apunta al c\u00f3digo QR.', cameraError: 'Error de c\u00e1mara: ',
    receivingFountain: 'Recibiendo c\u00f3digo fountain...', urFailed: 'Decodificaci\u00f3n UR fallida. Int\u00e9ntalo de nuevo.', psbtParseError: 'Error de an\u00e1lisis PSBT: ',
    confirmTx: 'Confirmar transacci\u00f3n', reviewBeforeSign: 'Revisa cuidadosamente antes de firmar.',
    inputs: 'Entradas', output: 'Salida', change: '(cambio)', fee: 'Comisi\u00f3n', reject: 'Rechazar', sign: 'Firmar', signingFailed: 'Error al firmar: ',
    signedPsbt: 'PSBT firmado', showQRDesc: 'Deja que tu app BitClutch escanee este QR para transmitir la transacci\u00f3n.', scanComplete: 'Escaneo completado', scanSignatureDesc: 'Deja que tu app BitClutch escanee este QR para enviar la firma.',
    singleQR: 'QR \u00fanico', fountainKeepShowing: 'c\u00f3digo fountain \u2014 sigue mostrando', frame: 'Fotograma',
    confirmBms: 'Confirmar firma de mensaje', reviewMessage: 'Revisa el mensaje antes de firmar.',
    type: 'Tipo', bmsType: 'BMS (Mensaje Bitcoin)', index: '\u00cdndice', address: 'Direcci\u00f3n', message: 'Mensaje',
    bmsSignature: 'Firma BMS', sigBase64: 'Firma (base64)', tapToCopy: 'Toca para copiar', copySig: 'Copiar firma', sha256: 'SHA-256',
    settings: 'Ajustes', version: 'Versi\u00f3n', language: 'Idioma', seedLanguage: 'Idioma semilla',
    onlineKeygenTitle: '\u00a1Red conectada!',
    onlineKeygenBody: 'Tu dispositivo est\u00e1 conectado a internet. Las claves generadas en l\u00ednea pueden ser interceptadas por malware. Desconecta TODAS las redes (WiFi, celular, Bluetooth, USB) antes de continuar.',
    proceedAnyway: 'Continuar de todos modos (inseguro)',
    installGuide: 'Gu\u00eda de instalaci\u00f3n', viewSource: 'Verificar integridad del c\u00f3digo', securityInfo: 'Info de seguridad',
    deleteKey: 'Eliminar clave', deleteConfirm1: '\u00bfEliminar tu clave? No se puede deshacer.\n\u00a1Aseg\u00farate de tener tu frase semilla respaldada!',
    deleteConfirm2: '\u00bfEst\u00e1s absolutamente seguro? Tus Bitcoin se PERDER\u00c1N si no tienes respaldo.',
    verifyIntegrity: 'Verificar integridad', verifyDesc: 'Compara los hashes SHA-256 con la versi\u00f3n oficial en GitHub.',
    computing: 'Calculando...', fetchFailed: '(error de descarga)',
    verifyFile: 'Verificar este archivo', verifyFileDesc: 'Toca aqu\u00ed y selecciona el archivo <strong>bitclutch-signer.html</strong> que descargaste.<br>Su hash SHA-256 se calcular\u00e1 localmente.',
    tapToSelect: 'Toca para seleccionar', compareGithub: 'Compara con <code>hashes.json</code> de la versi\u00f3n de GitHub.',
    auditableSource: 'C\u00f3digo auditable', auditableDesc: 'Toda la l\u00f3gica de esta app est\u00e1 en un solo archivo auditable. El c\u00f3digo fuente y los hashes oficiales est\u00e1n publicados en GitHub.',
    back: 'Volver',
    securityTitle: 'Informaci\u00f3n de seguridad', securityLevel: 'Nivel de seguridad: Air-gap por software',
    whatProvides: 'Lo que proporciona:', secProvide1: 'La clave privada nunca toca internet (despu\u00e9s de la configuraci\u00f3n)',
    secProvide2: 'El c\u00f3digo es auditable (un solo archivo app.js)', secProvide3: 'Entrop\u00eda solo de fuentes f\u00edsicas (dados/monedas)',
    secProvide4: 'Cifrado AES-256-GCM con 600K iteraciones PBKDF2',
    whatNot: 'Lo que NO proporciona:', secNot1: 'Secure Element (las billeteras hardware lo tienen)',
    secNot2: 'Air gap a nivel hardware (el chip WiFi sigue existiendo)', secNot3: 'Resistencia a ataques de canal lateral',
    keyStorage: 'Almacenamiento de claves', encryption: 'Cifrado:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600,000 iteraciones) + salt/IV aleatorio',
    warning: 'Advertencia:', clearDataWarning: 'Borrar los datos del navegador eliminar\u00e1 permanentemente tu clave cifrada. Siempre mant\u00e9n tu frase semilla respaldada sin conexi\u00f3n.',
    autoLock: 'Bloqueo autom\u00e1tico:', autoLockDesc: 'Las claves se borran de la memoria tras 5 minutos de inactividad.',
    storageEncKey: 'Clave privada cifrada (AES-256-GCM)', storageXpub: 'Clave p\u00fablica extendida de cuenta', storageFp: 'Huella BIP-32',
    storageNet: 'Configuraci\u00f3n de red (main/test)', storageLang: 'Idioma de la interfaz', storageSeedLang: 'Idioma de frase semilla', storageKeyCreated: 'Marca de tiempo de creaci\u00f3n', storageLastOnline: 'Marca de tiempo de red',
    guideTitle: 'Gu\u00eda de instalaci\u00f3n', guideDesc: 'Instala BitClutch Signer como app sin conexi\u00f3n, luego activa el modo avi\u00f3n antes de usarla.',
    detected: 'Detectado',
    guideIosSafari: '<strong>Instalar como app sin conexi\u00f3n:</strong><ol><li>Abre esta p\u00e1gina en <strong>Safari</strong></li><li>Toca el bot\u00f3n <strong>Share</strong> (cuadro con flecha)</li><li>Despl\u00e1zate hacia abajo y toca <strong>"Add to Home Screen"</strong></li><li>Toca <strong>"Add"</strong> en la esquina superior derecha</li></ol><strong>Activar modo avi\u00f3n:</strong><ol><li>Desliza hacia abajo desde la esquina superior derecha (o hacia arriba desde abajo en iPhones antiguos)</li><li>Toca el <strong>icono de avi\u00f3n</strong> para activarlo</li><li>Aseg\u00farate de que Wi-Fi y Bluetooth tambi\u00e9n est\u00e9n apagados</li></ol>',
    guideIosChrome: '<strong>Importante:</strong> Chrome en iOS no puede instalar apps sin conexi\u00f3n. Usa <strong>Safari</strong> en su lugar.<ol><li>Copia la URL de esta p\u00e1gina</li><li>Abre <strong>Safari</strong> y pega la URL</li><li>Sigue las instrucciones de <strong>iOS Safari</strong> de arriba</li></ol><strong>Activar modo avi\u00f3n:</strong><ol><li>Desliza hacia abajo desde la esquina superior derecha</li><li>Toca el <strong>icono de avi\u00f3n</strong></li></ol>',
    guideAndroidChrome: '<strong>Instalar como app sin conexi\u00f3n:</strong><ol><li>Abre esta p\u00e1gina en <strong>Chrome</strong></li><li>Toca el <strong>men\u00fa de tres puntos</strong> (arriba a la derecha)</li><li>Toca <strong>"Install app"</strong> o <strong>"Add to Home screen"</strong></li><li>Confirma tocando <strong>"Install"</strong></li></ol><strong>Activar modo avi\u00f3n:</strong><ol><li>Desliza hacia abajo desde la parte superior de la pantalla</li><li>Toca <strong>"Airplane mode"</strong></li><li>Verifica que Wi-Fi y datos m\u00f3viles est\u00e9n apagados</li></ol>',
    guideAndroidSamsung: '<strong>Instalar como app sin conexi\u00f3n:</strong><ol><li>Abre esta p\u00e1gina en <strong>Samsung Internet</strong></li><li>Toca el <strong>icono de men\u00fa</strong> (tres l\u00edneas, abajo a la derecha)</li><li>Toca <strong>"Add page to"</strong> y luego <strong>"Home screen"</strong></li></ol><strong>Activar modo avi\u00f3n:</strong><ol><li>Desliza hacia abajo desde la parte superior dos veces para abrir Ajustes r\u00e1pidos</li><li>Toca <strong>"Airplane mode"</strong></li></ol>',
    guideMacosSafari: '<strong>Instalar como app sin conexi\u00f3n (macOS Sonoma+):</strong><ol><li>Abre esta p\u00e1gina en <strong>Safari</strong></li><li>Haz clic en el men\u00fa <strong>File</strong> y luego en <strong>"Add to Dock"</strong></li><li>Haz clic en <strong>"Add"</strong></li></ol><strong>Desactivar red:</strong><ol><li>Haz clic en el <strong>icono de Wi-Fi</strong> en la barra de men\u00fa</li><li>Haz clic para <strong>desactivar Wi-Fi</strong></li><li>Desconecta cualquier cable Ethernet</li></ol>',
    guideMacosChrome: '<strong>Instalar como app sin conexi\u00f3n:</strong><ol><li>Abre esta p\u00e1gina en <strong>Chrome</strong></li><li>Haz clic en el <strong>icono de instalaci\u00f3n</strong> en la barra de direcciones (o men\u00fa de tres puntos &rarr; "Install BitClutch Signer")</li><li>Haz clic en <strong>"Install"</strong></li></ol><strong>Desactivar red:</strong><ol><li>Haz clic en el <strong>icono de Wi-Fi</strong> en la barra de men\u00fa</li><li>Haz clic para <strong>desactivar Wi-Fi</strong></li><li>Desconecta cualquier cable Ethernet</li></ol>',
    guideWindowsChrome: '<strong>Instalar como app sin conexi\u00f3n:</strong><ol><li>Abre esta p\u00e1gina en <strong>Chrome</strong></li><li>Haz clic en el <strong>icono de instalaci\u00f3n</strong> en la barra de direcciones (o men\u00fa de tres puntos &rarr; "Install BitClutch Signer")</li><li>Haz clic en <strong>"Install"</strong></li></ol><strong>Desactivar red:</strong><ol><li>Haz clic en el <strong>icono de Wi-Fi</strong> en la barra de tareas (abajo a la derecha)</li><li>Haz clic para <strong>desconectar Wi-Fi</strong></li><li>Desconecta cualquier cable Ethernet</li></ol>',
    guideWindowsEdge: '<strong>Instalar como app sin conexi\u00f3n:</strong><ol><li>Abre esta p\u00e1gina en <strong>Edge</strong></li><li>Haz clic en el <strong>icono de instalaci\u00f3n</strong> en la barra de direcciones (o men\u00fa de tres puntos &rarr; "Aplicaciones" &rarr; "Install BitClutch Signer")</li><li>Haz clic en <strong>"Install"</strong></li></ol><strong>Desactivar red:</strong><ol><li>Haz clic en el <strong>icono de Wi-Fi</strong> en la barra de tareas (abajo a la derecha)</li><li>Haz clic para <strong>desconectar Wi-Fi</strong></li><li>Desconecta cualquier cable Ethernet</li></ol>',
    accountXpubTitle: 'xpub de cuenta',
    noMnemonic: 'No hay mnemot\u00e9cnico disponible.', noTxData: 'No hay datos de transacci\u00f3n.', noSignedData: 'No hay datos firmados.',
    noBmsRequest: 'No hay solicitud BMS.', noSignature: 'No hay firma.', loading: 'Cargando...',
    bannerWarn: 'RED DETECTADA \u2014 Desconecte todas las redes antes de generar claves.',
    bannerOnline: 'RED CONECTADA \u2014 Descon\u00e9ctese AHORA y NUNCA vuelva a conectar este dispositivo. Las claves pueden estar expuestas.',
    bannerOffline: 'No se detect\u00f3 red inal\u00e1mbrica. Verifique que Bluetooth, NFC y cables USB de datos tambi\u00e9n est\u00e9n desconectados.',
  },
  ja: {
    unlocked: '\u30ed\u30c3\u30af\u89e3\u9664', locked: '\u30ed\u30c3\u30af\u6e08\u307f',
    tabKey: '\u9375', tabSign: '\u7f72\u540d', tabSettings: '\u8a2d\u5b9a',
    createKeys: '\u9375\u3092\u4f5c\u6210',
    setupDesc: '\u7269\u7406\u7684\u30a8\u30f3\u30c8\u30ed\u30d4\u30fc\u3067\u65b0\u3057\u3044\u9375\u3092\u751f\u6210\u3059\u308b\u304b\u3001<br>\u65e2\u5b58\u306e\u30b7\u30fc\u30c9\u30d5\u30ec\u30fc\u30ba\u3092\u30a4\u30f3\u30dd\u30fc\u30c8\u3057\u307e\u3059\u3002',
    diceBtn: '\u30b5\u30a4\u30b3\u30ed (99\u56de)', coinBtn: '\u30b3\u30a4\u30f3\u6295\u3052 (256\u56de)', importBtn: '\u30b7\u30fc\u30c9\u30d5\u30ec\u30fc\u30ba\u3092\u30a4\u30f3\u30dd\u30fc\u30c8',
    enterPassphrase: '\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u3092\u5165\u529b\u3057\u3066\u30ed\u30c3\u30af\u89e3\u9664', passphrase: '\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba', unlock: '\u30ed\u30c3\u30af\u89e3\u9664', wrongPassphrase: '\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u304c\u9055\u3044\u307e\u3059\u3002',
    yourKey: '\u3042\u306a\u305f\u306e\u9375', network: '\u30cd\u30c3\u30c8\u30ef\u30fc\u30af', fingerprint: '\u30d5\u30a3\u30f3\u30ac\u30fc\u30d7\u30ea\u30f3\u30c8', keyCreated: '\u4f5c\u6210\u65e5', lastOnline: '\u6700\u7d42\u30aa\u30f3\u30e9\u30a4\u30f3', neverOnline: '\u306a\u3057 (\u5b89\u5168)', onlineAfterKey: '\u9375\u4f5c\u6210\u5f8c\u306b\u30aa\u30f3\u30e9\u30a4\u30f3\u691c\u51fa', accountXpub: '\u30a2\u30ab\u30a6\u30f3\u30c8xpub',
    showXpubQR: 'xpub QR\u3092\u8868\u793a', lockBtn: '\u30ed\u30c3\u30af', mainnet: '\u30e1\u30a4\u30f3\u30cd\u30c3\u30c8', testnet: '\u30c6\u30b9\u30c8\u30cd\u30c3\u30c8',
    diceTitle: '\u30b5\u30a4\u30b3\u30ed\u9375\u751f\u6210', diceDesc: '\u5b9f\u969b\u306e6\u9762\u30b5\u30a4\u30b3\u30ed\u3092\u632f\u3063\u3066\u7d50\u679c\u3092\u30bf\u30c3\u30d7\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    progress: '\u9032\u6357', undoLast: '\u5143\u306b\u623b\u3059', cancel: '\u30ad\u30e3\u30f3\u30bb\u30eb', ok: 'OK',
    coinTitle: '\u30b3\u30a4\u30f3\u6295\u3052\u9375\u751f\u6210', coinDesc: '\u5b9f\u969b\u306e\u30b3\u30a4\u30f3\u3092\u6295\u3052\u3066\u7d50\u679c\u3092\u30bf\u30c3\u30d7\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    entropyWarning: '\u5b9f\u969b\u306e\u30b5\u30a4\u30b3\u30ed/\u30b3\u30a4\u30f3\u3092\u4f7f\u7528\u3057\u3066\u304f\u3060\u3055\u3044 \u2014 \u6570\u5b57\u3092\u9069\u5f53\u306b\u5165\u529b\u3057\u306a\u3044\u3067\u304f\u3060\u3055\u3044\u3002\u4eba\u9593\u306e\u9078\u629e\u306f\u4e88\u6e2c\u53ef\u80fd\u3067\u9375\u3092\u5f31\u4f53\u5316\u3055\u305b\u307e\u3059\u3002\u8fd1\u304f\u306b\u30ab\u30e1\u30e9\u3084\u30de\u30a4\u30af\u304c\u306a\u3044\u3053\u3068\u3092\u78ba\u8a8d \u2014 \u6295\u3052\u7d50\u679c\u3092\u898b\u305f\u4eba\u306f\u30d3\u30c3\u30c8\u30b3\u30a4\u30f3\u3092\u76d7\u3081\u307e\u3059\u3002',
    heads: 'H (\u8868)', tails: 'T (\u88cf)',
    writeDown: '\u3053\u306e\u5358\u8a9e\u3092\u66f8\u304d\u7559\u3081\u3066\u304f\u3060\u3055\u3044\uff01',
    mnemonicDesc: '\u3053\u308c\u306f\u30b7\u30fc\u30c9\u30d5\u30ec\u30fc\u30ba\u3067\u3059\u3002\u30aa\u30d5\u30e9\u30a4\u30f3\u3067\u5b89\u5168\u306b\u4fdd\u7ba1\u3057\u3066\u304f\u3060\u3055\u3044\u3002\u518d\u8868\u793a\u3055\u308c\u307e\u305b\u3093\u3002',
    stolenVsLost: '\u76d7\u96e3 vs. \u7d1b\u5931 \u2014 \u9055\u3044\u3092\u77e5\u308d\u3046',
    theft: '\u76d7\u96e3:', theftDesc: '\u8ab0\u304b\u304c\u30b7\u30fc\u30c9\u30d5\u30ec\u30fc\u30ba\u3092\u898b\u3064\u3051\u308b\u3068\u3001\u5373\u5ea7\u306b\u30d3\u30c3\u30c8\u30b3\u30a4\u30f3\u3092\u76d7\u307e\u308c\u307e\u3059\u3002\u8ab0\u3082\u53d6\u308a\u6d88\u305b\u307e\u305b\u3093\u3002',
    loss: '\u7d1b\u5931:', lossDesc: '\u30b7\u30fc\u30c9\u30d5\u30ec\u30fc\u30ba\u3092\u5931\u3044\u30c7\u30d0\u30a4\u30b9\u304c\u58ca\u308c\u308b\u3068\u3001\u30d3\u30c3\u30c8\u30b3\u30a4\u30f3\u306f\u6c38\u9060\u306b\u5931\u308f\u308c\u307e\u3059 \u2014 \u5fa9\u65e7\u8a08\u753b\u304c\u306a\u3044\u9650\u308a\u3002',
    bitclutchPromo: '<strong>BitClutch</strong>\u306f\u7d1b\u5931\u3068\u6b7b\u4ea1\u304b\u3089\u4fdd\u8b77\u3057\u307e\u3059\u3002\u76d7\u96e3\u3067\u306f\u3042\u308a\u307e\u305b\u3093\u3002\u30bf\u30a4\u30e0\u30ed\u30c3\u30af\u4ed8\u304d\u306e<strong>\u4fdd\u8b77\u30a6\u30a9\u30ec\u30c3\u30c8</strong>\u3092\u4f5c\u6210 \u2014 \u30d3\u30c3\u30c8\u30b3\u30a4\u30f3\u306f\u3042\u306a\u305f\u306e\u3082\u306e\u3067\u3059\u304c\u3001\u4e07\u304c\u4e00\u306e\u6642\u306b\u76f8\u7d9a\u4eba\u304c\u5fa9\u65e7\u3067\u304d\u307e\u3059\u3002',
    visitBitclutch: '\u30aa\u30f3\u30e9\u30a4\u30f3\u30c7\u30d0\u30a4\u30b9\u3067<strong>bitclutch.app</strong>\u306b\u30a2\u30af\u30bb\u30b9\u3057\u3066\u4fdd\u8b77\u30a6\u30a9\u30ec\u30c3\u30c8\u3092\u4f5c\u6210\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    confirmedWritten: '\u66f8\u304d\u7559\u3081\u307e\u3057\u305f',
    importTitle: '\u30b7\u30fc\u30c9\u30d5\u30ec\u30fc\u30ba\u3092\u30a4\u30f3\u30dd\u30fc\u30c8', importDesc: '\u5358\u8a9e\u6570\u3068\u8a00\u8a9e\u3092\u9078\u629e\u3057\u3001\u5404\u5358\u8a9e\u3092\u5165\u529b\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    importPlaceholder: '\u5358\u8a9e1 \u5358\u8a9e2 \u5358\u8a9e3 ...', importAction: '\u30a4\u30f3\u30dd\u30fc\u30c8', words: '\u5358\u8a9e',
    fillAllWords: '\u3059\u3079\u3066\u306e\u5358\u8a9e\u3092\u5165\u529b\u3057\u3066\u304f\u3060\u3055\u3044\u3002', needWords: '12\u307e\u305f\u306f24\u5358\u8a9e\u304c\u5fc5\u8981\u3067\u3059', invalidMnemonic: '\u7121\u52b9\u306a\u30cb\u30fc\u30e2\u30cb\u30c3\u30af',
    setPassTitle: '\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u8a2d\u5b9a', setPassDesc: '\u79d8\u5bc6\u9375\u3092\u6697\u53f7\u5316\u3059\u308b\u5f37\u529b\u306a\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u3092\u9078\u3093\u3067\u304f\u3060\u3055\u3044\u3002\u30ed\u30c3\u30af\u89e3\u9664\u306e\u305f\u3073\u306b\u5fc5\u8981\u3067\u3059\u3002',
    confirmPass: '\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u78ba\u8a8d', enterPass: '\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u5165\u529b',
    passRequired: '\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u306f\u5fc5\u9808\u3067\u3059\u3002', passTooShort: '\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u304c\u77ed\u3059\u304e\u307e\u3059\uff08\u6700\u4f4e4\u6587\u5b57\uff09\u3002', passNoMatch: '\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u304c\u4e00\u81f4\u3057\u307e\u305b\u3093\u3002',
    noKeyToSave: '\u4fdd\u5b58\u3059\u308b\u9375\u304c\u3042\u308a\u307e\u305b\u3093\u3002\u6700\u521d\u304b\u3089\u3084\u308a\u76f4\u3057\u3066\u304f\u3060\u3055\u3044\u3002', encryptSave: '\u6697\u53f7\u5316\u3057\u3066\u4fdd\u5b58', encryptFailed: '\u6697\u53f7\u5316\u5931\u6557: ',
    scanTitle: 'QR\u30b9\u30ad\u30e3\u30f3', scanDesc: 'BitClutch\u30a2\u30d7\u30ea\u306eQR\u30b3\u30fc\u30c9\u306b\u30ab\u30e1\u30e9\u3092\u5411\u3051\u3066\u304f\u3060\u3055\u3044\u3002',
    startingCamera: '\u30ab\u30e1\u30e9\u8d77\u52d5\u4e2d...', scanning: '\u30b9\u30ad\u30e3\u30f3\u4e2d... QR\u30b3\u30fc\u30c9\u3092\u5411\u3051\u3066\u304f\u3060\u3055\u3044\u3002', cameraError: '\u30ab\u30e1\u30e9\u30a8\u30e9\u30fc: ',
    receivingFountain: '\u30d5\u30a1\u30a6\u30f3\u30c6\u30f3\u30b3\u30fc\u30c9\u53d7\u4fe1\u4e2d...', urFailed: 'UR\u30c7\u30b3\u30fc\u30c9\u5931\u6557\u3002\u3082\u3046\u4e00\u5ea6\u304a\u8a66\u3057\u304f\u3060\u3055\u3044\u3002', psbtParseError: 'PSBT\u89e3\u6790\u30a8\u30e9\u30fc: ',
    confirmTx: '\u30c8\u30e9\u30f3\u30b6\u30af\u30b7\u30e7\u30f3\u78ba\u8a8d', reviewBeforeSign: '\u7f72\u540d\u524d\u306b\u6ce8\u610f\u6df1\u304f\u78ba\u8a8d\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    inputs: '\u5165\u529b', output: '\u51fa\u529b', change: '(\u304a\u91e3\u308a)', fee: '\u624b\u6570\u6599', reject: '\u62d2\u5426', sign: '\u7f72\u540d', signingFailed: '\u7f72\u540d\u5931\u6557: ',
    signedPsbt: '\u7f72\u540d\u6e08\u307fPSBT', showQRDesc: 'BitClutch\u30a2\u30d7\u30ea\u3067\u3053\u306eQR\u30b3\u30fc\u30c9\u3092\u30b9\u30ad\u30e3\u30f3\u3057\u3066\u30c8\u30e9\u30f3\u30b6\u30af\u30b7\u30e7\u30f3\u3092\u30d6\u30ed\u30fc\u30c9\u30ad\u30e3\u30b9\u30c8\u3057\u3066\u304f\u3060\u3055\u3044\u3002', scanComplete: '\u30b9\u30ad\u30e3\u30f3\u5b8c\u4e86', scanSignatureDesc: 'BitClutch\u30a2\u30d7\u30ea\u3067\u3053\u306eQR\u30b3\u30fc\u30c9\u3092\u30b9\u30ad\u30e3\u30f3\u3057\u3066\u7f72\u540d\u3092\u9001\u4fe1\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    singleQR: '\u5358\u4e00QR', fountainKeepShowing: '\u30d5\u30a1\u30a6\u30f3\u30c6\u30f3\u30b3\u30fc\u30c9 \u2014 \u8868\u793a\u3092\u7d9a\u3051\u3066\u304f\u3060\u3055\u3044', frame: '\u30d5\u30ec\u30fc\u30e0',
    confirmBms: '\u30e1\u30c3\u30bb\u30fc\u30b8\u7f72\u540d\u78ba\u8a8d', reviewMessage: '\u7f72\u540d\u524d\u306b\u30e1\u30c3\u30bb\u30fc\u30b8\u3092\u78ba\u8a8d\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    type: '\u30bf\u30a4\u30d7', bmsType: 'BMS (\u30d3\u30c3\u30c8\u30b3\u30a4\u30f3\u30e1\u30c3\u30bb\u30fc\u30b8)', index: '\u30a4\u30f3\u30c7\u30c3\u30af\u30b9', address: '\u30a2\u30c9\u30ec\u30b9', message: '\u30e1\u30c3\u30bb\u30fc\u30b8',
    bmsSignature: 'BMS\u7f72\u540d', sigBase64: '\u7f72\u540d (base64)', tapToCopy: '\u30bf\u30c3\u30d7\u3057\u3066\u30b3\u30d4\u30fc', copySig: '\u7f72\u540d\u3092\u30b3\u30d4\u30fc', sha256: 'SHA-256',
    settings: '\u8a2d\u5b9a', version: '\u30d0\u30fc\u30b8\u30e7\u30f3', language: '\u8a00\u8a9e', seedLanguage: '\u30b7\u30fc\u30c9\u8a00\u8a9e',
    onlineKeygenTitle: '\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u63a5\u7d9a\u4e2d\uff01',
    onlineKeygenBody: '\u30c7\u30d0\u30a4\u30b9\u304c\u30a4\u30f3\u30bf\u30fc\u30cd\u30c3\u30c8\u306b\u63a5\u7d9a\u3055\u308c\u3066\u3044\u307e\u3059\u3002\u30aa\u30f3\u30e9\u30a4\u30f3\u3067\u751f\u6210\u3055\u308c\u305f\u9375\u306f\u30de\u30eb\u30a6\u30a7\u30a2\u306b\u50b5\u53d7\u3055\u308c\u308b\u53ef\u80fd\u6027\u304c\u3042\u308a\u307e\u3059\u3002\u7d9a\u884c\u3059\u308b\u524d\u306b\u3059\u3079\u3066\u306e\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\uff08WiFi\u3001\u30e2\u30d0\u30a4\u30eb\u3001Bluetooth\u3001USB\uff09\u3092\u5207\u65ad\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    proceedAnyway: '\u305d\u306e\u307e\u307e\u7d9a\u884c\uff08\u5371\u967a\uff09',
    installGuide: '\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb\u30ac\u30a4\u30c9', viewSource: '\u30bd\u30fc\u30b9\u6574\u5408\u6027\u691c\u8a3c', securityInfo: '\u30bb\u30ad\u30e5\u30ea\u30c6\u30a3\u60c5\u5831',
    deleteKey: '\u9375\u3092\u524a\u9664', deleteConfirm1: '\u9375\u3092\u524a\u9664\u3057\u307e\u3059\u304b\uff1f\u53d6\u308a\u6d88\u305b\u307e\u305b\u3093\u3002\n\u30b7\u30fc\u30c9\u30d5\u30ec\u30fc\u30ba\u306e\u30d0\u30c3\u30af\u30a2\u30c3\u30d7\u3092\u78ba\u8a8d\u3057\u3066\u304f\u3060\u3055\u3044\uff01',
    deleteConfirm2: '\u672c\u5f53\u306b\u78ba\u5b9f\u3067\u3059\u304b\uff1f\u30d0\u30c3\u30af\u30a2\u30c3\u30d7\u304c\u306a\u3044\u3068\u30d3\u30c3\u30c8\u30b3\u30a4\u30f3\u304c\u5931\u308f\u308c\u307e\u3059\u3002',
    verifyIntegrity: '\u6574\u5408\u6027\u691c\u8a3c', verifyDesc: 'SHA-256\u30cf\u30c3\u30b7\u30e5\u3092GitHub\u306e\u516c\u5f0f\u30ea\u30ea\u30fc\u30b9\u3068\u6bd4\u8f03\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    computing: '\u8a08\u7b97\u4e2d...', fetchFailed: '(\u53d6\u5f97\u5931\u6557)',
    verifyFile: '\u3053\u306e\u30d5\u30a1\u30a4\u30eb\u3092\u691c\u8a3c', verifyFileDesc: '\u3053\u3053\u3092\u30bf\u30c3\u30d7\u3057\u3066\u30c0\u30a6\u30f3\u30ed\u30fc\u30c9\u3057\u305f<strong>bitclutch-signer.html</strong>\u3092\u9078\u629e\u3002<br>SHA-256\u30cf\u30c3\u30b7\u30e5\u304c\u30ed\u30fc\u30ab\u30eb\u3067\u8a08\u7b97\u3055\u308c\u307e\u3059\u3002',
    tapToSelect: '\u30bf\u30c3\u30d7\u3057\u3066\u9078\u629e', compareGithub: 'GitHub\u30ea\u30ea\u30fc\u30b9\u306e<code>hashes.json</code>\u3068\u6bd4\u8f03\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    auditableSource: '\u76e3\u67fb\u53ef\u80fd\u306a\u30bd\u30fc\u30b9', auditableDesc: '\u3053\u306e\u30a2\u30d7\u30ea\u306e\u5168\u30ed\u30b8\u30c3\u30af\u306f\u76e3\u67fb\u53ef\u80fd\u306a\u5358\u4e00\u30d5\u30a1\u30a4\u30eb\u306b\u3042\u308a\u307e\u3059\u3002\u30bd\u30fc\u30b9\u30b3\u30fc\u30c9\u3068\u516c\u5f0f\u30cf\u30c3\u30b7\u30e5\u306fGitHub\u3067\u516c\u958b\u3055\u308c\u3066\u3044\u307e\u3059\u3002',
    back: '\u623b\u308b',
    securityTitle: '\u30bb\u30ad\u30e5\u30ea\u30c6\u30a3\u60c5\u5831', securityLevel: '\u30bb\u30ad\u30e5\u30ea\u30c6\u30a3\u30ec\u30d9\u30eb: \u30bd\u30d5\u30c8\u30a6\u30a7\u30a2\u30a8\u30a2\u30ae\u30e3\u30c3\u30d7',
    whatProvides: '\u63d0\u4f9b\u3059\u308b\u3082\u306e:', secProvide1: '\u79d8\u5bc6\u9375\u306f\u30a4\u30f3\u30bf\u30fc\u30cd\u30c3\u30c8\u306b\u63a5\u7d9a\u3057\u306a\u3044\uff08\u8a2d\u5b9a\u5f8c\uff09',
    secProvide2: '\u30b3\u30fc\u30c9\u306f\u76e3\u67fb\u53ef\u80fd\uff08\u5358\u4e00\u306eapp.js\u30d5\u30a1\u30a4\u30eb\uff09', secProvide3: '\u7269\u7406\u30bd\u30fc\u30b9\u306e\u307f\u306e\u30a8\u30f3\u30c8\u30ed\u30d4\u30fc\uff08\u30b5\u30a4\u30b3\u30ed/\u30b3\u30a4\u30f3\uff09',
    secProvide4: 'AES-256-GCM\u6697\u53f7\u5316 + 600K PBKDF2\u30a4\u30c6\u30ec\u30fc\u30b7\u30e7\u30f3',
    whatNot: '\u63d0\u4f9b\u3057\u306a\u3044\u3082\u306e:', secNot1: 'Secure Element\uff08\u30cf\u30fc\u30c9\u30a6\u30a7\u30a2\u30a6\u30a9\u30ec\u30c3\u30c8\u306b\u306f\u3042\u308a\uff09',
    secNot2: '\u30cf\u30fc\u30c9\u30a6\u30a7\u30a2\u30ec\u30d9\u30eb\u306e\u30a8\u30a2\u30ae\u30e3\u30c3\u30d7\uff08WiFi\u30c1\u30c3\u30d7\u306f\u5b58\u5728\uff09', secNot3: '\u30b5\u30a4\u30c9\u30c1\u30e3\u30cd\u30eb\u653b\u6483\u8010\u6027',
    keyStorage: '\u9375\u306e\u4fdd\u7ba1', encryption: '\u6697\u53f7\u5316:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600,000\u56de) + \u30e9\u30f3\u30c0\u30e0\u30bd\u30eb\u30c8/IV',
    warning: '\u8b66\u544a:', clearDataWarning: '\u30d6\u30e9\u30a6\u30b6\u30c7\u30fc\u30bf\u3092\u524a\u9664\u3059\u308b\u3068\u6697\u53f7\u5316\u3055\u308c\u305f\u9375\u304c\u6c38\u4e45\u306b\u524a\u9664\u3055\u308c\u307e\u3059\u3002\u30b7\u30fc\u30c9\u30d5\u30ec\u30fc\u30ba\u3092\u5e38\u306b\u30aa\u30d5\u30e9\u30a4\u30f3\u3067\u30d0\u30c3\u30af\u30a2\u30c3\u30d7\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    autoLock: '\u81ea\u52d5\u30ed\u30c3\u30af:', autoLockDesc: '5\u5206\u9593\u64cd\u4f5c\u304c\u306a\u3044\u3068\u30e1\u30e2\u30ea\u304b\u3089\u9375\u304c\u524a\u9664\u3055\u308c\u307e\u3059\u3002',
    storageEncKey: '\u6697\u53f7\u5316\u3055\u308c\u305f\u79d8\u5bc6\u9375 (AES-256-GCM)', storageXpub: '\u30a2\u30ab\u30a6\u30f3\u30c8\u62e1\u5f35\u516c\u958b\u9375', storageFp: 'BIP-32\u30d5\u30a3\u30f3\u30ac\u30fc\u30d7\u30ea\u30f3\u30c8',
    storageNet: '\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u8a2d\u5b9a (main/test)', storageLang: 'UI\u8a00\u8a9e', storageSeedLang: '\u30b7\u30fc\u30c9\u30d5\u30ec\u30fc\u30ba\u8a00\u8a9e', storageKeyCreated: '\u9375\u4f5c\u6210\u65e5\u6642', storageLastOnline: '\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u691c\u51fa\u65e5',
    guideTitle: '\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb\u30ac\u30a4\u30c9', guideDesc: 'BitClutch Signer\u3092\u30aa\u30d5\u30e9\u30a4\u30f3\u30a2\u30d7\u30ea\u3068\u3057\u3066\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb\u3057\u3001\u4f7f\u7528\u524d\u306b\u6a5f\u5185\u30e2\u30fc\u30c9\u3092\u6709\u52b9\u306b\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    detected: '\u691c\u51fa',
    guideIosSafari: '<strong>\u30aa\u30d5\u30e9\u30a4\u30f3\u30a2\u30d7\u30ea\u3068\u3057\u3066\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb:</strong><ol><li><strong>Safari</strong>\u3067\u3053\u306e\u30da\u30fc\u30b8\u3092\u958b\u304d\u307e\u3059</li><li><strong>Share</strong>\u30dc\u30bf\u30f3\uff08\u77e2\u5370\u4ed8\u304d\u306e\u56db\u89d2\uff09\u3092\u30bf\u30c3\u30d7\u3057\u307e\u3059</li><li>\u4e0b\u306b\u30b9\u30af\u30ed\u30fc\u30eb\u3057\u3066<strong>\u201cAdd to Home Screen\u201d</strong>\u3092\u30bf\u30c3\u30d7\u3057\u307e\u3059</li><li>\u53f3\u4e0a\u306e<strong>\u201cAdd\u201d</strong>\u3092\u30bf\u30c3\u30d7\u3057\u307e\u3059</li></ol><strong>\u6a5f\u5185\u30e2\u30fc\u30c9\u3092\u6709\u52b9\u306b\u3059\u308b:</strong><ol><li>\u53f3\u4e0a\u304b\u3089\u4e0b\u306b\u30b9\u30ef\u30a4\u30d7\u3057\u307e\u3059\uff08\u53e4\u3044iPhone\u3067\u306f\u4e0b\u304b\u3089\u4e0a\uff09</li><li><strong>\u98db\u884c\u6a5f\u30a2\u30a4\u30b3\u30f3</strong>\u3092\u30bf\u30c3\u30d7\u3057\u3066\u6709\u52b9\u306b\u3057\u307e\u3059</li><li>Wi-Fi\u3068Bluetooth\u3082\u30aa\u30d5\u306b\u306a\u3063\u3066\u3044\u308b\u3053\u3068\u3092\u78ba\u8a8d\u3057\u3066\u304f\u3060\u3055\u3044</li></ol>',
    guideIosChrome: '<strong>\u91cd\u8981:</strong> iOS\u306eChrome\u3067\u306f\u30aa\u30d5\u30e9\u30a4\u30f3\u30a2\u30d7\u30ea\u3092\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb\u3067\u304d\u307e\u305b\u3093\u3002\u4ee3\u308f\u308a\u306b<strong>Safari</strong>\u3092\u4f7f\u7528\u3057\u3066\u304f\u3060\u3055\u3044\u3002<ol><li>\u3053\u306e\u30da\u30fc\u30b8\u306eURL\u3092\u30b3\u30d4\u30fc\u3057\u307e\u3059</li><li><strong>Safari</strong>\u3092\u958b\u3044\u3066URL\u3092\u8cbc\u308a\u4ed8\u3051\u307e\u3059</li><li>\u4e0a\u8a18\u306e<strong>iOS Safari</strong>\u306e\u624b\u9806\u306b\u5f93\u3063\u3066\u304f\u3060\u3055\u3044</li></ol><strong>\u6a5f\u5185\u30e2\u30fc\u30c9\u3092\u6709\u52b9\u306b\u3059\u308b:</strong><ol><li>\u53f3\u4e0a\u304b\u3089\u4e0b\u306b\u30b9\u30ef\u30a4\u30d7\u3057\u307e\u3059</li><li><strong>\u98db\u884c\u6a5f\u30a2\u30a4\u30b3\u30f3</strong>\u3092\u30bf\u30c3\u30d7\u3057\u307e\u3059</li></ol>',
    guideAndroidChrome: '<strong>\u30aa\u30d5\u30e9\u30a4\u30f3\u30a2\u30d7\u30ea\u3068\u3057\u3066\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb:</strong><ol><li><strong>Chrome</strong>\u3067\u3053\u306e\u30da\u30fc\u30b8\u3092\u958b\u304d\u307e\u3059</li><li>\u53f3\u4e0a\u306e<strong>\u4e09\u70b9\u30e1\u30cb\u30e5\u30fc</strong>\u3092\u30bf\u30c3\u30d7\u3057\u307e\u3059</li><li><strong>\u201cInstall app\u201d</strong>\u307e\u305f\u306f<strong>\u201cAdd to Home screen\u201d</strong>\u3092\u30bf\u30c3\u30d7\u3057\u307e\u3059</li><li><strong>\u201cInstall\u201d</strong>\u3092\u30bf\u30c3\u30d7\u3057\u3066\u78ba\u8a8d\u3057\u307e\u3059</li></ol><strong>\u6a5f\u5185\u30e2\u30fc\u30c9\u3092\u6709\u52b9\u306b\u3059\u308b:</strong><ol><li>\u753b\u9762\u4e0a\u90e8\u304b\u3089\u4e0b\u306b\u30b9\u30ef\u30a4\u30d7\u3057\u307e\u3059</li><li><strong>\u201cAirplane mode\u201d</strong>\u3092\u30bf\u30c3\u30d7\u3057\u307e\u3059</li><li>Wi-Fi\u3068\u30e2\u30d0\u30a4\u30eb\u30c7\u30fc\u30bf\u304c\u30aa\u30d5\u306b\u306a\u3063\u3066\u3044\u308b\u3053\u3068\u3092\u78ba\u8a8d\u3057\u307e\u3059</li></ol>',
    guideAndroidSamsung: '<strong>\u30aa\u30d5\u30e9\u30a4\u30f3\u30a2\u30d7\u30ea\u3068\u3057\u3066\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb:</strong><ol><li><strong>Samsung Internet</strong>\u3067\u3053\u306e\u30da\u30fc\u30b8\u3092\u958b\u304d\u307e\u3059</li><li>\u53f3\u4e0b\u306e<strong>\u30e1\u30cb\u30e5\u30fc\u30a2\u30a4\u30b3\u30f3</strong>\uff083\u672c\u7dda\uff09\u3092\u30bf\u30c3\u30d7\u3057\u307e\u3059</li><li><strong>\u201cAdd page to\u201d</strong>\u3092\u30bf\u30c3\u30d7\u3057\u3066\u304b\u3089<strong>\u201cHome screen\u201d</strong>\u3092\u30bf\u30c3\u30d7\u3057\u307e\u3059</li></ol><strong>\u6a5f\u5185\u30e2\u30fc\u30c9\u3092\u6709\u52b9\u306b\u3059\u308b:</strong><ol><li>\u4e0a\u304b\u3089\u4e0b\u306b2\u56de\u30b9\u30ef\u30a4\u30d7\u3057\u3066\u30af\u30a4\u30c3\u30af\u8a2d\u5b9a\u3092\u958b\u304d\u307e\u3059</li><li><strong>\u201cAirplane mode\u201d</strong>\u3092\u30bf\u30c3\u30d7\u3057\u307e\u3059</li></ol>',
    guideMacosSafari: '<strong>\u30aa\u30d5\u30e9\u30a4\u30f3\u30a2\u30d7\u30ea\u3068\u3057\u3066\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb (macOS Sonoma+):</strong><ol><li><strong>Safari</strong>\u3067\u3053\u306e\u30da\u30fc\u30b8\u3092\u958b\u304d\u307e\u3059</li><li><strong>File</strong>\u30e1\u30cb\u30e5\u30fc\u3092\u30af\u30ea\u30c3\u30af\u3057\u3066<strong>\u201cAdd to Dock\u201d</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059</li><li><strong>\u201cAdd\u201d</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059</li></ol><strong>\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u3092\u7121\u52b9\u306b\u3059\u308b:</strong><ol><li>\u30e1\u30cb\u30e5\u30fc\u30d0\u30fc\u306e<strong>Wi-Fi\u30a2\u30a4\u30b3\u30f3</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059</li><li>\u30af\u30ea\u30c3\u30af\u3057\u3066<strong>Wi-Fi\u3092\u30aa\u30d5</strong>\u306b\u3057\u307e\u3059</li><li>\u30a4\u30fc\u30b5\u30cd\u30c3\u30c8\u30b1\u30fc\u30d6\u30eb\u3092\u5916\u3057\u3066\u304f\u3060\u3055\u3044</li></ol>',
    guideMacosChrome: '<strong>\u30aa\u30d5\u30e9\u30a4\u30f3\u30a2\u30d7\u30ea\u3068\u3057\u3066\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb:</strong><ol><li><strong>Chrome</strong>\u3067\u3053\u306e\u30da\u30fc\u30b8\u3092\u958b\u304d\u307e\u3059</li><li>\u30a2\u30c9\u30ec\u30b9\u30d0\u30fc\u306e<strong>\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb\u30a2\u30a4\u30b3\u30f3</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059\uff08\u307e\u305f\u306f\u4e09\u70b9\u30e1\u30cb\u30e5\u30fc &rarr; \u201cInstall BitClutch Signer\u201d\uff09</li><li><strong>\u201cInstall\u201d</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059</li></ol><strong>\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u3092\u7121\u52b9\u306b\u3059\u308b:</strong><ol><li>\u30e1\u30cb\u30e5\u30fc\u30d0\u30fc\u306e<strong>Wi-Fi\u30a2\u30a4\u30b3\u30f3</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059</li><li>\u30af\u30ea\u30c3\u30af\u3057\u3066<strong>Wi-Fi\u3092\u30aa\u30d5</strong>\u306b\u3057\u307e\u3059</li><li>\u30a4\u30fc\u30b5\u30cd\u30c3\u30c8\u30b1\u30fc\u30d6\u30eb\u3092\u5916\u3057\u3066\u304f\u3060\u3055\u3044</li></ol>',
    guideWindowsChrome: '<strong>\u30aa\u30d5\u30e9\u30a4\u30f3\u30a2\u30d7\u30ea\u3068\u3057\u3066\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb:</strong><ol><li><strong>Chrome</strong>\u3067\u3053\u306e\u30da\u30fc\u30b8\u3092\u958b\u304d\u307e\u3059</li><li>\u30a2\u30c9\u30ec\u30b9\u30d0\u30fc\u306e<strong>\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb\u30a2\u30a4\u30b3\u30f3</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059\uff08\u307e\u305f\u306f\u4e09\u70b9\u30e1\u30cb\u30e5\u30fc &rarr; \u201cInstall BitClutch Signer\u201d\uff09</li><li><strong>\u201cInstall\u201d</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059</li></ol><strong>\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u3092\u7121\u52b9\u306b\u3059\u308b:</strong><ol><li>\u30bf\u30b9\u30af\u30d0\u30fc\uff08\u53f3\u4e0b\uff09\u306e<strong>Wi-Fi\u30a2\u30a4\u30b3\u30f3</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059</li><li>\u30af\u30ea\u30c3\u30af\u3057\u3066<strong>Wi-Fi\u3092\u5207\u65ad</strong>\u3057\u307e\u3059</li><li>\u30a4\u30fc\u30b5\u30cd\u30c3\u30c8\u30b1\u30fc\u30d6\u30eb\u3092\u5916\u3057\u3066\u304f\u3060\u3055\u3044</li></ol>',
    guideWindowsEdge: '<strong>\u30aa\u30d5\u30e9\u30a4\u30f3\u30a2\u30d7\u30ea\u3068\u3057\u3066\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb:</strong><ol><li><strong>Edge</strong>\u3067\u3053\u306e\u30da\u30fc\u30b8\u3092\u958b\u304d\u307e\u3059</li><li>\u30a2\u30c9\u30ec\u30b9\u30d0\u30fc\u306e<strong>\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb\u30a2\u30a4\u30b3\u30f3</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059\uff08\u307e\u305f\u306f\u4e09\u70b9\u30e1\u30cb\u30e5\u30fc &rarr; \u201c\u30a2\u30d7\u30ea\u201d &rarr; \u201cInstall BitClutch Signer\u201d\uff09</li><li><strong>\u201cInstall\u201d</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059</li></ol><strong>\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u3092\u7121\u52b9\u306b\u3059\u308b:</strong><ol><li>\u30bf\u30b9\u30af\u30d0\u30fc\uff08\u53f3\u4e0b\uff09\u306e<strong>Wi-Fi\u30a2\u30a4\u30b3\u30f3</strong>\u3092\u30af\u30ea\u30c3\u30af\u3057\u307e\u3059</li><li>\u30af\u30ea\u30c3\u30af\u3057\u3066<strong>Wi-Fi\u3092\u5207\u65ad</strong>\u3057\u307e\u3059</li><li>\u30a4\u30fc\u30b5\u30cd\u30c3\u30c8\u30b1\u30fc\u30d6\u30eb\u3092\u5916\u3057\u3066\u304f\u3060\u3055\u3044</li></ol>',
    accountXpubTitle: '\u30a2\u30ab\u30a6\u30f3\u30c8xpub',
    noMnemonic: '\u30cb\u30fc\u30e2\u30cb\u30c3\u30af\u304c\u3042\u308a\u307e\u305b\u3093\u3002', noTxData: '\u30c8\u30e9\u30f3\u30b6\u30af\u30b7\u30e7\u30f3\u30c7\u30fc\u30bf\u304c\u3042\u308a\u307e\u305b\u3093\u3002', noSignedData: '\u7f72\u540d\u30c7\u30fc\u30bf\u304c\u3042\u308a\u307e\u305b\u3093\u3002',
    noBmsRequest: 'BMS\u30ea\u30af\u30a8\u30b9\u30c8\u304c\u3042\u308a\u307e\u305b\u3093\u3002', noSignature: '\u7f72\u540d\u304c\u3042\u308a\u307e\u305b\u3093\u3002', loading: '\u8aad\u307f\u8fbc\u307f\u4e2d...',
    bannerWarn: '\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u691c\u51fa \u2014 \u9375\u3092\u751f\u6210\u3059\u308b\u524d\u306b\u3059\u3079\u3066\u306e\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u3092\u5207\u65ad\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
    bannerOnline: '\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u63a5\u7d9a\u4e2d \u2014 \u4eca\u3059\u3050\u5207\u65ad\u3057\u3001\u3053\u306e\u7aef\u672b\u3092\u7d76\u5bfe\u306b\u518d\u63a5\u7d9a\u3057\u306a\u3044\u3067\u304f\u3060\u3055\u3044\u3002\u9375\u304c\u65e2\u306b\u6f0f\u6d29\u3057\u3066\u3044\u308b\u53ef\u80fd\u6027\u304c\u3042\u308a\u307e\u3059\u3002',
    bannerOffline: '\u7121\u7dda\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u672a\u691c\u51fa\u3002Bluetooth\u3001NFC\u3001USB\u30c7\u30fc\u30bf\u30b1\u30fc\u30d6\u30eb\u3082\u5207\u65ad\u3055\u308c\u3066\u3044\u308b\u304b\u78ba\u8a8d\u3057\u3066\u304f\u3060\u3055\u3044\u3002',
  },
  pt: {
    unlocked: 'Desbloqueado', locked: 'Bloqueado',
    tabKey: 'Chave', tabSign: 'Assinar', tabSettings: 'Config.',
    createKeys: 'Crie sua chave',
    setupDesc: 'Gere uma nova chave com entropia f\u00edsica,<br>ou importe uma frase semente existente.',
    diceBtn: 'Dado (99 lan\u00e7amentos)', coinBtn: 'Moeda (256 lan\u00e7amentos)', importBtn: 'Importar frase semente',
    enterPassphrase: 'Digite a senha para desbloquear', passphrase: 'Senha', unlock: 'Desbloquear', wrongPassphrase: 'Senha incorreta.',
    yourKey: 'Sua chave', network: 'Rede', fingerprint: 'Impress\u00e3o digital', keyCreated: 'Criada em', lastOnline: '\u00dalt. online', neverOnline: 'Nunca (seguro)', onlineAfterKey: 'Online detectado ap\u00f3s cria\u00e7\u00e3o', accountXpub: 'xpub da conta',
    showXpubQR: 'Mostrar QR xpub', lockBtn: 'Bloquear', mainnet: 'Mainnet', testnet: 'Testnet',
    diceTitle: 'Gera\u00e7\u00e3o com dado', diceDesc: 'Lance um dado f\u00edsico real e toque no resultado.',
    progress: 'Progresso', undoLast: 'Desfazer', cancel: 'Cancelar', ok: 'OK',
    coinTitle: 'Gera\u00e7\u00e3o com moeda', coinDesc: 'Lance uma moeda f\u00edsica real e toque no resultado.',
    entropyWarning: 'Use um dado/moeda f\u00edsico real \u2014 nunca invente n\u00fameros. Escolhas humanas s\u00e3o previs\u00edveis e enfraquecem sua chave. Sem c\u00e2meras ou microfones por perto \u2014 quem vir seus lan\u00e7amentos pode roubar seu Bitcoin.',
    heads: 'H (Cara)', tails: 'T (Coroa)',
    writeDown: 'Anote estas palavras!',
    mnemonicDesc: 'Esta \u00e9 sua frase semente. Guarde-a com seguran\u00e7a offline. N\u00c3O ser\u00e1 mostrada novamente.',
    stolenVsLost: 'Roubado vs. Perdido \u2014 conhe\u00e7a a diferen\u00e7a',
    theft: 'Roubo:', theftDesc: 'Se algu\u00e9m encontrar sua frase semente, pode roubar seus Bitcoin imediatamente. Ningu\u00e9m pode reverter isso.',
    loss: 'Perda:', lossDesc: 'Se voc\u00ea perder sua frase semente e seu dispositivo quebrar, seus Bitcoin se perdem para sempre \u2014 a menos que tenha um plano de recupera\u00e7\u00e3o.',
    bitclutchPromo: '<strong>BitClutch</strong> protege contra perda e falecimento, n\u00e3o contra roubo. Crie uma <strong>Carteira Protegida</strong> com timelock \u2014 seus Bitcoin continuam seus, mas seus herdeiros podem recuper\u00e1-los se algo acontecer.',
    visitBitclutch: 'Visite <strong>bitclutch.app</strong> em um dispositivo online para criar uma Carteira Protegida.',
    confirmedWritten: 'Anotei',
    importTitle: 'Importar frase semente', importDesc: 'Selecione o n\u00famero de palavras e o idioma, depois insira cada palavra.',
    importPlaceholder: 'palavra1 palavra2 palavra3 ...', importAction: 'Importar', words: 'palavras',
    fillAllWords: 'Preencha todas as palavras.', needWords: 'Necess\u00e1rio 12 ou 24 palavras', invalidMnemonic: 'Mnem\u00f4nico inv\u00e1lido',
    setPassTitle: 'Definir senha', setPassDesc: 'Escolha uma senha forte para criptografar sua chave privada. Ser\u00e1 necess\u00e1ria a cada desbloqueio.',
    confirmPass: 'Confirmar senha', enterPass: 'Digite a senha',
    passRequired: 'Senha \u00e9 obrigat\u00f3ria.', passTooShort: 'Senha muito curta (m\u00edn. 4 caracteres).', passNoMatch: 'Senhas n\u00e3o coincidem.',
    noKeyToSave: 'Nenhuma chave para salvar. Recomece.', encryptSave: 'Criptografar e salvar', encryptFailed: 'Falha na criptografia: ',
    scanTitle: 'Escanear QR', scanDesc: 'Aponte a c\u00e2mera para o QR do seu app BitClutch.',
    startingCamera: 'Iniciando c\u00e2mera...', scanning: 'Escaneando... Aponte para o QR.', cameraError: 'Erro de c\u00e2mera: ',
    receivingFountain: 'Recebendo c\u00f3digo fountain...', urFailed: 'Decodifica\u00e7\u00e3o UR falhou. Tente novamente.', psbtParseError: 'Erro de an\u00e1lise PSBT: ',
    confirmTx: 'Confirmar transa\u00e7\u00e3o', reviewBeforeSign: 'Revise cuidadosamente antes de assinar.',
    inputs: 'Entradas', output: 'Sa\u00edda', change: '(troco)', fee: 'Taxa', reject: 'Rejeitar', sign: 'Assinar', signingFailed: 'Falha na assinatura: ',
    signedPsbt: 'PSBT assinado', showQRDesc: 'Deixe seu app BitClutch escanear este QR para transmitir a transa\u00e7\u00e3o.', scanComplete: 'Escaneamento conclu\u00eddo', scanSignatureDesc: 'Deixe seu app BitClutch escanear este QR para enviar a assinatura.',
    singleQR: 'QR \u00fanico', fountainKeepShowing: 'c\u00f3digo fountain \u2014 continue mostrando', frame: 'Quadro',
    confirmBms: 'Confirmar assinatura de mensagem', reviewMessage: 'Revise a mensagem antes de assinar.',
    type: 'Tipo', bmsType: 'BMS (Mensagem Bitcoin)', index: '\u00cdndice', address: 'Endere\u00e7o', message: 'Mensagem',
    bmsSignature: 'Assinatura BMS', sigBase64: 'Assinatura (base64)', tapToCopy: 'Toque para copiar', copySig: 'Copiar assinatura', sha256: 'SHA-256',
    settings: 'Configura\u00e7\u00f5es', version: 'Vers\u00e3o', language: 'Idioma', seedLanguage: 'Idioma semente',
    onlineKeygenTitle: 'Rede conectada!',
    onlineKeygenBody: 'Seu dispositivo est\u00e1 conectado \u00e0 internet. Chaves geradas online podem ser interceptadas por malware. Desconecte TODAS as redes (WiFi, celular, Bluetooth, USB) antes de continuar.',
    proceedAnyway: 'Continuar mesmo assim (inseguro)',
    installGuide: 'Guia de instala\u00e7\u00e3o', viewSource: 'Verificar integridade do c\u00f3digo', securityInfo: 'Info de seguran\u00e7a',
    deleteKey: 'Excluir chave', deleteConfirm1: 'Excluir sua chave? N\u00e3o pode ser desfeito.\nCertifique-se de ter sua frase semente salva!',
    deleteConfirm2: 'Tem certeza absoluta? Seus Bitcoin ser\u00e3o PERDIDOS se n\u00e3o tiver backup.',
    verifyIntegrity: 'Verificar integridade', verifyDesc: 'Compare os hashes SHA-256 com a vers\u00e3o oficial no GitHub.',
    computing: 'Calculando...', fetchFailed: '(falha ao baixar)',
    verifyFile: 'Verificar este arquivo', verifyFileDesc: 'Toque aqui e selecione o arquivo <strong>bitclutch-signer.html</strong> baixado.<br>O hash SHA-256 ser\u00e1 calculado localmente.',
    tapToSelect: 'Toque para selecionar', compareGithub: 'Compare com <code>hashes.json</code> da vers\u00e3o do GitHub.',
    auditableSource: 'C\u00f3digo audit\u00e1vel', auditableDesc: 'Toda a l\u00f3gica deste app est\u00e1 em um \u00fanico arquivo audit\u00e1vel. C\u00f3digo fonte e hashes oficiais est\u00e3o publicados no GitHub.',
    back: 'Voltar',
    securityTitle: 'Informa\u00e7\u00f5es de seguran\u00e7a', securityLevel: 'N\u00edvel de seguran\u00e7a: Air-gap por software',
    whatProvides: 'O que fornece:', secProvide1: 'Chave privada nunca toca a internet (ap\u00f3s configura\u00e7\u00e3o)',
    secProvide2: 'C\u00f3digo audit\u00e1vel (arquivo \u00fanico app.js)', secProvide3: 'Entropia apenas de fontes f\u00edsicas (dados/moedas)',
    secProvide4: 'Criptografia AES-256-GCM com 600K itera\u00e7\u00f5es PBKDF2',
    whatNot: 'O que N\u00c3O fornece:', secNot1: 'Secure Element (carteiras hardware t\u00eam isso)',
    secNot2: 'Air gap a n\u00edvel hardware (chip WiFi ainda existe)', secNot3: 'Resist\u00eancia a ataques de canal lateral',
    keyStorage: 'Armazenamento de chaves', encryption: 'Criptografia:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600.000 itera\u00e7\u00f5es) + salt/IV aleat\u00f3rio',
    warning: 'Aviso:', clearDataWarning: 'Limpar dados do navegador excluir\u00e1 permanentemente sua chave criptografada. Sempre mantenha sua frase semente salva offline.',
    autoLock: 'Bloqueio autom\u00e1tico:', autoLockDesc: 'Chaves s\u00e3o removidas da mem\u00f3ria ap\u00f3s 5 minutos de inatividade.',
    storageEncKey: 'Chave privada criptografada (AES-256-GCM)', storageXpub: 'Chave p\u00fablica estendida da conta', storageFp: 'Impress\u00e3o BIP-32',
    storageNet: 'Config. de rede (main/test)', storageLang: 'Idioma da interface', storageSeedLang: 'Idioma da frase semente', storageKeyCreated: 'Data de criação da chave', storageLastOnline: 'Data de detecção de rede',
    guideTitle: 'Guia de instala\u00e7\u00e3o', guideDesc: 'Instale o BitClutch Signer como app offline, depois ative o modo avi\u00e3o antes de usar.',
    detected: 'Detectado',
    guideIosSafari: '<strong>Instalar como app offline:</strong><ol><li>Abra esta p\u00e1gina no <strong>Safari</strong></li><li>Toque no bot\u00e3o <strong>Share</strong> (caixa com seta)</li><li>Role para baixo e toque em <strong>"Add to Home Screen"</strong></li><li>Toque em <strong>"Add"</strong> no canto superior direito</li></ol><strong>Ativar modo avi\u00e3o:</strong><ol><li>Deslize para baixo a partir do canto superior direito (ou para cima a partir de baixo em iPhones antigos)</li><li>Toque no <strong>\u00edcone de avi\u00e3o</strong> para ativar</li><li>Certifique-se de que Wi-Fi e Bluetooth tamb\u00e9m estejam desligados</li></ol>',
    guideIosChrome: '<strong>Importante:</strong> O Chrome no iOS n\u00e3o pode instalar apps offline. Use o <strong>Safari</strong> em vez disso.<ol><li>Copie a URL desta p\u00e1gina</li><li>Abra o <strong>Safari</strong> e cole a URL</li><li>Siga as instru\u00e7\u00f5es do <strong>iOS Safari</strong> acima</li></ol><strong>Ativar modo avi\u00e3o:</strong><ol><li>Deslize para baixo a partir do canto superior direito</li><li>Toque no <strong>\u00edcone de avi\u00e3o</strong></li></ol>',
    guideAndroidChrome: '<strong>Instalar como app offline:</strong><ol><li>Abra esta p\u00e1gina no <strong>Chrome</strong></li><li>Toque no <strong>menu de tr\u00eas pontos</strong> (canto superior direito)</li><li>Toque em <strong>"Install app"</strong> ou <strong>"Add to Home screen"</strong></li><li>Confirme tocando em <strong>"Install"</strong></li></ol><strong>Ativar modo avi\u00e3o:</strong><ol><li>Deslize para baixo a partir do topo da tela</li><li>Toque em <strong>"Airplane mode"</strong></li><li>Verifique se Wi-Fi e dados m\u00f3veis est\u00e3o desligados</li></ol>',
    guideAndroidSamsung: '<strong>Instalar como app offline:</strong><ol><li>Abra esta p\u00e1gina no <strong>Samsung Internet</strong></li><li>Toque no <strong>\u00edcone de menu</strong> (tr\u00eas linhas, canto inferior direito)</li><li>Toque em <strong>"Add page to"</strong> e depois em <strong>"Home screen"</strong></li></ol><strong>Ativar modo avi\u00e3o:</strong><ol><li>Deslize para baixo a partir do topo duas vezes para abrir Configura\u00e7\u00f5es r\u00e1pidas</li><li>Toque em <strong>"Airplane mode"</strong></li></ol>',
    guideMacosSafari: '<strong>Instalar como app offline (macOS Sonoma+):</strong><ol><li>Abra esta p\u00e1gina no <strong>Safari</strong></li><li>Clique no menu <strong>File</strong> e depois em <strong>"Add to Dock"</strong></li><li>Clique em <strong>"Add"</strong></li></ol><strong>Desativar rede:</strong><ol><li>Clique no <strong>\u00edcone de Wi-Fi</strong> na barra de menus</li><li>Clique para <strong>desligar o Wi-Fi</strong></li><li>Desconecte quaisquer cabos Ethernet</li></ol>',
    guideMacosChrome: '<strong>Instalar como app offline:</strong><ol><li>Abra esta p\u00e1gina no <strong>Chrome</strong></li><li>Clique no <strong>\u00edcone de instala\u00e7\u00e3o</strong> na barra de endere\u00e7os (ou menu de tr\u00eas pontos &rarr; "Install BitClutch Signer")</li><li>Clique em <strong>"Install"</strong></li></ol><strong>Desativar rede:</strong><ol><li>Clique no <strong>\u00edcone de Wi-Fi</strong> na barra de menus</li><li>Clique para <strong>desligar o Wi-Fi</strong></li><li>Desconecte quaisquer cabos Ethernet</li></ol>',
    guideWindowsChrome: '<strong>Instalar como app offline:</strong><ol><li>Abra esta p\u00e1gina no <strong>Chrome</strong></li><li>Clique no <strong>\u00edcone de instala\u00e7\u00e3o</strong> na barra de endere\u00e7os (ou menu de tr\u00eas pontos &rarr; "Install BitClutch Signer")</li><li>Clique em <strong>"Install"</strong></li></ol><strong>Desativar rede:</strong><ol><li>Clique no <strong>\u00edcone de Wi-Fi</strong> na barra de tarefas (canto inferior direito)</li><li>Clique para <strong>desconectar o Wi-Fi</strong></li><li>Desconecte quaisquer cabos Ethernet</li></ol>',
    guideWindowsEdge: '<strong>Instalar como app offline:</strong><ol><li>Abra esta p\u00e1gina no <strong>Edge</strong></li><li>Clique no <strong>\u00edcone de instala\u00e7\u00e3o</strong> na barra de endere\u00e7os (ou menu de tr\u00eas pontos &rarr; "Aplicativos" &rarr; "Install BitClutch Signer")</li><li>Clique em <strong>"Install"</strong></li></ol><strong>Desativar rede:</strong><ol><li>Clique no <strong>\u00edcone de Wi-Fi</strong> na barra de tarefas (canto inferior direito)</li><li>Clique para <strong>desconectar o Wi-Fi</strong></li><li>Desconecte quaisquer cabos Ethernet</li></ol>',
    accountXpubTitle: 'xpub da conta',
    noMnemonic: 'Nenhum mnem\u00f4nico dispon\u00edvel.', noTxData: 'Sem dados de transa\u00e7\u00e3o.', noSignedData: 'Sem dados assinados.',
    noBmsRequest: 'Sem solicita\u00e7\u00e3o BMS.', noSignature: 'Sem assinatura.', loading: 'Carregando...',
    bannerWarn: 'REDE DETECTADA \u2014 Desconecte todas as redes antes de gerar chaves.',
    bannerOnline: 'REDE CONECTADA \u2014 Desconecte AGORA e NUNCA reconecte este dispositivo. As chaves podem j\u00e1 estar expostas.',
    bannerOffline: 'Nenhuma rede sem fio detectada. Verifique se Bluetooth, NFC e cabos USB de dados tamb\u00e9m est\u00e3o desconectados.',
  },
  de: {
    unlocked: 'Entsperrt', locked: 'Gesperrt',
    tabKey: 'Schl\u00fcssel', tabSign: 'Signieren', tabSettings: 'Einstellungen',
    createKeys: 'Schl\u00fcssel erstellen',
    setupDesc: 'Erstelle einen neuen Schl\u00fcssel mit physischer Entropie,<br>oder importiere eine bestehende Seed-Phrase.',
    diceBtn: 'W\u00fcrfel (99 W\u00fcrfe)', coinBtn: 'M\u00fcnze (256 W\u00fcrfe)', importBtn: 'Seed-Phrase importieren',
    enterPassphrase: 'Passwort eingeben zum Entsperren', passphrase: 'Passwort', unlock: 'Entsperren', wrongPassphrase: 'Falsches Passwort.',
    yourKey: 'Dein Schl\u00fcssel', network: 'Netzwerk', fingerprint: 'Fingerabdruck', keyCreated: 'Erstellt', lastOnline: 'Zul. online', neverOnline: 'Nie (sicher)', onlineAfterKey: 'Online nach Erstellung erkannt', accountXpub: 'Konto-xpub',
    showXpubQR: 'xpub-QR anzeigen', lockBtn: 'Sperren', mainnet: 'Mainnet', testnet: 'Testnet',
    diceTitle: 'W\u00fcrfel-Schl\u00fcsselgenerierung', diceDesc: 'Wirf einen echten W\u00fcrfel und tippe das Ergebnis.',
    progress: 'Fortschritt', undoLast: 'R\u00fcckg\u00e4ngig', cancel: 'Abbrechen', ok: 'OK',
    coinTitle: 'M\u00fcnzwurf-Schl\u00fcsselgenerierung', coinDesc: 'Wirf eine echte M\u00fcnze und tippe das Ergebnis.',
    entropyWarning: 'Verwende einen echten W\u00fcrfel/M\u00fcnze \u2014 erfinde niemals Zahlen. Menschliche Entscheidungen sind vorhersehbar und schw\u00e4chen deinen Schl\u00fcssel. Keine Kameras oder Mikrofone in der N\u00e4he \u2014 wer deine W\u00fcrfe sieht, kann dein Bitcoin stehlen.',
    heads: 'H (Kopf)', tails: 'T (Zahl)',
    writeDown: 'Schreibe diese W\u00f6rter auf!',
    mnemonicDesc: 'Dies ist deine Seed-Phrase. Bewahre sie sicher offline auf. Sie wird NICHT erneut angezeigt.',
    stolenVsLost: 'Gestohlen vs. Verloren \u2014 kenne den Unterschied',
    theft: 'Diebstahl:', theftDesc: 'Wenn jemand deine Seed-Phrase findet, kann er sofort deine Bitcoin stehlen. Niemand kann das r\u00fcckg\u00e4ngig machen.',
    loss: 'Verlust:', lossDesc: 'Wenn du deine Seed-Phrase verlierst und dein Ger\u00e4t kaputt geht, sind deine Bitcoin f\u00fcr immer verloren \u2014 es sei denn, du hast einen Wiederherstellungsplan.',
    bitclutchPromo: '<strong>BitClutch</strong> sch\u00fctzt vor Verlust und Tod, nicht vor Diebstahl. Erstelle eine <strong>Gesch\u00fctzte Wallet</strong> mit Timelock \u2014 deine Bitcoin bleiben deine, aber deine Erben k\u00f6nnen sie wiederherstellen.',
    visitBitclutch: 'Besuche <strong>bitclutch.app</strong> auf einem Online-Ger\u00e4t, um eine Gesch\u00fctzte Wallet zu erstellen.',
    confirmedWritten: 'Aufgeschrieben',
    importTitle: 'Seed-Phrase importieren', importDesc: 'W\u00e4hle Wortanzahl und Sprache, dann gib jedes Wort ein.',
    importPlaceholder: 'Wort1 Wort2 Wort3 ...', importAction: 'Importieren', words: 'W\u00f6rter',
    fillAllWords: 'Bitte alle W\u00f6rter ausf\u00fcllen.', needWords: '12 oder 24 W\u00f6rter ben\u00f6tigt', invalidMnemonic: 'Ung\u00fcltiges Mnemonik',
    setPassTitle: 'Passwort festlegen', setPassDesc: 'W\u00e4hle ein starkes Passwort zur Verschl\u00fcsselung deines privaten Schl\u00fcssels. Du brauchst es bei jedem Entsperren.',
    confirmPass: 'Passwort best\u00e4tigen', enterPass: 'Passwort eingeben',
    passRequired: 'Passwort ist erforderlich.', passTooShort: 'Passwort zu kurz (mind. 4 Zeichen).', passNoMatch: 'Passw\u00f6rter stimmen nicht \u00fcberein.',
    noKeyToSave: 'Kein Schl\u00fcssel zum Speichern. Neu starten.', encryptSave: 'Verschl\u00fcsseln und speichern', encryptFailed: 'Verschl\u00fcsselung fehlgeschlagen: ',
    scanTitle: 'QR scannen', scanDesc: 'Richte die Kamera auf den QR-Code deiner BitClutch-App.',
    startingCamera: 'Kamera startet...', scanning: 'Scanne... Richte auf den QR-Code.', cameraError: 'Kamerafehler: ',
    receivingFountain: 'Empfange Fountain-Code...', urFailed: 'UR-Dekodierung fehlgeschlagen. Erneut versuchen.', psbtParseError: 'PSBT-Analysefehler: ',
    confirmTx: 'Transaktion best\u00e4tigen', reviewBeforeSign: 'Sorgf\u00e4ltig pr\u00fcfen vor dem Signieren.',
    inputs: 'Eingaben', output: 'Ausgabe', change: '(Wechselgeld)', fee: 'Geb\u00fchr', reject: 'Ablehnen', sign: 'Signieren', signingFailed: 'Signierung fehlgeschlagen: ',
    signedPsbt: 'Signierte PSBT', showQRDesc: 'Lass deine BitClutch-App diesen QR-Code scannen, um die Transaktion zu senden.', scanComplete: 'Scan abgeschlossen', scanSignatureDesc: 'Lass deine BitClutch-App diesen QR-Code scannen, um die Signatur zu senden.',
    singleQR: 'Einzel-QR', fountainKeepShowing: 'Fountain-Code \u2014 weiter anzeigen', frame: 'Bild',
    confirmBms: 'Nachrichtensignierung best\u00e4tigen', reviewMessage: 'Pr\u00fcfe die Nachricht vor dem Signieren.',
    type: 'Typ', bmsType: 'BMS (Bitcoin-Nachricht)', index: 'Index', address: 'Adresse', message: 'Nachricht',
    bmsSignature: 'BMS-Signatur', sigBase64: 'Signatur (base64)', tapToCopy: 'Tippen zum Kopieren', copySig: 'Signatur kopieren', sha256: 'SHA-256',
    settings: 'Einstellungen', version: 'Version', language: 'Sprache', seedLanguage: 'Seed-Sprache',
    onlineKeygenTitle: 'Netzwerk verbunden!',
    onlineKeygenBody: 'Ihr Ger\u00e4t ist mit dem Internet verbunden. Online generierte Schl\u00fcssel k\u00f6nnen von Malware abgefangen werden. Trennen Sie ALLE Netzwerke (WiFi, Mobilfunk, Bluetooth, USB) bevor Sie fortfahren.',
    proceedAnyway: 'Trotzdem fortfahren (unsicher)',
    installGuide: 'Installationsanleitung', viewSource: 'Quellcode-Integrit\u00e4t pr\u00fcfen', securityInfo: 'Sicherheitsinfo',
    deleteKey: 'Schl\u00fcssel l\u00f6schen', deleteConfirm1: 'Schl\u00fcssel l\u00f6schen? Kann nicht r\u00fcckg\u00e4ngig gemacht werden.\nStelle sicher, dass du deine Seed-Phrase gesichert hast!',
    deleteConfirm2: 'Bist du absolut sicher? Deine Bitcoin gehen VERLOREN wenn du kein Backup hast.',
    verifyIntegrity: 'Integrit\u00e4t pr\u00fcfen', verifyDesc: 'Vergleiche SHA-256-Hashes mit der offiziellen Version auf GitHub.',
    computing: 'Berechne...', fetchFailed: '(Download fehlgeschlagen)',
    verifyFile: 'Diese Datei pr\u00fcfen', verifyFileDesc: 'Tippe hier und w\u00e4hle die heruntergeladene <strong>bitclutch-signer.html</strong>-Datei.<br>Der SHA-256-Hash wird lokal berechnet.',
    tapToSelect: 'Tippen zum Ausw\u00e4hlen', compareGithub: 'Vergleiche mit <code>hashes.json</code> vom GitHub-Release.',
    auditableSource: 'Pr\u00fcfbarer Quellcode', auditableDesc: 'Die gesamte App-Logik ist in einer einzigen pr\u00fcfbaren Datei. Quellcode und offizielle Hashes sind auf GitHub ver\u00f6ffentlicht.',
    back: 'Zur\u00fcck',
    securityTitle: 'Sicherheitsinformationen', securityLevel: 'Sicherheitsstufe: Software-Air-Gap',
    whatProvides: 'Was es bietet:', secProvide1: 'Privater Schl\u00fcssel ber\u00fchrt nie das Internet (nach Einrichtung)',
    secProvide2: 'Code ist pr\u00fcfbar (einzelne app.js-Datei)', secProvide3: 'Entropie nur aus physischen Quellen (W\u00fcrfel/M\u00fcnzen)',
    secProvide4: 'AES-256-GCM-Verschl\u00fcsselung mit 600K PBKDF2-Iterationen',
    whatNot: 'Was es NICHT bietet:', secNot1: 'Secure Element (Hardware-Wallets haben das)',
    secNot2: 'Hardware-Level Air-Gap (WiFi-Chip existiert noch)', secNot3: 'Seitenkanalangriff-Resistenz',
    keyStorage: 'Schl\u00fcsselspeicher', encryption: 'Verschl\u00fcsselung:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600.000 Iterationen) + zuf\u00e4lliges Salt/IV',
    warning: 'Warnung:', clearDataWarning: 'Browserdaten l\u00f6schen entfernt dauerhaft deinen verschl\u00fcsselten Schl\u00fcssel. Halte deine Seed-Phrase immer offline gesichert.',
    autoLock: 'Auto-Sperre:', autoLockDesc: 'Schl\u00fcssel werden nach 5 Minuten Inaktivit\u00e4t aus dem Speicher gel\u00f6scht.',
    storageEncKey: 'Verschl\u00fcsselter privater Schl\u00fcssel (AES-256-GCM)', storageXpub: 'Erweiterter \u00f6ffentlicher Kontoschl\u00fcssel', storageFp: 'BIP-32-Fingerabdruck',
    storageNet: 'Netzwerkeinstellung (main/test)', storageLang: 'Benutzeroberfl\u00e4chensprache', storageSeedLang: 'Seed-Phrase-Sprache', storageKeyCreated: 'Schl\u00fcssel-Erstellungsdatum', storageLastOnline: 'Netzwerk-Erkennungsdatum',
    guideTitle: 'Installationsanleitung', guideDesc: 'Installiere BitClutch Signer als Offline-App und aktiviere vor der Nutzung den Flugmodus.',
    detected: 'Erkannt',
    guideIosSafari: '<strong>Als Offline-App installieren:</strong><ol><li>\u00d6ffne diese Seite in <strong>Safari</strong></li><li>Tippe auf die <strong>Share</strong>-Taste (Quadrat mit Pfeil)</li><li>Scrolle nach unten und tippe auf <strong>"Add to Home Screen"</strong></li><li>Tippe oben rechts auf <strong>"Add"</strong></li></ol><strong>Flugmodus aktivieren:</strong><ol><li>Streiche von der oberen rechten Ecke nach unten (oder bei \u00e4lteren iPhones von unten nach oben)</li><li>Tippe auf das <strong>Flugzeug-Symbol</strong> zum Aktivieren</li><li>Stelle sicher, dass Wi-Fi und Bluetooth ebenfalls ausgeschaltet sind</li></ol>',
    guideIosChrome: '<strong>Wichtig:</strong> Chrome auf iOS kann keine Offline-Apps installieren. Verwende stattdessen <strong>Safari</strong>.<ol><li>Kopiere die URL dieser Seite</li><li>\u00d6ffne <strong>Safari</strong> und f\u00fcge die URL ein</li><li>Folge den <strong>iOS Safari</strong>-Anweisungen oben</li></ol><strong>Flugmodus aktivieren:</strong><ol><li>Streiche von der oberen rechten Ecke nach unten</li><li>Tippe auf das <strong>Flugzeug-Symbol</strong></li></ol>',
    guideAndroidChrome: '<strong>Als Offline-App installieren:</strong><ol><li>\u00d6ffne diese Seite in <strong>Chrome</strong></li><li>Tippe auf das <strong>Drei-Punkte-Men\u00fc</strong> (oben rechts)</li><li>Tippe auf <strong>"Install app"</strong> oder <strong>"Add to Home screen"</strong></li><li>Best\u00e4tige mit <strong>"Install"</strong></li></ol><strong>Flugmodus aktivieren:</strong><ol><li>Streiche vom oberen Bildschirmrand nach unten</li><li>Tippe auf <strong>"Airplane mode"</strong></li><li>\u00dcberpr\u00fcfe, ob Wi-Fi und mobile Daten ausgeschaltet sind</li></ol>',
    guideAndroidSamsung: '<strong>Als Offline-App installieren:</strong><ol><li>\u00d6ffne diese Seite in <strong>Samsung Internet</strong></li><li>Tippe auf das <strong>Men\u00fc-Symbol</strong> (drei Linien, unten rechts)</li><li>Tippe auf <strong>"Add page to"</strong> und dann auf <strong>"Home screen"</strong></li></ol><strong>Flugmodus aktivieren:</strong><ol><li>Streiche zweimal vom oberen Rand nach unten, um die Schnelleinstellungen zu \u00f6ffnen</li><li>Tippe auf <strong>"Airplane mode"</strong></li></ol>',
    guideMacosSafari: '<strong>Als Offline-App installieren (macOS Sonoma+):</strong><ol><li>\u00d6ffne diese Seite in <strong>Safari</strong></li><li>Klicke auf das <strong>File</strong>-Men\u00fc und dann auf <strong>"Add to Dock"</strong></li><li>Klicke auf <strong>"Add"</strong></li></ol><strong>Netzwerk deaktivieren:</strong><ol><li>Klicke auf das <strong>Wi-Fi-Symbol</strong> in der Men\u00fcleiste</li><li>Klicke, um <strong>Wi-Fi auszuschalten</strong></li><li>Trenne alle Ethernet-Kabel</li></ol>',
    guideMacosChrome: '<strong>Als Offline-App installieren:</strong><ol><li>\u00d6ffne diese Seite in <strong>Chrome</strong></li><li>Klicke auf das <strong>Installations-Symbol</strong> in der Adressleiste (oder Drei-Punkte-Men\u00fc &rarr; "Install BitClutch Signer")</li><li>Klicke auf <strong>"Install"</strong></li></ol><strong>Netzwerk deaktivieren:</strong><ol><li>Klicke auf das <strong>Wi-Fi-Symbol</strong> in der Men\u00fcleiste</li><li>Klicke, um <strong>Wi-Fi auszuschalten</strong></li><li>Trenne alle Ethernet-Kabel</li></ol>',
    guideWindowsChrome: '<strong>Als Offline-App installieren:</strong><ol><li>\u00d6ffne diese Seite in <strong>Chrome</strong></li><li>Klicke auf das <strong>Installations-Symbol</strong> in der Adressleiste (oder Drei-Punkte-Men\u00fc &rarr; "Install BitClutch Signer")</li><li>Klicke auf <strong>"Install"</strong></li></ol><strong>Netzwerk deaktivieren:</strong><ol><li>Klicke auf das <strong>Wi-Fi-Symbol</strong> in der Taskleiste (unten rechts)</li><li>Klicke, um <strong>Wi-Fi zu trennen</strong></li><li>Trenne alle Ethernet-Kabel</li></ol>',
    guideWindowsEdge: '<strong>Als Offline-App installieren:</strong><ol><li>\u00d6ffne diese Seite in <strong>Edge</strong></li><li>Klicke auf das <strong>Installations-Symbol</strong> in der Adressleiste (oder Drei-Punkte-Men\u00fc &rarr; "Apps" &rarr; "Install BitClutch Signer")</li><li>Klicke auf <strong>"Install"</strong></li></ol><strong>Netzwerk deaktivieren:</strong><ol><li>Klicke auf das <strong>Wi-Fi-Symbol</strong> in der Taskleiste (unten rechts)</li><li>Klicke, um <strong>Wi-Fi zu trennen</strong></li><li>Trenne alle Ethernet-Kabel</li></ol>',
    accountXpubTitle: 'Konto-xpub',
    noMnemonic: 'Kein Mnemonik verf\u00fcgbar.', noTxData: 'Keine Transaktionsdaten.', noSignedData: 'Keine signierten Daten.',
    noBmsRequest: 'Keine BMS-Anfrage.', noSignature: 'Keine Signatur.', loading: 'Lade...',
    bannerWarn: 'NETZWERK ERKANNT \u2014 Trennen Sie alle Netzwerke bevor Sie Schl\u00fcssel generieren.',
    bannerOnline: 'NETZWERK VERBUNDEN \u2014 Sofort trennen und dieses Ger\u00e4t NIE wieder verbinden. Schl\u00fcssel k\u00f6nnten bereits offengelegt sein.',
    bannerOffline: 'Kein drahtloses Netzwerk erkannt. Stellen Sie sicher, dass Bluetooth, NFC und USB-Datenkabel ebenfalls getrennt sind.',
  },
  fr: {
    unlocked: 'D\u00e9verrouill\u00e9', locked: 'Verrouill\u00e9',
    tabKey: 'Cl\u00e9', tabSign: 'Signer', tabSettings: 'Param\u00e8tres',
    createKeys: 'Cr\u00e9ez votre cl\u00e9',
    setupDesc: 'G\u00e9n\u00e9rez une nouvelle cl\u00e9 avec de l\u2019entropie physique,<br>ou importez une phrase de r\u00e9cup\u00e9ration existante.',
    diceBtn: 'D\u00e9 (99 lancers)', coinBtn: 'Pi\u00e8ce (256 lancers)', importBtn: 'Importer phrase de r\u00e9cup\u00e9ration',
    enterPassphrase: 'Entrez le mot de passe pour d\u00e9verrouiller', passphrase: 'Mot de passe', unlock: 'D\u00e9verrouiller', wrongPassphrase: 'Mot de passe incorrect.',
    yourKey: 'Votre cl\u00e9', network: 'R\u00e9seau', fingerprint: 'Empreinte', keyCreated: 'Cr\u00e9\u00e9e le', lastOnline: 'Dern. en ligne', neverOnline: 'Jamais (s\u00fbr)', onlineAfterKey: 'En ligne d\u00e9tect\u00e9 apr\u00e8s cr\u00e9ation', accountXpub: 'xpub du compte',
    showXpubQR: 'Afficher QR xpub', lockBtn: 'Verrouiller', mainnet: 'Mainnet', testnet: 'Testnet',
    diceTitle: 'G\u00e9n\u00e9ration par d\u00e9', diceDesc: 'Lancez un vrai d\u00e9 physique et touchez le r\u00e9sultat.',
    progress: 'Progression', undoLast: 'Annuler', cancel: 'Annuler', ok: 'OK',
    coinTitle: 'G\u00e9n\u00e9ration par pi\u00e8ce', coinDesc: 'Lancez une vraie pi\u00e8ce physique et touchez le r\u00e9sultat.',
    entropyWarning: 'Utilisez un vrai d\u00e9/pi\u00e8ce \u2014 n\u2019inventez jamais de nombres. Les choix humains sont pr\u00e9visibles et affaiblissent votre cl\u00e9. Pas de cam\u00e9ras ni microphones \u00e0 proximit\u00e9 \u2014 quiconque voit vos lancers peut voler vos Bitcoin.',
    heads: 'H (Pile)', tails: 'T (Face)',
    writeDown: 'Notez ces mots !',
    mnemonicDesc: 'Ceci est votre phrase de r\u00e9cup\u00e9ration. Conservez-la en lieu s\u00fbr hors ligne. Elle ne sera PAS r\u00e9affich\u00e9e.',
    stolenVsLost: 'Vol\u00e9 vs. Perdu \u2014 connaissez la diff\u00e9rence',
    theft: 'Vol :', theftDesc: 'Si quelqu\u2019un trouve votre phrase, il peut voler vos Bitcoin imm\u00e9diatement. Personne ne peut l\u2019annuler.',
    loss: 'Perte :', lossDesc: 'Si vous perdez votre phrase et votre appareil tombe en panne, vos Bitcoin sont perdus \u00e0 jamais \u2014 sauf si vous avez un plan de r\u00e9cup\u00e9ration.',
    bitclutchPromo: '<strong>BitClutch</strong> prot\u00e8ge contre la perte et le d\u00e9c\u00e8s, pas le vol. Cr\u00e9ez un <strong>Portefeuille Prot\u00e9g\u00e9</strong> avec timelock \u2014 vos Bitcoin restent les v\u00f4tres, mais vos h\u00e9ritiers peuvent les r\u00e9cup\u00e9rer.',
    visitBitclutch: 'Visitez <strong>bitclutch.app</strong> sur un appareil en ligne pour cr\u00e9er un Portefeuille Prot\u00e9g\u00e9.',
    confirmedWritten: 'C\u2019est not\u00e9',
    importTitle: 'Importer phrase de r\u00e9cup\u00e9ration', importDesc: 'S\u00e9lectionnez le nombre de mots et la langue, puis entrez chaque mot.',
    importPlaceholder: 'mot1 mot2 mot3 ...', importAction: 'Importer', words: 'mots',
    fillAllWords: 'Veuillez remplir tous les mots.', needWords: '12 ou 24 mots requis', invalidMnemonic: 'Mn\u00e9monique invalide',
    setPassTitle: 'D\u00e9finir mot de passe', setPassDesc: 'Choisissez un mot de passe fort pour chiffrer votre cl\u00e9 priv\u00e9e. Requis \u00e0 chaque d\u00e9verrouillage.',
    confirmPass: 'Confirmer mot de passe', enterPass: 'Entrer mot de passe',
    passRequired: 'Mot de passe requis.', passTooShort: 'Mot de passe trop court (min. 4 caract\u00e8res).', passNoMatch: 'Les mots de passe ne correspondent pas.',
    noKeyToSave: 'Pas de cl\u00e9 \u00e0 sauvegarder. Recommencez.', encryptSave: 'Chiffrer et sauvegarder', encryptFailed: '\u00c9chec du chiffrement : ',
    scanTitle: 'Scanner QR', scanDesc: 'Pointez la cam\u00e9ra vers le QR de votre app BitClutch.',
    startingCamera: 'D\u00e9marrage cam\u00e9ra...', scanning: 'Scan en cours... Pointez vers le QR.', cameraError: 'Erreur cam\u00e9ra : ',
    receivingFountain: 'R\u00e9ception du code fountain...', urFailed: 'D\u00e9codage UR \u00e9chou\u00e9. R\u00e9essayez.', psbtParseError: 'Erreur d\u2019analyse PSBT : ',
    confirmTx: 'Confirmer la transaction', reviewBeforeSign: 'V\u00e9rifiez attentivement avant de signer.',
    inputs: 'Entr\u00e9es', output: 'Sortie', change: '(monnaie)', fee: 'Frais', reject: 'Rejeter', sign: 'Signer', signingFailed: '\u00c9chec de la signature : ',
    signedPsbt: 'PSBT sign\u00e9', showQRDesc: 'Laissez votre app BitClutch scanner ce QR pour diffuser la transaction.', scanComplete: 'Scan termin\u00e9', scanSignatureDesc: 'Laissez votre app BitClutch scanner ce QR pour soumettre la signature.',
    singleQR: 'QR unique', fountainKeepShowing: 'code fountain \u2014 continuez \u00e0 montrer', frame: 'Image',
    confirmBms: 'Confirmer la signature du message', reviewMessage: 'V\u00e9rifiez le message avant de signer.',
    type: 'Type', bmsType: 'BMS (Message Bitcoin)', index: 'Index', address: 'Adresse', message: 'Message',
    bmsSignature: 'Signature BMS', sigBase64: 'Signature (base64)', tapToCopy: 'Touchez pour copier', copySig: 'Copier signature', sha256: 'SHA-256',
    settings: 'Param\u00e8tres', version: 'Version', language: 'Langue', seedLanguage: 'Langue de la phrase',
    onlineKeygenTitle: 'R\u00e9seau connect\u00e9 !',
    onlineKeygenBody: 'Votre appareil est connect\u00e9 \u00e0 Internet. Les cl\u00e9s g\u00e9n\u00e9r\u00e9es en ligne peuvent \u00eatre intercept\u00e9es par des malwares. D\u00e9connectez TOUS les r\u00e9seaux (WiFi, cellulaire, Bluetooth, USB) avant de continuer.',
    proceedAnyway: 'Continuer quand m\u00eame (dangereux)',
    installGuide: 'Guide d\u2019installation', viewSource: 'V\u00e9rifier l\u2019int\u00e9grit\u00e9 du code', securityInfo: 'Infos s\u00e9curit\u00e9',
    deleteKey: 'Supprimer la cl\u00e9', deleteConfirm1: 'Supprimer votre cl\u00e9 ? Irr\u00e9versible.\nAssurez-vous d\u2019avoir sauvegard\u00e9 votre phrase !',
    deleteConfirm2: '\u00cates-vous absolument s\u00fbr ? Vos Bitcoin seront PERDUS sans sauvegarde.',
    verifyIntegrity: 'V\u00e9rifier l\u2019int\u00e9grit\u00e9', verifyDesc: 'Comparez les hashes SHA-256 avec la version officielle sur GitHub.',
    computing: 'Calcul...', fetchFailed: '(\u00e9chec du t\u00e9l\u00e9chargement)',
    verifyFile: 'V\u00e9rifier ce fichier', verifyFileDesc: 'Touchez ici et s\u00e9lectionnez le fichier <strong>bitclutch-signer.html</strong> t\u00e9l\u00e9charg\u00e9.<br>Le hash SHA-256 sera calcul\u00e9 localement.',
    tapToSelect: 'Touchez pour s\u00e9lectionner', compareGithub: 'Comparez avec <code>hashes.json</code> de la version GitHub.',
    auditableSource: 'Code auditable', auditableDesc: 'Toute la logique de cette app est dans un seul fichier auditable. Le code source et les hashes officiels sont publi\u00e9s sur GitHub.',
    back: 'Retour',
    securityTitle: 'Informations de s\u00e9curit\u00e9', securityLevel: 'Niveau de s\u00e9curit\u00e9 : Air-gap logiciel',
    whatProvides: 'Ce que cela fournit :', secProvide1: 'La cl\u00e9 priv\u00e9e ne touche jamais internet (apr\u00e8s configuration)',
    secProvide2: 'Code auditable (fichier unique app.js)', secProvide3: 'Entropie uniquement physique (d\u00e9s/pi\u00e8ces)',
    secProvide4: 'Chiffrement AES-256-GCM avec 600K it\u00e9rations PBKDF2',
    whatNot: 'Ce que cela NE fournit PAS :', secNot1: 'Secure Element (les portefeuilles mat\u00e9riels en ont)',
    secNot2: 'Air gap mat\u00e9riel (la puce WiFi existe toujours)', secNot3: 'R\u00e9sistance aux attaques par canal auxiliaire',
    keyStorage: 'Stockage des cl\u00e9s', encryption: 'Chiffrement :', encryptionDesc: 'AES-256-GCM + PBKDF2 (600 000 it\u00e9rations) + sel/IV al\u00e9atoire',
    warning: 'Avertissement :', clearDataWarning: 'Effacer les donn\u00e9es du navigateur supprimera d\u00e9finitivement votre cl\u00e9 chiffr\u00e9e. Conservez toujours votre phrase hors ligne.',
    autoLock: 'Verrouillage auto :', autoLockDesc: 'Les cl\u00e9s sont effac\u00e9es de la m\u00e9moire apr\u00e8s 5 minutes d\u2019inactivit\u00e9.',
    storageEncKey: 'Cl\u00e9 priv\u00e9e chiffr\u00e9e (AES-256-GCM)', storageXpub: 'Cl\u00e9 publique \u00e9tendue du compte', storageFp: 'Empreinte BIP-32',
    storageNet: 'Param\u00e8tre r\u00e9seau (main/test)', storageLang: 'Langue de l\u2019interface', storageSeedLang: 'Langue de la phrase', storageKeyCreated: 'Date de cr\u00e9ation de la cl\u00e9', storageLastOnline: 'Date de d\u00e9tection r\u00e9seau',
    guideTitle: 'Guide d\u2019installation', guideDesc: 'Installez BitClutch Signer comme app hors ligne, puis activez le mode avion avant utilisation.',
    detected: 'D\u00e9tect\u00e9',
    guideIosSafari: '<strong>Installer comme app hors ligne :</strong><ol><li>Ouvrez cette page dans <strong>Safari</strong></li><li>Appuyez sur le bouton <strong>Share</strong> (carr\u00e9 avec fl\u00e8che)</li><li>Faites d\u00e9filer vers le bas et appuyez sur <strong>\u00abAdd to Home Screen\u00bb</strong></li><li>Appuyez sur <strong>\u00abAdd\u00bb</strong> en haut \u00e0 droite</li></ol><strong>Activer le mode avion :</strong><ol><li>Balayez vers le bas depuis le coin sup\u00e9rieur droit (\u00e0 partir du bas sur les anciens iPhone)</li><li>Appuyez sur l\u2019<strong>ic\u00f4ne d\u2019avion</strong> pour activer</li><li>V\u00e9rifiez que Wi-Fi et Bluetooth sont \u00e9galement d\u00e9sactiv\u00e9s</li></ol>',
    guideIosChrome: '<strong>Important :</strong> Chrome sur iOS ne peut pas installer d\u2019apps hors ligne. Utilisez <strong>Safari</strong> \u00e0 la place.<ol><li>Copiez l\u2019URL de cette page</li><li>Ouvrez <strong>Safari</strong> et collez l\u2019URL</li><li>Suivez les instructions <strong>iOS Safari</strong> ci-dessus</li></ol><strong>Activer le mode avion :</strong><ol><li>Balayez vers le bas depuis le coin sup\u00e9rieur droit</li><li>Appuyez sur l\u2019<strong>ic\u00f4ne d\u2019avion</strong></li></ol>',
    guideAndroidChrome: '<strong>Installer comme app hors ligne :</strong><ol><li>Ouvrez cette page dans <strong>Chrome</strong></li><li>Appuyez sur le <strong>menu \u00e0 trois points</strong> (en haut \u00e0 droite)</li><li>Appuyez sur <strong>\u00abInstall app\u00bb</strong> ou <strong>\u00abAdd to Home screen\u00bb</strong></li><li>Confirmez en appuyant sur <strong>\u00abInstall\u00bb</strong></li></ol><strong>Activer le mode avion :</strong><ol><li>Balayez vers le bas depuis le haut de l\u2019\u00e9cran</li><li>Appuyez sur <strong>\u00abAirplane mode\u00bb</strong></li><li>V\u00e9rifiez que Wi-Fi et donn\u00e9es mobiles sont d\u00e9sactiv\u00e9s</li></ol>',
    guideAndroidSamsung: '<strong>Installer comme app hors ligne :</strong><ol><li>Ouvrez cette page dans <strong>Samsung Internet</strong></li><li>Appuyez sur l\u2019<strong>ic\u00f4ne de menu</strong> (trois lignes, en bas \u00e0 droite)</li><li>Appuyez sur <strong>\u00abAdd page to\u00bb</strong> puis <strong>\u00abHome screen\u00bb</strong></li></ol><strong>Activer le mode avion :</strong><ol><li>Balayez deux fois vers le bas depuis le haut pour ouvrir les Param\u00e8tres rapides</li><li>Appuyez sur <strong>\u00abAirplane mode\u00bb</strong></li></ol>',
    guideMacosSafari: '<strong>Installer comme app hors ligne (macOS Sonoma+) :</strong><ol><li>Ouvrez cette page dans <strong>Safari</strong></li><li>Cliquez sur le menu <strong>File</strong> puis sur <strong>\u00abAdd to Dock\u00bb</strong></li><li>Cliquez sur <strong>\u00abAdd\u00bb</strong></li></ol><strong>D\u00e9sactiver le r\u00e9seau :</strong><ol><li>Cliquez sur l\u2019<strong>ic\u00f4ne Wi-Fi</strong> dans la barre de menus</li><li>Cliquez pour <strong>d\u00e9sactiver le Wi-Fi</strong></li><li>D\u00e9branchez tout c\u00e2ble Ethernet</li></ol>',
    guideMacosChrome: '<strong>Installer comme app hors ligne :</strong><ol><li>Ouvrez cette page dans <strong>Chrome</strong></li><li>Cliquez sur l\u2019<strong>ic\u00f4ne d\u2019installation</strong> dans la barre d\u2019adresse (ou menu \u00e0 trois points &rarr; \u00abInstall BitClutch Signer\u00bb)</li><li>Cliquez sur <strong>\u00abInstall\u00bb</strong></li></ol><strong>D\u00e9sactiver le r\u00e9seau :</strong><ol><li>Cliquez sur l\u2019<strong>ic\u00f4ne Wi-Fi</strong> dans la barre de menus</li><li>Cliquez pour <strong>d\u00e9sactiver le Wi-Fi</strong></li><li>D\u00e9branchez tout c\u00e2ble Ethernet</li></ol>',
    guideWindowsChrome: '<strong>Installer comme app hors ligne :</strong><ol><li>Ouvrez cette page dans <strong>Chrome</strong></li><li>Cliquez sur l\u2019<strong>ic\u00f4ne d\u2019installation</strong> dans la barre d\u2019adresse (ou menu \u00e0 trois points &rarr; \u00abInstall BitClutch Signer\u00bb)</li><li>Cliquez sur <strong>\u00abInstall\u00bb</strong></li></ol><strong>D\u00e9sactiver le r\u00e9seau :</strong><ol><li>Cliquez sur l\u2019<strong>ic\u00f4ne Wi-Fi</strong> dans la barre des t\u00e2ches (en bas \u00e0 droite)</li><li>Cliquez pour <strong>d\u00e9connecter le Wi-Fi</strong></li><li>D\u00e9branchez tout c\u00e2ble Ethernet</li></ol>',
    guideWindowsEdge: '<strong>Installer comme app hors ligne :</strong><ol><li>Ouvrez cette page dans <strong>Edge</strong></li><li>Cliquez sur l\u2019<strong>ic\u00f4ne d\u2019installation</strong> dans la barre d\u2019adresse (ou menu \u00e0 trois points &rarr; \u00abApplications\u00bb &rarr; \u00abInstall BitClutch Signer\u00bb)</li><li>Cliquez sur <strong>\u00abInstall\u00bb</strong></li></ol><strong>D\u00e9sactiver le r\u00e9seau :</strong><ol><li>Cliquez sur l\u2019<strong>ic\u00f4ne Wi-Fi</strong> dans la barre des t\u00e2ches (en bas \u00e0 droite)</li><li>Cliquez pour <strong>d\u00e9connecter le Wi-Fi</strong></li><li>D\u00e9branchez tout c\u00e2ble Ethernet</li></ol>',
    accountXpubTitle: 'xpub du compte',
    noMnemonic: 'Aucun mn\u00e9monique disponible.', noTxData: 'Pas de donn\u00e9es de transaction.', noSignedData: 'Pas de donn\u00e9es sign\u00e9es.',
    noBmsRequest: 'Pas de demande BMS.', noSignature: 'Pas de signature.', loading: 'Chargement...',
    bannerWarn: 'R\u00c9SEAU D\u00c9TECT\u00c9 \u2014 D\u00e9connectez tous les r\u00e9seaux avant de g\u00e9n\u00e9rer des cl\u00e9s.',
    bannerOnline: 'R\u00c9SEAU CONNECT\u00c9 \u2014 D\u00e9connectez MAINTENANT et ne reconnectez JAMAIS cet appareil. Les cl\u00e9s peuvent d\u00e9j\u00e0 \u00eatre expos\u00e9es.',
    bannerOffline: 'Aucun r\u00e9seau sans fil d\u00e9tect\u00e9. V\u00e9rifiez que Bluetooth, NFC et les c\u00e2bles USB de donn\u00e9es sont \u00e9galement d\u00e9connect\u00e9s.',
  },
  'zh-s': {
    unlocked: '\u5df2\u89e3\u9501', locked: '\u5df2\u9501\u5b9a',
    tabKey: '\u5bc6\u94a5', tabSign: '\u7b7e\u540d', tabSettings: '\u8bbe\u7f6e',
    createKeys: '\u521b\u5efa\u5bc6\u94a5',
    setupDesc: '\u4f7f\u7528\u7269\u7406\u71b5\u751f\u6210\u65b0\u5bc6\u94a5\uff0c<br>\u6216\u5bfc\u5165\u73b0\u6709\u52a9\u8bb0\u8bcd\u3002',
    diceBtn: '\u9ab0\u5b50 (99\u6b21)', coinBtn: '\u786c\u5e01 (256\u6b21)', importBtn: '\u5bfc\u5165\u52a9\u8bb0\u8bcd',
    enterPassphrase: '\u8f93\u5165\u5bc6\u7801\u89e3\u9501', passphrase: '\u5bc6\u7801', unlock: '\u89e3\u9501', wrongPassphrase: '\u5bc6\u7801\u9519\u8bef\u3002',
    yourKey: '\u4f60\u7684\u5bc6\u94a5', network: '\u7f51\u7edc', fingerprint: '\u6307\u7eb9', keyCreated: '\u521b\u5efa\u65e5\u671f', lastOnline: '\u6700\u540e\u5728\u7ebf', neverOnline: '\u65e0 (\u5b89\u5168)', onlineAfterKey: '\u5bc6\u94a5\u521b\u5efa\u540e\u68c0\u6d4b\u5230\u5728\u7ebf', accountXpub: '\u8d26\u6237xpub',
    showXpubQR: '\u663e\u793axpub\u4e8c\u7ef4\u7801', lockBtn: '\u9501\u5b9a', mainnet: '\u4e3b\u7f51', testnet: '\u6d4b\u8bd5\u7f51',
    diceTitle: '\u9ab0\u5b50\u5bc6\u94a5\u751f\u6210', diceDesc: '\u63b7\u771f\u5b9e\u9ab0\u5b50\u5e76\u70b9\u51fb\u7ed3\u679c\u3002',
    progress: '\u8fdb\u5ea6', undoLast: '\u64a4\u9500', cancel: '\u53d6\u6d88', ok: '\u786e\u5b9a',
    coinTitle: '\u786c\u5e01\u5bc6\u94a5\u751f\u6210', coinDesc: '\u629b\u771f\u5b9e\u786c\u5e01\u5e76\u70b9\u51fb\u7ed3\u679c\u3002',
    entropyWarning: '\u4f7f\u7528\u771f\u5b9e\u9ab0\u5b50/\u786c\u5e01 \u2014 \u5207\u52ff\u81ea\u7f16\u6570\u5b57\u3002\u4eba\u7c7b\u9009\u62e9\u53ef\u9884\u6d4b\uff0c\u4f1a\u524a\u5f31\u5bc6\u94a5\u3002\u786e\u4fdd\u9644\u8fd1\u65e0\u6444\u50cf\u5934\u6216\u9ea6\u514b\u98ce \u2014 \u770b\u5230\u6295\u63b7\u7ed3\u679c\u7684\u4eba\u53ef\u4ee5\u7a83\u53d6\u4f60\u7684\u6bd4\u7279\u5e01\u3002',
    heads: 'H (\u6b63\u9762)', tails: 'T (\u53cd\u9762)',
    writeDown: '\u8bf7\u8bb0\u4e0b\u8fd9\u4e9b\u5355\u8bcd\uff01',
    mnemonicDesc: '\u8fd9\u662f\u4f60\u7684\u52a9\u8bb0\u8bcd\u3002\u8bf7\u79bb\u7ebf\u5b89\u5168\u4fdd\u5b58\u3002\u5c06\u4e0d\u4f1a\u518d\u6b21\u663e\u793a\u3002',
    stolenVsLost: '\u88ab\u76d7 vs. \u4e22\u5931 \u2014 \u4e86\u89e3\u533a\u522b',
    theft: '\u76d7\u7a83\uff1a', theftDesc: '\u5982\u679c\u6709\u4eba\u627e\u5230\u4f60\u7684\u52a9\u8bb0\u8bcd\uff0c\u53ef\u4ee5\u7acb\u5373\u76d7\u53d6\u4f60\u7684\u6bd4\u7279\u5e01\u3002\u6ca1\u4eba\u80fd\u64a4\u9500\u3002',
    loss: '\u4e22\u5931\uff1a', lossDesc: '\u5982\u679c\u4f60\u4e22\u5931\u52a9\u8bb0\u8bcd\u4e14\u8bbe\u5907\u635f\u574f\uff0c\u4f60\u7684\u6bd4\u7279\u5e01\u5c06\u6c38\u8fdc\u4e22\u5931 \u2014 \u9664\u975e\u4f60\u6709\u6062\u590d\u8ba1\u5212\u3002',
    bitclutchPromo: '<strong>BitClutch</strong>\u4fdd\u62a4\u4f60\u514d\u53d7\u4e22\u5931\u548c\u6b7b\u4ea1\u98ce\u9669\uff0c\u800c\u975e\u76d7\u7a83\u3002\u521b\u5efa\u5e26\u65f6\u95f4\u9501\u7684<strong>\u4fdd\u62a4\u94b1\u5305</strong> \u2014 \u6bd4\u7279\u5e01\u4ecd\u5c5e\u4e8e\u4f60\uff0c\u4f46\u7ee7\u627f\u4eba\u53ef\u4ee5\u6062\u590d\u3002',
    visitBitclutch: '\u5728\u8054\u7f51\u8bbe\u5907\u4e0a\u8bbf\u95ee<strong>bitclutch.app</strong>\u521b\u5efa\u4fdd\u62a4\u94b1\u5305\u3002',
    confirmedWritten: '\u5df2\u8bb0\u5f55',
    importTitle: '\u5bfc\u5165\u52a9\u8bb0\u8bcd', importDesc: '\u9009\u62e9\u5355\u8bcd\u6570\u548c\u8bed\u8a00\uff0c\u7136\u540e\u8f93\u5165\u6bcf\u4e2a\u5355\u8bcd\u3002',
    importPlaceholder: '\u5355\u8bcd1 \u5355\u8bcd2 \u5355\u8bcd3 ...', importAction: '\u5bfc\u5165', words: '\u4e2a\u5355\u8bcd',
    fillAllWords: '\u8bf7\u586b\u5199\u6240\u6709\u5355\u8bcd\u3002', needWords: '\u9700\u896112\u621624\u4e2a\u5355\u8bcd', invalidMnemonic: '\u65e0\u6548\u7684\u52a9\u8bb0\u8bcd',
    setPassTitle: '\u8bbe\u7f6e\u5bc6\u7801', setPassDesc: '\u9009\u62e9\u4e00\u4e2a\u5f3a\u5bc6\u7801\u6765\u52a0\u5bc6\u4f60\u7684\u79c1\u94a5\u3002\u6bcf\u6b21\u89e3\u9501\u90fd\u9700\u8981\u3002',
    confirmPass: '\u786e\u8ba4\u5bc6\u7801', enterPass: '\u8f93\u5165\u5bc6\u7801',
    passRequired: '\u5bc6\u7801\u4e3a\u5fc5\u586b\u9879\u3002', passTooShort: '\u5bc6\u7801\u592a\u77ed\uff08\u81f3\u5c114\u4e2a\u5b57\u7b26\uff09\u3002', passNoMatch: '\u5bc6\u7801\u4e0d\u5339\u914d\u3002',
    noKeyToSave: '\u6ca1\u6709\u5bc6\u94a5\u53ef\u4fdd\u5b58\u3002\u8bf7\u91cd\u65b0\u5f00\u59cb\u3002', encryptSave: '\u52a0\u5bc6\u5e76\u4fdd\u5b58', encryptFailed: '\u52a0\u5bc6\u5931\u8d25\uff1a',
    scanTitle: '\u626b\u63cf\u4e8c\u7ef4\u7801', scanDesc: '\u5c06\u6444\u50cf\u5934\u5bf9\u51c6BitClutch\u5e94\u7528\u7684\u4e8c\u7ef4\u7801\u3002',
    startingCamera: '\u542f\u52a8\u6444\u50cf\u5934...', scanning: '\u626b\u63cf\u4e2d...\u8bf7\u5bf9\u51c6\u4e8c\u7ef4\u7801\u3002', cameraError: '\u6444\u50cf\u5934\u9519\u8bef\uff1a',
    receivingFountain: '\u63a5\u6536\u55b7\u6cc9\u7801\u4e2d...', urFailed: 'UR\u89e3\u7801\u5931\u8d25\u3002\u8bf7\u91cd\u8bd5\u3002', psbtParseError: 'PSBT\u89e3\u6790\u9519\u8bef\uff1a',
    confirmTx: '\u786e\u8ba4\u4ea4\u6613', reviewBeforeSign: '\u7b7e\u540d\u524d\u8bf7\u4ed4\u7ec6\u68c0\u67e5\u3002',
    inputs: '\u8f93\u5165', output: '\u8f93\u51fa', change: '(\u627e\u96f6)', fee: '\u8d39\u7528', reject: '\u62d2\u7edd', sign: '\u7b7e\u540d', signingFailed: '\u7b7e\u540d\u5931\u8d25\uff1a',
    signedPsbt: '\u5df2\u7b7e\u540dPSBT', showQRDesc: '\u8ba9BitClutch\u5e94\u7528\u626b\u63cf\u6b64QR\u7801\u4ee5\u5e7f\u64ad\u4ea4\u6613\u3002', scanComplete: '\u626b\u63cf\u5b8c\u6210', scanSignatureDesc: '\u8ba9BitClutch\u5e94\u7528\u626b\u63cf\u6b64QR\u7801\u4ee5\u63d0\u4ea4\u7b7e\u540d\u3002',
    singleQR: '\u5355\u4e2a\u4e8c\u7ef4\u7801', fountainKeepShowing: '\u55b7\u6cc9\u7801 \u2014 \u8bf7\u7ee7\u7eed\u5c55\u793a', frame: '\u5e27',
    confirmBms: '\u786e\u8ba4\u6d88\u606f\u7b7e\u540d', reviewMessage: '\u7b7e\u540d\u524d\u8bf7\u68c0\u67e5\u6d88\u606f\u3002',
    type: '\u7c7b\u578b', bmsType: 'BMS (\u6bd4\u7279\u5e01\u6d88\u606f)', index: '\u7d22\u5f15', address: '\u5730\u5740', message: '\u6d88\u606f',
    bmsSignature: 'BMS\u7b7e\u540d', sigBase64: '\u7b7e\u540d (base64)', tapToCopy: '\u70b9\u51fb\u590d\u5236', copySig: '\u590d\u5236\u7b7e\u540d', sha256: 'SHA-256',
    settings: '\u8bbe\u7f6e', version: '\u7248\u672c', language: '\u8bed\u8a00', seedLanguage: '\u52a9\u8bb0\u8bcd\u8bed\u8a00',
    onlineKeygenTitle: '\u7f51\u7edc\u5df2\u8fde\u63a5\uff01',
    onlineKeygenBody: '\u60a8\u7684\u8bbe\u5907\u5df2\u8fde\u63a5\u5230\u4e92\u8054\u7f51\u3002\u5728\u7ebf\u751f\u6210\u7684\u5bc6\u94a5\u53ef\u80fd\u88ab\u6076\u610f\u8f6f\u4ef6\u62e6\u622a\u3002\u8bf7\u5728\u7ee7\u7eed\u4e4b\u524d\u65ad\u5f00\u6240\u6709\u7f51\u7edc\uff08WiFi\u3001\u79fb\u52a8\u6570\u636e\u3001\u84dd\u7259\u3001USB\uff09\u3002',
    proceedAnyway: '\u4ecd\u7136\u7ee7\u7eed\uff08\u4e0d\u5b89\u5168\uff09',
    installGuide: '\u5b89\u88c5\u6307\u5357', viewSource: '\u9a8c\u8bc1\u6e90\u4ee3\u7801\u5b8c\u6574\u6027', securityInfo: '\u5b89\u5168\u4fe1\u606f',
    deleteKey: '\u5220\u9664\u5bc6\u94a5', deleteConfirm1: '\u5220\u9664\u5bc6\u94a5\uff1f\u65e0\u6cd5\u64a4\u9500\u3002\n\u8bf7\u786e\u4fdd\u5df2\u5907\u4efd\u52a9\u8bb0\u8bcd\uff01',
    deleteConfirm2: '\u4f60\u786e\u5b9a\u5417\uff1f\u6ca1\u6709\u5907\u4efd\u5c06\u6c38\u4e45\u4e22\u5931\u6bd4\u7279\u5e01\u3002',
    verifyIntegrity: '\u9a8c\u8bc1\u5b8c\u6574\u6027', verifyDesc: '\u5c06SHA-256\u54c8\u5e0c\u4e0eGitHub\u5b98\u65b9\u7248\u672c\u8fdb\u884c\u6bd4\u8f83\u3002',
    computing: '\u8ba1\u7b97\u4e2d...', fetchFailed: '(\u83b7\u53d6\u5931\u8d25)',
    verifyFile: '\u9a8c\u8bc1\u6b64\u6587\u4ef6', verifyFileDesc: '\u70b9\u51fb\u6b64\u5904\u9009\u62e9\u4e0b\u8f7d\u7684<strong>bitclutch-signer.html</strong>\u6587\u4ef6\u3002<br>SHA-256\u54c8\u5e0c\u5c06\u5728\u672c\u5730\u8ba1\u7b97\u3002',
    tapToSelect: '\u70b9\u51fb\u9009\u62e9', compareGithub: '\u4e0eGitHub\u7248\u672c\u7684<code>hashes.json</code>\u8fdb\u884c\u6bd4\u8f83\u3002',
    auditableSource: '\u53ef\u5ba1\u8ba1\u6e90\u4ee3\u7801', auditableDesc: '\u6b64\u5e94\u7528\u7684\u6240\u6709\u903b\u8f91\u90fd\u5728\u4e00\u4e2a\u53ef\u5ba1\u8ba1\u7684\u6587\u4ef6\u4e2d\u3002\u6e90\u4ee3\u7801\u548c\u5b98\u65b9\u54c8\u5e0c\u5df2\u53d1\u5e03\u5728GitHub\u3002',
    back: '\u8fd4\u56de',
    securityTitle: '\u5b89\u5168\u4fe1\u606f', securityLevel: '\u5b89\u5168\u7ea7\u522b\uff1a\u8f6f\u4ef6\u6c14\u9699',
    whatProvides: '\u63d0\u4f9b\uff1a', secProvide1: '\u79c1\u94a5\u6c38\u4e0d\u63a5\u89e6\u4e92\u8054\u7f51\uff08\u8bbe\u7f6e\u540e\uff09',
    secProvide2: '\u4ee3\u7801\u53ef\u5ba1\u8ba1\uff08\u5355\u4e00app.js\u6587\u4ef6\uff09', secProvide3: '\u4ec5\u4f7f\u7528\u7269\u7406\u6e90\u71b5\uff08\u9ab0\u5b50/\u786c\u5e01\uff09',
    secProvide4: 'AES-256-GCM\u52a0\u5bc6 + 600K PBKDF2\u8fed\u4ee3',
    whatNot: '\u4e0d\u63d0\u4f9b\uff1a', secNot1: 'Secure Element\uff08\u786c\u4ef6\u94b1\u5305\u6709\uff09',
    secNot2: '\u786c\u4ef6\u7ea7\u6c14\u9699\uff08WiFi\u82af\u7247\u4ecd\u5b58\u5728\uff09', secNot3: '\u4fa7\u4fe1\u9053\u653b\u51fb\u62b5\u6297\u529b',
    keyStorage: '\u5bc6\u94a5\u5b58\u50a8', encryption: '\u52a0\u5bc6\uff1a', encryptionDesc: 'AES-256-GCM + PBKDF2 (600,000\u6b21) + \u968f\u673a\u76d0/IV',
    warning: '\u8b66\u544a\uff1a', clearDataWarning: '\u6e05\u9664\u6d4f\u89c8\u5668\u6570\u636e\u5c06\u6c38\u4e45\u5220\u9664\u52a0\u5bc6\u5bc6\u94a5\u3002\u8bf7\u59cb\u7ec8\u79bb\u7ebf\u5907\u4efd\u52a9\u8bb0\u8bcd\u3002',
    autoLock: '\u81ea\u52a8\u9501\u5b9a\uff1a', autoLockDesc: '5\u5206\u949f\u65e0\u64cd\u4f5c\u540e\u5bc6\u94a5\u5c06\u4ece\u5185\u5b58\u4e2d\u6e05\u9664\u3002',
    storageEncKey: '\u52a0\u5bc6\u79c1\u94a5 (AES-256-GCM)', storageXpub: '\u8d26\u6237\u6269\u5c55\u516c\u94a5', storageFp: 'BIP-32\u6307\u7eb9',
    storageNet: '\u7f51\u7edc\u8bbe\u7f6e (main/test)', storageLang: '\u754c\u9762\u8bed\u8a00', storageSeedLang: '\u52a9\u8bb0\u8bcd\u8bed\u8a00', storageKeyCreated: '\u5bc6\u94a5\u521b\u5efa\u65e5\u671f', storageLastOnline: '\u7f51\u7edc\u68c0\u6d4b\u65e5\u671f',
    guideTitle: '\u5b89\u88c5\u6307\u5357', guideDesc: '\u5c06BitClutch Signer\u5b89\u88c5\u4e3a\u79bb\u7ebf\u5e94\u7528\uff0c\u7136\u540e\u5728\u4f7f\u7528\u524d\u5f00\u542f\u98de\u884c\u6a21\u5f0f\u3002',
    detected: '\u5df2\u68c0\u6d4b',
    guideIosSafari: '<strong>\u5b89\u88c5\u4e3a\u79bb\u7ebf\u5e94\u7528\uff1a</strong><ol><li>\u5728 <strong>Safari</strong> \u4e2d\u6253\u5f00\u6b64\u9875\u9762</li><li>\u70b9\u51fb <strong>Share</strong> \u6309\u94ae\uff08\u5e26\u7bad\u5934\u7684\u65b9\u6846\uff09</li><li>\u5411\u4e0b\u6eda\u52a8\u5e76\u70b9\u51fb <strong>\u201cAdd to Home Screen\u201d</strong></li><li>\u70b9\u51fb\u53f3\u4e0a\u89d2\u7684 <strong>\u201cAdd\u201d</strong></li></ol><strong>\u542f\u7528\u98de\u884c\u6a21\u5f0f\uff1a</strong><ol><li>\u4ece\u53f3\u4e0a\u89d2\u5411\u4e0b\u6ed1\u52a8\uff08\u65e7\u6b3eiPhone\u4ece\u5e95\u90e8\u5411\u4e0a\u6ed1\u52a8\uff09</li><li>\u70b9\u51fb<strong>\u98de\u884c\u6a21\u5f0f\u56fe\u6807</strong>\u4ee5\u542f\u7528</li><li>\u786e\u4fddWi-Fi\u548cBluetooth\u4e5f\u5df2\u5173\u95ed</li></ol>',
    guideIosChrome: '<strong>\u91cd\u8981\u63d0\u793a\uff1a</strong>iOS\u4e0a\u7684Chrome\u65e0\u6cd5\u5b89\u88c5\u79bb\u7ebf\u5e94\u7528\u3002\u8bf7\u4f7f\u7528 <strong>Safari</strong> \u4ee3\u66ff\u3002<ol><li>\u590d\u5236\u6b64\u9875\u9762URL</li><li>\u6253\u5f00 <strong>Safari</strong> \u5e76\u7c98\u8d34URL</li><li>\u6309\u7167\u4e0a\u8ff0 <strong>iOS Safari</strong> \u8bf4\u660e\u64cd\u4f5c</li></ol><strong>\u542f\u7528\u98de\u884c\u6a21\u5f0f\uff1a</strong><ol><li>\u4ece\u53f3\u4e0a\u89d2\u5411\u4e0b\u6ed1\u52a8</li><li>\u70b9\u51fb<strong>\u98de\u884c\u6a21\u5f0f\u56fe\u6807</strong></li></ol>',
    guideAndroidChrome: '<strong>\u5b89\u88c5\u4e3a\u79bb\u7ebf\u5e94\u7528\uff1a</strong><ol><li>\u5728 <strong>Chrome</strong> \u4e2d\u6253\u5f00\u6b64\u9875\u9762</li><li>\u70b9\u51fb\u53f3\u4e0a\u89d2\u7684<strong>\u4e09\u70b9\u83dc\u5355</strong></li><li>\u70b9\u51fb <strong>\u201cInstall app\u201d</strong> \u6216 <strong>\u201cAdd to Home screen\u201d</strong></li><li>\u70b9\u51fb <strong>\u201cInstall\u201d</strong> \u786e\u8ba4</li></ol><strong>\u542f\u7528\u98de\u884c\u6a21\u5f0f\uff1a</strong><ol><li>\u4ece\u5c4f\u5e55\u9876\u90e8\u5411\u4e0b\u6ed1\u52a8</li><li>\u70b9\u51fb <strong>\u201cAirplane mode\u201d</strong></li><li>\u786e\u8ba4Wi-Fi\u548c\u79fb\u52a8\u6570\u636e\u5df2\u5173\u95ed</li></ol>',
    guideAndroidSamsung: '<strong>\u5b89\u88c5\u4e3a\u79bb\u7ebf\u5e94\u7528\uff1a</strong><ol><li>\u5728 <strong>Samsung Internet</strong> \u4e2d\u6253\u5f00\u6b64\u9875\u9762</li><li>\u70b9\u51fb\u53f3\u4e0b\u89d2\u7684<strong>\u83dc\u5355\u56fe\u6807</strong>\uff08\u4e09\u6761\u6a2a\u7ebf\uff09</li><li>\u70b9\u51fb <strong>\u201cAdd page to\u201d</strong> \u7136\u540e\u9009\u62e9 <strong>\u201cHome screen\u201d</strong></li></ol><strong>\u542f\u7528\u98de\u884c\u6a21\u5f0f\uff1a</strong><ol><li>\u4ece\u9876\u90e8\u5411\u4e0b\u6ed1\u52a8\u4e24\u6b21\u4ee5\u6253\u5f00\u5feb\u901f\u8bbe\u7f6e</li><li>\u70b9\u51fb <strong>\u201cAirplane mode\u201d</strong></li></ol>',
    guideMacosSafari: '<strong>\u5b89\u88c5\u4e3a\u79bb\u7ebf\u5e94\u7528\uff08macOS Sonoma+\uff09\uff1a</strong><ol><li>\u5728 <strong>Safari</strong> \u4e2d\u6253\u5f00\u6b64\u9875\u9762</li><li>\u70b9\u51fb <strong>File</strong> \u83dc\u5355\uff0c\u7136\u540e\u70b9\u51fb <strong>\u201cAdd to Dock\u201d</strong></li><li>\u70b9\u51fb <strong>\u201cAdd\u201d</strong></li></ol><strong>\u7981\u7528\u7f51\u7edc\uff1a</strong><ol><li>\u70b9\u51fb\u83dc\u5355\u680f\u4e2d\u7684 <strong>Wi-Fi icon</strong></li><li>\u70b9\u51fb<strong>\u5173\u95edWi-Fi</strong></li><li>\u62d4\u6389\u6240\u6709\u4ee5\u592a\u7f51\u7ebf\u7f06</li></ol>',
    guideMacosChrome: '<strong>\u5b89\u88c5\u4e3a\u79bb\u7ebf\u5e94\u7528\uff1a</strong><ol><li>\u5728 <strong>Chrome</strong> \u4e2d\u6253\u5f00\u6b64\u9875\u9762</li><li>\u70b9\u51fb\u5730\u5740\u680f\u4e2d\u7684 <strong>install icon</strong>\uff08\u6216\u4e09\u70b9\u83dc\u5355 &rarr; \u201cInstall BitClutch Signer\u201d\uff09</li><li>\u70b9\u51fb <strong>\u201cInstall\u201d</strong></li></ol><strong>\u7981\u7528\u7f51\u7edc\uff1a</strong><ol><li>\u70b9\u51fb\u83dc\u5355\u680f\u4e2d\u7684 <strong>Wi-Fi icon</strong></li><li>\u70b9\u51fb<strong>\u5173\u95edWi-Fi</strong></li><li>\u62d4\u6389\u6240\u6709\u4ee5\u592a\u7f51\u7ebf\u7f06</li></ol>',
    guideWindowsChrome: '<strong>\u5b89\u88c5\u4e3a\u79bb\u7ebf\u5e94\u7528\uff1a</strong><ol><li>\u5728 <strong>Chrome</strong> \u4e2d\u6253\u5f00\u6b64\u9875\u9762</li><li>\u70b9\u51fb\u5730\u5740\u680f\u4e2d\u7684 <strong>install icon</strong>\uff08\u6216\u4e09\u70b9\u83dc\u5355 &rarr; \u201cInstall BitClutch Signer\u201d\uff09</li><li>\u70b9\u51fb <strong>\u201cInstall\u201d</strong></li></ol><strong>\u7981\u7528\u7f51\u7edc\uff1a</strong><ol><li>\u70b9\u51fb\u4efb\u52a1\u680f\uff08\u53f3\u4e0b\u89d2\uff09\u4e2d\u7684 <strong>Wi-Fi icon</strong></li><li>\u70b9\u51fb<strong>\u65ad\u5f00Wi-Fi\u8fde\u63a5</strong></li><li>\u62d4\u6389\u6240\u6709\u4ee5\u592a\u7f51\u7ebf\u7f06</li></ol>',
    guideWindowsEdge: '<strong>\u5b89\u88c5\u4e3a\u79bb\u7ebf\u5e94\u7528\uff1a</strong><ol><li>\u5728 <strong>Edge</strong> \u4e2d\u6253\u5f00\u6b64\u9875\u9762</li><li>\u70b9\u51fb\u5730\u5740\u680f\u4e2d\u7684 <strong>install icon</strong>\uff08\u6216\u4e09\u70b9\u83dc\u5355 &rarr; \u201c\u5e94\u7528\u201d &rarr; \u201cInstall BitClutch Signer\u201d\uff09</li><li>\u70b9\u51fb <strong>\u201cInstall\u201d</strong></li></ol><strong>\u7981\u7528\u7f51\u7edc\uff1a</strong><ol><li>\u70b9\u51fb\u4efb\u52a1\u680f\uff08\u53f3\u4e0b\u89d2\uff09\u4e2d\u7684 <strong>Wi-Fi icon</strong></li><li>\u70b9\u51fb<strong>\u65ad\u5f00Wi-Fi\u8fde\u63a5</strong></li><li>\u62d4\u6389\u6240\u6709\u4ee5\u592a\u7f51\u7ebf\u7f06</li></ol>',
    accountXpubTitle: '\u8d26\u6237xpub',
    noMnemonic: '\u65e0\u53ef\u7528\u52a9\u8bb0\u8bcd\u3002', noTxData: '\u65e0\u4ea4\u6613\u6570\u636e\u3002', noSignedData: '\u65e0\u7b7e\u540d\u6570\u636e\u3002',
    noBmsRequest: '\u65e0BMS\u8bf7\u6c42\u3002', noSignature: '\u65e0\u7b7e\u540d\u3002', loading: '\u52a0\u8f7d\u4e2d...',
    bannerWarn: '\u68c0\u6d4b\u5230\u7f51\u7edc \u2014 \u751f\u6210\u5bc6\u94a5\u524d\u8bf7\u65ad\u5f00\u6240\u6709\u7f51\u7edc\u3002',
    bannerOnline: '\u7f51\u7edc\u5df2\u8fde\u63a5 \u2014 \u7acb\u5373\u65ad\u5f00\uff0c\u5e76\u4e14\u7edd\u5bf9\u4e0d\u8981\u518d\u6b21\u8fde\u63a5\u6b64\u8bbe\u5907\u3002\u5bc6\u94a5\u53ef\u80fd\u5df2\u7ecf\u6cc4\u9732\u3002',
    bannerOffline: '\u672a\u68c0\u6d4b\u5230\u65e0\u7ebf\u7f51\u7edc\u3002\u8bf7\u786e\u8ba4\u84dd\u7259\u3001NFC\u548cUSB\u6570\u636e\u7ebf\u4e5f\u5df2\u65ad\u5f00\u3002',
  },
  'zh-t': {
    unlocked: '\u5df2\u89e3\u9396', locked: '\u5df2\u9396\u5b9a',
    tabKey: '\u5bc6\u9470', tabSign: '\u7c3d\u540d', tabSettings: '\u8a2d\u5b9a',
    createKeys: '\u5efa\u7acb\u5bc6\u9470',
    setupDesc: '\u4f7f\u7528\u7269\u7406\u71b5\u7522\u751f\u65b0\u5bc6\u9470\uff0c<br>\u6216\u532f\u5165\u73fe\u6709\u52a9\u8a18\u8a5e\u3002',
    diceBtn: '\u9ab0\u5b50 (99\u6b21)', coinBtn: '\u786c\u5e63 (256\u6b21)', importBtn: '\u532f\u5165\u52a9\u8a18\u8a5e',
    enterPassphrase: '\u8f38\u5165\u5bc6\u78bc\u89e3\u9396', passphrase: '\u5bc6\u78bc', unlock: '\u89e3\u9396', wrongPassphrase: '\u5bc6\u78bc\u932f\u8aa4\u3002',
    yourKey: '\u4f60\u7684\u5bc6\u9470', network: '\u7db2\u8def', fingerprint: '\u6307\u7d0b', keyCreated: '\u5efa\u7acb\u65e5\u671f', lastOnline: '\u6700\u5f8c\u5728\u7dda', neverOnline: '\u7121 (\u5b89\u5168)', onlineAfterKey: '\u5bc6\u9470\u5efa\u7acb\u5f8c\u5075\u6e2c\u5230\u5728\u7dda', accountXpub: '\u5e33\u6236xpub',
    showXpubQR: '\u986f\u793axpub QR', lockBtn: '\u9396\u5b9a', mainnet: '\u4e3b\u7db2', testnet: '\u6e2c\u8a66\u7db2',
    diceTitle: '\u9ab0\u5b50\u5bc6\u9470\u7522\u751f', diceDesc: '\u64f2\u771f\u5be6\u9ab0\u5b50\u4e26\u9ede\u64ca\u7d50\u679c\u3002',
    progress: '\u9032\u5ea6', undoLast: '\u5fa9\u539f', cancel: '\u53d6\u6d88', ok: '\u78ba\u5b9a',
    coinTitle: '\u786c\u5e63\u5bc6\u9470\u7522\u751f', coinDesc: '\u62cb\u771f\u5be6\u786c\u5e63\u4e26\u9ede\u64ca\u7d50\u679c\u3002',
    entropyWarning: '\u4f7f\u7528\u771f\u5be6\u9ab0\u5b50/\u786c\u5e63 \u2014 \u5207\u52ff\u81ea\u7de8\u6578\u5b57\u3002\u4eba\u985e\u9078\u64c7\u53ef\u9810\u6e2c\uff0c\u6703\u524a\u5f31\u5bc6\u9470\u3002\u78ba\u4fdd\u9644\u8fd1\u7121\u651d\u50cf\u982d\u6216\u9ea5\u514b\u98a8 \u2014 \u770b\u5230\u64f2\u7d50\u679c\u7684\u4eba\u53ef\u4ee5\u7a8a\u53d6\u4f60\u7684\u6bd4\u7279\u5e63\u3002',
    heads: 'H (\u6b63\u9762)', tails: 'T (\u53cd\u9762)',
    writeDown: '\u8acb\u8a18\u4e0b\u9019\u4e9b\u5b57\u8a5e\uff01',
    mnemonicDesc: '\u9019\u662f\u4f60\u7684\u52a9\u8a18\u8a5e\u3002\u8acb\u96e2\u7dda\u5b89\u5168\u4fdd\u5b58\u3002\u5c07\u4e0d\u6703\u518d\u6b21\u986f\u793a\u3002',
    stolenVsLost: '\u88ab\u76dc vs. \u907a\u5931 \u2014 \u4e86\u89e3\u5340\u5225',
    theft: '\u76dc\u7aca\uff1a', theftDesc: '\u5982\u679c\u6709\u4eba\u627e\u5230\u4f60\u7684\u52a9\u8a18\u8a5e\uff0c\u53ef\u4ee5\u7acb\u5373\u7aca\u53d6\u4f60\u7684\u6bd4\u7279\u5e63\u3002\u6c92\u4eba\u80fd\u64a4\u92b7\u3002',
    loss: '\u907a\u5931\uff1a', lossDesc: '\u5982\u679c\u4f60\u907a\u5931\u52a9\u8a18\u8a5e\u4e14\u88dd\u7f6e\u640d\u58de\uff0c\u4f60\u7684\u6bd4\u7279\u5e63\u5c07\u6c38\u9060\u4e1f\u5931 \u2014 \u9664\u975e\u4f60\u6709\u6062\u5fa9\u8a08\u756b\u3002',
    bitclutchPromo: '<strong>BitClutch</strong>\u4fdd\u8b77\u4f60\u514d\u53d7\u907a\u5931\u548c\u6b7b\u4ea1\u98a8\u96aa\uff0c\u800c\u975e\u76dc\u7aca\u3002\u5efa\u7acb\u5e36\u6642\u9593\u9396\u7684<strong>\u4fdd\u8b77\u9322\u5305</strong> \u2014 \u6bd4\u7279\u5e63\u4ecd\u5c6c\u65bc\u4f60\uff0c\u4f46\u7e7c\u627f\u4eba\u53ef\u4ee5\u6062\u5fa9\u3002',
    visitBitclutch: '\u5728\u806f\u7db2\u88dd\u7f6e\u4e0a\u8a2a\u554f<strong>bitclutch.app</strong>\u5efa\u7acb\u4fdd\u8b77\u9322\u5305\u3002',
    confirmedWritten: '\u5df2\u8a18\u9304',
    importTitle: '\u532f\u5165\u52a9\u8a18\u8a5e', importDesc: '\u9078\u64c7\u5b57\u6578\u548c\u8a9e\u8a00\uff0c\u7136\u5f8c\u8f38\u5165\u6bcf\u500b\u5b57\u3002',
    importPlaceholder: '\u5b57\u8a5e1 \u5b57\u8a5e2 \u5b57\u8a5e3 ...', importAction: '\u532f\u5165', words: '\u500b\u5b57',
    fillAllWords: '\u8acb\u586b\u5beb\u6240\u6709\u5b57\u8a5e\u3002', needWords: '\u9700\u898112\u621624\u500b\u5b57', invalidMnemonic: '\u7121\u6548\u7684\u52a9\u8a18\u8a5e',
    setPassTitle: '\u8a2d\u5b9a\u5bc6\u78bc', setPassDesc: '\u9078\u64c7\u4e00\u500b\u5f37\u5bc6\u78bc\u4f86\u52a0\u5bc6\u4f60\u7684\u79c1\u9470\u3002\u6bcf\u6b21\u89e3\u9396\u90fd\u9700\u8981\u3002',
    confirmPass: '\u78ba\u8a8d\u5bc6\u78bc', enterPass: '\u8f38\u5165\u5bc6\u78bc',
    passRequired: '\u5bc6\u78bc\u70ba\u5fc5\u586b\u3002', passTooShort: '\u5bc6\u78bc\u592a\u77ed\uff08\u81f3\u5c114\u500b\u5b57\u5143\uff09\u3002', passNoMatch: '\u5bc6\u78bc\u4e0d\u5339\u914d\u3002',
    noKeyToSave: '\u6c92\u6709\u5bc6\u9470\u53ef\u4fdd\u5b58\u3002\u8acb\u91cd\u65b0\u958b\u59cb\u3002', encryptSave: '\u52a0\u5bc6\u4e26\u4fdd\u5b58', encryptFailed: '\u52a0\u5bc6\u5931\u6557\uff1a',
    scanTitle: '\u6383\u63cf QR', scanDesc: '\u5c07\u93e1\u982d\u5c0d\u6e96BitClutch\u61c9\u7528\u7684QR\u78bc\u3002',
    startingCamera: '\u555f\u52d5\u93e1\u982d...', scanning: '\u6383\u63cf\u4e2d...\u8acb\u5c0d\u6e96QR\u78bc\u3002', cameraError: '\u93e1\u982d\u932f\u8aa4\uff1a',
    receivingFountain: '\u63a5\u6536\u5674\u6cc9\u78bc\u4e2d...', urFailed: 'UR\u89e3\u78bc\u5931\u6557\u3002\u8acb\u91cd\u8a66\u3002', psbtParseError: 'PSBT\u89e3\u6790\u932f\u8aa4\uff1a',
    confirmTx: '\u78ba\u8a8d\u4ea4\u6613', reviewBeforeSign: '\u7c3d\u540d\u524d\u8acb\u4ed4\u7d30\u6aa2\u67e5\u3002',
    inputs: '\u8f38\u5165', output: '\u8f38\u51fa', change: '(\u627e\u96f6)', fee: '\u8cbb\u7528', reject: '\u62d2\u7d55', sign: '\u7c3d\u540d', signingFailed: '\u7c3d\u540d\u5931\u6557\uff1a',
    signedPsbt: '\u5df2\u7c3d\u540dPSBT', showQRDesc: '\u8b93BitClutch\u61c9\u7528\u6383\u63cf\u6b64QR\u78bc\u4ee5\u5ee3\u64ad\u4ea4\u6613\u3002', scanComplete: '\u6383\u63cf\u5b8c\u6210', scanSignatureDesc: '\u8b93BitClutch\u61c9\u7528\u6383\u63cf\u6b64QR\u78bc\u4ee5\u63d0\u4ea4\u7c3d\u540d\u3002',
    singleQR: '\u55ae\u500bQR', fountainKeepShowing: '\u5674\u6cc9\u78bc \u2014 \u8acb\u7e7c\u7e8c\u5c55\u793a', frame: '\u5e40',
    confirmBms: '\u78ba\u8a8d\u8a0a\u606f\u7c3d\u540d', reviewMessage: '\u7c3d\u540d\u524d\u8acb\u6aa2\u67e5\u8a0a\u606f\u3002',
    type: '\u985e\u578b', bmsType: 'BMS (\u6bd4\u7279\u5e63\u8a0a\u606f)', index: '\u7d22\u5f15', address: '\u5730\u5740', message: '\u8a0a\u606f',
    bmsSignature: 'BMS\u7c3d\u540d', sigBase64: '\u7c3d\u540d (base64)', tapToCopy: '\u9ede\u64ca\u8907\u88fd', copySig: '\u8907\u88fd\u7c3d\u540d', sha256: 'SHA-256',
    settings: '\u8a2d\u5b9a', version: '\u7248\u672c', language: '\u8a9e\u8a00', seedLanguage: '\u52a9\u8a18\u8a5e\u8a9e\u8a00',
    onlineKeygenTitle: '\u7db2\u8def\u5df2\u9023\u63a5\uff01',
    onlineKeygenBody: '\u60a8\u7684\u88dd\u7f6e\u5df2\u9023\u63a5\u5230\u7db2\u969b\u7db2\u8def\u3002\u7dda\u4e0a\u7522\u751f\u7684\u91d1\u9470\u53ef\u80fd\u88ab\u60e1\u610f\u8edf\u9ad4\u6514\u622a\u3002\u8acb\u5728\u7e7c\u7e8c\u4e4b\u524d\u65b7\u958b\u6240\u6709\u7db2\u8def\uff08WiFi\u3001\u884c\u52d5\u6578\u64da\u3001\u85cd\u7259\u3001USB\uff09\u3002',
    proceedAnyway: '\u4ecd\u7136\u7e7c\u7e8c\uff08\u4e0d\u5b89\u5168\uff09',
    installGuide: '\u5b89\u88dd\u6307\u5357', viewSource: '\u9a57\u8b49\u539f\u59cb\u78bc\u5b8c\u6574\u6027', securityInfo: '\u5b89\u5168\u8cc7\u8a0a',
    deleteKey: '\u522a\u9664\u5bc6\u9470', deleteConfirm1: '\u522a\u9664\u5bc6\u9470\uff1f\u7121\u6cd5\u5fa9\u539f\u3002\n\u8acb\u78ba\u4fdd\u5df2\u5099\u4efd\u52a9\u8a18\u8a5e\uff01',
    deleteConfirm2: '\u4f60\u78ba\u5b9a\u55ce\uff1f\u6c92\u6709\u5099\u4efd\u5c07\u6c38\u4e45\u4e1f\u5931\u6bd4\u7279\u5e63\u3002',
    verifyIntegrity: '\u9a57\u8b49\u5b8c\u6574\u6027', verifyDesc: '\u5c07SHA-256\u96dc\u6e4a\u8207GitHub\u5b98\u65b9\u7248\u672c\u9032\u884c\u6bd4\u8f03\u3002',
    computing: '\u8a08\u7b97\u4e2d...', fetchFailed: '(\u7372\u53d6\u5931\u6557)',
    verifyFile: '\u9a57\u8b49\u6b64\u6a94\u6848', verifyFileDesc: '\u9ede\u64ca\u6b64\u8655\u9078\u64c7\u4e0b\u8f09\u7684<strong>bitclutch-signer.html</strong>\u6a94\u6848\u3002<br>SHA-256\u96dc\u6e4a\u5c07\u5728\u672c\u5730\u8a08\u7b97\u3002',
    tapToSelect: '\u9ede\u64ca\u9078\u64c7', compareGithub: '\u8207GitHub\u7248\u672c\u7684<code>hashes.json</code>\u9032\u884c\u6bd4\u8f03\u3002',
    auditableSource: '\u53ef\u5be9\u8a08\u539f\u59cb\u78bc', auditableDesc: '\u6b64\u61c9\u7528\u7684\u6240\u6709\u908f\u8f2f\u90fd\u5728\u4e00\u500b\u53ef\u5be9\u8a08\u7684\u6a94\u6848\u4e2d\u3002\u539f\u59cb\u78bc\u548c\u5b98\u65b9\u96dc\u6e4a\u5df2\u767c\u4f48\u5728GitHub\u3002',
    back: '\u8fd4\u56de',
    securityTitle: '\u5b89\u5168\u8cc7\u8a0a', securityLevel: '\u5b89\u5168\u7d1a\u5225\uff1a\u8edf\u9ad4\u6c23\u96d9',
    whatProvides: '\u63d0\u4f9b\uff1a', secProvide1: '\u79c1\u9470\u6c38\u4e0d\u63a5\u89f8\u7db2\u969b\u7db2\u8def\uff08\u8a2d\u5b9a\u5f8c\uff09',
    secProvide2: '\u4ee3\u78bc\u53ef\u5be9\u8a08\uff08\u55ae\u4e00app.js\u6a94\u6848\uff09', secProvide3: '\u50c5\u4f7f\u7528\u7269\u7406\u6e90\u71b5\uff08\u9ab0\u5b50/\u786c\u5e63\uff09',
    secProvide4: 'AES-256-GCM\u52a0\u5bc6 + 600K PBKDF2\u8fed\u4ee3',
    whatNot: '\u4e0d\u63d0\u4f9b\uff1a', secNot1: 'Secure Element\uff08\u786c\u9ad4\u9322\u5305\u6709\uff09',
    secNot2: '\u786c\u9ad4\u7d1a\u6c23\u96d9\uff08WiFi\u6676\u7247\u4ecd\u5b58\u5728\uff09', secNot3: '\u5074\u4fe1\u9053\u653b\u64ca\u62b5\u6297\u529b',
    keyStorage: '\u5bc6\u9470\u5132\u5b58', encryption: '\u52a0\u5bc6\uff1a', encryptionDesc: 'AES-256-GCM + PBKDF2 (600,000\u6b21) + \u96a8\u6a5f\u9e7d/IV',
    warning: '\u8b66\u544a\uff1a', clearDataWarning: '\u6e05\u9664\u700f\u89bd\u5668\u8cc7\u6599\u5c07\u6c38\u4e45\u522a\u9664\u52a0\u5bc6\u5bc6\u9470\u3002\u8acb\u59cb\u7d42\u96e2\u7dda\u5099\u4efd\u52a9\u8a18\u8a5e\u3002',
    autoLock: '\u81ea\u52d5\u9396\u5b9a\uff1a', autoLockDesc: '5\u5206\u9418\u7121\u64cd\u4f5c\u5f8c\u5bc6\u9470\u5c07\u5f9e\u8a18\u61b6\u9ad4\u4e2d\u6e05\u9664\u3002',
    storageEncKey: '\u52a0\u5bc6\u79c1\u9470 (AES-256-GCM)', storageXpub: '\u5e33\u6236\u64f4\u5c55\u516c\u9470', storageFp: 'BIP-32\u6307\u7d0b',
    storageNet: '\u7db2\u8def\u8a2d\u5b9a (main/test)', storageLang: '\u4ecb\u9762\u8a9e\u8a00', storageSeedLang: '\u52a9\u8a18\u8a5e\u8a9e\u8a00', storageKeyCreated: '\u5bc6\u9470\u5efa\u7acb\u65e5\u671f', storageLastOnline: '\u7db2\u8def\u5075\u6e2c\u65e5\u671f',
    guideTitle: '\u5b89\u88dd\u6307\u5357', guideDesc: '\u5c07BitClutch Signer\u5b89\u88dd\u70ba\u96e2\u7dda\u61c9\u7528\uff0c\u7136\u5f8c\u5728\u4f7f\u7528\u524d\u958b\u555f\u98db\u884c\u6a21\u5f0f\u3002',
    detected: '\u5df2\u5075\u6e2c',
    guideIosSafari: '<strong>\u5b89\u88dd\u70ba\u96e2\u7dda\u61c9\u7528\uff1a</strong><ol><li>\u5728 <strong>Safari</strong> \u4e2d\u958b\u555f\u6b64\u9801\u9762</li><li>\u9ede\u64ca <strong>Share</strong> \u6309\u9215\uff08\u5e36\u7bad\u982d\u7684\u65b9\u6846\uff09</li><li>\u5411\u4e0b\u6eff\u52d5\u4e26\u9ede\u64ca <strong>\u201cAdd to Home Screen\u201d</strong></li><li>\u9ede\u64ca\u53f3\u4e0a\u89d2\u7684 <strong>\u201cAdd\u201d</strong></li></ol><strong>\u555f\u7528\u98db\u884c\u6a21\u5f0f\uff1a</strong><ol><li>\u5f9e\u53f3\u4e0a\u89d2\u5411\u4e0b\u6ed1\u52d5\uff08\u820a\u6b3eiPhone\u5f9e\u5e95\u90e8\u5411\u4e0a\u6ed1\u52d5\uff09</li><li>\u9ede\u64ca<strong>\u98db\u884c\u6a21\u5f0f\u5716\u793a</strong>\u4ee5\u555f\u7528</li><li>\u78ba\u4fddWi-Fi\u548cBluetooth\u4e5f\u5df2\u95dc\u9589</li></ol>',
    guideIosChrome: '<strong>\u91cd\u8981\u63d0\u793a\uff1a</strong>iOS\u4e0a\u7684Chrome\u7121\u6cd5\u5b89\u88dd\u96e2\u7dda\u61c9\u7528\u3002\u8acb\u4f7f\u7528 <strong>Safari</strong> \u4ee3\u66ff\u3002<ol><li>\u8907\u88fd\u6b64\u9801\u9762URL</li><li>\u958b\u555f <strong>Safari</strong> \u4e26\u8cbc\u4e0aURL</li><li>\u6309\u7167\u4e0a\u8ff0 <strong>iOS Safari</strong> \u8aaa\u660e\u64cd\u4f5c</li></ol><strong>\u555f\u7528\u98db\u884c\u6a21\u5f0f\uff1a</strong><ol><li>\u5f9e\u53f3\u4e0a\u89d2\u5411\u4e0b\u6ed1\u52d5</li><li>\u9ede\u64ca<strong>\u98db\u884c\u6a21\u5f0f\u5716\u793a</strong></li></ol>',
    guideAndroidChrome: '<strong>\u5b89\u88dd\u70ba\u96e2\u7dda\u61c9\u7528\uff1a</strong><ol><li>\u5728 <strong>Chrome</strong> \u4e2d\u958b\u555f\u6b64\u9801\u9762</li><li>\u9ede\u64ca\u53f3\u4e0a\u89d2\u7684<strong>\u4e09\u9ede\u9078\u55ae</strong></li><li>\u9ede\u64ca <strong>\u201cInstall app\u201d</strong> \u6216 <strong>\u201cAdd to Home screen\u201d</strong></li><li>\u9ede\u64ca <strong>\u201cInstall\u201d</strong> \u78ba\u8a8d</li></ol><strong>\u555f\u7528\u98db\u884c\u6a21\u5f0f\uff1a</strong><ol><li>\u5f9e\u87a2\u5e55\u9802\u90e8\u5411\u4e0b\u6ed1\u52d5</li><li>\u9ede\u64ca <strong>\u201cAirplane mode\u201d</strong></li><li>\u78ba\u8a8dWi-Fi\u548c\u884c\u52d5\u6578\u64da\u5df2\u95dc\u9589</li></ol>',
    guideAndroidSamsung: '<strong>\u5b89\u88dd\u70ba\u96e2\u7dda\u61c9\u7528\uff1a</strong><ol><li>\u5728 <strong>Samsung Internet</strong> \u4e2d\u958b\u555f\u6b64\u9801\u9762</li><li>\u9ede\u64ca\u53f3\u4e0b\u89d2\u7684<strong>\u9078\u55ae\u5716\u793a</strong>\uff08\u4e09\u689d\u6a6b\u7dda\uff09</li><li>\u9ede\u64ca <strong>\u201cAdd page to\u201d</strong> \u7136\u5f8c\u9078\u64c7 <strong>\u201cHome screen\u201d</strong></li></ol><strong>\u555f\u7528\u98db\u884c\u6a21\u5f0f\uff1a</strong><ol><li>\u5f9e\u9802\u90e8\u5411\u4e0b\u6ed1\u52d5\u5169\u6b21\u4ee5\u958b\u555f\u5feb\u901f\u8a2d\u5b9a</li><li>\u9ede\u64ca <strong>\u201cAirplane mode\u201d</strong></li></ol>',
    guideMacosSafari: '<strong>\u5b89\u88dd\u70ba\u96e2\u7dda\u61c9\u7528\uff08macOS Sonoma+\uff09\uff1a</strong><ol><li>\u5728 <strong>Safari</strong> \u4e2d\u958b\u555f\u6b64\u9801\u9762</li><li>\u9ede\u64ca <strong>File</strong> \u9078\u55ae\uff0c\u7136\u5f8c\u9ede\u64ca <strong>\u201cAdd to Dock\u201d</strong></li><li>\u9ede\u64ca <strong>\u201cAdd\u201d</strong></li></ol><strong>\u505c\u7528\u7db2\u8def\uff1a</strong><ol><li>\u9ede\u64ca\u9078\u55ae\u5217\u4e2d\u7684 <strong>Wi-Fi icon</strong></li><li>\u9ede\u64ca<strong>\u95dc\u9589Wi-Fi</strong></li><li>\u62d4\u6389\u6240\u6709\u4e59\u592a\u7db2\u8def\u7dda\u7f06</li></ol>',
    guideMacosChrome: '<strong>\u5b89\u88dd\u70ba\u96e2\u7dda\u61c9\u7528\uff1a</strong><ol><li>\u5728 <strong>Chrome</strong> \u4e2d\u958b\u555f\u6b64\u9801\u9762</li><li>\u9ede\u64ca\u7db2\u5740\u5217\u4e2d\u7684 <strong>install icon</strong>\uff08\u6216\u4e09\u9ede\u9078\u55ae &rarr; \u201cInstall BitClutch Signer\u201d\uff09</li><li>\u9ede\u64ca <strong>\u201cInstall\u201d</strong></li></ol><strong>\u505c\u7528\u7db2\u8def\uff1a</strong><ol><li>\u9ede\u64ca\u9078\u55ae\u5217\u4e2d\u7684 <strong>Wi-Fi icon</strong></li><li>\u9ede\u64ca<strong>\u95dc\u9589Wi-Fi</strong></li><li>\u62d4\u6389\u6240\u6709\u4e59\u592a\u7db2\u8def\u7dda\u7f06</li></ol>',
    guideWindowsChrome: '<strong>\u5b89\u88dd\u70ba\u96e2\u7dda\u61c9\u7528\uff1a</strong><ol><li>\u5728 <strong>Chrome</strong> \u4e2d\u958b\u555f\u6b64\u9801\u9762</li><li>\u9ede\u64ca\u7db2\u5740\u5217\u4e2d\u7684 <strong>install icon</strong>\uff08\u6216\u4e09\u9ede\u9078\u55ae &rarr; \u201cInstall BitClutch Signer\u201d\uff09</li><li>\u9ede\u64ca <strong>\u201cInstall\u201d</strong></li></ol><strong>\u505c\u7528\u7db2\u8def\uff1a</strong><ol><li>\u9ede\u64ca\u5de5\u4f5c\u5217\uff08\u53f3\u4e0b\u89d2\uff09\u4e2d\u7684 <strong>Wi-Fi icon</strong></li><li>\u9ede\u64ca<strong>\u4e2d\u65b7Wi-Fi\u9023\u7dda</strong></li><li>\u62d4\u6389\u6240\u6709\u4e59\u592a\u7db2\u8def\u7dda\u7f06</li></ol>',
    guideWindowsEdge: '<strong>\u5b89\u88dd\u70ba\u96e2\u7dda\u61c9\u7528\uff1a</strong><ol><li>\u5728 <strong>Edge</strong> \u4e2d\u958b\u555f\u6b64\u9801\u9762</li><li>\u9ede\u64ca\u7db2\u5740\u5217\u4e2d\u7684 <strong>install icon</strong>\uff08\u6216\u4e09\u9ede\u9078\u55ae &rarr; \u201c\u61c9\u7528\u7a0b\u5f0f\u201d &rarr; \u201cInstall BitClutch Signer\u201d\uff09</li><li>\u9ede\u64ca <strong>\u201cInstall\u201d</strong></li></ol><strong>\u505c\u7528\u7db2\u8def\uff1a</strong><ol><li>\u9ede\u64ca\u5de5\u4f5c\u5217\uff08\u53f3\u4e0b\u89d2\uff09\u4e2d\u7684 <strong>Wi-Fi icon</strong></li><li>\u9ede\u64ca<strong>\u4e2d\u65b7Wi-Fi\u9023\u7dda</strong></li><li>\u62d4\u6389\u6240\u6709\u4e59\u592a\u7db2\u8def\u7dda\u7f06</li></ol>',
    accountXpubTitle: '\u5e33\u6236xpub',
    noMnemonic: '\u7121\u53ef\u7528\u52a9\u8a18\u8a5e\u3002', noTxData: '\u7121\u4ea4\u6613\u8cc7\u6599\u3002', noSignedData: '\u7121\u7c3d\u540d\u8cc7\u6599\u3002',
    noBmsRequest: '\u7121BMS\u8acb\u6c42\u3002', noSignature: '\u7121\u7c3d\u540d\u3002', loading: '\u8f09\u5165\u4e2d...',
    bannerWarn: '\u5075\u6e2c\u5230\u7db2\u8def \u2014 \u7522\u751f\u91d1\u9470\u524d\u8acb\u65b7\u958b\u6240\u6709\u7db2\u8def\u3002',
    bannerOnline: '\u7db2\u8def\u5df2\u9023\u63a5 \u2014 \u7acb\u5373\u65b7\u958b\uff0c\u4e26\u4e14\u7d55\u5c0d\u4e0d\u8981\u518d\u6b21\u9023\u63a5\u6b64\u8a2d\u5099\u3002\u91d1\u9470\u53ef\u80fd\u5df2\u7d93\u6d29\u9732\u3002',
    bannerOffline: '\u672a\u5075\u6e2c\u5230\u7121\u7dda\u7db2\u8def\u3002\u8acb\u78ba\u8a8d\u85cd\u7259\u3001NFC\u548cUSB\u6578\u64da\u7dda\u4e5f\u5df2\u65b7\u958b\u3002',
  },
  tr: {
    unlocked: 'Kilit a\u00e7\u0131k', locked: 'Kilitli',
    tabKey: 'Anahtar', tabSign: '\u0130mzala', tabSettings: 'Ayarlar',
    createKeys: 'Anahtar\u0131n\u0131 olu\u015ftur',
    setupDesc: 'Fiziksel entropi ile yeni bir anahtar olu\u015fturun,<br>veya mevcut bir tohum ifadesi i\u00e7e aktar\u0131n.',
    diceBtn: 'Zar (99 at\u0131\u015f)', coinBtn: 'Yaz\u0131-Tura (256 at\u0131\u015f)', importBtn: 'Tohum ifadesi i\u00e7e aktar',
    enterPassphrase: 'Kilidi a\u00e7mak i\u00e7in parola girin', passphrase: 'Parola', unlock: 'Kilidi a\u00e7', wrongPassphrase: 'Yanl\u0131\u015f parola.',
    yourKey: 'Anahtar\u0131n\u0131z', network: 'A\u011f', fingerprint: 'Parmak izi', keyCreated: 'Olu\u015fturulma', lastOnline: 'Son \u00e7evrim.', neverOnline: 'Hi\u00e7 (g\u00fcvenli)', onlineAfterKey: 'Olu\u015fturmadan sonra \u00e7evrimi\u00e7i tespit', accountXpub: 'Hesap xpub',
    showXpubQR: 'xpub QR g\u00f6ster', lockBtn: 'Kilitle', mainnet: 'Ana a\u011f', testnet: 'Test a\u011f\u0131',
    diceTitle: 'Zar ile anahtar \u00fcretimi', diceDesc: 'Ger\u00e7ek bir zar at\u0131n ve sonuca dokunun.',
    progress: '\u0130lerleme', undoLast: 'Geri al', cancel: '\u0130ptal', ok: 'Tamam',
    coinTitle: 'Yaz\u0131-tura ile anahtar \u00fcretimi', coinDesc: 'Ger\u00e7ek bir madeni para at\u0131n ve sonuca dokunun.',
    entropyWarning: 'Ger\u00e7ek zar/madeni para kullan\u0131n \u2014 asla say\u0131 uydurmay\u0131n. \u0130nsan se\u00e7imleri tahmin edilebilir ve anahtar\u0131n\u0131z\u0131 zay\u0131flat\u0131r. Yak\u0131nda kamera veya mikrofon olmad\u0131\u011f\u0131ndan emin olun \u2014 at\u0131\u015flar\u0131n\u0131z\u0131 g\u00f6ren biri Bitcoin\u2019inizi \u00e7alabilir.',
    heads: 'H (Yaz\u0131)', tails: 'T (Tura)',
    writeDown: 'Bu kelimeleri yaz\u0131n!',
    mnemonicDesc: 'Bu tohum ifadenizdir. \u00c7evrimd\u0131\u015f\u0131 g\u00fcvenle saklay\u0131n. Tekrar G\u00d6STER\u0130LMEYECEK.',
    stolenVsLost: '\u00c7al\u0131nm\u0131\u015f vs. Kaybolmu\u015f \u2014 fark\u0131 bilin',
    theft: 'H\u0131rs\u0131zl\u0131k:', theftDesc: 'Biri tohum ifadenizi bulursa, Bitcoin\u2019lerinizi anında \u00e7alabilir. Kimse bunu geri alamaz.',
    loss: 'Kay\u0131p:', lossDesc: 'Tohum ifadenizi kaybederseniz ve cihaz\u0131n\u0131z bozulursa, Bitcoin\u2019leriniz sonsuza dek kaybolur \u2014 bir kurtarma plan\u0131n\u0131z yoksa.',
    bitclutchPromo: '<strong>BitClutch</strong> kayba ve \u00f6l\u00fcme kar\u015f\u0131 korur, h\u0131rs\u0131zl\u0131\u011fa de\u011fil. Zaman kilidi ile bir <strong>Korumal\u0131 C\u00fczdan</strong> olu\u015fturun \u2014 Bitcoin\u2019leriniz sizin kal\u0131r, ancak miras\u00e7\u0131lar\u0131n\u0131z kurtarabilir.',
    visitBitclutch: 'Korumal\u0131 C\u00fczdan olu\u015fturmak i\u00e7in \u00e7evrimi\u00e7i bir cihazda <strong>bitclutch.app</strong> adresini ziyaret edin.',
    confirmedWritten: 'Yazd\u0131m',
    importTitle: 'Tohum ifadesi i\u00e7e aktar', importDesc: 'Kelime say\u0131s\u0131 ve dili se\u00e7in, sonra her kelimeyi girin.',
    importPlaceholder: 'kelime1 kelime2 kelime3 ...', importAction: '\u0130\u00e7e aktar', words: 'kelime',
    fillAllWords: 'L\u00fctfen t\u00fcm kelimeleri doldurun.', needWords: '12 veya 24 kelime gerekli', invalidMnemonic: 'Ge\u00e7ersiz an\u0131msat\u0131c\u0131',
    setPassTitle: 'Parola belirle', setPassDesc: '\u00d6zel anahtar\u0131n\u0131z\u0131 \u015fifrelemek i\u00e7in g\u00fc\u00e7l\u00fc bir parola se\u00e7in. Her kilidi a\u00e7t\u0131\u011f\u0131n\u0131zda gerekecek.',
    confirmPass: 'Parolay\u0131 onayla', enterPass: 'Parola girin',
    passRequired: 'Parola gereklidir.', passTooShort: 'Parola \u00e7ok k\u0131sa (min. 4 karakter).', passNoMatch: 'Parolalar e\u015fle\u015fmiyor.',
    noKeyToSave: 'Kaydedilecek anahtar yok. Ba\u015ftan ba\u015flay\u0131n.', encryptSave: '\u015eifrele ve kaydet', encryptFailed: '\u015eifreleme hatas\u0131: ',
    scanTitle: 'QR tara', scanDesc: 'Kameray\u0131 BitClutch uygulaman\u0131zdaki QR koduna y\u00f6nlendirin.',
    startingCamera: 'Kamera ba\u015flat\u0131l\u0131yor...', scanning: 'Taran\u0131yor... QR koduna y\u00f6nlendirin.', cameraError: 'Kamera hatas\u0131: ',
    receivingFountain: 'Fountain kodu al\u0131n\u0131yor...', urFailed: 'UR \u00e7\u00f6zme ba\u015far\u0131s\u0131z. Tekrar deneyin.', psbtParseError: 'PSBT ayr\u0131\u015ft\u0131rma hatas\u0131: ',
    confirmTx: '\u0130\u015flemi onayla', reviewBeforeSign: '\u0130mzalamadan \u00f6nce dikkatlice inceleyin.',
    inputs: 'Girdiler', output: '\u00c7\u0131kt\u0131', change: '(\u00fcst\u00fc)', fee: '\u00dccret', reject: 'Reddet', sign: '\u0130mzala', signingFailed: '\u0130mzalama hatas\u0131: ',
    signedPsbt: '\u0130mzal\u0131 PSBT', showQRDesc: '\u0130\u015flemi yay\u0131nlamak i\u00e7in BitClutch uygulaman\u0131z\u0131n bu QR kodunu taramas\u0131n\u0131 sa\u011flay\u0131n.', scanComplete: 'Tarama tamamland\u0131', scanSignatureDesc: '\u0130mzay\u0131 g\u00f6ndermek i\u00e7in BitClutch uygulaman\u0131z\u0131n bu QR kodunu taramas\u0131n\u0131 sa\u011flay\u0131n.',
    singleQR: 'Tek QR', fountainKeepShowing: 'fountain kodu \u2014 g\u00f6stermeye devam edin', frame: 'Kare',
    confirmBms: 'Mesaj imzalamay\u0131 onayla', reviewMessage: '\u0130mzalamadan \u00f6nce mesaj\u0131 inceleyin.',
    type: 'T\u00fcr', bmsType: 'BMS (Bitcoin Mesaj\u0131)', index: '\u0130ndeks', address: 'Adres', message: 'Mesaj',
    bmsSignature: 'BMS \u0130mzas\u0131', sigBase64: '\u0130mza (base64)', tapToCopy: 'Kopyalamak i\u00e7in dokun', copySig: '\u0130mzay\u0131 kopyala', sha256: 'SHA-256',
    settings: 'Ayarlar', version: 'S\u00fcr\u00fcm', language: 'Dil', seedLanguage: 'Tohum dili',
    onlineKeygenTitle: 'A\u011f ba\u011fl\u0131!',
    onlineKeygenBody: 'Cihaz\u0131n\u0131z internete ba\u011fl\u0131. \u00c7evrimi\u00e7i olu\u015fturulan anahtarlar zararl\u0131 yaz\u0131l\u0131m taraf\u0131ndan ele ge\u00e7irilebilir. Devam etmeden \u00f6nce T\u00dcM a\u011flar\u0131 (WiFi, h\u00fccresel, Bluetooth, USB) kesin.',
    proceedAnyway: 'Yine de devam et (g\u00fcvensiz)',
    installGuide: 'Kurulum k\u0131lavuzu', viewSource: 'Kaynak kodu b\u00fct\u00fcnl\u00fc\u011f\u00fcn\u00fc do\u011frula', securityInfo: 'G\u00fcvenlik bilgisi',
    deleteKey: 'Anahtar\u0131 sil', deleteConfirm1: 'Anahtar\u0131n\u0131z\u0131 silmek mi? Geri al\u0131namaz.\nTohum ifadenizi yedekledi\u011finizden emin olun!',
    deleteConfirm2: 'Kesinlikle emin misiniz? Yede\u011finiz yoksa Bitcoin\u2019leriniz KAYBOLACAK.',
    verifyIntegrity: 'B\u00fct\u00fcnl\u00fc\u011f\u00fc do\u011frula', verifyDesc: 'SHA-256 hash\u2019lerini GitHub\u2019daki resmi s\u00fcr\u00fcmle kar\u015f\u0131la\u015ft\u0131r\u0131n.',
    computing: 'Hesaplan\u0131yor...', fetchFailed: '(indirme ba\u015far\u0131s\u0131z)',
    verifyFile: 'Bu dosyay\u0131 do\u011frula', verifyFileDesc: 'Buraya dokunun ve indirdi\u011finiz <strong>bitclutch-signer.html</strong> dosyas\u0131n\u0131 se\u00e7in.<br>SHA-256 hash yerel olarak hesaplanacak.',
    tapToSelect: 'Se\u00e7mek i\u00e7in dokun', compareGithub: 'GitHub s\u00fcr\u00fcm\u00fcndeki <code>hashes.json</code> ile kar\u015f\u0131la\u015ft\u0131r\u0131n.',
    auditableSource: 'Denetlenebilir kaynak', auditableDesc: 'Bu uygulaman\u0131n t\u00fcm mant\u0131\u011f\u0131 tek bir denetlenebilir dosyadad\u0131r. Kaynak kodu ve resmi hash\u2019ler GitHub\u2019da yay\u0131nlanm\u0131\u015ft\u0131r.',
    back: 'Geri',
    securityTitle: 'G\u00fcvenlik bilgileri', securityLevel: 'G\u00fcvenlik seviyesi: Yaz\u0131l\u0131m hava bo\u015flu\u011fu',
    whatProvides: 'Sa\u011flad\u0131klar\u0131:', secProvide1: '\u00d6zel anahtar asla internete ba\u011flanmaz (kurulumdan sonra)',
    secProvide2: 'Kod denetlenebilir (tek app.js dosyas\u0131)', secProvide3: 'Yaln\u0131zca fiziksel kaynakl\u0131 entropi (zar/madeni para)',
    secProvide4: 'AES-256-GCM \u015fifreleme + 600K PBKDF2 iterasyon',
    whatNot: 'Sa\u011flamad\u0131klar\u0131:', secNot1: 'Secure Element (donan\u0131m c\u00fczdanlar\u0131nda var)',
    secNot2: 'Donan\u0131m d\u00fczeyinde hava bo\u015flu\u011fu (WiFi \u00e7ipi hala mevcut)', secNot3: 'Yan kanal sald\u0131r\u0131s\u0131 direnci',
    keyStorage: 'Anahtar depolama', encryption: '\u015eifreleme:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600.000 iterasyon) + rastgele tuz/IV',
    warning: 'Uyar\u0131:', clearDataWarning: 'Taray\u0131c\u0131 verilerini temizlemek \u015fifreli anahtar\u0131n\u0131z\u0131 kal\u0131c\u0131 olarak siler. Tohum ifadenizi her zaman \u00e7evrimd\u0131\u015f\u0131 yedekleyin.',
    autoLock: 'Otomatik kilit:', autoLockDesc: '5 dakika hareketsizlik sonras\u0131 anahtarlar bellekten silinir.',
    storageEncKey: '\u015eifreli \u00f6zel anahtar (AES-256-GCM)', storageXpub: 'Hesap geni\u015fletilmi\u015f genel anahtar', storageFp: 'BIP-32 parmak izi',
    storageNet: 'A\u011f ayar\u0131 (main/test)', storageLang: 'Aray\u00fcz dili', storageSeedLang: 'Tohum ifadesi dili', storageKeyCreated: 'Anahtar olu\u015fturma tarihi', storageLastOnline: 'A\u011f alg\u0131lama tarihi',
    guideTitle: 'Kurulum k\u0131lavuzu', guideDesc: 'BitClutch Signer\u2019\u0131 \u00e7evrimd\u0131\u015f\u0131 uygulama olarak kurun, kullanmadan \u00f6nce u\u00e7ak modunu etkinle\u015ftirin.',
    detected: 'Alg\u0131land\u0131',
    guideIosSafari: '<strong>\u00c7evrimd\u0131\u015f\u0131 uygulama olarak kurun:</strong><ol><li>Bu sayfay\u0131 <strong>Safari</strong> ile a\u00e7\u0131n</li><li><strong>Share</strong> d\u00fc\u011fmesine dokunun (oklu kutu)</li><li>A\u015fa\u011f\u0131 kayd\u0131r\u0131p <strong>\u201cAdd to Home Screen\u201d</strong> se\u00e7ene\u011fine dokunun</li><li>Sa\u011f \u00fcstteki <strong>\u201cAdd\u201d</strong> d\u00fc\u011fmesine dokunun</li></ol><strong>U\u00e7ak Modunu Etkinle\u015ftirin:</strong><ol><li>Sa\u011f \u00fcst k\u00f6\u015feden a\u015fa\u011f\u0131 kayd\u0131r\u0131n (eski iPhone\'larda alttan yukar\u0131)</li><li>Etkinle\u015ftirmek i\u00e7in <strong>u\u00e7ak simgesine</strong> dokunun</li><li>Wi-Fi ve Bluetooth\'un da KAPALI oldu\u011fundan emin olun</li></ol>',
    guideIosChrome: '<strong>\u00d6nemli:</strong> iOS\'taki Chrome \u00e7evrimd\u0131\u015f\u0131 uygulama kuramaz. Bunun yerine <strong>Safari</strong> kullan\u0131n.<ol><li>Bu sayfan\u0131n URL\'sini kopyalay\u0131n</li><li><strong>Safari</strong> a\u00e7\u0131p URL\'yi yap\u0131\u015ft\u0131r\u0131n</li><li>Yukar\u0131daki <strong>iOS Safari</strong> talimatlar\u0131n\u0131 izleyin</li></ol><strong>U\u00e7ak Modunu Etkinle\u015ftirin:</strong><ol><li>Sa\u011f \u00fcst k\u00f6\u015feden a\u015fa\u011f\u0131 kayd\u0131r\u0131n</li><li><strong>U\u00e7ak simgesine</strong> dokunun</li></ol>',
    guideAndroidChrome: '<strong>\u00c7evrimd\u0131\u015f\u0131 uygulama olarak kurun:</strong><ol><li>Bu sayfay\u0131 <strong>Chrome</strong> ile a\u00e7\u0131n</li><li>Sa\u011f \u00fcstteki <strong>\u00fc\u00e7 nokta men\u00fcs\u00fcne</strong> dokunun</li><li><strong>\u201cInstall app\u201d</strong> veya <strong>\u201cAdd to Home screen\u201d</strong> se\u00e7ene\u011fine dokunun</li><li><strong>\u201cInstall\u201d</strong> ile onaylay\u0131n</li></ol><strong>U\u00e7ak Modunu Etkinle\u015ftirin:</strong><ol><li>Ekran\u0131n \u00fcst\u00fcnden a\u015fa\u011f\u0131 kayd\u0131r\u0131n</li><li><strong>\u201cAirplane mode\u201d</strong> se\u00e7ene\u011fine dokunun</li><li>Wi-Fi ve mobil verinin KAPALI oldu\u011funu do\u011frulay\u0131n</li></ol>',
    guideAndroidSamsung: '<strong>\u00c7evrimd\u0131\u015f\u0131 uygulama olarak kurun:</strong><ol><li>Bu sayfay\u0131 <strong>Samsung Internet</strong> ile a\u00e7\u0131n</li><li>Sa\u011f alttaki <strong>men\u00fc simgesine</strong> dokunun (\u00fc\u00e7 \u00e7izgi)</li><li><strong>\u201cAdd page to\u201d</strong> ard\u0131ndan <strong>\u201cHome screen\u201d</strong> se\u00e7ene\u011fine dokunun</li></ol><strong>U\u00e7ak Modunu Etkinle\u015ftirin:</strong><ol><li>H\u0131zl\u0131 Ayarlar\u0131 a\u00e7mak i\u00e7in \u00fcstten iki kez a\u015fa\u011f\u0131 kayd\u0131r\u0131n</li><li><strong>\u201cAirplane mode\u201d</strong> se\u00e7ene\u011fine dokunun</li></ol>',
    guideMacosSafari: '<strong>\u00c7evrimd\u0131\u015f\u0131 uygulama olarak kurun (macOS Sonoma+):</strong><ol><li>Bu sayfay\u0131 <strong>Safari</strong> ile a\u00e7\u0131n</li><li><strong>File</strong> men\u00fcs\u00fcne, ard\u0131ndan <strong>\u201cAdd to Dock\u201d</strong> se\u00e7ene\u011fine t\u0131klay\u0131n</li><li><strong>\u201cAdd\u201d</strong> d\u00fc\u011fmesine t\u0131klay\u0131n</li></ol><strong>A\u011f\u0131 Devre D\u0131\u015f\u0131 B\u0131rak\u0131n:</strong><ol><li>Men\u00fc \u00e7ubu\u011fundaki <strong>Wi-Fi icon</strong> simgesine t\u0131klay\u0131n</li><li><strong>Wi-Fi\'yi kapatmak</strong> i\u00e7in t\u0131klay\u0131n</li><li>T\u00fcm Ethernet kablolar\u0131n\u0131 \u00e7\u0131kar\u0131n</li></ol>',
    guideMacosChrome: '<strong>\u00c7evrimd\u0131\u015f\u0131 uygulama olarak kurun:</strong><ol><li>Bu sayfay\u0131 <strong>Chrome</strong> ile a\u00e7\u0131n</li><li>Adres \u00e7ubu\u011fundaki <strong>install icon</strong> simgesine t\u0131klay\u0131n (veya \u00fc\u00e7 nokta men\u00fcs\u00fc &rarr; \u201cInstall BitClutch Signer\u201d)</li><li><strong>\u201cInstall\u201d</strong> d\u00fc\u011fmesine t\u0131klay\u0131n</li></ol><strong>A\u011f\u0131 Devre D\u0131\u015f\u0131 B\u0131rak\u0131n:</strong><ol><li>Men\u00fc \u00e7ubu\u011fundaki <strong>Wi-Fi icon</strong> simgesine t\u0131klay\u0131n</li><li><strong>Wi-Fi\'yi kapatmak</strong> i\u00e7in t\u0131klay\u0131n</li><li>T\u00fcm Ethernet kablolar\u0131n\u0131 \u00e7\u0131kar\u0131n</li></ol>',
    guideWindowsChrome: '<strong>\u00c7evrimd\u0131\u015f\u0131 uygulama olarak kurun:</strong><ol><li>Bu sayfay\u0131 <strong>Chrome</strong> ile a\u00e7\u0131n</li><li>Adres \u00e7ubu\u011fundaki <strong>install icon</strong> simgesine t\u0131klay\u0131n (veya \u00fc\u00e7 nokta men\u00fcs\u00fc &rarr; \u201cInstall BitClutch Signer\u201d)</li><li><strong>\u201cInstall\u201d</strong> d\u00fc\u011fmesine t\u0131klay\u0131n</li></ol><strong>A\u011f\u0131 Devre D\u0131\u015f\u0131 B\u0131rak\u0131n:</strong><ol><li>G\u00f6rev \u00e7ubu\u011fundaki (sa\u011f alt) <strong>Wi-Fi icon</strong> simgesine t\u0131klay\u0131n</li><li><strong>Wi-Fi ba\u011flant\u0131s\u0131n\u0131 kesmek</strong> i\u00e7in t\u0131klay\u0131n</li><li>T\u00fcm Ethernet kablolar\u0131n\u0131 \u00e7\u0131kar\u0131n</li></ol>',
    guideWindowsEdge: '<strong>\u00c7evrimd\u0131\u015f\u0131 uygulama olarak kurun:</strong><ol><li>Bu sayfay\u0131 <strong>Edge</strong> ile a\u00e7\u0131n</li><li>Adres \u00e7ubu\u011fundaki <strong>install icon</strong> simgesine t\u0131klay\u0131n (veya \u00fc\u00e7 nokta men\u00fcs\u00fc &rarr; \u201cUygulamalar\u201d &rarr; \u201cInstall BitClutch Signer\u201d)</li><li><strong>\u201cInstall\u201d</strong> d\u00fc\u011fmesine t\u0131klay\u0131n</li></ol><strong>A\u011f\u0131 Devre D\u0131\u015f\u0131 B\u0131rak\u0131n:</strong><ol><li>G\u00f6rev \u00e7ubu\u011fundaki (sa\u011f alt) <strong>Wi-Fi icon</strong> simgesine t\u0131klay\u0131n</li><li><strong>Wi-Fi ba\u011flant\u0131s\u0131n\u0131 kesmek</strong> i\u00e7in t\u0131klay\u0131n</li><li>T\u00fcm Ethernet kablolar\u0131n\u0131 \u00e7\u0131kar\u0131n</li></ol>',
    accountXpubTitle: 'Hesap xpub',
    noMnemonic: 'An\u0131msat\u0131c\u0131 yok.', noTxData: '\u0130\u015flem verisi yok.', noSignedData: '\u0130mzal\u0131 veri yok.',
    noBmsRequest: 'BMS iste\u011fi yok.', noSignature: '\u0130mza yok.', loading: 'Y\u00fckleniyor...',
    bannerWarn: 'A\u011e ALGILANDI \u2014 Anahtar olu\u015fturmadan \u00f6nce t\u00fcm a\u011flar\u0131 kesin.',
    bannerOnline: 'A\u011e BA\u011eLANTISI VAR \u2014 Hemen kesin ve bu cihaz\u0131 ASLA tekrar ba\u011flamay\u0131n. Anahtarlar zaten a\u00e7\u0131\u011fa \u00e7\u0131km\u0131\u015f olabilir.',
    bannerOffline: 'Kablosuz a\u011f alg\u0131lanmad\u0131. Bluetooth, NFC ve USB veri kablolar\u0131n\u0131n da ba\u011fl\u0131 olmad\u0131\u011f\u0131n\u0131 do\u011frulay\u0131n.',
  },
  it: {
    unlocked: 'Sbloccato', locked: 'Bloccato',
    tabKey: 'Chiave', tabSign: 'Firma', tabSettings: 'Impostazioni',
    createKeys: 'Crea la tua chiave',
    setupDesc: 'Genera una nuova chiave con entropia fisica,<br>o importa una frase seme esistente.',
    diceBtn: 'Dado (99 lanci)', coinBtn: 'Moneta (256 lanci)', importBtn: 'Importa frase seme',
    enterPassphrase: 'Inserisci la password per sbloccare', passphrase: 'Password', unlock: 'Sblocca', wrongPassphrase: 'Password errata.',
    yourKey: 'La tua chiave', network: 'Rete', fingerprint: 'Impronta', keyCreated: 'Creata il', lastOnline: 'Ult. online', neverOnline: 'Mai (sicuro)', onlineAfterKey: 'Online rilevato dopo creazione', accountXpub: 'xpub account',
    showXpubQR: 'Mostra QR xpub', lockBtn: 'Blocca', mainnet: 'Mainnet', testnet: 'Testnet',
    diceTitle: 'Generazione con dado', diceDesc: 'Lancia un dado fisico reale e tocca il risultato.',
    progress: 'Progresso', undoLast: 'Annulla', cancel: 'Annulla', ok: 'OK',
    coinTitle: 'Generazione con moneta', coinDesc: 'Lancia una moneta fisica reale e tocca il risultato.',
    entropyWarning: 'Usa un dado/moneta fisico reale \u2014 non inventare mai numeri. Le scelte umane sono prevedibili e indeboliscono la chiave. Nessuna telecamera o microfono nelle vicinanze \u2014 chi vede i tuoi lanci pu\u00f2 rubare i tuoi Bitcoin.',
    heads: 'H (Testa)', tails: 'T (Croce)',
    writeDown: 'Scrivi queste parole!',
    mnemonicDesc: 'Questa \u00e8 la tua frase seme. Conservala offline in modo sicuro. NON verr\u00e0 mostrata di nuovo.',
    stolenVsLost: 'Rubato vs. Perso \u2014 conosci la differenza',
    theft: 'Furto:', theftDesc: 'Se qualcuno trova la tua frase seme, pu\u00f2 rubare i tuoi Bitcoin immediatamente. Nessuno pu\u00f2 annullarlo.',
    loss: 'Perdita:', lossDesc: 'Se perdi la frase seme e il dispositivo si rompe, i tuoi Bitcoin sono persi per sempre \u2014 a meno che tu non abbia un piano di recupero.',
    bitclutchPromo: '<strong>BitClutch</strong> protegge da perdita e decesso, non dal furto. Crea un <strong>Portafoglio Protetto</strong> con timelock \u2014 i tuoi Bitcoin restano tuoi, ma i tuoi eredi possono recuperarli.',
    visitBitclutch: 'Visita <strong>bitclutch.app</strong> su un dispositivo online per creare un Portafoglio Protetto.',
    confirmedWritten: 'Ho scritto tutto',
    importTitle: 'Importa frase seme', importDesc: 'Seleziona il numero di parole e la lingua, poi inserisci ogni parola.',
    importPlaceholder: 'parola1 parola2 parola3 ...', importAction: 'Importa', words: 'parole',
    fillAllWords: 'Compila tutte le parole.', needWords: 'Servono 12 o 24 parole', invalidMnemonic: 'Mnemonico non valido',
    setPassTitle: 'Imposta password', setPassDesc: 'Scegli una password forte per cifrare la tua chiave privata. Sar\u00e0 necessaria ad ogni sblocco.',
    confirmPass: 'Conferma password', enterPass: 'Inserisci password',
    passRequired: 'Password obbligatoria.', passTooShort: 'Password troppo corta (min. 4 caratteri).', passNoMatch: 'Le password non corrispondono.',
    noKeyToSave: 'Nessuna chiave da salvare. Ricomincia.', encryptSave: 'Cifra e salva', encryptFailed: 'Cifratura fallita: ',
    scanTitle: 'Scansiona QR', scanDesc: 'Punta la fotocamera sul QR della tua app BitClutch.',
    startingCamera: 'Avvio fotocamera...', scanning: 'Scansione... Punta sul QR.', cameraError: 'Errore fotocamera: ',
    receivingFountain: 'Ricezione codice fountain...', urFailed: 'Decodifica UR fallita. Riprova.', psbtParseError: 'Errore analisi PSBT: ',
    confirmTx: 'Conferma transazione', reviewBeforeSign: 'Controlla attentamente prima di firmare.',
    inputs: 'Input', output: 'Output', change: '(resto)', fee: 'Commissione', reject: 'Rifiuta', sign: 'Firma', signingFailed: 'Firma fallita: ',
    signedPsbt: 'PSBT firmato', showQRDesc: 'Lascia che la tua app BitClutch scansioni questo QR per trasmettere la transazione.', scanComplete: 'Scansione completata', scanSignatureDesc: 'Lascia che la tua app BitClutch scansioni questo QR per inviare la firma.',
    singleQR: 'QR singolo', fountainKeepShowing: 'codice fountain \u2014 continua a mostrare', frame: 'Fotogramma',
    confirmBms: 'Conferma firma messaggio', reviewMessage: 'Controlla il messaggio prima di firmare.',
    type: 'Tipo', bmsType: 'BMS (Messaggio Bitcoin)', index: 'Indice', address: 'Indirizzo', message: 'Messaggio',
    bmsSignature: 'Firma BMS', sigBase64: 'Firma (base64)', tapToCopy: 'Tocca per copiare', copySig: 'Copia firma', sha256: 'SHA-256',
    settings: 'Impostazioni', version: 'Versione', language: 'Lingua', seedLanguage: 'Lingua seme',
    onlineKeygenTitle: 'Rete connessa!',
    onlineKeygenBody: 'Il tuo dispositivo \u00e8 connesso a Internet. Le chiavi generate online possono essere intercettate da malware. Disconnetti TUTTE le reti (WiFi, cellulare, Bluetooth, USB) prima di continuare.',
    proceedAnyway: 'Continua comunque (non sicuro)',
    installGuide: 'Guida installazione', viewSource: 'Verifica integrit\u00e0 del codice', securityInfo: 'Info sicurezza',
    deleteKey: 'Elimina chiave', deleteConfirm1: 'Eliminare la chiave? Non pu\u00f2 essere annullato.\nAssicurati di avere la frase seme salvata!',
    deleteConfirm2: 'Sei assolutamente sicuro? I tuoi Bitcoin saranno PERSI senza backup.',
    verifyIntegrity: 'Verifica integrit\u00e0', verifyDesc: 'Confronta gli hash SHA-256 con la versione ufficiale su GitHub.',
    computing: 'Calcolo...', fetchFailed: '(download fallito)',
    verifyFile: 'Verifica questo file', verifyFileDesc: 'Tocca qui e seleziona il file <strong>bitclutch-signer.html</strong> scaricato.<br>L\u2019hash SHA-256 sar\u00e0 calcolato localmente.',
    tapToSelect: 'Tocca per selezionare', compareGithub: 'Confronta con <code>hashes.json</code> dalla versione GitHub.',
    auditableSource: 'Codice verificabile', auditableDesc: 'Tutta la logica di questa app \u00e8 in un unico file verificabile. Codice sorgente e hash ufficiali sono pubblicati su GitHub.',
    back: 'Indietro',
    securityTitle: 'Informazioni di sicurezza', securityLevel: 'Livello di sicurezza: Air-gap software',
    whatProvides: 'Cosa fornisce:', secProvide1: 'La chiave privata non tocca mai internet (dopo la configurazione)',
    secProvide2: 'Codice verificabile (singolo file app.js)', secProvide3: 'Entropia solo da fonti fisiche (dadi/monete)',
    secProvide4: 'Cifratura AES-256-GCM con 600K iterazioni PBKDF2',
    whatNot: 'Cosa NON fornisce:', secNot1: 'Secure Element (i portafogli hardware ce l\u2019hanno)',
    secNot2: 'Air gap hardware (il chip WiFi esiste ancora)', secNot3: 'Resistenza agli attacchi side-channel',
    keyStorage: 'Archiviazione chiavi', encryption: 'Cifratura:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600.000 iterazioni) + salt/IV casuale',
    warning: 'Attenzione:', clearDataWarning: 'Cancellare i dati del browser eliminer\u00e0 permanentemente la chiave cifrata. Conserva sempre la frase seme offline.',
    autoLock: 'Blocco automatico:', autoLockDesc: 'Le chiavi vengono cancellate dalla memoria dopo 5 minuti di inattivit\u00e0.',
    storageEncKey: 'Chiave privata cifrata (AES-256-GCM)', storageXpub: 'Chiave pubblica estesa account', storageFp: 'Impronta BIP-32',
    storageNet: 'Impostazione rete (main/test)', storageLang: 'Lingua interfaccia', storageSeedLang: 'Lingua frase seme', storageKeyCreated: 'Data creazione chiave', storageLastOnline: 'Data rilevamento rete',
    guideTitle: 'Guida installazione', guideDesc: 'Installa BitClutch Signer come app offline, poi attiva la modalit\u00e0 aereo prima dell\u2019uso.',
    detected: 'Rilevato',
    guideIosSafari: '<strong>Installa come app offline:</strong><ol><li>Apri questa pagina in <strong>Safari</strong></li><li>Tocca il pulsante <strong>Share</strong> (riquadro con freccia)</li><li>Scorri verso il basso e tocca <strong>\u201cAdd to Home Screen\u201d</strong></li><li>Tocca <strong>\u201cAdd\u201d</strong> in alto a destra</li></ol><strong>Attiva la Modalit\u00e0 Aereo:</strong><ol><li>Scorri verso il basso dall\'angolo in alto a destra (o verso l\'alto dal basso sui vecchi iPhone)</li><li>Tocca l\'<strong>icona dell\'aereo</strong> per attivare</li><li>Assicurati che Wi-Fi e Bluetooth siano anch\'essi SPENTI</li></ol>',
    guideIosChrome: '<strong>Importante:</strong> Chrome su iOS non pu\u00f2 installare app offline. Usa <strong>Safari</strong> invece.<ol><li>Copia l\'URL di questa pagina</li><li>Apri <strong>Safari</strong> e incolla l\'URL</li><li>Segui le istruzioni <strong>iOS Safari</strong> sopra</li></ol><strong>Attiva la Modalit\u00e0 Aereo:</strong><ol><li>Scorri verso il basso dall\'angolo in alto a destra</li><li>Tocca l\'<strong>icona dell\'aereo</strong></li></ol>',
    guideAndroidChrome: '<strong>Installa come app offline:</strong><ol><li>Apri questa pagina in <strong>Chrome</strong></li><li>Tocca il <strong>menu a tre punti</strong> (in alto a destra)</li><li>Tocca <strong>\u201cInstall app\u201d</strong> o <strong>\u201cAdd to Home screen\u201d</strong></li><li>Conferma toccando <strong>\u201cInstall\u201d</strong></li></ol><strong>Attiva la Modalit\u00e0 Aereo:</strong><ol><li>Scorri verso il basso dalla parte superiore dello schermo</li><li>Tocca <strong>\u201cAirplane mode\u201d</strong></li><li>Verifica che Wi-Fi e dati mobili siano SPENTI</li></ol>',
    guideAndroidSamsung: '<strong>Installa come app offline:</strong><ol><li>Apri questa pagina in <strong>Samsung Internet</strong></li><li>Tocca l\'<strong>icona del menu</strong> (tre linee, in basso a destra)</li><li>Tocca <strong>\u201cAdd page to\u201d</strong> poi <strong>\u201cHome screen\u201d</strong></li></ol><strong>Attiva la Modalit\u00e0 Aereo:</strong><ol><li>Scorri verso il basso due volte dalla parte superiore per aprire le Impostazioni Rapide</li><li>Tocca <strong>\u201cAirplane mode\u201d</strong></li></ol>',
    guideMacosSafari: '<strong>Installa come app offline (macOS Sonoma+):</strong><ol><li>Apri questa pagina in <strong>Safari</strong></li><li>Clicca sul menu <strong>File</strong> poi su <strong>\u201cAdd to Dock\u201d</strong></li><li>Clicca su <strong>\u201cAdd\u201d</strong></li></ol><strong>Disattiva la Rete:</strong><ol><li>Clicca sull\'<strong>icona Wi-Fi</strong> nella barra dei menu</li><li>Clicca per <strong>disattivare il Wi-Fi</strong></li><li>Scollega tutti i cavi Ethernet</li></ol>',
    guideMacosChrome: '<strong>Installa come app offline:</strong><ol><li>Apri questa pagina in <strong>Chrome</strong></li><li>Clicca sull\'<strong>install icon</strong> nella barra degli indirizzi (o menu a tre punti &rarr; \u201cInstall BitClutch Signer\u201d)</li><li>Clicca su <strong>\u201cInstall\u201d</strong></li></ol><strong>Disattiva la Rete:</strong><ol><li>Clicca sull\'<strong>icona Wi-Fi</strong> nella barra dei menu</li><li>Clicca per <strong>disattivare il Wi-Fi</strong></li><li>Scollega tutti i cavi Ethernet</li></ol>',
    guideWindowsChrome: '<strong>Installa come app offline:</strong><ol><li>Apri questa pagina in <strong>Chrome</strong></li><li>Clicca sull\'<strong>install icon</strong> nella barra degli indirizzi (o menu a tre punti &rarr; \u201cInstall BitClutch Signer\u201d)</li><li>Clicca su <strong>\u201cInstall\u201d</strong></li></ol><strong>Disattiva la Rete:</strong><ol><li>Clicca sull\'<strong>icona Wi-Fi</strong> nella barra delle applicazioni (in basso a destra)</li><li>Clicca per <strong>disconnettere il Wi-Fi</strong></li><li>Scollega tutti i cavi Ethernet</li></ol>',
    guideWindowsEdge: '<strong>Installa come app offline:</strong><ol><li>Apri questa pagina in <strong>Edge</strong></li><li>Clicca sull\'<strong>install icon</strong> nella barra degli indirizzi (o menu a tre punti &rarr; \u201cApp\u201d &rarr; \u201cInstall BitClutch Signer\u201d)</li><li>Clicca su <strong>\u201cInstall\u201d</strong></li></ol><strong>Disattiva la Rete:</strong><ol><li>Clicca sull\'<strong>icona Wi-Fi</strong> nella barra delle applicazioni (in basso a destra)</li><li>Clicca per <strong>disconnettere il Wi-Fi</strong></li><li>Scollega tutti i cavi Ethernet</li></ol>',
    accountXpubTitle: 'xpub account',
    noMnemonic: 'Nessun mnemonico disponibile.', noTxData: 'Nessun dato transazione.', noSignedData: 'Nessun dato firmato.',
    noBmsRequest: 'Nessuna richiesta BMS.', noSignature: 'Nessuna firma.', loading: 'Caricamento...',
    bannerWarn: 'RETE RILEVATA \u2014 Disconnetti tutte le reti prima di generare le chiavi.',
    bannerOnline: 'RETE CONNESSA \u2014 Disconnetti ORA e non riconnettere MAI questo dispositivo. Le chiavi potrebbero essere gi\u00e0 esposte.',
    bannerOffline: 'Nessuna rete wireless rilevata. Verificare che Bluetooth, NFC e cavi USB dati siano anch\u2019essi scollegati.',
  },
  vi: {
    unlocked: '\u0110\u00e3 m\u1edf kh\u00f3a', locked: '\u0110\u00e3 kh\u00f3a',
    tabKey: 'Kh\u00f3a', tabSign: 'K\u00fd', tabSettings: 'C\u00e0i \u0111\u1eb7t',
    createKeys: 'T\u1ea1o kh\u00f3a c\u1ee7a b\u1ea1n',
    setupDesc: 'T\u1ea1o kh\u00f3a m\u1edbi b\u1eb1ng entropy v\u1eadt l\u00fd,<br>ho\u1eb7c nh\u1eadp c\u1ee5m t\u1eeb kh\u00f4i ph\u1ee5c hi\u1ec7n c\u00f3.',
    diceBtn: 'X\u00fac x\u1eafc (99 l\u1ea7n)', coinBtn: 'T\u1ea1ng \u0111\u1ed3ng xu (256 l\u1ea7n)', importBtn: 'Nh\u1eadp c\u1ee5m t\u1eeb kh\u00f4i ph\u1ee5c',
    enterPassphrase: 'Nh\u1eadp m\u1eadt kh\u1ea9u \u0111\u1ec3 m\u1edf kh\u00f3a', passphrase: 'M\u1eadt kh\u1ea9u', unlock: 'M\u1edf kh\u00f3a', wrongPassphrase: 'Sai m\u1eadt kh\u1ea9u.',
    yourKey: 'Kh\u00f3a c\u1ee7a b\u1ea1n', network: 'M\u1ea1ng', fingerprint: 'V\u00e2n tay', keyCreated: 'Ng\u00e0y t\u1ea1o', lastOnline: 'L\u1ea7n cu\u1ed1i', neverOnline: 'Ch\u01b0a (an to\u00e0n)', onlineAfterKey: 'Ph\u00e1t hi\u1ec7n tr\u1ef1c tuy\u1ebfn sau t\u1ea1o kh\u00f3a', accountXpub: 'xpub t\u00e0i kho\u1ea3n',
    showXpubQR: 'Hi\u1ec3n QR xpub', lockBtn: 'Kh\u00f3a', mainnet: 'Mainnet', testnet: 'Testnet',
    diceTitle: 'T\u1ea1o kh\u00f3a b\u1eb1ng x\u00fac x\u1eafc', diceDesc: 'Tung x\u00fac x\u1eafc th\u1eadt v\u00e0 ch\u1ea1m k\u1ebft qu\u1ea3.',
    progress: 'Ti\u1ebfn \u0111\u1ed9', undoLast: 'Ho\u00e0n t\u00e1c', cancel: 'H\u1ee7y', ok: 'OK',
    coinTitle: 'T\u1ea1o kh\u00f3a b\u1eb1ng \u0111\u1ed3ng xu', coinDesc: 'Tung \u0111\u1ed3ng xu th\u1eadt v\u00e0 ch\u1ea1m k\u1ebft qu\u1ea3.',
    entropyWarning: 'D\u00f9ng x\u00fac x\u1eafc/\u0111\u1ed3ng xu th\u1eadt \u2014 \u0111\u1eebng bao gi\u1edd t\u1ef1 ngh\u0129 ra s\u1ed1. L\u1ef1a ch\u1ecdn c\u1ee7a con ng\u01b0\u1eddi d\u1ec5 \u0111o\u00e1n v\u00e0 l\u00e0m y\u1ebfu kh\u00f3a. Kh\u00f4ng camera hay micro g\u1ea7n \u0111\u00e2y \u2014 ai th\u1ea5y k\u1ebft qu\u1ea3 tung c\u00f3 th\u1ec3 \u0111\u00e1nh c\u1eafp Bitcoin c\u1ee7a b\u1ea1n.',
    heads: 'H (\u1ea4p)', tails: 'T (Ng\u1eeda)',
    writeDown: 'H\u00e3y ghi l\u1ea1i c\u00e1c t\u1eeb n\u00e0y!',
    mnemonicDesc: '\u0110\u00e2y l\u00e0 c\u1ee5m t\u1eeb kh\u00f4i ph\u1ee5c c\u1ee7a b\u1ea1n. L\u01b0u tr\u1eef an to\u00e0n ngo\u1ea1i tuy\u1ebfn. S\u1ebd KH\u00d4NG hi\u1ec3n l\u1ea1i.',
    stolenVsLost: 'B\u1ecb \u0111\u00e1nh c\u1eafp vs. B\u1ecb m\u1ea5t \u2014 bi\u1ebft s\u1ef1 kh\u00e1c bi\u1ec7t',
    theft: 'Tr\u1ed9m c\u1eafp:', theftDesc: 'N\u1ebfu ai \u0111\u00f3 t\u00ecm th\u1ea5y c\u1ee5m t\u1eeb c\u1ee7a b\u1ea1n, h\u1ecd c\u00f3 th\u1ec3 \u0111\u00e1nh c\u1eafp Bitcoin ngay l\u1eadp t\u1ee9c. Kh\u00f4ng ai c\u00f3 th\u1ec3 ho\u00e0n t\u00e1c.',
    loss: 'M\u1ea5t:', lossDesc: 'N\u1ebfu b\u1ea1n m\u1ea5t c\u1ee5m t\u1eeb v\u00e0 thi\u1ebft b\u1ecb h\u1ecfng, Bitcoin c\u1ee7a b\u1ea1n m\u1ea5t v\u0129nh vi\u1ec5n \u2014 tr\u1eeb khi c\u00f3 k\u1ebf ho\u1ea1ch kh\u00f4i ph\u1ee5c.',
    bitclutchPromo: '<strong>BitClutch</strong> b\u1ea3o v\u1ec7 kh\u1ecfi m\u1ea5t m\u00e1t v\u00e0 t\u1eed vong, kh\u00f4ng ph\u1ea3i tr\u1ed9m c\u1eafp. T\u1ea1o <strong>V\u00ed B\u1ea3o v\u1ec7</strong> v\u1edbi timelock \u2014 Bitcoin v\u1eabn l\u00e0 c\u1ee7a b\u1ea1n, nh\u01b0ng ng\u01b0\u1eddi th\u1eeba k\u1ebf c\u00f3 th\u1ec3 kh\u00f4i ph\u1ee5c.',
    visitBitclutch: 'Truy c\u1eadp <strong>bitclutch.app</strong> tr\u00ean thi\u1ebft b\u1ecb tr\u1ef1c tuy\u1ebfn \u0111\u1ec3 t\u1ea1o V\u00ed B\u1ea3o v\u1ec7.',
    confirmedWritten: '\u0110\u00e3 ghi l\u1ea1i',
    importTitle: 'Nh\u1eadp c\u1ee5m t\u1eeb kh\u00f4i ph\u1ee5c', importDesc: 'Ch\u1ecdn s\u1ed1 t\u1eeb v\u00e0 ng\u00f4n ng\u1eef, sau \u0111\u00f3 nh\u1eadp t\u1eebng t\u1eeb.',
    importPlaceholder: 't\u1eeb1 t\u1eeb2 t\u1eeb3 ...', importAction: 'Nh\u1eadp', words: 't\u1eeb',
    fillAllWords: 'Vui l\u00f2ng \u0111i\u1ec1n \u0111\u1ee7 c\u00e1c t\u1eeb.', needWords: 'C\u1ea7n 12 ho\u1eb7c 24 t\u1eeb', invalidMnemonic: 'Mnemonic kh\u00f4ng h\u1ee3p l\u1ec7',
    setPassTitle: '\u0110\u1eb7t m\u1eadt kh\u1ea9u', setPassDesc: 'Ch\u1ecdn m\u1eadt kh\u1ea9u m\u1ea1nh \u0111\u1ec3 m\u00e3 h\u00f3a kh\u00f3a ri\u00eang c\u1ee7a b\u1ea1n. C\u1ea7n thi\u1ebft m\u1ed7i l\u1ea7n m\u1edf kh\u00f3a.',
    confirmPass: 'X\u00e1c nh\u1eadn m\u1eadt kh\u1ea9u', enterPass: 'Nh\u1eadp m\u1eadt kh\u1ea9u',
    passRequired: 'B\u1eaft bu\u1ed9c nh\u1eadp m\u1eadt kh\u1ea9u.', passTooShort: 'M\u1eadt kh\u1ea9u qu\u00e1 ng\u1eafn (t\u1ed1i thi\u1ec3u 4 k\u00fd t\u1ef1).', passNoMatch: 'M\u1eadt kh\u1ea9u kh\u00f4ng kh\u1edbp.',
    noKeyToSave: 'Kh\u00f4ng c\u00f3 kh\u00f3a \u0111\u1ec3 l\u01b0u. B\u1eaft \u0111\u1ea7u l\u1ea1i.', encryptSave: 'M\u00e3 h\u00f3a v\u00e0 l\u01b0u', encryptFailed: 'M\u00e3 h\u00f3a th\u1ea5t b\u1ea1i: ',
    scanTitle: 'Qu\u00e9t QR', scanDesc: 'H\u01b0\u1edbng camera v\u00e0o m\u00e3 QR t\u1eeb \u1ee9ng d\u1ee5ng BitClutch.',
    startingCamera: '\u0110ang kh\u1edfi \u0111\u1ed9ng camera...', scanning: '\u0110ang qu\u00e9t... H\u01b0\u1edbng v\u00e0o m\u00e3 QR.', cameraError: 'L\u1ed7i camera: ',
    receivingFountain: '\u0110ang nh\u1eadn m\u00e3 fountain...', urFailed: 'Gi\u1ea3i m\u00e3 UR th\u1ea5t b\u1ea1i. Th\u1eed l\u1ea1i.', psbtParseError: 'L\u1ed7i ph\u00e2n t\u00edch PSBT: ',
    confirmTx: 'X\u00e1c nh\u1eadn giao d\u1ecbch', reviewBeforeSign: 'Ki\u1ec3m tra c\u1ea9n th\u1eadn tr\u01b0\u1edbc khi k\u00fd.',
    inputs: '\u0110\u1ea7u v\u00e0o', output: '\u0110\u1ea7u ra', change: '(ti\u1ec1n th\u1eeba)', fee: 'Ph\u00ed', reject: 'T\u1eeb ch\u1ed1i', sign: 'K\u00fd', signingFailed: 'K\u00fd th\u1ea5t b\u1ea1i: ',
    signedPsbt: 'PSBT \u0111\u00e3 k\u00fd', showQRDesc: '\u0110\u1ec3 \u1ee9ng d\u1ee5ng BitClutch qu\u00e9t m\u00e3 QR n\u00e0y \u0111\u1ec3 ph\u00e1t s\u00f3ng giao d\u1ecbch.', scanComplete: 'Qu\u00e9t ho\u00e0n t\u1ea5t', scanSignatureDesc: '\u0110\u1ec3 \u1ee9ng d\u1ee5ng BitClutch qu\u00e9t m\u00e3 QR n\u00e0y \u0111\u1ec3 g\u1eedi ch\u1eef k\u00fd.',
    singleQR: 'QR \u0111\u01a1n', fountainKeepShowing: 'm\u00e3 fountain \u2014 ti\u1ebfp t\u1ee5c hi\u1ec3n', frame: 'Khung h\u00ecnh',
    confirmBms: 'X\u00e1c nh\u1eadn k\u00fd tin nh\u1eafn', reviewMessage: 'Ki\u1ec3m tra tin nh\u1eafn tr\u01b0\u1edbc khi k\u00fd.',
    type: 'Lo\u1ea1i', bmsType: 'BMS (Tin nh\u1eafn Bitcoin)', index: 'Ch\u1ec9 s\u1ed1', address: '\u0110\u1ecba ch\u1ec9', message: 'Tin nh\u1eafn',
    bmsSignature: 'Ch\u1eef k\u00fd BMS', sigBase64: 'Ch\u1eef k\u00fd (base64)', tapToCopy: 'Ch\u1ea1m \u0111\u1ec3 sao ch\u00e9p', copySig: 'Sao ch\u00e9p ch\u1eef k\u00fd', sha256: 'SHA-256',
    settings: 'C\u00e0i \u0111\u1eb7t', version: 'Phi\u00ean b\u1ea3n', language: 'Ng\u00f4n ng\u1eef', seedLanguage: 'Ng\u00f4n ng\u1eef seed',
    onlineKeygenTitle: 'M\u1ea1ng \u0111\u00e3 k\u1ebft n\u1ed1i!',
    onlineKeygenBody: 'Thi\u1ebft b\u1ecb c\u1ee7a b\u1ea1n \u0111ang k\u1ebft n\u1ed1i internet. Kh\u00f3a \u0111\u01b0\u1ee3c t\u1ea1o tr\u1ef1c tuy\u1ebfn c\u00f3 th\u1ec3 b\u1ecb ph\u1ea7n m\u1ec1m \u0111\u1ed9c h\u1ea1i ch\u1eb7n. Ng\u1eaft T\u1ea4T C\u1ea2 m\u1ea1ng (WiFi, di \u0111\u1ed9ng, Bluetooth, USB) tr\u01b0\u1edbc khi ti\u1ebfp t\u1ee5c.',
    proceedAnyway: 'V\u1eabn ti\u1ebfp t\u1ee5c (kh\u00f4ng an to\u00e0n)',
    installGuide: 'H\u01b0\u1edbng d\u1eabn c\u00e0i \u0111\u1eb7t', viewSource: 'X\u00e1c minh t\u00ednh to\u00e0n v\u1eb9n m\u00e3 ngu\u1ed3n', securityInfo: 'Th\u00f4ng tin b\u1ea3o m\u1eadt',
    deleteKey: 'X\u00f3a kh\u00f3a', deleteConfirm1: 'X\u00f3a kh\u00f3a? Kh\u00f4ng th\u1ec3 ho\u00e0n t\u00e1c.\nH\u00e3y \u0111\u1ea3m b\u1ea3o \u0111\u00e3 sao l\u01b0u c\u1ee5m t\u1eeb!',
    deleteConfirm2: 'B\u1ea1n ch\u1eafc ch\u1eafn ch\u1ee9? Bitcoin s\u1ebd M\u1ea4T n\u1ebfu kh\u00f4ng c\u00f3 b\u1ea3n sao l\u01b0u.',
    verifyIntegrity: 'X\u00e1c minh t\u00ednh to\u00e0n v\u1eb9n', verifyDesc: 'So s\u00e1nh hash SHA-256 v\u1edbi phi\u00ean b\u1ea3n ch\u00ednh th\u1ee9c tr\u00ean GitHub.',
    computing: '\u0110ang t\u00ednh...', fetchFailed: '(t\u1ea3i th\u1ea5t b\u1ea1i)',
    verifyFile: 'X\u00e1c minh t\u1ec7p n\u00e0y', verifyFileDesc: 'Ch\u1ea1m \u0111\u00e2y v\u00e0 ch\u1ecdn t\u1ec7p <strong>bitclutch-signer.html</strong> \u0111\u00e3 t\u1ea3i.<br>Hash SHA-256 s\u1ebd \u0111\u01b0\u1ee3c t\u00ednh c\u1ee5c b\u1ed9.',
    tapToSelect: 'Ch\u1ea1m \u0111\u1ec3 ch\u1ecdn', compareGithub: 'So s\u00e1nh v\u1edbi <code>hashes.json</code> t\u1eeb phi\u00ean b\u1ea3n GitHub.',
    auditableSource: 'M\u00e3 ngu\u1ed3n ki\u1ec3m to\u00e1n \u0111\u01b0\u1ee3c', auditableDesc: 'To\u00e0n b\u1ed9 logic c\u1ee7a \u1ee9ng d\u1ee5ng n\u1eb1m trong m\u1ed9t t\u1ec7p ki\u1ec3m to\u00e1n \u0111\u01b0\u1ee3c. M\u00e3 ngu\u1ed3n v\u00e0 hash ch\u00ednh th\u1ee9c \u0111\u01b0\u1ee3c c\u00f4ng b\u1ed1 tr\u00ean GitHub.',
    back: 'Quay l\u1ea1i',
    securityTitle: 'Th\u00f4ng tin b\u1ea3o m\u1eadt', securityLevel: 'M\u1ee9c b\u1ea3o m\u1eadt: Air-gap ph\u1ea7n m\u1ec1m',
    whatProvides: 'Cung c\u1ea5p:', secProvide1: 'Kh\u00f3a ri\u00eang kh\u00f4ng bao gi\u1edd ch\u1ea1m internet (sau c\u00e0i \u0111\u1eb7t)',
    secProvide2: 'M\u00e3 ki\u1ec3m to\u00e1n \u0111\u01b0\u1ee3c (t\u1ec7p app.js duy nh\u1ea5t)', secProvide3: 'Entropy ch\u1ec9 t\u1eeb ngu\u1ed3n v\u1eadt l\u00fd (x\u00fac x\u1eafc/\u0111\u1ed3ng xu)',
    secProvide4: 'M\u00e3 h\u00f3a AES-256-GCM v\u1edbi 600K l\u1ea7n l\u1eb7p PBKDF2',
    whatNot: 'Kh\u00f4ng cung c\u1ea5p:', secNot1: 'Secure Element (v\u00ed ph\u1ea7n c\u1ee9ng c\u00f3)',
    secNot2: 'Air gap ph\u1ea7n c\u1ee9ng (chip WiFi v\u1eabn t\u1ed3n t\u1ea1i)', secNot3: 'Kh\u00e1ng t\u1ea5n c\u00f4ng k\u00eanh ph\u1ee5',
    keyStorage: 'L\u01b0u tr\u1eef kh\u00f3a', encryption: 'M\u00e3 h\u00f3a:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600,000 l\u1ea7n) + salt/IV ng\u1eabu nhi\u00ean',
    warning: 'C\u1ea3nh b\u00e1o:', clearDataWarning: 'X\u00f3a d\u1eef li\u1ec7u tr\u00ecnh duy\u1ec7t s\u1ebd x\u00f3a v\u0129nh vi\u1ec5n kh\u00f3a m\u00e3 h\u00f3a. Lu\u00f4n sao l\u01b0u c\u1ee5m t\u1eeb ngo\u1ea1i tuy\u1ebfn.',
    autoLock: 'T\u1ef1 \u0111\u1ed9ng kh\u00f3a:', autoLockDesc: 'Kh\u00f3a b\u1ecb x\u00f3a kh\u1ecfi b\u1ed9 nh\u1edb sau 5 ph\u00fat kh\u00f4ng ho\u1ea1t \u0111\u1ed9ng.',
    storageEncKey: 'Kh\u00f3a ri\u00eang m\u00e3 h\u00f3a (AES-256-GCM)', storageXpub: 'Kh\u00f3a c\u00f4ng m\u1edf r\u1ed9ng t\u00e0i kho\u1ea3n', storageFp: 'V\u00e2n tay BIP-32',
    storageNet: 'C\u00e0i \u0111\u1eb7t m\u1ea1ng (main/test)', storageLang: 'Ng\u00f4n ng\u1eef giao di\u1ec7n', storageSeedLang: 'Ng\u00f4n ng\u1eef c\u1ee5m t\u1eeb', storageKeyCreated: 'Ng\u00e0y t\u1ea1o kh\u00f3a', storageLastOnline: 'Ng\u00e0y ph\u00e1t hi\u1ec7n m\u1ea1ng',
    guideTitle: 'H\u01b0\u1edbng d\u1eabn c\u00e0i \u0111\u1eb7t', guideDesc: 'C\u00e0i \u0111\u1eb7t BitClutch Signer nh\u01b0 \u1ee9ng d\u1ee5ng ngo\u1ea1i tuy\u1ebfn, sau \u0111\u00f3 b\u1eadt ch\u1ebf \u0111\u1ed9 m\u00e1y bay tr\u01b0\u1edbc khi s\u1eed d\u1ee5ng.',
    detected: '\u0110\u00e3 ph\u00e1t hi\u1ec7n',
    guideIosSafari: '<strong>C\u00e0i \u0111\u1eb7t nh\u01b0 \u1ee9ng d\u1ee5ng ngo\u1ea1i tuy\u1ebfn:</strong><ol><li>M\u1edf trang n\u00e0y trong <strong>Safari</strong></li><li>Nh\u1ea5n n\u00fat <strong>Share</strong> (h\u1ed9p c\u00f3 m\u0169i t\u00ean)</li><li>Cu\u1ed9n xu\u1ed1ng v\u00e0 nh\u1ea5n <strong>\u201cAdd to Home Screen\u201d</strong></li><li>Nh\u1ea5n <strong>\u201cAdd\u201d</strong> \u1edf g\u00f3c tr\u00ean b\u00ean ph\u1ea3i</li></ol><strong>B\u1eadt Ch\u1ebf \u0111\u1ed9 M\u00e1y bay:</strong><ol><li>Vu\u1ed1t xu\u1ed1ng t\u1eeb g\u00f3c tr\u00ean b\u00ean ph\u1ea3i (ho\u1eb7c vu\u1ed1t l\u00ean t\u1eeb d\u01b0\u1edbi tr\u00ean iPhone c\u0169)</li><li>Nh\u1ea5n <strong>bi\u1ec3u t\u01b0\u1ee3ng m\u00e1y bay</strong> \u0111\u1ec3 b\u1eadt</li><li>\u0110\u1ea3m b\u1ea3o Wi-Fi v\u00e0 Bluetooth c\u0169ng \u0111\u00e3 T\u1eaeT</li></ol>',
    guideIosChrome: '<strong>Quan tr\u1ecdng:</strong> Chrome tr\u00ean iOS kh\u00f4ng th\u1ec3 c\u00e0i \u0111\u1eb7t \u1ee9ng d\u1ee5ng ngo\u1ea1i tuy\u1ebfn. H\u00e3y d\u00f9ng <strong>Safari</strong> thay th\u1ebf.<ol><li>Sao ch\u00e9p URL trang n\u00e0y</li><li>M\u1edf <strong>Safari</strong> v\u00e0 d\u00e1n URL</li><li>L\u00e0m theo h\u01b0\u1edbng d\u1eabn <strong>iOS Safari</strong> \u1edf tr\u00ean</li></ol><strong>B\u1eadt Ch\u1ebf \u0111\u1ed9 M\u00e1y bay:</strong><ol><li>Vu\u1ed1t xu\u1ed1ng t\u1eeb g\u00f3c tr\u00ean b\u00ean ph\u1ea3i</li><li>Nh\u1ea5n <strong>bi\u1ec3u t\u01b0\u1ee3ng m\u00e1y bay</strong></li></ol>',
    guideAndroidChrome: '<strong>C\u00e0i \u0111\u1eb7t nh\u01b0 \u1ee9ng d\u1ee5ng ngo\u1ea1i tuy\u1ebfn:</strong><ol><li>M\u1edf trang n\u00e0y trong <strong>Chrome</strong></li><li>Nh\u1ea5n v\u00e0o <strong>menu ba ch\u1ea5m</strong> (g\u00f3c tr\u00ean b\u00ean ph\u1ea3i)</li><li>Nh\u1ea5n <strong>\u201cInstall app\u201d</strong> ho\u1eb7c <strong>\u201cAdd to Home screen\u201d</strong></li><li>X\u00e1c nh\u1eadn b\u1eb1ng c\u00e1ch nh\u1ea5n <strong>\u201cInstall\u201d</strong></li></ol><strong>B\u1eadt Ch\u1ebf \u0111\u1ed9 M\u00e1y bay:</strong><ol><li>Vu\u1ed1t xu\u1ed1ng t\u1eeb \u0111\u1ea7u m\u00e0n h\u00ecnh</li><li>Nh\u1ea5n <strong>\u201cAirplane mode\u201d</strong></li><li>X\u00e1c nh\u1eadn Wi-Fi v\u00e0 d\u1eef li\u1ec7u di \u0111\u1ed9ng \u0111\u00e3 T\u1eaeT</li></ol>',
    guideAndroidSamsung: '<strong>C\u00e0i \u0111\u1eb7t nh\u01b0 \u1ee9ng d\u1ee5ng ngo\u1ea1i tuy\u1ebfn:</strong><ol><li>M\u1edf trang n\u00e0y trong <strong>Samsung Internet</strong></li><li>Nh\u1ea5n v\u00e0o <strong>bi\u1ec3u t\u01b0\u1ee3ng menu</strong> (ba \u0111\u01b0\u1eddng, g\u00f3c d\u01b0\u1edbi b\u00ean ph\u1ea3i)</li><li>Nh\u1ea5n <strong>\u201cAdd page to\u201d</strong> r\u1ed3i ch\u1ecdn <strong>\u201cHome screen\u201d</strong></li></ol><strong>B\u1eadt Ch\u1ebf \u0111\u1ed9 M\u00e1y bay:</strong><ol><li>Vu\u1ed1t xu\u1ed1ng hai l\u1ea7n t\u1eeb \u0111\u1ea7u m\u00e0n h\u00ecnh \u0111\u1ec3 m\u1edf C\u00e0i \u0111\u1eb7t nhanh</li><li>Nh\u1ea5n <strong>\u201cAirplane mode\u201d</strong></li></ol>',
    guideMacosSafari: '<strong>C\u00e0i \u0111\u1eb7t nh\u01b0 \u1ee9ng d\u1ee5ng ngo\u1ea1i tuy\u1ebfn (macOS Sonoma+):</strong><ol><li>M\u1edf trang n\u00e0y trong <strong>Safari</strong></li><li>Nh\u1ea5n menu <strong>File</strong> r\u1ed3i ch\u1ecdn <strong>\u201cAdd to Dock\u201d</strong></li><li>Nh\u1ea5n <strong>\u201cAdd\u201d</strong></li></ol><strong>T\u1eaft M\u1ea1ng:</strong><ol><li>Nh\u1ea5n v\u00e0o <strong>bi\u1ec3u t\u01b0\u1ee3ng Wi-Fi</strong> tr\u00ean thanh menu</li><li>Nh\u1ea5n \u0111\u1ec3 <strong>t\u1eaft Wi-Fi</strong></li><li>R\u00fat t\u1ea5t c\u1ea3 c\u00e1p Ethernet</li></ol>',
    guideMacosChrome: '<strong>C\u00e0i \u0111\u1eb7t nh\u01b0 \u1ee9ng d\u1ee5ng ngo\u1ea1i tuy\u1ebfn:</strong><ol><li>M\u1edf trang n\u00e0y trong <strong>Chrome</strong></li><li>Nh\u1ea5n v\u00e0o <strong>install icon</strong> tr\u00ean thanh \u0111\u1ecba ch\u1ec9 (ho\u1eb7c menu ba ch\u1ea5m &rarr; \u201cInstall BitClutch Signer\u201d)</li><li>Nh\u1ea5n <strong>\u201cInstall\u201d</strong></li></ol><strong>T\u1eaft M\u1ea1ng:</strong><ol><li>Nh\u1ea5n v\u00e0o <strong>bi\u1ec3u t\u01b0\u1ee3ng Wi-Fi</strong> tr\u00ean thanh menu</li><li>Nh\u1ea5n \u0111\u1ec3 <strong>t\u1eaft Wi-Fi</strong></li><li>R\u00fat t\u1ea5t c\u1ea3 c\u00e1p Ethernet</li></ol>',
    guideWindowsChrome: '<strong>C\u00e0i \u0111\u1eb7t nh\u01b0 \u1ee9ng d\u1ee5ng ngo\u1ea1i tuy\u1ebfn:</strong><ol><li>M\u1edf trang n\u00e0y trong <strong>Chrome</strong></li><li>Nh\u1ea5n v\u00e0o <strong>install icon</strong> tr\u00ean thanh \u0111\u1ecba ch\u1ec9 (ho\u1eb7c menu ba ch\u1ea5m &rarr; \u201cInstall BitClutch Signer\u201d)</li><li>Nh\u1ea5n <strong>\u201cInstall\u201d</strong></li></ol><strong>T\u1eaft M\u1ea1ng:</strong><ol><li>Nh\u1ea5n v\u00e0o <strong>bi\u1ec3u t\u01b0\u1ee3ng Wi-Fi</strong> tr\u00ean thanh t\u00e1c v\u1ee5 (g\u00f3c d\u01b0\u1edbi b\u00ean ph\u1ea3i)</li><li>Nh\u1ea5n \u0111\u1ec3 <strong>ng\u1eaft k\u1ebft n\u1ed1i Wi-Fi</strong></li><li>R\u00fat t\u1ea5t c\u1ea3 c\u00e1p Ethernet</li></ol>',
    guideWindowsEdge: '<strong>C\u00e0i \u0111\u1eb7t nh\u01b0 \u1ee9ng d\u1ee5ng ngo\u1ea1i tuy\u1ebfn:</strong><ol><li>M\u1edf trang n\u00e0y trong <strong>Edge</strong></li><li>Nh\u1ea5n v\u00e0o <strong>install icon</strong> tr\u00ean thanh \u0111\u1ecba ch\u1ec9 (ho\u1eb7c menu ba ch\u1ea5m &rarr; \u201c\u1ee8ng d\u1ee5ng\u201d &rarr; \u201cInstall BitClutch Signer\u201d)</li><li>Nh\u1ea5n <strong>\u201cInstall\u201d</strong></li></ol><strong>T\u1eaft M\u1ea1ng:</strong><ol><li>Nh\u1ea5n v\u00e0o <strong>bi\u1ec3u t\u01b0\u1ee3ng Wi-Fi</strong> tr\u00ean thanh t\u00e1c v\u1ee5 (g\u00f3c d\u01b0\u1edbi b\u00ean ph\u1ea3i)</li><li>Nh\u1ea5n \u0111\u1ec3 <strong>ng\u1eaft k\u1ebft n\u1ed1i Wi-Fi</strong></li><li>R\u00fat t\u1ea5t c\u1ea3 c\u00e1p Ethernet</li></ol>',
    accountXpubTitle: 'xpub t\u00e0i kho\u1ea3n',
    noMnemonic: 'Kh\u00f4ng c\u00f3 mnemonic.', noTxData: 'Kh\u00f4ng c\u00f3 d\u1eef li\u1ec7u giao d\u1ecbch.', noSignedData: 'Kh\u00f4ng c\u00f3 d\u1eef li\u1ec7u \u0111\u00e3 k\u00fd.',
    noBmsRequest: 'Kh\u00f4ng c\u00f3 y\u00eau c\u1ea7u BMS.', noSignature: 'Kh\u00f4ng c\u00f3 ch\u1eef k\u00fd.', loading: '\u0110ang t\u1ea3i...',
    bannerWarn: 'PH\u00c1T HI\u1ec6N M\u1ea0NG \u2014 Ng\u1eaft t\u1ea5t c\u1ea3 m\u1ea1ng tr\u01b0\u1edbc khi t\u1ea1o kh\u00f3a.',
    bannerOnline: 'M\u1ea0NG \u0110\u00c3 K\u1ebeT N\u1ed0I \u2014 Ng\u1eaft NGAY v\u00e0 KH\u00d4NG BAO GI\u1ede k\u1ebft n\u1ed1i l\u1ea1i thi\u1ebft b\u1ecb n\u00e0y. Kh\u00f3a c\u00f3 th\u1ec3 \u0111\u00e3 b\u1ecb l\u1ed9.',
    bannerOffline: 'Kh\u00f4ng ph\u00e1t hi\u1ec7n m\u1ea1ng kh\u00f4ng d\u00e2y. X\u00e1c nh\u1eadn Bluetooth, NFC v\u00e0 c\u00e1p USB d\u1eef li\u1ec7u c\u0169ng \u0111\u00e3 ng\u1eaft.',
  },
  th: {
    unlocked: '\u0e1b\u0e25\u0e14\u0e25\u0e47\u0e2d\u0e01\u0e41\u0e25\u0e49\u0e27', locked: '\u0e25\u0e47\u0e2d\u0e01\u0e2d\u0e22\u0e39\u0e48',
    tabKey: '\u0e04\u0e35\u0e22\u0e4c', tabSign: '\u0e40\u0e0b\u0e47\u0e19', tabSettings: '\u0e15\u0e31\u0e49\u0e07\u0e04\u0e48\u0e32',
    createKeys: '\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e04\u0e35\u0e22\u0e4c\u0e02\u0e2d\u0e07\u0e04\u0e38\u0e13',
    setupDesc: '\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e04\u0e35\u0e22\u0e4c\u0e43\u0e2b\u0e21\u0e48\u0e14\u0e49\u0e27\u0e22\u0e40\u0e2d\u0e19\u0e42\u0e17\u0e23\u0e1b\u0e35\u0e17\u0e32\u0e07\u0e01\u0e32\u0e22\u0e20\u0e32\u0e1e,<br>\u0e2b\u0e23\u0e37\u0e2d\u0e19\u0e33\u0e40\u0e02\u0e49\u0e32\u0e0a\u0e38\u0e14\u0e04\u0e33\u0e01\u0e39\u0e49\u0e04\u0e37\u0e19\u0e17\u0e35\u0e48\u0e21\u0e35\u0e2d\u0e22\u0e39\u0e48',
    diceBtn: '\u0e25\u0e39\u0e01\u0e40\u0e15\u0e4b\u0e32 (99 \u0e04\u0e23\u0e31\u0e49\u0e07)', coinBtn: '\u0e42\u0e22\u0e19\u0e40\u0e2b\u0e23\u0e35\u0e22\u0e0d (256 \u0e04\u0e23\u0e31\u0e49\u0e07)', importBtn: '\u0e19\u0e33\u0e40\u0e02\u0e49\u0e32\u0e0a\u0e38\u0e14\u0e04\u0e33\u0e01\u0e39\u0e49\u0e04\u0e37\u0e19',
    enterPassphrase: '\u0e1b\u0e49\u0e2d\u0e19\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e1b\u0e25\u0e14\u0e25\u0e47\u0e2d\u0e01', passphrase: '\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19', unlock: '\u0e1b\u0e25\u0e14\u0e25\u0e47\u0e2d\u0e01', wrongPassphrase: '\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19\u0e44\u0e21\u0e48\u0e16\u0e39\u0e01\u0e15\u0e49\u0e2d\u0e07',
    yourKey: '\u0e04\u0e35\u0e22\u0e4c\u0e02\u0e2d\u0e07\u0e04\u0e38\u0e13', network: '\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22', fingerprint: '\u0e25\u0e32\u0e22\u0e19\u0e34\u0e49\u0e27\u0e21\u0e37\u0e2d', keyCreated: '\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e40\u0e21\u0e37\u0e48\u0e2d', lastOnline: '\u0e2d\u0e2d\u0e19\u0e44\u0e25\u0e19\u0e4c\u0e25\u0e48\u0e32\u0e2a\u0e38\u0e14', neverOnline: '\u0e44\u0e21\u0e48\u0e40\u0e04\u0e22 (\u0e1b\u0e25\u0e2d\u0e14\u0e20\u0e31\u0e22)', onlineAfterKey: '\u0e15\u0e23\u0e27\u0e08\u0e1e\u0e1a\u0e2d\u0e2d\u0e19\u0e44\u0e25\u0e19\u0e4c\u0e2b\u0e25\u0e31\u0e07\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e04\u0e35\u0e22\u0e4c', accountXpub: 'xpub \u0e1a\u0e31\u0e0d\u0e0a\u0e35',
    showXpubQR: '\u0e41\u0e2a\u0e14\u0e07 QR xpub', lockBtn: '\u0e25\u0e47\u0e2d\u0e01', mainnet: 'Mainnet', testnet: 'Testnet',
    diceTitle: '\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e04\u0e35\u0e22\u0e4c\u0e14\u0e49\u0e27\u0e22\u0e25\u0e39\u0e01\u0e40\u0e15\u0e4b\u0e32', diceDesc: '\u0e17\u0e2d\u0e22\u0e25\u0e39\u0e01\u0e40\u0e15\u0e4b\u0e32\u0e08\u0e23\u0e34\u0e07\u0e41\u0e25\u0e49\u0e27\u0e41\u0e15\u0e30\u0e1c\u0e25\u0e25\u0e31\u0e1e\u0e18\u0e4c',
    progress: '\u0e04\u0e27\u0e32\u0e21\u0e04\u0e37\u0e1a\u0e2b\u0e19\u0e49\u0e32', undoLast: '\u0e22\u0e49\u0e2d\u0e19\u0e01\u0e25\u0e31\u0e1a', cancel: '\u0e22\u0e01\u0e40\u0e25\u0e34\u0e01', ok: '\u0e15\u0e01\u0e25\u0e07',
    coinTitle: '\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e04\u0e35\u0e22\u0e4c\u0e14\u0e49\u0e27\u0e22\u0e40\u0e2b\u0e23\u0e35\u0e22\u0e0d', coinDesc: '\u0e42\u0e22\u0e19\u0e40\u0e2b\u0e23\u0e35\u0e22\u0e0d\u0e08\u0e23\u0e34\u0e07\u0e41\u0e25\u0e49\u0e27\u0e41\u0e15\u0e30\u0e1c\u0e25\u0e25\u0e31\u0e1e\u0e18\u0e4c',
    entropyWarning: '\u0e43\u0e0a\u0e49\u0e25\u0e39\u0e01\u0e40\u0e15\u0e4b\u0e32/\u0e40\u0e2b\u0e23\u0e35\u0e22\u0e0d\u0e08\u0e23\u0e34\u0e07 \u2014 \u0e2d\u0e22\u0e48\u0e32\u0e04\u0e34\u0e14\u0e15\u0e31\u0e27\u0e40\u0e25\u0e02\u0e40\u0e2d\u0e07 \u0e01\u0e32\u0e23\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e02\u0e2d\u0e07\u0e21\u0e19\u0e38\u0e29\u0e22\u0e4c\u0e04\u0e32\u0e14\u0e40\u0e14\u0e32\u0e44\u0e14\u0e49\u0e41\u0e25\u0e30\u0e17\u0e33\u0e43\u0e2b\u0e49\u0e04\u0e35\u0e22\u0e4c\u0e2d\u0e48\u0e2d\u0e19\u0e41\u0e2d \u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e27\u0e48\u0e32\u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e25\u0e49\u0e2d\u0e07\u0e2b\u0e23\u0e37\u0e2d\u0e44\u0e21\u0e42\u0e04\u0e23\u0e42\u0e1f\u0e19\u0e43\u0e01\u0e25\u0e49 \u2014 \u0e1c\u0e39\u0e49\u0e17\u0e35\u0e48\u0e40\u0e2b\u0e47\u0e19\u0e1c\u0e25\u0e01\u0e32\u0e23\u0e17\u0e2d\u0e22\u0e2a\u0e32\u0e21\u0e32\u0e23\u0e16\u0e02\u0e42\u0e21\u0e22 Bitcoin \u0e02\u0e2d\u0e07\u0e04\u0e38\u0e13\u0e44\u0e14\u0e49',
    heads: 'H (\u0e2b\u0e31\u0e27)', tails: 'T (\u0e01\u0e49\u0e2d\u0e22)',
    writeDown: '\u0e08\u0e14\u0e04\u0e33\u0e40\u0e2b\u0e25\u0e48\u0e32\u0e19\u0e35\u0e49\u0e44\u0e27\u0e49!',
    mnemonicDesc: '\u0e19\u0e35\u0e48\u0e04\u0e37\u0e2d\u0e0a\u0e38\u0e14\u0e04\u0e33\u0e01\u0e39\u0e49\u0e04\u0e37\u0e19\u0e02\u0e2d\u0e07\u0e04\u0e38\u0e13 \u0e40\u0e01\u0e47\u0e1a\u0e23\u0e31\u0e01\u0e29\u0e32\u0e2d\u0e22\u0e48\u0e32\u0e07\u0e1b\u0e25\u0e2d\u0e14\u0e20\u0e31\u0e22\u0e41\u0e1a\u0e1a\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c \u0e08\u0e30\u0e44\u0e21\u0e48\u0e41\u0e2a\u0e14\u0e07\u0e2d\u0e35\u0e01',
    stolenVsLost: '\u0e16\u0e39\u0e01\u0e02\u0e42\u0e21\u0e22 vs. \u0e2a\u0e39\u0e0d\u0e2b\u0e32\u0e22 \u2014 \u0e23\u0e39\u0e49\u0e04\u0e27\u0e32\u0e21\u0e41\u0e15\u0e01\u0e15\u0e48\u0e32\u0e07',
    theft: '\u0e01\u0e32\u0e23\u0e42\u0e08\u0e23\u0e01\u0e23\u0e23\u0e21:', theftDesc: '\u0e16\u0e49\u0e32\u0e43\u0e04\u0e23\u0e1e\u0e1a\u0e0a\u0e38\u0e14\u0e04\u0e33\u0e02\u0e2d\u0e07\u0e04\u0e38\u0e13 \u0e2a\u0e32\u0e21\u0e32\u0e23\u0e16\u0e02\u0e42\u0e21\u0e22 Bitcoin \u0e44\u0e14\u0e49\u0e17\u0e31\u0e19\u0e17\u0e35 \u0e44\u0e21\u0e48\u0e21\u0e35\u0e43\u0e04\u0e23\u0e22\u0e49\u0e2d\u0e19\u0e01\u0e25\u0e31\u0e1a\u0e44\u0e14\u0e49',
    loss: '\u0e2a\u0e39\u0e0d\u0e2b\u0e32\u0e22:', lossDesc: '\u0e16\u0e49\u0e32\u0e04\u0e38\u0e13\u0e17\u0e33\u0e0a\u0e38\u0e14\u0e04\u0e33\u0e2b\u0e32\u0e22\u0e41\u0e25\u0e30\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e40\u0e2a\u0e35\u0e22 Bitcoin \u0e08\u0e30\u0e2a\u0e39\u0e0d\u0e2b\u0e32\u0e22\u0e15\u0e25\u0e2d\u0e14\u0e44\u0e1b \u2014 \u0e40\u0e27\u0e49\u0e19\u0e41\u0e15\u0e48\u0e21\u0e35\u0e41\u0e1c\u0e19\u0e01\u0e39\u0e49\u0e04\u0e37\u0e19',
    bitclutchPromo: '<strong>BitClutch</strong> \u0e1b\u0e01\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23\u0e2a\u0e39\u0e0d\u0e2b\u0e32\u0e22\u0e41\u0e25\u0e30\u0e01\u0e32\u0e23\u0e40\u0e2a\u0e35\u0e22\u0e0a\u0e35\u0e27\u0e34\u0e15 \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e01\u0e32\u0e23\u0e42\u0e08\u0e23\u0e01\u0e23\u0e23\u0e21 \u0e2a\u0e23\u0e49\u0e32\u0e07<strong>\u0e01\u0e23\u0e30\u0e40\u0e1b\u0e4b\u0e32\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19</strong>\u0e1e\u0e23\u0e49\u0e2d\u0e21 timelock \u2014 Bitcoin \u0e22\u0e31\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e02\u0e2d\u0e07\u0e04\u0e38\u0e13 \u0e41\u0e15\u0e48\u0e17\u0e32\u0e22\u0e32\u0e17\u0e2a\u0e32\u0e21\u0e32\u0e23\u0e16\u0e01\u0e39\u0e49\u0e04\u0e37\u0e19\u0e44\u0e14\u0e49',
    visitBitclutch: '\u0e40\u0e22\u0e35\u0e48\u0e22\u0e21\u0e0a\u0e21 <strong>bitclutch.app</strong> \u0e1a\u0e19\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2d\u0e2d\u0e19\u0e44\u0e25\u0e19\u0e4c\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e01\u0e23\u0e30\u0e40\u0e1b\u0e4b\u0e32\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19',
    confirmedWritten: '\u0e08\u0e14\u0e44\u0e27\u0e49\u0e41\u0e25\u0e49\u0e27',
    importTitle: '\u0e19\u0e33\u0e40\u0e02\u0e49\u0e32\u0e0a\u0e38\u0e14\u0e04\u0e33\u0e01\u0e39\u0e49\u0e04\u0e37\u0e19', importDesc: '\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e08\u0e33\u0e19\u0e27\u0e19\u0e04\u0e33\u0e41\u0e25\u0e30\u0e20\u0e32\u0e29\u0e32 \u0e41\u0e25\u0e49\u0e27\u0e1b\u0e49\u0e2d\u0e19\u0e41\u0e15\u0e48\u0e25\u0e30\u0e04\u0e33',
    importPlaceholder: '\u0e04\u0e331 \u0e04\u0e332 \u0e04\u0e333 ...', importAction: '\u0e19\u0e33\u0e40\u0e02\u0e49\u0e32', words: '\u0e04\u0e33',
    fillAllWords: '\u0e01\u0e23\u0e38\u0e13\u0e32\u0e01\u0e23\u0e2d\u0e01\u0e04\u0e33\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14', needWords: '\u0e15\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23 12 \u0e2b\u0e23\u0e37\u0e2d 24 \u0e04\u0e33', invalidMnemonic: 'Mnemonic \u0e44\u0e21\u0e48\u0e16\u0e39\u0e01\u0e15\u0e49\u0e2d\u0e07',
    setPassTitle: '\u0e15\u0e31\u0e49\u0e07\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19', setPassDesc: '\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19\u0e17\u0e35\u0e48\u0e23\u0e31\u0e14\u0e01\u0e38\u0e21\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e40\u0e02\u0e49\u0e32\u0e23\u0e2b\u0e31\u0e2a\u0e04\u0e35\u0e22\u0e4c\u0e2a\u0e48\u0e27\u0e19\u0e15\u0e31\u0e27 \u0e15\u0e49\u0e2d\u0e07\u0e43\u0e0a\u0e49\u0e17\u0e38\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e35\u0e48\u0e1b\u0e25\u0e14\u0e25\u0e47\u0e2d\u0e01',
    confirmPass: '\u0e22\u0e37\u0e19\u0e22\u0e31\u0e19\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19', enterPass: '\u0e1b\u0e49\u0e2d\u0e19\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19',
    passRequired: '\u0e15\u0e49\u0e2d\u0e07\u0e23\u0e30\u0e1a\u0e38\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19', passTooShort: '\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19\u0e2a\u0e31\u0e49\u0e19\u0e40\u0e01\u0e34\u0e19\u0e44\u0e1b (\u0e2d\u0e22\u0e48\u0e32\u0e07\u0e19\u0e49\u0e2d\u0e22 4 \u0e15\u0e31\u0e27\u0e2d\u0e31\u0e01\u0e29\u0e23)', passNoMatch: '\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19\u0e44\u0e21\u0e48\u0e15\u0e23\u0e07\u0e01\u0e31\u0e19',
    noKeyToSave: '\u0e44\u0e21\u0e48\u0e21\u0e35\u0e04\u0e35\u0e22\u0e4c\u0e43\u0e2b\u0e49\u0e1a\u0e31\u0e19\u0e17\u0e36\u0e01 \u0e40\u0e23\u0e34\u0e48\u0e21\u0e43\u0e2b\u0e21\u0e48', encryptSave: '\u0e40\u0e02\u0e49\u0e32\u0e23\u0e2b\u0e31\u0e2a\u0e41\u0e25\u0e30\u0e1a\u0e31\u0e19\u0e17\u0e36\u0e01', encryptFailed: '\u0e40\u0e02\u0e49\u0e32\u0e23\u0e2b\u0e31\u0e2a\u0e25\u0e49\u0e21\u0e40\u0e2b\u0e25\u0e27: ',
    scanTitle: '\u0e2a\u0e41\u0e01\u0e19 QR', scanDesc: '\u0e0a\u0e35\u0e49\u0e01\u0e25\u0e49\u0e2d\u0e07\u0e44\u0e1b\u0e17\u0e35\u0e48 QR \u0e02\u0e2d\u0e07\u0e41\u0e2d\u0e1b BitClutch',
    startingCamera: '\u0e40\u0e23\u0e34\u0e48\u0e21\u0e01\u0e25\u0e49\u0e2d\u0e07...', scanning: '\u0e01\u0e33\u0e25\u0e31\u0e07\u0e2a\u0e41\u0e01\u0e19... \u0e0a\u0e35\u0e49\u0e44\u0e1b\u0e17\u0e35\u0e48 QR', cameraError: '\u0e01\u0e25\u0e49\u0e2d\u0e07\u0e1c\u0e34\u0e14\u0e1e\u0e25\u0e32\u0e14: ',
    receivingFountain: '\u0e01\u0e33\u0e25\u0e31\u0e07\u0e23\u0e31\u0e1a fountain code...', urFailed: '\u0e16\u0e2d\u0e14\u0e23\u0e2b\u0e31\u0e2a UR \u0e25\u0e49\u0e21\u0e40\u0e2b\u0e25\u0e27 \u0e25\u0e2d\u0e07\u0e43\u0e2b\u0e21\u0e48', psbtParseError: 'PSBT \u0e27\u0e34\u0e40\u0e04\u0e23\u0e32\u0e30\u0e2b\u0e4c\u0e1c\u0e34\u0e14\u0e1e\u0e25\u0e32\u0e14: ',
    confirmTx: '\u0e22\u0e37\u0e19\u0e22\u0e31\u0e19\u0e18\u0e38\u0e23\u0e01\u0e23\u0e23\u0e21', reviewBeforeSign: '\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e2d\u0e22\u0e48\u0e32\u0e07\u0e23\u0e30\u0e21\u0e31\u0e14\u0e23\u0e30\u0e27\u0e31\u0e07\u0e01\u0e48\u0e2d\u0e19\u0e40\u0e0b\u0e47\u0e19',
    inputs: '\u0e2d\u0e34\u0e19\u0e1e\u0e38\u0e15', output: '\u0e40\u0e2d\u0e32\u0e15\u0e4c\u0e1e\u0e38\u0e15', change: '(\u0e40\u0e07\u0e34\u0e19\u0e17\u0e2d\u0e19)', fee: '\u0e04\u0e48\u0e32\u0e18\u0e23\u0e23\u0e21\u0e40\u0e19\u0e35\u0e22\u0e21', reject: '\u0e1b\u0e0f\u0e34\u0e40\u0e2a\u0e18', sign: '\u0e40\u0e0b\u0e47\u0e19', signingFailed: '\u0e40\u0e0b\u0e47\u0e19\u0e25\u0e49\u0e21\u0e40\u0e2b\u0e25\u0e27: ',
    signedPsbt: 'PSBT \u0e17\u0e35\u0e48\u0e40\u0e0b\u0e47\u0e19\u0e41\u0e25\u0e49\u0e27', showQRDesc: '\u0e43\u0e2b\u0e49\u0e41\u0e2d\u0e1b BitClutch \u0e2a\u0e41\u0e01\u0e19 QR \u0e19\u0e35\u0e49\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e1b\u0e23\u0e30\u0e01\u0e32\u0e28\u0e18\u0e38\u0e23\u0e01\u0e23\u0e23\u0e21', scanComplete: '\u0e2a\u0e41\u0e01\u0e19\u0e40\u0e2a\u0e23\u0e47\u0e08', scanSignatureDesc: '\u0e43\u0e2b\u0e49\u0e41\u0e2d\u0e1b BitClutch \u0e2a\u0e41\u0e01\u0e19 QR \u0e19\u0e35\u0e49\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e2a\u0e48\u0e07\u0e25\u0e32\u0e22\u0e40\u0e0b\u0e47\u0e19',
    singleQR: 'QR \u0e40\u0e14\u0e35\u0e22\u0e27', fountainKeepShowing: 'fountain code \u2014 \u0e41\u0e2a\u0e14\u0e07\u0e15\u0e48\u0e2d\u0e44\u0e1b', frame: '\u0e40\u0e1f\u0e23\u0e21',
    confirmBms: '\u0e22\u0e37\u0e19\u0e22\u0e31\u0e19\u0e01\u0e32\u0e23\u0e40\u0e0b\u0e47\u0e19\u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21', reviewMessage: '\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21\u0e01\u0e48\u0e2d\u0e19\u0e40\u0e0b\u0e47\u0e19',
    type: '\u0e1b\u0e23\u0e30\u0e40\u0e20\u0e17', bmsType: 'BMS (\u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21 Bitcoin)', index: '\u0e14\u0e31\u0e0a\u0e19\u0e35', address: '\u0e17\u0e35\u0e48\u0e2d\u0e22\u0e39\u0e48', message: '\u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21',
    bmsSignature: '\u0e25\u0e32\u0e22\u0e40\u0e0b\u0e47\u0e19 BMS', sigBase64: '\u0e25\u0e32\u0e22\u0e40\u0e0b\u0e47\u0e19 (base64)', tapToCopy: '\u0e41\u0e15\u0e30\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e04\u0e31\u0e14\u0e25\u0e2d\u0e01', copySig: '\u0e04\u0e31\u0e14\u0e25\u0e2d\u0e01\u0e25\u0e32\u0e22\u0e40\u0e0b\u0e47\u0e19', sha256: 'SHA-256',
    settings: '\u0e15\u0e31\u0e49\u0e07\u0e04\u0e48\u0e32', version: '\u0e40\u0e27\u0e2d\u0e23\u0e4c\u0e0a\u0e31\u0e19', language: '\u0e20\u0e32\u0e29\u0e32', seedLanguage: '\u0e20\u0e32\u0e29\u0e32\u0e0a\u0e38\u0e14\u0e04\u0e33',
    onlineKeygenTitle: '\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22\u0e41\u0e25\u0e49\u0e27!',
    onlineKeygenBody: '\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e02\u0e2d\u0e07\u0e04\u0e38\u0e13\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d\u0e2d\u0e34\u0e19\u0e40\u0e17\u0e2d\u0e23\u0e4c\u0e40\u0e19\u0e47\u0e15 \u0e04\u0e35\u0e22\u0e4c\u0e17\u0e35\u0e48\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e02\u0e13\u0e30\u0e2d\u0e2d\u0e19\u0e44\u0e25\u0e19\u0e4c\u0e2d\u0e32\u0e08\u0e16\u0e39\u0e01\u0e14\u0e31\u0e01\u0e08\u0e31\u0e1a\u0e42\u0e14\u0e22\u0e21\u0e31\u0e25\u0e41\u0e27\u0e23\u0e4c \u0e15\u0e31\u0e14\u0e01\u0e32\u0e23\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 (WiFi, \u0e21\u0e37\u0e2d\u0e16\u0e37\u0e2d, Bluetooth, USB) \u0e01\u0e48\u0e2d\u0e19\u0e14\u0e33\u0e40\u0e19\u0e34\u0e19\u0e01\u0e32\u0e23',
    proceedAnyway: '\u0e14\u0e33\u0e40\u0e19\u0e34\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d (\u0e44\u0e21\u0e48\u0e1b\u0e25\u0e2d\u0e14\u0e20\u0e31\u0e22)',
    installGuide: '\u0e04\u0e39\u0e48\u0e21\u0e37\u0e2d\u0e01\u0e32\u0e23\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07', viewSource: '\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e04\u0e27\u0e32\u0e21\u0e2a\u0e21\u0e1a\u0e39\u0e23\u0e13\u0e4c\u0e02\u0e2d\u0e07\u0e42\u0e04\u0e49\u0e14', securityInfo: '\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e04\u0e27\u0e32\u0e21\u0e1b\u0e25\u0e2d\u0e14\u0e20\u0e31\u0e22',
    deleteKey: '\u0e25\u0e1a\u0e04\u0e35\u0e22\u0e4c', deleteConfirm1: '\u0e25\u0e1a\u0e04\u0e35\u0e22\u0e4c? \u0e44\u0e21\u0e48\u0e2a\u0e32\u0e21\u0e32\u0e23\u0e16\u0e22\u0e49\u0e2d\u0e19\u0e01\u0e25\u0e31\u0e1a\u0e44\u0e14\u0e49\n\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e27\u0e48\u0e32\u0e2a\u0e33\u0e23\u0e2d\u0e07\u0e0a\u0e38\u0e14\u0e04\u0e33\u0e44\u0e27\u0e49\u0e41\u0e25\u0e49\u0e27!',
    deleteConfirm2: '\u0e04\u0e38\u0e13\u0e41\u0e19\u0e48\u0e43\u0e08\u0e2b\u0e23\u0e37\u0e2d? Bitcoin \u0e08\u0e30\u0e2a\u0e39\u0e0d\u0e2b\u0e32\u0e22\u0e16\u0e49\u0e32\u0e44\u0e21\u0e48\u0e21\u0e35\u0e2a\u0e33\u0e23\u0e2d\u0e07',
    verifyIntegrity: '\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e04\u0e27\u0e32\u0e21\u0e2a\u0e21\u0e1a\u0e39\u0e23\u0e13\u0e4c', verifyDesc: '\u0e40\u0e1b\u0e23\u0e35\u0e22\u0e1a\u0e40\u0e17\u0e35\u0e22\u0e1a\u0e41\u0e2e\u0e0a SHA-256 \u0e01\u0e31\u0e1a\u0e40\u0e27\u0e2d\u0e23\u0e4c\u0e0a\u0e31\u0e19\u0e17\u0e32\u0e07\u0e01\u0e32\u0e23\u0e1a\u0e19 GitHub',
    computing: '\u0e01\u0e33\u0e25\u0e31\u0e07\u0e04\u0e33\u0e19\u0e27\u0e13...', fetchFailed: '(\u0e14\u0e32\u0e27\u0e19\u0e4c\u0e42\u0e2b\u0e25\u0e14\u0e25\u0e49\u0e21\u0e40\u0e2b\u0e25\u0e27)',
    verifyFile: '\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49', verifyFileDesc: '\u0e41\u0e15\u0e30\u0e17\u0e35\u0e48\u0e19\u0e35\u0e48\u0e41\u0e25\u0e49\u0e27\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e44\u0e1f\u0e25\u0e4c <strong>bitclutch-signer.html</strong> \u0e17\u0e35\u0e48\u0e14\u0e32\u0e27\u0e19\u0e4c\u0e42\u0e2b\u0e25\u0e14<br>SHA-256 \u0e08\u0e30\u0e04\u0e33\u0e19\u0e27\u0e13\u0e43\u0e19\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07',
    tapToSelect: '\u0e41\u0e15\u0e30\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e01', compareGithub: '\u0e40\u0e1b\u0e23\u0e35\u0e22\u0e1a\u0e01\u0e31\u0e1a <code>hashes.json</code> \u0e08\u0e32\u0e01 GitHub',
    auditableSource: '\u0e0b\u0e2d\u0e23\u0e4c\u0e2a\u0e42\u0e04\u0e49\u0e14\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e44\u0e14\u0e49', auditableDesc: '\u0e25\u0e2d\u0e08\u0e34\u0e01\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\u0e02\u0e2d\u0e07\u0e41\u0e2d\u0e1b\u0e2d\u0e22\u0e39\u0e48\u0e43\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e40\u0e14\u0e35\u0e22\u0e27\u0e17\u0e35\u0e48\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e44\u0e14\u0e49 \u0e0b\u0e2d\u0e23\u0e4c\u0e2a\u0e42\u0e04\u0e49\u0e14\u0e41\u0e25\u0e30\u0e41\u0e2e\u0e0a\u0e2d\u0e22\u0e39\u0e48\u0e1a\u0e19 GitHub',
    back: '\u0e01\u0e25\u0e31\u0e1a',
    securityTitle: '\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e04\u0e27\u0e32\u0e21\u0e1b\u0e25\u0e2d\u0e14\u0e20\u0e31\u0e22', securityLevel: '\u0e23\u0e30\u0e14\u0e31\u0e1a\u0e04\u0e27\u0e32\u0e21\u0e1b\u0e25\u0e2d\u0e14\u0e20\u0e31\u0e22: \u0e0b\u0e2d\u0e1f\u0e15\u0e4c\u0e41\u0e27\u0e23\u0e4c\u0e41\u0e2d\u0e23\u0e4c\u0e41\u0e01\u0e1b',
    whatProvides: '\u0e2a\u0e34\u0e48\u0e07\u0e17\u0e35\u0e48\u0e43\u0e2b\u0e49:', secProvide1: '\u0e04\u0e35\u0e22\u0e4c\u0e2a\u0e48\u0e27\u0e19\u0e15\u0e31\u0e27\u0e44\u0e21\u0e48\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d\u0e2d\u0e34\u0e19\u0e40\u0e17\u0e2d\u0e23\u0e4c\u0e40\u0e19\u0e47\u0e15 (\u0e2b\u0e25\u0e31\u0e07\u0e15\u0e31\u0e49\u0e07\u0e04\u0e48\u0e32)',
    secProvide2: '\u0e42\u0e04\u0e49\u0e14\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e44\u0e14\u0e49 (\u0e44\u0e1f\u0e25\u0e4c app.js \u0e40\u0e14\u0e35\u0e22\u0e27)', secProvide3: '\u0e40\u0e2d\u0e19\u0e42\u0e17\u0e23\u0e1b\u0e35\u0e08\u0e32\u0e01\u0e41\u0e2b\u0e25\u0e48\u0e07\u0e01\u0e32\u0e22\u0e20\u0e32\u0e1e\u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19 (\u0e25\u0e39\u0e01\u0e40\u0e15\u0e4b\u0e32/\u0e40\u0e2b\u0e23\u0e35\u0e22\u0e0d)',
    secProvide4: '\u0e01\u0e32\u0e23\u0e40\u0e02\u0e49\u0e32\u0e23\u0e2b\u0e31\u0e2a AES-256-GCM + 600K PBKDF2',
    whatNot: '\u0e2a\u0e34\u0e48\u0e07\u0e17\u0e35\u0e48\u0e44\u0e21\u0e48\u0e43\u0e2b\u0e49:', secNot1: 'Secure Element (\u0e01\u0e23\u0e30\u0e40\u0e1b\u0e4b\u0e32\u0e2e\u0e32\u0e23\u0e4c\u0e14\u0e41\u0e27\u0e23\u0e4c\u0e21\u0e35)',
    secNot2: '\u0e41\u0e2d\u0e23\u0e4c\u0e41\u0e01\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a\u0e2e\u0e32\u0e23\u0e4c\u0e14\u0e41\u0e27\u0e23\u0e4c (\u0e0a\u0e34\u0e1b WiFi \u0e22\u0e31\u0e07\u0e21\u0e35\u0e2d\u0e22\u0e39\u0e48)', secNot3: '\u0e01\u0e32\u0e23\u0e15\u0e49\u0e32\u0e19\u0e17\u0e32\u0e19\u0e01\u0e32\u0e23\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0a\u0e48\u0e2d\u0e07\u0e17\u0e32\u0e07\u0e02\u0e49\u0e32\u0e07',
    keyStorage: '\u0e17\u0e35\u0e48\u0e40\u0e01\u0e47\u0e1a\u0e04\u0e35\u0e22\u0e4c', encryption: '\u0e01\u0e32\u0e23\u0e40\u0e02\u0e49\u0e32\u0e23\u0e2b\u0e31\u0e2a:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600,000 \u0e23\u0e2d\u0e1a) + salt/IV \u0e2a\u0e38\u0e48\u0e21',
    warning: '\u0e04\u0e33\u0e40\u0e15\u0e37\u0e2d\u0e19:', clearDataWarning: '\u0e01\u0e32\u0e23\u0e25\u0e49\u0e32\u0e07\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e40\u0e1a\u0e23\u0e32\u0e27\u0e40\u0e0b\u0e2d\u0e23\u0e4c\u0e08\u0e30\u0e25\u0e1a\u0e04\u0e35\u0e22\u0e4c\u0e17\u0e35\u0e48\u0e40\u0e02\u0e49\u0e32\u0e23\u0e2b\u0e31\u0e2a\u0e16\u0e32\u0e27\u0e23 \u0e2a\u0e33\u0e23\u0e2d\u0e07\u0e0a\u0e38\u0e14\u0e04\u0e33\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c\u0e40\u0e2a\u0e21\u0e2d',
    autoLock: '\u0e25\u0e47\u0e2d\u0e01\u0e2d\u0e31\u0e15\u0e42\u0e19\u0e21\u0e31\u0e15\u0e34:', autoLockDesc: '\u0e04\u0e35\u0e22\u0e4c\u0e08\u0e30\u0e16\u0e39\u0e01\u0e25\u0e1a\u0e08\u0e32\u0e01\u0e2b\u0e19\u0e48\u0e27\u0e22\u0e04\u0e27\u0e32\u0e21\u0e08\u0e33\u0e2b\u0e25\u0e31\u0e07 5 \u0e19\u0e32\u0e17\u0e35\u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e43\u0e0a\u0e49\u0e07\u0e32\u0e19',
    storageEncKey: '\u0e04\u0e35\u0e22\u0e4c\u0e2a\u0e48\u0e27\u0e19\u0e15\u0e31\u0e27\u0e17\u0e35\u0e48\u0e40\u0e02\u0e49\u0e32\u0e23\u0e2b\u0e31\u0e2a (AES-256-GCM)', storageXpub: '\u0e04\u0e35\u0e22\u0e4c\u0e2a\u0e32\u0e18\u0e32\u0e23\u0e13\u0e30\u0e02\u0e22\u0e32\u0e22\u0e02\u0e2d\u0e07\u0e1a\u0e31\u0e0d\u0e0a\u0e35', storageFp: '\u0e25\u0e32\u0e22\u0e19\u0e34\u0e49\u0e27\u0e21\u0e37\u0e2d BIP-32',
    storageNet: '\u0e01\u0e32\u0e23\u0e15\u0e31\u0e49\u0e07\u0e04\u0e48\u0e32\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22 (main/test)', storageLang: '\u0e20\u0e32\u0e29\u0e32\u0e2d\u0e34\u0e19\u0e40\u0e17\u0e2d\u0e23\u0e4c\u0e40\u0e1f\u0e0b', storageSeedLang: '\u0e20\u0e32\u0e29\u0e32\u0e0a\u0e38\u0e14\u0e04\u0e33', storageKeyCreated: '\u0e27\u0e31\u0e19\u0e17\u0e35\u0e48\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e04\u0e35\u0e22\u0e4c', storageLastOnline: '\u0e27\u0e31\u0e19\u0e17\u0e35\u0e48\u0e15\u0e23\u0e27\u0e08\u0e1e\u0e1a\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22',
    guideTitle: '\u0e04\u0e39\u0e48\u0e21\u0e37\u0e2d\u0e01\u0e32\u0e23\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07', guideDesc: '\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07 BitClutch Signer \u0e40\u0e1b\u0e47\u0e19\u0e41\u0e2d\u0e1b\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c \u0e08\u0e32\u0e01\u0e19\u0e31\u0e49\u0e19\u0e40\u0e1b\u0e34\u0e14\u0e42\u0e2b\u0e21\u0e14\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1a\u0e34\u0e19\u0e01\u0e48\u0e2d\u0e19\u0e43\u0e0a\u0e49\u0e07\u0e32\u0e19',
    detected: '\u0e15\u0e23\u0e27\u0e08\u0e1e\u0e1a', accountXpubTitle: 'xpub \u0e1a\u0e31\u0e0d\u0e0a\u0e35',
    guideIosSafari: '<strong>\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e41\u0e2d\u0e1b\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c:</strong><ol><li>\u0e40\u0e1b\u0e34\u0e14\u0e2b\u0e19\u0e49\u0e32\u0e19\u0e35\u0e49\u0e43\u0e19 <strong>Safari</strong></li><li>\u0e41\u0e15\u0e30\u0e1b\u0e38\u0e48\u0e21 <strong>Share</strong> (\u0e01\u0e25\u0e48\u0e2d\u0e07\u0e21\u0e35\u0e25\u0e39\u0e01\u0e28\u0e23)</li><li>\u0e40\u0e25\u0e37\u0e48\u0e2d\u0e19\u0e25\u0e07\u0e41\u0e25\u0e49\u0e27\u0e41\u0e15\u0e30 <strong>"Add to Home Screen"</strong></li><li>\u0e41\u0e15\u0e30 <strong>"Add"</strong> \u0e17\u0e35\u0e48\u0e21\u0e38\u0e21\u0e02\u0e27\u0e32\u0e1a\u0e19</li></ol><strong>\u0e40\u0e1b\u0e34\u0e14\u0e43\u0e0a\u0e49\u0e42\u0e2b\u0e21\u0e14\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1a\u0e34\u0e19:</strong><ol><li>\u0e1b\u0e31\u0e14\u0e25\u0e07\u0e08\u0e32\u0e01\u0e21\u0e38\u0e21\u0e02\u0e27\u0e32\u0e1a\u0e19 (\u0e2b\u0e23\u0e37\u0e2d\u0e1b\u0e31\u0e14\u0e02\u0e36\u0e49\u0e19\u0e08\u0e32\u0e01\u0e14\u0e49\u0e32\u0e19\u0e25\u0e48\u0e32\u0e07\u0e2a\u0e33\u0e2b\u0e23\u0e31\u0e1a iPhone \u0e23\u0e38\u0e48\u0e19\u0e40\u0e01\u0e48\u0e32)</li><li>\u0e41\u0e15\u0e30\u0e44\u0e2d\u0e04\u0e2d\u0e19 <strong>airplane icon</strong> \u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e40\u0e1b\u0e34\u0e14\u0e43\u0e0a\u0e49\u0e07\u0e32\u0e19</li><li>\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e27\u0e48\u0e32 Wi-Fi \u0e41\u0e25\u0e30 Bluetooth \u0e1b\u0e34\u0e14\u0e2d\u0e22\u0e39\u0e48\u0e14\u0e49\u0e27\u0e22</li></ol>',
    guideIosChrome: '<strong>\u0e2a\u0e33\u0e04\u0e31\u0e0d:</strong> Chrome \u0e1a\u0e19 iOS \u0e44\u0e21\u0e48\u0e2a\u0e32\u0e21\u0e32\u0e23\u0e16\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07\u0e41\u0e2d\u0e1b\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c\u0e44\u0e14\u0e49 \u0e43\u0e0a\u0e49 <strong>Safari</strong> \u0e41\u0e17\u0e19<ol><li>\u0e04\u0e31\u0e14\u0e25\u0e2d\u0e01 URL \u0e02\u0e2d\u0e07\u0e2b\u0e19\u0e49\u0e32\u0e19\u0e35\u0e49</li><li>\u0e40\u0e1b\u0e34\u0e14 <strong>Safari</strong> \u0e41\u0e25\u0e49\u0e27\u0e27\u0e32\u0e07 URL</li><li>\u0e17\u0e33\u0e15\u0e32\u0e21\u0e04\u0e33\u0e41\u0e19\u0e30\u0e19\u0e33 <strong>iOS Safari</strong> \u0e14\u0e49\u0e32\u0e19\u0e1a\u0e19</li></ol><strong>\u0e40\u0e1b\u0e34\u0e14\u0e43\u0e0a\u0e49\u0e42\u0e2b\u0e21\u0e14\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1a\u0e34\u0e19:</strong><ol><li>\u0e1b\u0e31\u0e14\u0e25\u0e07\u0e08\u0e32\u0e01\u0e21\u0e38\u0e21\u0e02\u0e27\u0e32\u0e1a\u0e19</li><li>\u0e41\u0e15\u0e30\u0e44\u0e2d\u0e04\u0e2d\u0e19 <strong>airplane icon</strong></li></ol>',
    guideAndroidChrome: '<strong>\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e41\u0e2d\u0e1b\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c:</strong><ol><li>\u0e40\u0e1b\u0e34\u0e14\u0e2b\u0e19\u0e49\u0e32\u0e19\u0e35\u0e49\u0e43\u0e19 <strong>Chrome</strong></li><li>\u0e41\u0e15\u0e30 <strong>three-dot menu</strong> (\u0e21\u0e38\u0e21\u0e02\u0e27\u0e32\u0e1a\u0e19)</li><li>\u0e41\u0e15\u0e30 <strong>"Install app"</strong> \u0e2b\u0e23\u0e37\u0e2d <strong>"Add to Home screen"</strong></li><li>\u0e22\u0e37\u0e19\u0e22\u0e31\u0e19\u0e42\u0e14\u0e22\u0e41\u0e15\u0e30 <strong>"Install"</strong></li></ol><strong>\u0e40\u0e1b\u0e34\u0e14\u0e43\u0e0a\u0e49\u0e42\u0e2b\u0e21\u0e14\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1a\u0e34\u0e19:</strong><ol><li>\u0e1b\u0e31\u0e14\u0e25\u0e07\u0e08\u0e32\u0e01\u0e14\u0e49\u0e32\u0e19\u0e1a\u0e19\u0e02\u0e2d\u0e07\u0e2b\u0e19\u0e49\u0e32\u0e08\u0e2d</li><li>\u0e41\u0e15\u0e30 <strong>"Airplane mode"</strong></li><li>\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e27\u0e48\u0e32 Wi-Fi \u0e41\u0e25\u0e30\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e21\u0e37\u0e2d\u0e16\u0e37\u0e2d\u0e1b\u0e34\u0e14\u0e2d\u0e22\u0e39\u0e48</li></ol>',
    guideAndroidSamsung: '<strong>\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e41\u0e2d\u0e1b\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c:</strong><ol><li>\u0e40\u0e1b\u0e34\u0e14\u0e2b\u0e19\u0e49\u0e32\u0e19\u0e35\u0e49\u0e43\u0e19 <strong>Samsung Internet</strong></li><li>\u0e41\u0e15\u0e30 <strong>menu icon</strong> (\u0e2a\u0e32\u0e21\u0e40\u0e2a\u0e49\u0e19 \u0e21\u0e38\u0e21\u0e25\u0e48\u0e32\u0e07\u0e02\u0e27\u0e32)</li><li>\u0e41\u0e15\u0e30 <strong>"Add page to"</strong> \u0e41\u0e25\u0e49\u0e27\u0e40\u0e25\u0e37\u0e2d\u0e01 <strong>"Home screen"</strong></li></ol><strong>\u0e40\u0e1b\u0e34\u0e14\u0e43\u0e0a\u0e49\u0e42\u0e2b\u0e21\u0e14\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1a\u0e34\u0e19:</strong><ol><li>\u0e1b\u0e31\u0e14\u0e25\u0e07\u0e08\u0e32\u0e01\u0e14\u0e49\u0e32\u0e19\u0e1a\u0e19\u0e2a\u0e2d\u0e07\u0e04\u0e23\u0e31\u0e49\u0e07\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e40\u0e1b\u0e34\u0e14 Quick Settings</li><li>\u0e41\u0e15\u0e30 <strong>"Airplane mode"</strong></li></ol>',
    guideMacosSafari: '<strong>\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e41\u0e2d\u0e1b\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c (macOS Sonoma+):</strong><ol><li>\u0e40\u0e1b\u0e34\u0e14\u0e2b\u0e19\u0e49\u0e32\u0e19\u0e35\u0e49\u0e43\u0e19 <strong>Safari</strong></li><li>\u0e04\u0e25\u0e34\u0e01\u0e40\u0e21\u0e19\u0e39 <strong>File</strong> \u0e41\u0e25\u0e49\u0e27\u0e40\u0e25\u0e37\u0e2d\u0e01 <strong>"Add to Dock"</strong></li><li>\u0e04\u0e25\u0e34\u0e01 <strong>"Add"</strong></li></ol><strong>\u0e1b\u0e34\u0e14\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22:</strong><ol><li>\u0e04\u0e25\u0e34\u0e01\u0e44\u0e2d\u0e04\u0e2d\u0e19 <strong>Wi-Fi icon</strong> \u0e43\u0e19\u0e41\u0e16\u0e1a\u0e40\u0e21\u0e19\u0e39</li><li>\u0e04\u0e25\u0e34\u0e01\u0e40\u0e1e\u0e37\u0e48\u0e2d <strong>turn Wi-Fi off</strong></li><li>\u0e16\u0e2d\u0e14\u0e2a\u0e32\u0e22 Ethernet \u0e2d\u0e2d\u0e01</li></ol>',
    guideMacosChrome: '<strong>\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e41\u0e2d\u0e1b\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c:</strong><ol><li>\u0e40\u0e1b\u0e34\u0e14\u0e2b\u0e19\u0e49\u0e32\u0e19\u0e35\u0e49\u0e43\u0e19 <strong>Chrome</strong></li><li>\u0e04\u0e25\u0e34\u0e01 <strong>install icon</strong> \u0e43\u0e19\u0e41\u0e16\u0e1a\u0e17\u0e35\u0e48\u0e2d\u0e22\u0e39\u0e48 (\u0e2b\u0e23\u0e37\u0e2d three-dot menu &rarr; "Install BitClutch Signer")</li><li>\u0e04\u0e25\u0e34\u0e01 <strong>"Install"</strong></li></ol><strong>\u0e1b\u0e34\u0e14\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22:</strong><ol><li>\u0e04\u0e25\u0e34\u0e01\u0e44\u0e2d\u0e04\u0e2d\u0e19 <strong>Wi-Fi icon</strong> \u0e43\u0e19\u0e41\u0e16\u0e1a\u0e40\u0e21\u0e19\u0e39</li><li>\u0e04\u0e25\u0e34\u0e01\u0e40\u0e1e\u0e37\u0e48\u0e2d <strong>turn Wi-Fi off</strong></li><li>\u0e16\u0e2d\u0e14\u0e2a\u0e32\u0e22 Ethernet \u0e2d\u0e2d\u0e01</li></ol>',
    guideWindowsChrome: '<strong>\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e41\u0e2d\u0e1b\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c:</strong><ol><li>\u0e40\u0e1b\u0e34\u0e14\u0e2b\u0e19\u0e49\u0e32\u0e19\u0e35\u0e49\u0e43\u0e19 <strong>Chrome</strong></li><li>\u0e04\u0e25\u0e34\u0e01 <strong>install icon</strong> \u0e43\u0e19\u0e41\u0e16\u0e1a\u0e17\u0e35\u0e48\u0e2d\u0e22\u0e39\u0e48 (\u0e2b\u0e23\u0e37\u0e2d three-dot menu &rarr; "Install BitClutch Signer")</li><li>\u0e04\u0e25\u0e34\u0e01 <strong>"Install"</strong></li></ol><strong>\u0e1b\u0e34\u0e14\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22:</strong><ol><li>\u0e04\u0e25\u0e34\u0e01\u0e44\u0e2d\u0e04\u0e2d\u0e19 <strong>Wi-Fi icon</strong> \u0e43\u0e19\u0e41\u0e16\u0e1a\u0e07\u0e32\u0e19 (\u0e25\u0e48\u0e32\u0e07\u0e02\u0e27\u0e32)</li><li>\u0e04\u0e25\u0e34\u0e01\u0e40\u0e1e\u0e37\u0e48\u0e2d<strong>\u0e15\u0e31\u0e14\u0e01\u0e32\u0e23\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d Wi-Fi</strong></li><li>\u0e16\u0e2d\u0e14\u0e2a\u0e32\u0e22 Ethernet \u0e2d\u0e2d\u0e01</li></ol>',
    guideWindowsEdge: '<strong>\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e41\u0e2d\u0e1b\u0e2d\u0e2d\u0e1f\u0e44\u0e25\u0e19\u0e4c:</strong><ol><li>\u0e40\u0e1b\u0e34\u0e14\u0e2b\u0e19\u0e49\u0e32\u0e19\u0e35\u0e49\u0e43\u0e19 <strong>Edge</strong></li><li>\u0e04\u0e25\u0e34\u0e01 <strong>install icon</strong> \u0e43\u0e19\u0e41\u0e16\u0e1a\u0e17\u0e35\u0e48\u0e2d\u0e22\u0e39\u0e48 (\u0e2b\u0e23\u0e37\u0e2d three-dot menu &rarr; "\u0e41\u0e2d\u0e1b" &rarr; "Install BitClutch Signer")</li><li>\u0e04\u0e25\u0e34\u0e01 <strong>"Install"</strong></li></ol><strong>\u0e1b\u0e34\u0e14\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22:</strong><ol><li>\u0e04\u0e25\u0e34\u0e01\u0e44\u0e2d\u0e04\u0e2d\u0e19 <strong>Wi-Fi icon</strong> \u0e43\u0e19\u0e41\u0e16\u0e1a\u0e07\u0e32\u0e19 (\u0e25\u0e48\u0e32\u0e07\u0e02\u0e27\u0e32)</li><li>\u0e04\u0e25\u0e34\u0e01\u0e40\u0e1e\u0e37\u0e48\u0e2d<strong>\u0e15\u0e31\u0e14\u0e01\u0e32\u0e23\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d Wi-Fi</strong></li><li>\u0e16\u0e2d\u0e14\u0e2a\u0e32\u0e22 Ethernet \u0e2d\u0e2d\u0e01</li></ol>',
    noMnemonic: '\u0e44\u0e21\u0e48\u0e21\u0e35 mnemonic', noTxData: '\u0e44\u0e21\u0e48\u0e21\u0e35\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e18\u0e38\u0e23\u0e01\u0e23\u0e23\u0e21', noSignedData: '\u0e44\u0e21\u0e48\u0e21\u0e35\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e17\u0e35\u0e48\u0e40\u0e0b\u0e47\u0e19',
    noBmsRequest: '\u0e44\u0e21\u0e48\u0e21\u0e35\u0e04\u0e33\u0e02\u0e2d BMS', noSignature: '\u0e44\u0e21\u0e48\u0e21\u0e35\u0e25\u0e32\u0e22\u0e40\u0e0b\u0e47\u0e19', loading: '\u0e01\u0e33\u0e25\u0e31\u0e07\u0e42\u0e2b\u0e25\u0e14...',
    bannerWarn: '\u0e1e\u0e1a\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22 \u2014 \u0e15\u0e31\u0e14\u0e01\u0e32\u0e23\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\u0e01\u0e48\u0e2d\u0e19\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e04\u0e35\u0e22\u0e4c',
    bannerOnline: '\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d\u0e2d\u0e22\u0e39\u0e48 \u2014 \u0e15\u0e31\u0e14\u0e01\u0e32\u0e23\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d\u0e17\u0e31\u0e19\u0e17\u0e35\u0e41\u0e25\u0e30\u0e2b\u0e49\u0e32\u0e21\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e19\u0e35\u0e49\u0e2d\u0e35\u0e01 \u0e04\u0e35\u0e22\u0e4c\u0e2d\u0e32\u0e08\u0e16\u0e39\u0e01\u0e40\u0e1b\u0e34\u0e14\u0e40\u0e1c\u0e22\u0e41\u0e25\u0e49\u0e27',
    bannerOffline: '\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e40\u0e04\u0e23\u0e37\u0e2d\u0e02\u0e48\u0e32\u0e22\u0e44\u0e23\u0e49\u0e2a\u0e32\u0e22 \u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e27\u0e48\u0e32 Bluetooth, NFC \u0e41\u0e25\u0e30\u0e2a\u0e32\u0e22 USB \u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e16\u0e39\u0e01\u0e15\u0e31\u0e14\u0e01\u0e32\u0e23\u0e40\u0e0a\u0e37\u0e48\u0e2d\u0e21\u0e15\u0e48\u0e2d\u0e14\u0e49\u0e27\u0e22',
  },
  id: {
    unlocked: 'Terbuka', locked: 'Terkunci',
    tabKey: 'Kunci', tabSign: 'Tanda tangan', tabSettings: 'Pengaturan',
    createKeys: 'Buat kunci Anda',
    setupDesc: 'Buat kunci baru dengan entropi fisik,<br>atau impor frasa benih yang sudah ada.',
    diceBtn: 'Dadu (99 lemparan)', coinBtn: 'Koin (256 lemparan)', importBtn: 'Impor frasa benih',
    enterPassphrase: 'Masukkan kata sandi untuk membuka', passphrase: 'Kata sandi', unlock: 'Buka kunci', wrongPassphrase: 'Kata sandi salah.',
    yourKey: 'Kunci Anda', network: 'Jaringan', fingerprint: 'Sidik jari', keyCreated: 'Dibuat', lastOnline: 'Terakhir online', neverOnline: 'Belum pernah (aman)', onlineAfterKey: 'Online terdeteksi setelah pembuatan', accountXpub: 'xpub akun',
    showXpubQR: 'Tampilkan QR xpub', lockBtn: 'Kunci', mainnet: 'Mainnet', testnet: 'Testnet',
    diceTitle: 'Pembuatan kunci dadu', diceDesc: 'Lempar dadu fisik asli dan ketuk hasilnya.',
    progress: 'Kemajuan', undoLast: 'Batalkan', cancel: 'Batal', ok: 'OK',
    coinTitle: 'Pembuatan kunci koin', coinDesc: 'Lempar koin fisik asli dan ketuk hasilnya.',
    entropyWarning: 'Gunakan dadu/koin fisik asli \u2014 jangan pernah mengarang angka. Pilihan manusia dapat diprediksi dan melemahkan kunci Anda. Pastikan tidak ada kamera atau mikrofon di dekat \u2014 siapa pun yang melihat lemparan Anda dapat mencuri Bitcoin Anda.',
    heads: 'H (Kepala)', tails: 'T (Ekor)',
    writeDown: 'Tuliskan kata-kata ini!',
    mnemonicDesc: 'Ini adalah frasa benih Anda. Simpan secara aman offline. TIDAK akan ditampilkan lagi.',
    stolenVsLost: 'Dicuri vs. Hilang \u2014 ketahui perbedaannya',
    theft: 'Pencurian:', theftDesc: 'Jika seseorang menemukan frasa benih Anda, mereka bisa langsung mencuri Bitcoin Anda. Tidak ada yang bisa membatalkannya.',
    loss: 'Kehilangan:', lossDesc: 'Jika Anda kehilangan frasa benih dan perangkat rusak, Bitcoin Anda hilang selamanya \u2014 kecuali Anda punya rencana pemulihan.',
    bitclutchPromo: '<strong>BitClutch</strong> melindungi dari kehilangan dan kematian, bukan pencurian. Buat <strong>Dompet Terlindungi</strong> dengan timelock \u2014 Bitcoin tetap milik Anda, tapi pewaris dapat memulihkannya.',
    visitBitclutch: 'Kunjungi <strong>bitclutch.app</strong> di perangkat online untuk membuat Dompet Terlindungi.',
    confirmedWritten: 'Sudah ditulis',
    importTitle: 'Impor frasa benih', importDesc: 'Pilih jumlah kata dan bahasa, lalu masukkan setiap kata.',
    importPlaceholder: 'kata1 kata2 kata3 ...', importAction: 'Impor', words: 'kata',
    fillAllWords: 'Mohon isi semua kata.', needWords: 'Butuh 12 atau 24 kata', invalidMnemonic: 'Mnemonik tidak valid',
    setPassTitle: 'Atur kata sandi', setPassDesc: 'Pilih kata sandi kuat untuk mengenkripsi kunci pribadi Anda. Diperlukan setiap kali membuka.',
    confirmPass: 'Konfirmasi kata sandi', enterPass: 'Masukkan kata sandi',
    passRequired: 'Kata sandi wajib.', passTooShort: 'Kata sandi terlalu pendek (min. 4 karakter).', passNoMatch: 'Kata sandi tidak cocok.',
    noKeyToSave: 'Tidak ada kunci untuk disimpan. Mulai ulang.', encryptSave: 'Enkripsi & simpan', encryptFailed: 'Enkripsi gagal: ',
    scanTitle: 'Pindai QR', scanDesc: 'Arahkan kamera ke kode QR dari aplikasi BitClutch Anda.',
    startingCamera: 'Memulai kamera...', scanning: 'Memindai... Arahkan ke QR.', cameraError: 'Error kamera: ',
    receivingFountain: 'Menerima kode fountain...', urFailed: 'Dekode UR gagal. Coba lagi.', psbtParseError: 'Error parsing PSBT: ',
    confirmTx: 'Konfirmasi transaksi', reviewBeforeSign: 'Periksa dengan teliti sebelum menandatangani.',
    inputs: 'Input', output: 'Output', change: '(kembalian)', fee: 'Biaya', reject: 'Tolak', sign: 'Tanda tangan', signingFailed: 'Penandatanganan gagal: ',
    signedPsbt: 'PSBT ditandatangani', showQRDesc: 'Biarkan aplikasi BitClutch memindai kode QR ini untuk menyiarkan transaksi.', scanComplete: 'Pemindaian selesai', scanSignatureDesc: 'Biarkan aplikasi BitClutch memindai kode QR ini untuk mengirim tanda tangan.',
    singleQR: 'QR tunggal', fountainKeepShowing: 'kode fountain \u2014 terus tampilkan', frame: 'Bingkai',
    confirmBms: 'Konfirmasi tanda tangan pesan', reviewMessage: 'Periksa pesan sebelum menandatangani.',
    type: 'Tipe', bmsType: 'BMS (Pesan Bitcoin)', index: 'Indeks', address: 'Alamat', message: 'Pesan',
    bmsSignature: 'Tanda tangan BMS', sigBase64: 'Tanda tangan (base64)', tapToCopy: 'Ketuk untuk menyalin', copySig: 'Salin tanda tangan', sha256: 'SHA-256',
    settings: 'Pengaturan', version: 'Versi', language: 'Bahasa', seedLanguage: 'Bahasa benih',
    onlineKeygenTitle: 'Jaringan terhubung!',
    onlineKeygenBody: 'Perangkat Anda terhubung ke internet. Kunci yang dibuat secara online dapat dicegat oleh malware. Putuskan SEMUA jaringan (WiFi, seluler, Bluetooth, USB) sebelum melanjutkan.',
    proceedAnyway: 'Tetap lanjutkan (tidak aman)',
    installGuide: 'Panduan instalasi', viewSource: 'Verifikasi integritas kode', securityInfo: 'Info keamanan',
    deleteKey: 'Hapus kunci', deleteConfirm1: 'Hapus kunci? Tidak dapat dibatalkan.\nPastikan frasa benih sudah dicadangkan!',
    deleteConfirm2: 'Apakah Anda yakin? Bitcoin akan HILANG tanpa cadangan.',
    verifyIntegrity: 'Verifikasi integritas', verifyDesc: 'Bandingkan hash SHA-256 dengan rilis resmi di GitHub.',
    computing: 'Menghitung...', fetchFailed: '(unduhan gagal)',
    verifyFile: 'Verifikasi file ini', verifyFileDesc: 'Ketuk di sini dan pilih file <strong>bitclutch-signer.html</strong> yang diunduh.<br>Hash SHA-256 akan dihitung secara lokal.',
    tapToSelect: 'Ketuk untuk memilih', compareGithub: 'Bandingkan dengan <code>hashes.json</code> dari rilis GitHub.',
    auditableSource: 'Kode sumber yang dapat diaudit', auditableDesc: 'Seluruh logika aplikasi ada dalam satu file yang dapat diaudit. Kode sumber dan hash resmi dipublikasikan di GitHub.',
    back: 'Kembali',
    securityTitle: 'Informasi keamanan', securityLevel: 'Tingkat keamanan: Air-gap perangkat lunak',
    whatProvides: 'Yang disediakan:', secProvide1: 'Kunci pribadi tidak pernah menyentuh internet (setelah pengaturan)',
    secProvide2: 'Kode dapat diaudit (file app.js tunggal)', secProvide3: 'Entropi hanya dari sumber fisik (dadu/koin)',
    secProvide4: 'Enkripsi AES-256-GCM dengan 600K iterasi PBKDF2',
    whatNot: 'Yang TIDAK disediakan:', secNot1: 'Secure Element (dompet perangkat keras memilikinya)',
    secNot2: 'Air gap perangkat keras (chip WiFi masih ada)', secNot3: 'Ketahanan terhadap serangan side-channel',
    keyStorage: 'Penyimpanan kunci', encryption: 'Enkripsi:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600.000 iterasi) + salt/IV acak',
    warning: 'Peringatan:', clearDataWarning: 'Menghapus data browser akan menghapus kunci terenkripsi secara permanen. Selalu cadangkan frasa benih secara offline.',
    autoLock: 'Kunci otomatis:', autoLockDesc: 'Kunci dihapus dari memori setelah 5 menit tidak aktif.',
    storageEncKey: 'Kunci pribadi terenkripsi (AES-256-GCM)', storageXpub: 'Kunci publik diperluas akun', storageFp: 'Sidik jari BIP-32',
    storageNet: 'Pengaturan jaringan (main/test)', storageLang: 'Bahasa antarmuka', storageSeedLang: 'Bahasa frasa benih', storageKeyCreated: 'Tanggal pembuatan kunci', storageLastOnline: 'Tanggal deteksi jaringan',
    guideTitle: 'Panduan instalasi', guideDesc: 'Instal BitClutch Signer sebagai aplikasi offline, lalu aktifkan mode pesawat sebelum menggunakan.',
    detected: 'Terdeteksi', accountXpubTitle: 'xpub akun',
    guideIosSafari: '<strong>Instal sebagai aplikasi offline:</strong><ol><li>Buka halaman ini di <strong>Safari</strong></li><li>Ketuk tombol <strong>Share</strong> (kotak dengan panah)</li><li>Gulir ke bawah dan ketuk <strong>"Add to Home Screen"</strong></li><li>Ketuk <strong>"Add"</strong> di kanan atas</li></ol><strong>Aktifkan Mode Pesawat:</strong><ol><li>Geser ke bawah dari sudut kanan atas (atau ke atas dari bawah pada iPhone lama)</li><li>Ketuk ikon <strong>airplane icon</strong> untuk mengaktifkan</li><li>Pastikan Wi-Fi dan Bluetooth juga MATI</li></ol>',
    guideIosChrome: '<strong>Penting:</strong> Chrome di iOS tidak dapat menginstal aplikasi offline. Gunakan <strong>Safari</strong> sebagai gantinya.<ol><li>Salin URL halaman ini</li><li>Buka <strong>Safari</strong> dan tempel URL</li><li>Ikuti petunjuk <strong>iOS Safari</strong> di atas</li></ol><strong>Aktifkan Mode Pesawat:</strong><ol><li>Geser ke bawah dari sudut kanan atas</li><li>Ketuk ikon <strong>airplane icon</strong></li></ol>',
    guideAndroidChrome: '<strong>Instal sebagai aplikasi offline:</strong><ol><li>Buka halaman ini di <strong>Chrome</strong></li><li>Ketuk <strong>three-dot menu</strong> (kanan atas)</li><li>Ketuk <strong>"Install app"</strong> atau <strong>"Add to Home screen"</strong></li><li>Konfirmasi dengan mengetuk <strong>"Install"</strong></li></ol><strong>Aktifkan Mode Pesawat:</strong><ol><li>Geser ke bawah dari bagian atas layar</li><li>Ketuk <strong>"Airplane mode"</strong></li><li>Pastikan Wi-Fi dan data seluler MATI</li></ol>',
    guideAndroidSamsung: '<strong>Instal sebagai aplikasi offline:</strong><ol><li>Buka halaman ini di <strong>Samsung Internet</strong></li><li>Ketuk <strong>menu icon</strong> (tiga garis, kanan bawah)</li><li>Ketuk <strong>"Add page to"</strong> lalu <strong>"Home screen"</strong></li></ol><strong>Aktifkan Mode Pesawat:</strong><ol><li>Geser ke bawah dari atas dua kali untuk membuka Quick Settings</li><li>Ketuk <strong>"Airplane mode"</strong></li></ol>',
    guideMacosSafari: '<strong>Instal sebagai aplikasi offline (macOS Sonoma+):</strong><ol><li>Buka halaman ini di <strong>Safari</strong></li><li>Klik menu <strong>File</strong> lalu <strong>"Add to Dock"</strong></li><li>Klik <strong>"Add"</strong></li></ol><strong>Nonaktifkan Jaringan:</strong><ol><li>Klik ikon <strong>Wi-Fi icon</strong> di bilah menu</li><li>Klik untuk <strong>turn Wi-Fi off</strong></li><li>Cabut semua kabel Ethernet</li></ol>',
    guideMacosChrome: '<strong>Instal sebagai aplikasi offline:</strong><ol><li>Buka halaman ini di <strong>Chrome</strong></li><li>Klik <strong>install icon</strong> di bilah alamat (atau three-dot menu &rarr; "Install BitClutch Signer")</li><li>Klik <strong>"Install"</strong></li></ol><strong>Nonaktifkan Jaringan:</strong><ol><li>Klik ikon <strong>Wi-Fi icon</strong> di bilah menu</li><li>Klik untuk <strong>turn Wi-Fi off</strong></li><li>Cabut semua kabel Ethernet</li></ol>',
    guideWindowsChrome: '<strong>Instal sebagai aplikasi offline:</strong><ol><li>Buka halaman ini di <strong>Chrome</strong></li><li>Klik <strong>install icon</strong> di bilah alamat (atau three-dot menu &rarr; "Install BitClutch Signer")</li><li>Klik <strong>"Install"</strong></li></ol><strong>Nonaktifkan Jaringan:</strong><ol><li>Klik ikon <strong>Wi-Fi icon</strong> di bilah tugas (kanan bawah)</li><li>Klik untuk <strong>memutuskan Wi-Fi</strong></li><li>Cabut semua kabel Ethernet</li></ol>',
    guideWindowsEdge: '<strong>Instal sebagai aplikasi offline:</strong><ol><li>Buka halaman ini di <strong>Edge</strong></li><li>Klik <strong>install icon</strong> di bilah alamat (atau three-dot menu &rarr; "Aplikasi" &rarr; "Install BitClutch Signer")</li><li>Klik <strong>"Install"</strong></li></ol><strong>Nonaktifkan Jaringan:</strong><ol><li>Klik ikon <strong>Wi-Fi icon</strong> di bilah tugas (kanan bawah)</li><li>Klik untuk <strong>memutuskan Wi-Fi</strong></li><li>Cabut semua kabel Ethernet</li></ol>',
    noMnemonic: 'Tidak ada mnemonik.', noTxData: 'Tidak ada data transaksi.', noSignedData: 'Tidak ada data yang ditandatangani.',
    noBmsRequest: 'Tidak ada permintaan BMS.', noSignature: 'Tidak ada tanda tangan.', loading: 'Memuat...',
    bannerWarn: 'JARINGAN TERDETEKSI \u2014 Putuskan semua jaringan sebelum membuat kunci.',
    bannerOnline: 'JARINGAN TERHUBUNG \u2014 Putuskan SEKARANG dan JANGAN PERNAH hubungkan lagi perangkat ini. Kunci mungkin sudah terekspos.',
    bannerOffline: 'Tidak ada jaringan nirkabel terdeteksi. Pastikan Bluetooth, NFC, dan kabel USB data juga terputus.',
  },
  ar: {
    unlocked: '\u063a\u064a\u0631 \u0645\u0642\u0641\u0644', locked: '\u0645\u0642\u0641\u0644',
    tabKey: '\u0645\u0641\u062a\u0627\u062d', tabSign: '\u062a\u0648\u0642\u064a\u0639', tabSettings: '\u0625\u0639\u062f\u0627\u062f\u0627\u062a',
    createKeys: '\u0623\u0646\u0634\u0626 \u0645\u0641\u062a\u0627\u062d\u0643',
    setupDesc: '\u0623\u0646\u0634\u0626 \u0645\u0641\u062a\u0627\u062d\u064b\u0627 \u062c\u062f\u064a\u062f\u064b\u0627 \u0628\u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0625\u0646\u062a\u0631\u0648\u0628\u064a\u0627 \u0641\u064a\u0632\u064a\u0627\u0626\u064a\u0629,<br>\u0623\u0648 \u0627\u0633\u062a\u0648\u0631\u062f \u0639\u0628\u0627\u0631\u0629 \u0628\u0630\u0631\u0629 \u0645\u0648\u062c\u0648\u062f\u0629.',
    diceBtn: '\u0646\u0631\u062f (99 \u0631\u0645\u064a\u0629)', coinBtn: '\u0639\u0645\u0644\u0629 (256 \u0631\u0645\u064a\u0629)', importBtn: '\u0627\u0633\u062a\u064a\u0631\u0627\u062f \u0639\u0628\u0627\u0631\u0629 \u0627\u0644\u0628\u0630\u0631\u0629',
    enterPassphrase: '\u0623\u062f\u062e\u0644 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0644\u0641\u062a\u062d \u0627\u0644\u0642\u0641\u0644', passphrase: '\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631', unlock: '\u0641\u062a\u062d', wrongPassphrase: '\u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u062e\u0627\u0637\u0626\u0629.',
    yourKey: '\u0645\u0641\u062a\u0627\u062d\u0643', network: '\u0627\u0644\u0634\u0628\u0643\u0629', fingerprint: '\u0627\u0644\u0628\u0635\u0645\u0629', keyCreated: '\u062a\u0627\u0631\u064a\u062e \u0627\u0644\u0625\u0646\u0634\u0627\u0621', lastOnline: '\u0622\u062e\u0631 \u0627\u062a\u0635\u0627\u0644', neverOnline: '\u0623\u0628\u062f\u064b\u0627 (\u0622\u0645\u0646)', onlineAfterKey: '\u062a\u0645 \u0627\u0644\u0643\u0634\u0641 \u0639\u0646 \u0627\u062a\u0635\u0627\u0644 \u0628\u0639\u062f \u0627\u0644\u0625\u0646\u0634\u0627\u0621', accountXpub: 'xpub \u0627\u0644\u062d\u0633\u0627\u0628',
    showXpubQR: '\u0639\u0631\u0636 QR xpub', lockBtn: '\u0642\u0641\u0644', mainnet: '\u0627\u0644\u0634\u0628\u0643\u0629 \u0627\u0644\u0631\u0626\u064a\u0633\u064a\u0629', testnet: '\u0634\u0628\u0643\u0629 \u0627\u0644\u0627\u062e\u062a\u0628\u0627\u0631',
    diceTitle: '\u062a\u0648\u0644\u064a\u062f \u0645\u0641\u062a\u0627\u062d \u0628\u0627\u0644\u0646\u0631\u062f', diceDesc: '\u0627\u0631\u0645\u0650 \u0646\u0631\u062f\u064b\u0627 \u062d\u0642\u064a\u0642\u064a\u064b\u0627 \u0648\u0627\u0646\u0642\u0631 \u0627\u0644\u0646\u062a\u064a\u062c\u0629.',
    progress: '\u0627\u0644\u062a\u0642\u062f\u0645', undoLast: '\u062a\u0631\u0627\u062c\u0639', cancel: '\u0625\u0644\u063a\u0627\u0621', ok: '\u0645\u0648\u0627\u0641\u0642',
    coinTitle: '\u062a\u0648\u0644\u064a\u062f \u0645\u0641\u062a\u0627\u062d \u0628\u0627\u0644\u0639\u0645\u0644\u0629', coinDesc: '\u0627\u0631\u0645\u0650 \u0639\u0645\u0644\u0629 \u062d\u0642\u064a\u0642\u064a\u0629 \u0648\u0627\u0646\u0642\u0631 \u0627\u0644\u0646\u062a\u064a\u062c\u0629.',
    entropyWarning: '\u0627\u0633\u062a\u062e\u062f\u0645 \u0646\u0631\u062f\u064b\u0627/\u0639\u0645\u0644\u0629 \u062d\u0642\u064a\u0642\u064a\u0629 \u2014 \u0644\u0627 \u062a\u062e\u062a\u0644\u0642 \u0623\u0631\u0642\u0627\u0645\u064b\u0627 \u0623\u0628\u062f\u064b\u0627. \u0627\u062e\u062a\u064a\u0627\u0631\u0627\u062a \u0627\u0644\u0625\u0646\u0633\u0627\u0646 \u0642\u0627\u0628\u0644\u0629 \u0644\u0644\u062a\u0646\u0628\u0624 \u0648\u062a\u064f\u0636\u0639\u0641 \u0645\u0641\u062a\u0627\u062d\u0643. \u062a\u0623\u0643\u062f \u0645\u0646 \u0639\u062f\u0645 \u0648\u062c\u0648\u062f \u0643\u0627\u0645\u064a\u0631\u0627\u062a \u0623\u0648 \u0645\u064a\u0643\u0631\u0648\u0641\u0648\u0646\u0627\u062a \u0642\u0631\u064a\u0628\u0629 \u2014 \u0645\u0646 \u064a\u0631\u0649 \u0631\u0645\u064a\u0627\u062a\u0643 \u064a\u0645\u0643\u0646\u0647 \u0633\u0631\u0642\u0629 \u0628\u062a\u0643\u0648\u064a\u0646\u0643.',
    heads: 'H (\u0635\u0648\u0631\u0629)', tails: 'T (\u0643\u062a\u0627\u0628\u0629)',
    writeDown: '\u0627\u0643\u062a\u0628 \u0647\u0630\u0647 \u0627\u0644\u0643\u0644\u0645\u0627\u062a!',
    mnemonicDesc: '\u0647\u0630\u0647 \u0639\u0628\u0627\u0631\u0629 \u0627\u0644\u0628\u0630\u0631\u0629 \u0627\u0644\u062e\u0627\u0635\u0629 \u0628\u0643. \u0627\u062d\u0641\u0638\u0647\u0627 \u0628\u0623\u0645\u0627\u0646 \u0628\u062f\u0648\u0646 \u0627\u062a\u0635\u0627\u0644. \u0644\u0646 \u062a\u064f\u0639\u0631\u0636 \u0645\u0631\u0629 \u0623\u062e\u0631\u0649.',
    stolenVsLost: '\u0645\u0633\u0631\u0648\u0642 \u0645\u0642\u0627\u0628\u0644 \u0645\u0641\u0642\u0648\u062f \u2014 \u0627\u0639\u0631\u0641 \u0627\u0644\u0641\u0631\u0642',
    theft: '\u0633\u0631\u0642\u0629:', theftDesc: '\u0625\u0630\u0627 \u0648\u062c\u062f \u0634\u062e\u0635 \u0639\u0628\u0627\u0631\u0629 \u0627\u0644\u0628\u0630\u0631\u0629\u060c \u064a\u0645\u0643\u0646\u0647 \u0633\u0631\u0642\u0629 \u0628\u062a\u0643\u0648\u064a\u0646 \u0641\u0648\u0631\u064b\u0627. \u0644\u0627 \u064a\u0645\u0643\u0646 \u0644\u0623\u062d\u062f \u0639\u0643\u0633 \u0630\u0644\u0643.',
    loss: '\u0641\u0642\u062f\u0627\u0646:', lossDesc: '\u0625\u0630\u0627 \u0641\u0642\u062f\u062a \u0627\u0644\u0639\u0628\u0627\u0631\u0629 \u0648\u062a\u0639\u0637\u0644 \u0627\u0644\u062c\u0647\u0627\u0632\u060c \u062a\u0636\u064a\u0639 \u0628\u062a\u0643\u0648\u064a\u0646 \u0644\u0644\u0623\u0628\u062f \u2014 \u0625\u0644\u0627 \u0625\u0630\u0627 \u0643\u0627\u0646 \u0644\u062f\u064a\u0643 \u062e\u0637\u0629 \u0627\u0633\u062a\u0631\u062f\u0627\u062f.',
    bitclutchPromo: '<strong>BitClutch</strong> \u064a\u062d\u0645\u064a \u0645\u0646 \u0627\u0644\u0641\u0642\u062f\u0627\u0646 \u0648\u0627\u0644\u0648\u0641\u0627\u0629\u060c \u0644\u064a\u0633 \u0627\u0644\u0633\u0631\u0642\u0629. \u0623\u0646\u0634\u0626 <strong>\u0645\u062d\u0641\u0638\u0629 \u0645\u062d\u0645\u064a\u0629</strong> \u0628\u0642\u0641\u0644 \u0632\u0645\u0646\u064a \u2014 \u0628\u062a\u0643\u0648\u064a\u0646 \u062a\u0628\u0642\u0649 \u0645\u0644\u0643\u0643\u060c \u0644\u0643\u0646 \u0648\u0631\u062b\u062a\u0643 \u064a\u0645\u0643\u0646\u0647\u0645 \u0627\u0633\u062a\u0631\u062f\u0627\u062f\u0647\u0627.',
    visitBitclutch: '\u0632\u0631 <strong>bitclutch.app</strong> \u0639\u0644\u0649 \u062c\u0647\u0627\u0632 \u0645\u062a\u0635\u0644 \u0644\u0625\u0646\u0634\u0627\u0621 \u0645\u062d\u0641\u0638\u0629 \u0645\u062d\u0645\u064a\u0629.',
    confirmedWritten: '\u0644\u0642\u062f \u0643\u062a\u0628\u062a\u0647\u0627',
    importTitle: '\u0627\u0633\u062a\u064a\u0631\u0627\u062f \u0639\u0628\u0627\u0631\u0629 \u0627\u0644\u0628\u0630\u0631\u0629', importDesc: '\u0627\u062e\u062a\u0631 \u0639\u062f\u062f \u0627\u0644\u0643\u0644\u0645\u0627\u062a \u0648\u0627\u0644\u0644\u063a\u0629\u060c \u062b\u0645 \u0623\u062f\u062e\u0644 \u0643\u0644 \u0643\u0644\u0645\u0629.',
    importPlaceholder: '\u0643\u0644\u0645\u06291 \u0643\u0644\u0645\u06292 \u0643\u0644\u0645\u06293 ...', importAction: '\u0627\u0633\u062a\u064a\u0631\u0627\u062f', words: '\u0643\u0644\u0645\u0629',
    fillAllWords: '\u064a\u0631\u062c\u0649 \u0645\u0644\u0621 \u062c\u0645\u064a\u0639 \u0627\u0644\u0643\u0644\u0645\u0627\u062a.', needWords: '\u0645\u0637\u0644\u0648\u0628 12 \u0623\u0648 24 \u0643\u0644\u0645\u0629', invalidMnemonic: '\u0639\u0628\u0627\u0631\u0629 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629',
    setPassTitle: '\u062a\u0639\u064a\u064a\u0646 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631', setPassDesc: '\u0627\u062e\u062a\u0631 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0642\u0648\u064a\u0629 \u0644\u062a\u0634\u0641\u064a\u0631 \u0645\u0641\u062a\u0627\u062d\u0643 \u0627\u0644\u062e\u0627\u0635. \u0633\u062a\u062d\u062a\u0627\u062c\u0647\u0627 \u0641\u064a \u0643\u0644 \u0645\u0631\u0629 \u062a\u0641\u062a\u062d \u0627\u0644\u0642\u0641\u0644.',
    confirmPass: '\u062a\u0623\u0643\u064a\u062f \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631', enterPass: '\u0623\u062f\u062e\u0644 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631',
    passRequired: '\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0645\u0637\u0644\u0648\u0628\u0629.', passTooShort: '\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0642\u0635\u064a\u0631\u0629 (\u0623\u0642\u0644 4 \u0623\u062d\u0631\u0641).', passNoMatch: '\u0643\u0644\u0645\u062a\u0627 \u0627\u0644\u0645\u0631\u0648\u0631 \u063a\u064a\u0631 \u0645\u062a\u0637\u0627\u0628\u0642\u062a\u064a\u0646.',
    noKeyToSave: '\u0644\u0627 \u064a\u0648\u062c\u062f \u0645\u0641\u062a\u0627\u062d \u0644\u0644\u062d\u0641\u0638. \u0627\u0628\u062f\u0623 \u0645\u0646 \u062c\u062f\u064a\u062f.', encryptSave: '\u062a\u0634\u0641\u064a\u0631 \u0648\u062d\u0641\u0638', encryptFailed: '\u0641\u0634\u0644 \u0627\u0644\u062a\u0634\u0641\u064a\u0631: ',
    scanTitle: '\u0645\u0633\u062d QR', scanDesc: '\u0648\u062c\u0651\u0647 \u0627\u0644\u0643\u0627\u0645\u064a\u0631\u0627 \u0625\u0644\u0649 \u0631\u0645\u0632 QR \u0645\u0646 \u062a\u0637\u0628\u064a\u0642 BitClutch.',
    startingCamera: '\u062a\u0634\u063a\u064a\u0644 \u0627\u0644\u0643\u0627\u0645\u064a\u0631\u0627...', scanning: '\u062c\u0627\u0631\u064a \u0627\u0644\u0645\u0633\u062d... \u0648\u062c\u0651\u0647 \u0625\u0644\u0649 QR.', cameraError: '\u062e\u0637\u0623 \u0627\u0644\u0643\u0627\u0645\u064a\u0631\u0627: ',
    receivingFountain: '\u0627\u0633\u062a\u0642\u0628\u0627\u0644 \u0643\u0648\u062f fountain...', urFailed: '\u0641\u0634\u0644 \u0641\u0643 \u062a\u0634\u0641\u064a\u0631 UR. \u062d\u0627\u0648\u0644 \u0645\u062c\u062f\u062f\u064b\u0627.', psbtParseError: '\u062e\u0637\u0623 \u062a\u062d\u0644\u064a\u0644 PSBT: ',
    confirmTx: '\u062a\u0623\u0643\u064a\u062f \u0627\u0644\u0645\u0639\u0627\u0645\u0644\u0629', reviewBeforeSign: '\u0631\u0627\u062c\u0639 \u0628\u0639\u0646\u0627\u064a\u0629 \u0642\u0628\u0644 \u0627\u0644\u062a\u0648\u0642\u064a\u0639.',
    inputs: '\u0627\u0644\u0645\u062f\u062e\u0644\u0627\u062a', output: '\u0627\u0644\u0645\u062e\u0631\u062c', change: '(\u0628\u0627\u0642\u064a)', fee: '\u0631\u0633\u0648\u0645', reject: '\u0631\u0641\u0636', sign: '\u062a\u0648\u0642\u064a\u0639', signingFailed: '\u0641\u0634\u0644 \u0627\u0644\u062a\u0648\u0642\u064a\u0639: ',
    signedPsbt: 'PSBT \u0645\u0648\u0642\u0651\u0639', showQRDesc: '\u0627\u062a\u0631\u0643 \u062a\u0637\u0628\u064a\u0642 BitClutch \u064a\u0645\u0633\u062d \u0631\u0645\u0632 QR \u0647\u0630\u0627 \u0644\u0628\u062b \u0627\u0644\u0645\u0639\u0627\u0645\u0644\u0629.', scanComplete: '\u0627\u0643\u062a\u0645\u0644 \u0627\u0644\u0645\u0633\u062d', scanSignatureDesc: '\u0627\u062a\u0631\u0643 \u062a\u0637\u0628\u064a\u0642 BitClutch \u064a\u0645\u0633\u062d \u0631\u0645\u0632 QR \u0647\u0630\u0627 \u0644\u0625\u0631\u0633\u0627\u0644 \u0627\u0644\u062a\u0648\u0642\u064a\u0639.',
    singleQR: 'QR \u0648\u0627\u062d\u062f', fountainKeepShowing: '\u0643\u0648\u062f fountain \u2014 \u0627\u0633\u062a\u0645\u0631 \u0628\u0627\u0644\u0639\u0631\u0636', frame: '\u0625\u0637\u0627\u0631',
    confirmBms: '\u062a\u0623\u0643\u064a\u062f \u062a\u0648\u0642\u064a\u0639 \u0627\u0644\u0631\u0633\u0627\u0644\u0629', reviewMessage: '\u0631\u0627\u062c\u0639 \u0627\u0644\u0631\u0633\u0627\u0644\u0629 \u0642\u0628\u0644 \u0627\u0644\u062a\u0648\u0642\u064a\u0639.',
    type: '\u0627\u0644\u0646\u0648\u0639', bmsType: 'BMS (\u0631\u0633\u0627\u0644\u0629 \u0628\u062a\u0643\u0648\u064a\u0646)', index: '\u0627\u0644\u0641\u0647\u0631\u0633', address: '\u0627\u0644\u0639\u0646\u0648\u0627\u0646', message: '\u0627\u0644\u0631\u0633\u0627\u0644\u0629',
    bmsSignature: '\u062a\u0648\u0642\u064a\u0639 BMS', sigBase64: '\u0627\u0644\u062a\u0648\u0642\u064a\u0639 (base64)', tapToCopy: '\u0627\u0646\u0642\u0631 \u0644\u0644\u0646\u0633\u062e', copySig: '\u0646\u0633\u062e \u0627\u0644\u062a\u0648\u0642\u064a\u0639', sha256: 'SHA-256',
    settings: '\u0625\u0639\u062f\u0627\u062f\u0627\u062a', version: '\u0627\u0644\u0625\u0635\u062f\u0627\u0631', language: '\u0627\u0644\u0644\u063a\u0629', seedLanguage: '\u0644\u063a\u0629 \u0627\u0644\u0628\u0630\u0631\u0629',
    onlineKeygenTitle: '\u0627\u0644\u0634\u0628\u0643\u0629 \u0645\u062a\u0635\u0644\u0629!',
    onlineKeygenBody: '\u062c\u0647\u0627\u0632\u0643 \u0645\u062a\u0635\u0644 \u0628\u0627\u0644\u0625\u0646\u062a\u0631\u0646\u062a. \u0627\u0644\u0645\u0641\u0627\u062a\u064a\u062d \u0627\u0644\u0645\u064f\u0646\u0634\u0623\u0629 \u0639\u0628\u0631 \u0627\u0644\u0625\u0646\u062a\u0631\u0646\u062a \u0642\u062f \u064a\u062a\u0645 \u0627\u0639\u062a\u0631\u0627\u0636\u0647\u0627 \u0628\u0648\u0627\u0633\u0637\u0629 \u0628\u0631\u0627\u0645\u062c \u0636\u0627\u0631\u0629. \u0627\u0641\u0635\u0644 \u062c\u0645\u064a\u0639 \u0627\u0644\u0634\u0628\u0643\u0627\u062a (WiFi\u060c \u0627\u0644\u062e\u0644\u0648\u064a\u0629\u060c Bluetooth\u060c USB) \u0642\u0628\u0644 \u0627\u0644\u0645\u062a\u0627\u0628\u0639\u0629.',
    proceedAnyway: '\u0627\u0633\u062a\u0645\u0631 \u0639\u0644\u0649 \u0623\u064a \u062d\u0627\u0644 (\u063a\u064a\u0631 \u0622\u0645\u0646)',
    installGuide: '\u062f\u0644\u064a\u0644 \u0627\u0644\u062a\u062b\u0628\u064a\u062a', viewSource: '\u062a\u062d\u0642\u0642 \u0645\u0646 \u0633\u0644\u0627\u0645\u0629 \u0627\u0644\u0643\u0648\u062f', securityInfo: '\u0645\u0639\u0644\u0648\u0645\u0627\u062a \u0627\u0644\u0623\u0645\u0627\u0646',
    deleteKey: '\u062d\u0630\u0641 \u0627\u0644\u0645\u0641\u062a\u0627\u062d', deleteConfirm1: '\u062d\u0630\u0641 \u0627\u0644\u0645\u0641\u062a\u0627\u062d\u061f \u0644\u0627 \u064a\u0645\u0643\u0646 \u0627\u0644\u062a\u0631\u0627\u062c\u0639.\n\u062a\u0623\u0643\u062f \u0645\u0646 \u0646\u0633\u062e \u0639\u0628\u0627\u0631\u0629 \u0627\u0644\u0628\u0630\u0631\u0629!',
    deleteConfirm2: '\u0647\u0644 \u0623\u0646\u062a \u0645\u062a\u0623\u0643\u062f \u062a\u0645\u0627\u0645\u064b\u0627\u061f \u0633\u062a\u0641\u0642\u062f \u0628\u062a\u0643\u0648\u064a\u0646 \u0628\u062f\u0648\u0646 \u0646\u0633\u062e\u0629 \u0627\u062d\u062a\u064a\u0627\u0637\u064a\u0629.',
    verifyIntegrity: '\u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0627\u0644\u0633\u0644\u0627\u0645\u0629', verifyDesc: '\u0642\u0627\u0631\u0646 \u062a\u062c\u0632\u0626\u0627\u062a SHA-256 \u0645\u0639 \u0627\u0644\u0625\u0635\u062f\u0627\u0631 \u0627\u0644\u0631\u0633\u0645\u064a \u0639\u0644\u0649 GitHub.',
    computing: '\u062c\u0627\u0631\u064a \u0627\u0644\u062d\u0633\u0627\u0628...', fetchFailed: '(\u0641\u0634\u0644 \u0627\u0644\u062a\u0646\u0632\u064a\u0644)',
    verifyFile: '\u062a\u062d\u0642\u0642 \u0645\u0646 \u0627\u0644\u0645\u0644\u0641', verifyFileDesc: '\u0627\u0646\u0642\u0631 \u0647\u0646\u0627 \u0648\u0627\u062e\u062a\u0631 \u0645\u0644\u0641 <strong>bitclutch-signer.html</strong> \u0627\u0644\u0645\u064f\u0646\u0632\u0651\u0644.<br>\u0633\u064a\u062a\u0645 \u062d\u0633\u0627\u0628 \u062a\u062c\u0632\u0626\u0629 SHA-256 \u0645\u062d\u0644\u064a\u064b\u0627.',
    tapToSelect: '\u0627\u0646\u0642\u0631 \u0644\u0644\u0627\u062e\u062a\u064a\u0627\u0631', compareGithub: '\u0642\u0627\u0631\u0646 \u0645\u0639 <code>hashes.json</code> \u0645\u0646 \u0625\u0635\u062f\u0627\u0631 GitHub.',
    auditableSource: '\u0643\u0648\u062f \u0642\u0627\u0628\u0644 \u0644\u0644\u062a\u062f\u0642\u064a\u0642', auditableDesc: '\u0643\u0644 \u0645\u0646\u0637\u0642 \u0627\u0644\u062a\u0637\u0628\u064a\u0642 \u0641\u064a \u0645\u0644\u0641 \u0648\u0627\u062d\u062f \u0642\u0627\u0628\u0644 \u0644\u0644\u062a\u062f\u0642\u064a\u0642. \u0627\u0644\u0643\u0648\u062f \u0648\u0627\u0644\u062a\u062c\u0632\u0626\u0627\u062a \u0645\u0646\u0634\u0648\u0631\u0629 \u0639\u0644\u0649 GitHub.',
    back: '\u0631\u062c\u0648\u0639',
    securityTitle: '\u0645\u0639\u0644\u0648\u0645\u0627\u062a \u0627\u0644\u0623\u0645\u0627\u0646', securityLevel: '\u0645\u0633\u062a\u0648\u0649 \u0627\u0644\u0623\u0645\u0627\u0646: \u0641\u062c\u0648\u0629 \u0647\u0648\u0627\u0626\u064a\u0629 \u0628\u0631\u0645\u062c\u064a\u0629',
    whatProvides: '\u0645\u0627 \u064a\u0648\u0641\u0631\u0647:', secProvide1: '\u0627\u0644\u0645\u0641\u062a\u0627\u062d \u0627\u0644\u062e\u0627\u0635 \u0644\u0627 \u064a\u0644\u0645\u0633 \u0627\u0644\u0625\u0646\u062a\u0631\u0646\u062a (\u0628\u0639\u062f \u0627\u0644\u0625\u0639\u062f\u0627\u062f)',
    secProvide2: '\u0627\u0644\u0643\u0648\u062f \u0642\u0627\u0628\u0644 \u0644\u0644\u062a\u062f\u0642\u064a\u0642 (\u0645\u0644\u0641 app.js \u0648\u0627\u062d\u062f)', secProvide3: '\u0625\u0646\u062a\u0631\u0648\u0628\u064a\u0627 \u0645\u0646 \u0645\u0635\u0627\u062f\u0631 \u0641\u064a\u0632\u064a\u0627\u0626\u064a\u0629 \u0641\u0642\u0637 (\u0646\u0631\u062f/\u0639\u0645\u0644\u0627\u062a)',
    secProvide4: '\u062a\u0634\u0641\u064a\u0631 AES-256-GCM \u0645\u0639 600K \u062a\u0643\u0631\u0627\u0631 PBKDF2',
    whatNot: '\u0645\u0627 \u0644\u0627 \u064a\u0648\u0641\u0631\u0647:', secNot1: 'Secure Element (\u0645\u062d\u0627\u0641\u0638 \u0627\u0644\u0623\u062c\u0647\u0632\u0629 \u062a\u0645\u0644\u0643\u0647\u0627)',
    secNot2: '\u0641\u062c\u0648\u0629 \u0647\u0648\u0627\u0626\u064a\u0629 \u0639\u0644\u0649 \u0645\u0633\u062a\u0648\u0649 \u0627\u0644\u0623\u062c\u0647\u0632\u0629 (\u0634\u0631\u064a\u062d\u0629 WiFi \u0645\u0648\u062c\u0648\u062f\u0629)', secNot3: '\u0645\u0642\u0627\u0648\u0645\u0629 \u0647\u062c\u0645\u0627\u062a \u0627\u0644\u0642\u0646\u0627\u0629 \u0627\u0644\u062c\u0627\u0646\u0628\u064a\u0629',
    keyStorage: '\u062a\u062e\u0632\u064a\u0646 \u0627\u0644\u0645\u0641\u0627\u062a\u064a\u062d', encryption: '\u0627\u0644\u062a\u0634\u0641\u064a\u0631:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600,000 \u062a\u0643\u0631\u0627\u0631) + \u0645\u0644\u062d/IV \u0639\u0634\u0648\u0627\u0626\u064a',
    warning: '\u062a\u062d\u0630\u064a\u0631:', clearDataWarning: '\u0645\u0633\u062d \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0645\u062a\u0635\u0641\u062d \u0633\u064a\u062d\u0630\u0641 \u0627\u0644\u0645\u0641\u062a\u0627\u062d \u0627\u0644\u0645\u0634\u0641\u0631 \u0646\u0647\u0627\u0626\u064a\u064b\u0627. \u0627\u062d\u0641\u0638 \u0639\u0628\u0627\u0631\u0629 \u0627\u0644\u0628\u0630\u0631\u0629 \u062f\u0627\u0626\u0645\u064b\u0627 \u0628\u062f\u0648\u0646 \u0627\u062a\u0635\u0627\u0644.',
    autoLock: '\u0642\u0641\u0644 \u062a\u0644\u0642\u0627\u0626\u064a:', autoLockDesc: '\u062a\u064f\u0645\u0633\u062d \u0627\u0644\u0645\u0641\u0627\u062a\u064a\u062d \u0645\u0646 \u0627\u0644\u0630\u0627\u0643\u0631\u0629 \u0628\u0639\u062f 5 \u062f\u0642\u0627\u0626\u0642 \u0645\u0646 \u0627\u0644\u062e\u0645\u0648\u0644.',
    storageEncKey: '\u0645\u0641\u062a\u0627\u062d \u062e\u0627\u0635 \u0645\u0634\u0641\u0631 (AES-256-GCM)', storageXpub: '\u0645\u0641\u062a\u0627\u062d \u0639\u0627\u0645 \u0645\u0645\u062a\u062f \u0644\u0644\u062d\u0633\u0627\u0628', storageFp: '\u0628\u0635\u0645\u0629 BIP-32',
    storageNet: '\u0625\u0639\u062f\u0627\u062f \u0627\u0644\u0634\u0628\u0643\u0629 (main/test)', storageLang: '\u0644\u063a\u0629 \u0627\u0644\u0648\u0627\u062c\u0647\u0629', storageSeedLang: '\u0644\u063a\u0629 \u0639\u0628\u0627\u0631\u0629 \u0627\u0644\u0628\u0630\u0631\u0629', storageKeyCreated: '\u062a\u0627\u0631\u064a\u062e \u0625\u0646\u0634\u0627\u0621 \u0627\u0644\u0645\u0641\u062a\u0627\u062d', storageLastOnline: '\u062a\u0627\u0631\u064a\u062e \u0627\u0643\u062a\u0634\u0627\u0641 \u0627\u0644\u0634\u0628\u0643\u0629',
    guideTitle: '\u062f\u0644\u064a\u0644 \u0627\u0644\u062a\u062b\u0628\u064a\u062a', guideDesc: '\u062b\u0628\u0651\u062a BitClutch Signer \u0643\u062a\u0637\u0628\u064a\u0642 \u063a\u064a\u0631 \u0645\u062a\u0635\u0644\u060c \u062b\u0645 \u0641\u0639\u0651\u0644 \u0648\u0636\u0639 \u0627\u0644\u0637\u064a\u0631\u0627\u0646 \u0642\u0628\u0644 \u0627\u0644\u0627\u0633\u062a\u062e\u062f\u0627\u0645.',
    detected: '\u062a\u0645 \u0627\u0644\u0643\u0634\u0641', accountXpubTitle: 'xpub \u0627\u0644\u062d\u0633\u0627\u0628',
    guideIosSafari: '<strong>\u0627\u0644\u062a\u062b\u0628\u064a\u062a \u0643\u062a\u0637\u0628\u064a\u0642 \u063a\u064a\u0631 \u0645\u062a\u0635\u0644:</strong><ol><li>\u0627\u0641\u062a\u062d \u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629 \u0641\u064a <strong>Safari</strong></li><li>\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 \u0632\u0631 <strong>Share</strong> (\u0645\u0631\u0628\u0639 \u0628\u0647 \u0633\u0647\u0645)</li><li>\u0645\u0631\u0631 \u0644\u0644\u0623\u0633\u0641\u0644 \u0648\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 <strong>"Add to Home Screen"</strong></li><li>\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 <strong>"Add"</strong> \u0641\u064a \u0627\u0644\u0632\u0627\u0648\u064a\u0629 \u0627\u0644\u0639\u0644\u0648\u064a\u0629 \u0627\u0644\u064a\u0645\u0646\u0649</li></ol><strong>\u062a\u0641\u0639\u064a\u0644 \u0648\u0636\u0639 \u0627\u0644\u0637\u064a\u0631\u0627\u0646:</strong><ol><li>\u0627\u0633\u062d\u0628 \u0644\u0644\u0623\u0633\u0641\u0644 \u0645\u0646 \u0627\u0644\u0632\u0627\u0648\u064a\u0629 \u0627\u0644\u0639\u0644\u0648\u064a\u0629 \u0627\u0644\u064a\u0645\u0646\u0649 (\u0623\u0648 \u0644\u0644\u0623\u0639\u0644\u0649 \u0645\u0646 \u0627\u0644\u0623\u0633\u0641\u0644 \u0641\u064a \u0623\u062c\u0647\u0632\u0629 iPhone \u0627\u0644\u0623\u0642\u062f\u0645)</li><li>\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 \u0623\u064a\u0642\u0648\u0646\u0629 <strong>airplane icon</strong> \u0644\u0644\u062a\u0641\u0639\u064a\u0644</li><li>\u062a\u0623\u0643\u062f \u0645\u0646 \u0623\u0646 Wi-Fi \u0648Bluetooth \u0645\u063a\u0644\u0642\u0627\u0646 \u0623\u064a\u0636\u064b\u0627</li></ol>',
    guideIosChrome: '<strong>\u0645\u0647\u0645:</strong> \u0644\u0627 \u064a\u0633\u062a\u0637\u064a\u0639 Chrome \u0639\u0644\u0649 iOS \u062a\u062b\u0628\u064a\u062a \u062a\u0637\u0628\u064a\u0642\u0627\u062a \u063a\u064a\u0631 \u0645\u062a\u0635\u0644\u0629. \u0627\u0633\u062a\u062e\u062f\u0645 <strong>Safari</strong> \u0628\u062f\u0644\u0627\u064b \u0645\u0646 \u0630\u0644\u0643.<ol><li>\u0627\u0646\u0633\u062e URL \u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629</li><li>\u0627\u0641\u062a\u062d <strong>Safari</strong> \u0648\u0627\u0644\u0635\u0642 URL</li><li>\u0627\u062a\u0628\u0639 \u062a\u0639\u0644\u064a\u0645\u0627\u062a <strong>iOS Safari</strong> \u0623\u0639\u0644\u0627\u0647</li></ol><strong>\u062a\u0641\u0639\u064a\u0644 \u0648\u0636\u0639 \u0627\u0644\u0637\u064a\u0631\u0627\u0646:</strong><ol><li>\u0627\u0633\u062d\u0628 \u0644\u0644\u0623\u0633\u0641\u0644 \u0645\u0646 \u0627\u0644\u0632\u0627\u0648\u064a\u0629 \u0627\u0644\u0639\u0644\u0648\u064a\u0629 \u0627\u0644\u064a\u0645\u0646\u0649</li><li>\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 \u0623\u064a\u0642\u0648\u0646\u0629 <strong>airplane icon</strong></li></ol>',
    guideAndroidChrome: '<strong>\u0627\u0644\u062a\u062b\u0628\u064a\u062a \u0643\u062a\u0637\u0628\u064a\u0642 \u063a\u064a\u0631 \u0645\u062a\u0635\u0644:</strong><ol><li>\u0627\u0641\u062a\u062d \u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629 \u0641\u064a <strong>Chrome</strong></li><li>\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 <strong>three-dot menu</strong> (\u0623\u0639\u0644\u0649 \u0627\u0644\u064a\u0645\u064a\u0646)</li><li>\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 <strong>"Install app"</strong> \u0623\u0648 <strong>"Add to Home screen"</strong></li><li>\u0623\u0643\u062f \u0628\u0627\u0644\u0636\u063a\u0637 \u0639\u0644\u0649 <strong>"Install"</strong></li></ol><strong>\u062a\u0641\u0639\u064a\u0644 \u0648\u0636\u0639 \u0627\u0644\u0637\u064a\u0631\u0627\u0646:</strong><ol><li>\u0627\u0633\u062d\u0628 \u0644\u0644\u0623\u0633\u0641\u0644 \u0645\u0646 \u0623\u0639\u0644\u0649 \u0627\u0644\u0634\u0627\u0634\u0629</li><li>\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 <strong>"Airplane mode"</strong></li><li>\u062a\u062d\u0642\u0642 \u0645\u0646 \u0623\u0646 Wi-Fi \u0648\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0647\u0627\u062a\u0641 \u0645\u063a\u0644\u0642\u0629</li></ol>',
    guideAndroidSamsung: '<strong>\u0627\u0644\u062a\u062b\u0628\u064a\u062a \u0643\u062a\u0637\u0628\u064a\u0642 \u063a\u064a\u0631 \u0645\u062a\u0635\u0644:</strong><ol><li>\u0627\u0641\u062a\u062d \u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629 \u0641\u064a <strong>Samsung Internet</strong></li><li>\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 <strong>menu icon</strong> (\u062b\u0644\u0627\u062b\u0629 \u062e\u0637\u0648\u0637\u060c \u0623\u0633\u0641\u0644 \u0627\u0644\u064a\u0645\u064a\u0646)</li><li>\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 <strong>"Add page to"</strong> \u062b\u0645 <strong>"Home screen"</strong></li></ol><strong>\u062a\u0641\u0639\u064a\u0644 \u0648\u0636\u0639 \u0627\u0644\u0637\u064a\u0631\u0627\u0646:</strong><ol><li>\u0627\u0633\u062d\u0628 \u0644\u0644\u0623\u0633\u0641\u0644 \u0645\u0646 \u0627\u0644\u0623\u0639\u0644\u0649 \u0645\u0631\u062a\u064a\u0646 \u0644\u0641\u062a\u062d Quick Settings</li><li>\u0627\u0636\u063a\u0637 \u0639\u0644\u0649 <strong>"Airplane mode"</strong></li></ol>',
    guideMacosSafari: '<strong>\u0627\u0644\u062a\u062b\u0628\u064a\u062a \u0643\u062a\u0637\u0628\u064a\u0642 \u063a\u064a\u0631 \u0645\u062a\u0635\u0644 (macOS Sonoma+):</strong><ol><li>\u0627\u0641\u062a\u062d \u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629 \u0641\u064a <strong>Safari</strong></li><li>\u0627\u0646\u0642\u0631 \u0639\u0644\u0649 \u0642\u0627\u0626\u0645\u0629 <strong>File</strong> \u062b\u0645 <strong>"Add to Dock"</strong></li><li>\u0627\u0646\u0642\u0631 <strong>"Add"</strong></li></ol><strong>\u062a\u0639\u0637\u064a\u0644 \u0627\u0644\u0634\u0628\u0643\u0629:</strong><ol><li>\u0627\u0646\u0642\u0631 \u0639\u0644\u0649 \u0623\u064a\u0642\u0648\u0646\u0629 <strong>Wi-Fi icon</strong> \u0641\u064a \u0634\u0631\u064a\u0637 \u0627\u0644\u0642\u0648\u0627\u0626\u0645</li><li>\u0627\u0646\u0642\u0631 \u0644\u0640 <strong>turn Wi-Fi off</strong></li><li>\u0627\u0641\u0635\u0644 \u0623\u064a \u0643\u0627\u0628\u0644\u0627\u062a Ethernet</li></ol>',
    guideMacosChrome: '<strong>\u0627\u0644\u062a\u062b\u0628\u064a\u062a \u0643\u062a\u0637\u0628\u064a\u0642 \u063a\u064a\u0631 \u0645\u062a\u0635\u0644:</strong><ol><li>\u0627\u0641\u062a\u062d \u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629 \u0641\u064a <strong>Chrome</strong></li><li>\u0627\u0646\u0642\u0631 \u0639\u0644\u0649 <strong>install icon</strong> \u0641\u064a \u0634\u0631\u064a\u0637 \u0627\u0644\u0639\u0646\u0648\u0627\u0646 (\u0623\u0648 three-dot menu &rarr; "Install BitClutch Signer")</li><li>\u0627\u0646\u0642\u0631 <strong>"Install"</strong></li></ol><strong>\u062a\u0639\u0637\u064a\u0644 \u0627\u0644\u0634\u0628\u0643\u0629:</strong><ol><li>\u0627\u0646\u0642\u0631 \u0639\u0644\u0649 \u0623\u064a\u0642\u0648\u0646\u0629 <strong>Wi-Fi icon</strong> \u0641\u064a \u0634\u0631\u064a\u0637 \u0627\u0644\u0642\u0648\u0627\u0626\u0645</li><li>\u0627\u0646\u0642\u0631 \u0644\u0640 <strong>turn Wi-Fi off</strong></li><li>\u0627\u0641\u0635\u0644 \u0623\u064a \u0643\u0627\u0628\u0644\u0627\u062a Ethernet</li></ol>',
    guideWindowsChrome: '<strong>\u0627\u0644\u062a\u062b\u0628\u064a\u062a \u0643\u062a\u0637\u0628\u064a\u0642 \u063a\u064a\u0631 \u0645\u062a\u0635\u0644:</strong><ol><li>\u0627\u0641\u062a\u062d \u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629 \u0641\u064a <strong>Chrome</strong></li><li>\u0627\u0646\u0642\u0631 \u0639\u0644\u0649 <strong>install icon</strong> \u0641\u064a \u0634\u0631\u064a\u0637 \u0627\u0644\u0639\u0646\u0648\u0627\u0646 (\u0623\u0648 three-dot menu &rarr; "Install BitClutch Signer")</li><li>\u0627\u0646\u0642\u0631 <strong>"Install"</strong></li></ol><strong>\u062a\u0639\u0637\u064a\u0644 \u0627\u0644\u0634\u0628\u0643\u0629:</strong><ol><li>\u0627\u0646\u0642\u0631 \u0639\u0644\u0649 \u0623\u064a\u0642\u0648\u0646\u0629 <strong>Wi-Fi icon</strong> \u0641\u064a \u0634\u0631\u064a\u0637 \u0627\u0644\u0645\u0647\u0627\u0645 (\u0623\u0633\u0641\u0644 \u0627\u0644\u064a\u0645\u064a\u0646)</li><li>\u0627\u0646\u0642\u0631 \u0644\u0640 <strong>\u0642\u0637\u0639 \u0627\u062a\u0635\u0627\u0644 Wi-Fi</strong></li><li>\u0627\u0641\u0635\u0644 \u0623\u064a \u0643\u0627\u0628\u0644\u0627\u062a Ethernet</li></ol>',
    guideWindowsEdge: '<strong>\u0627\u0644\u062a\u062b\u0628\u064a\u062a \u0643\u062a\u0637\u0628\u064a\u0642 \u063a\u064a\u0631 \u0645\u062a\u0635\u0644:</strong><ol><li>\u0627\u0641\u062a\u062d \u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629 \u0641\u064a <strong>Edge</strong></li><li>\u0627\u0646\u0642\u0631 \u0639\u0644\u0649 <strong>install icon</strong> \u0641\u064a \u0634\u0631\u064a\u0637 \u0627\u0644\u0639\u0646\u0648\u0627\u0646 (\u0623\u0648 three-dot menu &rarr; "\u0627\u0644\u062a\u0637\u0628\u064a\u0642\u0627\u062a" &rarr; "Install BitClutch Signer")</li><li>\u0627\u0646\u0642\u0631 <strong>"Install"</strong></li></ol><strong>\u062a\u0639\u0637\u064a\u0644 \u0627\u0644\u0634\u0628\u0643\u0629:</strong><ol><li>\u0627\u0646\u0642\u0631 \u0639\u0644\u0649 \u0623\u064a\u0642\u0648\u0646\u0629 <strong>Wi-Fi icon</strong> \u0641\u064a \u0634\u0631\u064a\u0637 \u0627\u0644\u0645\u0647\u0627\u0645 (\u0623\u0633\u0641\u0644 \u0627\u0644\u064a\u0645\u064a\u0646)</li><li>\u0627\u0646\u0642\u0631 \u0644\u0640 <strong>\u0642\u0637\u0639 \u0627\u062a\u0635\u0627\u0644 Wi-Fi</strong></li><li>\u0627\u0641\u0635\u0644 \u0623\u064a \u0643\u0627\u0628\u0644\u0627\u062a Ethernet</li></ol>',
    noMnemonic: '\u0644\u0627 \u064a\u0648\u062c\u062f \u0639\u0628\u0627\u0631\u0629 \u0645\u062a\u0627\u062d\u0629.', noTxData: '\u0644\u0627 \u062a\u0648\u062c\u062f \u0628\u064a\u0627\u0646\u0627\u062a \u0645\u0639\u0627\u0645\u0644\u0629.', noSignedData: '\u0644\u0627 \u062a\u0648\u062c\u062f \u0628\u064a\u0627\u0646\u0627\u062a \u0645\u0648\u0642\u0639\u0629.',
    noBmsRequest: '\u0644\u0627 \u064a\u0648\u062c\u062f \u0637\u0644\u0628 BMS.', noSignature: '\u0644\u0627 \u064a\u0648\u062c\u062f \u062a\u0648\u0642\u064a\u0639.', loading: '\u062c\u0627\u0631\u064a \u0627\u0644\u062a\u062d\u0645\u064a\u0644...',
    bannerWarn: '\u062a\u0645 \u0627\u0643\u062a\u0634\u0627\u0641 \u0634\u0628\u0643\u0629 \u2014 \u0627\u0641\u0635\u0644 \u062c\u0645\u064a\u0639 \u0627\u0644\u0634\u0628\u0643\u0627\u062a \u0642\u0628\u0644 \u0625\u0646\u0634\u0627\u0621 \u0627\u0644\u0645\u0641\u0627\u062a\u064a\u062d.',
    bannerOnline: '\u0627\u0644\u0634\u0628\u0643\u0629 \u0645\u062a\u0635\u0644\u0629 \u2014 \u0627\u0641\u0635\u0644 \u0627\u0644\u0622\u0646 \u0648\u0644\u0627 \u062a\u064f\u0639\u062f \u062a\u0648\u0635\u064a\u0644 \u0647\u0630\u0627 \u0627\u0644\u062c\u0647\u0627\u0632 \u0623\u0628\u062f\u064b\u0627. \u0642\u062f \u062a\u0643\u0648\u0646 \u0627\u0644\u0645\u0641\u0627\u062a\u064a\u062d \u0642\u062f \u0627\u0646\u0643\u0634\u0641\u062a.',
    bannerOffline: '\u0644\u0645 \u064a\u062a\u0645 \u0627\u0643\u062a\u0634\u0627\u0641 \u0634\u0628\u0643\u0629 \u0644\u0627\u0633\u0644\u0643\u064a\u0629. \u062a\u0623\u0643\u062f \u0645\u0646 \u0641\u0635\u0644 Bluetooth \u0648NFC \u0648\u0643\u0627\u0628\u0644\u0627\u062a USB \u0623\u064a\u0636\u064b\u0627.',
  },
  nl: {
    unlocked: 'Ontgrendeld', locked: 'Vergrendeld',
    tabKey: 'Sleutel', tabSign: 'Ondertekenen', tabSettings: 'Instellingen',
    createKeys: 'Maak je sleutel',
    setupDesc: 'Genereer een nieuwe sleutel met fysieke entropie,<br>of importeer een bestaande herstelzin.',
    diceBtn: 'Dobbelsteen (99 worpen)', coinBtn: 'Munt (256 worpen)', importBtn: 'Herstelzin importeren',
    enterPassphrase: 'Voer wachtwoord in om te ontgrendelen', passphrase: 'Wachtwoord', unlock: 'Ontgrendelen', wrongPassphrase: 'Verkeerd wachtwoord.',
    yourKey: 'Jouw sleutel', network: 'Netwerk', fingerprint: 'Vingerafdruk', keyCreated: 'Aangemaakt', lastOnline: 'Laatst online', neverOnline: 'Nooit (veilig)', onlineAfterKey: 'Online gedetecteerd na aanmaak', accountXpub: 'Account-xpub',
    showXpubQR: 'xpub QR tonen', lockBtn: 'Vergrendelen', mainnet: 'Mainnet', testnet: 'Testnet',
    diceTitle: 'Dobbelsteen sleutelgeneratie', diceDesc: 'Gooi een echte dobbelsteen en tik het resultaat.',
    progress: 'Voortgang', undoLast: 'Ongedaan maken', cancel: 'Annuleren', ok: 'OK',
    coinTitle: 'Muntwerp sleutelgeneratie', coinDesc: 'Gooi een echte munt en tik het resultaat.',
    entropyWarning: 'Gebruik een echte dobbelsteen/munt \u2014 verzin nooit getallen. Menselijke keuzes zijn voorspelbaar en verzwakken je sleutel. Geen camera\u2019s of microfoons in de buurt \u2014 wie je worpen ziet kan je Bitcoin stelen.',
    heads: 'H (Kop)', tails: 'T (Munt)',
    writeDown: 'Schrijf deze woorden op!',
    mnemonicDesc: 'Dit is je herstelzin. Bewaar deze veilig offline. Wordt NIET opnieuw getoond.',
    stolenVsLost: 'Gestolen vs. Verloren \u2014 ken het verschil',
    theft: 'Diefstal:', theftDesc: 'Als iemand je herstelzin vindt, kan hij direct je Bitcoin stelen. Niemand kan dit terugdraaien.',
    loss: 'Verlies:', lossDesc: 'Als je je herstelzin verliest en je apparaat kapot gaat, is je Bitcoin voor altijd verloren \u2014 tenzij je een herstelplan hebt.',
    bitclutchPromo: '<strong>BitClutch</strong> beschermt tegen verlies en overlijden, niet tegen diefstal. Maak een <strong>Beschermde Portemonnee</strong> met tijdslot \u2014 je Bitcoin blijft van jou, maar je erfgenamen kunnen het herstellen.',
    visitBitclutch: 'Bezoek <strong>bitclutch.app</strong> op een online apparaat om een Beschermde Portemonnee aan te maken.',
    confirmedWritten: 'Opgeschreven',
    importTitle: 'Herstelzin importeren', importDesc: 'Selecteer het aantal woorden en de taal, voer dan elk woord in.',
    importPlaceholder: 'woord1 woord2 woord3 ...', importAction: 'Importeren', words: 'woorden',
    fillAllWords: 'Vul alle woorden in.', needWords: '12 of 24 woorden nodig', invalidMnemonic: 'Ongeldig geheugensteuntje',
    setPassTitle: 'Wachtwoord instellen', setPassDesc: 'Kies een sterk wachtwoord om je priv\u00e9sleutel te versleutelen. Nodig bij elke ontgrendeling.',
    confirmPass: 'Wachtwoord bevestigen', enterPass: 'Wachtwoord invoeren',
    passRequired: 'Wachtwoord is vereist.', passTooShort: 'Wachtwoord te kort (min. 4 tekens).', passNoMatch: 'Wachtwoorden komen niet overeen.',
    noKeyToSave: 'Geen sleutel om op te slaan. Begin opnieuw.', encryptSave: 'Versleutelen en opslaan', encryptFailed: 'Versleuteling mislukt: ',
    scanTitle: 'QR scannen', scanDesc: 'Richt de camera op de QR-code van je BitClutch-app.',
    startingCamera: 'Camera starten...', scanning: 'Scannen... Richt op de QR-code.', cameraError: 'Camerafout: ',
    receivingFountain: 'Fountain-code ontvangen...', urFailed: 'UR-decodering mislukt. Probeer opnieuw.', psbtParseError: 'PSBT-parseerfout: ',
    confirmTx: 'Transactie bevestigen', reviewBeforeSign: 'Controleer zorgvuldig voor het ondertekenen.',
    inputs: 'Invoer', output: 'Uitvoer', change: '(wisselgeld)', fee: 'Kosten', reject: 'Weigeren', sign: 'Ondertekenen', signingFailed: 'Ondertekening mislukt: ',
    signedPsbt: 'Ondertekende PSBT', showQRDesc: 'Laat je BitClutch-app deze QR-code scannen om de transactie uit te zenden.', scanComplete: 'Scan voltooid', scanSignatureDesc: 'Laat je BitClutch-app deze QR-code scannen om de handtekening te verzenden.',
    singleQR: 'Enkele QR', fountainKeepShowing: 'fountain-code \u2014 blijf tonen', frame: 'Frame',
    confirmBms: 'Berichtondertekening bevestigen', reviewMessage: 'Controleer het bericht voor ondertekening.',
    type: 'Type', bmsType: 'BMS (Bitcoin-bericht)', index: 'Index', address: 'Adres', message: 'Bericht',
    bmsSignature: 'BMS-handtekening', sigBase64: 'Handtekening (base64)', tapToCopy: 'Tik om te kopi\u00ebren', copySig: 'Handtekening kopi\u00ebren', sha256: 'SHA-256',
    settings: 'Instellingen', version: 'Versie', language: 'Taal', seedLanguage: 'Zaadtaal',
    onlineKeygenTitle: 'Netwerk verbonden!',
    onlineKeygenBody: 'Uw apparaat is verbonden met internet. Online gegenereerde sleutels kunnen worden onderschept door malware. Verbreek ALLE netwerken (WiFi, mobiel, Bluetooth, USB) voordat u doorgaat.',
    proceedAnyway: 'Toch doorgaan (onveilig)',
    installGuide: 'Installatiegids', viewSource: 'Broncode-integriteit verifi\u00ebren', securityInfo: 'Beveiligingsinfo',
    deleteKey: 'Sleutel verwijderen', deleteConfirm1: 'Sleutel verwijderen? Kan niet ongedaan worden.\nZorg dat je je herstelzin hebt opgeslagen!',
    deleteConfirm2: 'Weet je het absoluut zeker? Je Bitcoin gaat VERLOREN zonder back-up.',
    verifyIntegrity: 'Integriteit verifi\u00ebren', verifyDesc: 'Vergelijk SHA-256-hashes met de offici\u00eble versie op GitHub.',
    computing: 'Berekenen...', fetchFailed: '(download mislukt)',
    verifyFile: 'Dit bestand verifi\u00ebren', verifyFileDesc: 'Tik hier en selecteer het gedownloade <strong>bitclutch-signer.html</strong>-bestand.<br>De SHA-256-hash wordt lokaal berekend.',
    tapToSelect: 'Tik om te selecteren', compareGithub: 'Vergelijk met <code>hashes.json</code> van de GitHub-release.',
    auditableSource: 'Controleerbare broncode', auditableDesc: 'Alle logica van deze app zit in \u00e9\u00e9n controleerbaar bestand. Broncode en offici\u00eble hashes zijn gepubliceerd op GitHub.',
    back: 'Terug',
    securityTitle: 'Beveiligingsinformatie', securityLevel: 'Beveiligingsniveau: Software air-gap',
    whatProvides: 'Wat het biedt:', secProvide1: 'Priv\u00e9sleutel raakt nooit het internet (na installatie)',
    secProvide2: 'Code is controleerbaar (enkel app.js-bestand)', secProvide3: 'Entropie alleen uit fysieke bronnen (dobbelstenen/munten)',
    secProvide4: 'AES-256-GCM-versleuteling met 600K PBKDF2-iteraties',
    whatNot: 'Wat het NIET biedt:', secNot1: 'Secure Element (hardware-portemonnees hebben dit)',
    secNot2: 'Hardware-niveau air-gap (WiFi-chip bestaat nog)', secNot3: 'Zijkanaalaanval-resistentie',
    keyStorage: 'Sleutelopslag', encryption: 'Versleuteling:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600.000 iteraties) + willekeurig zout/IV',
    warning: 'Waarschuwing:', clearDataWarning: 'Browsergegevens wissen verwijdert je versleutelde sleutel permanent. Bewaar je herstelzin altijd offline.',
    autoLock: 'Automatisch vergrendelen:', autoLockDesc: 'Sleutels worden na 5 minuten inactiviteit uit het geheugen gewist.',
    storageEncKey: 'Versleutelde priv\u00e9sleutel (AES-256-GCM)', storageXpub: 'Uitgebreide openbare accountsleutel', storageFp: 'BIP-32-vingerafdruk',
    storageNet: 'Netwerkinstelling (main/test)', storageLang: 'Interfacetaal', storageSeedLang: 'Herstelzintaal', storageKeyCreated: 'Aanmaakdatum sleutel', storageLastOnline: 'Netwerkdetectiedatum',
    guideTitle: 'Installatiegids', guideDesc: 'Installeer BitClutch Signer als offline app en zet de vliegtuigmodus aan voor gebruik.',
    detected: 'Gedetecteerd', accountXpubTitle: 'Account-xpub',
    guideIosSafari: '<strong>Installeer als offline app:</strong><ol><li>Open deze pagina in <strong>Safari</strong></li><li>Tik op de <strong>Share</strong>-knop (vierkant met pijl)</li><li>Scroll naar beneden en tik op <strong>"Add to Home Screen"</strong></li><li>Tik op <strong>"Add"</strong> rechtsboven</li></ol><strong>Vliegtuigmodus inschakelen:</strong><ol><li>Veeg omlaag vanuit de rechterbovenhoek (of omhoog vanaf de onderkant bij oudere iPhones)</li><li>Tik op het <strong>airplane icon</strong> om in te schakelen</li><li>Controleer of Wi-Fi en Bluetooth ook UIT zijn</li></ol>',
    guideIosChrome: '<strong>Belangrijk:</strong> Chrome op iOS kan geen offline apps installeren. Gebruik in plaats daarvan <strong>Safari</strong>.<ol><li>Kopieer de URL van deze pagina</li><li>Open <strong>Safari</strong> en plak de URL</li><li>Volg de <strong>iOS Safari</strong>-instructies hierboven</li></ol><strong>Vliegtuigmodus inschakelen:</strong><ol><li>Veeg omlaag vanuit de rechterbovenhoek</li><li>Tik op het <strong>airplane icon</strong></li></ol>',
    guideAndroidChrome: '<strong>Installeer als offline app:</strong><ol><li>Open deze pagina in <strong>Chrome</strong></li><li>Tik op het <strong>three-dot menu</strong> (rechtsboven)</li><li>Tik op <strong>"Install app"</strong> of <strong>"Add to Home screen"</strong></li><li>Bevestig door op <strong>"Install"</strong> te tikken</li></ol><strong>Vliegtuigmodus inschakelen:</strong><ol><li>Veeg omlaag vanaf de bovenkant van het scherm</li><li>Tik op <strong>"Airplane mode"</strong></li><li>Controleer of Wi-Fi en mobiele data UIT zijn</li></ol>',
    guideAndroidSamsung: '<strong>Installeer als offline app:</strong><ol><li>Open deze pagina in <strong>Samsung Internet</strong></li><li>Tik op het <strong>menu icon</strong> (drie lijnen, rechtsonder)</li><li>Tik op <strong>"Add page to"</strong> en dan <strong>"Home screen"</strong></li></ol><strong>Vliegtuigmodus inschakelen:</strong><ol><li>Veeg twee keer omlaag vanaf de bovenkant om Snelle instellingen te openen</li><li>Tik op <strong>"Airplane mode"</strong></li></ol>',
    guideMacosSafari: '<strong>Installeer als offline app (macOS Sonoma+):</strong><ol><li>Open deze pagina in <strong>Safari</strong></li><li>Klik op het menu <strong>File</strong> en dan <strong>"Add to Dock"</strong></li><li>Klik op <strong>"Add"</strong></li></ol><strong>Netwerk uitschakelen:</strong><ol><li>Klik op het <strong>Wi-Fi icon</strong> in de menubalk</li><li>Klik om <strong>turn Wi-Fi off</strong></li><li>Koppel alle Ethernet-kabels los</li></ol>',
    guideMacosChrome: '<strong>Installeer als offline app:</strong><ol><li>Open deze pagina in <strong>Chrome</strong></li><li>Klik op het <strong>install icon</strong> in de adresbalk (of three-dot menu &rarr; "Install BitClutch Signer")</li><li>Klik op <strong>"Install"</strong></li></ol><strong>Netwerk uitschakelen:</strong><ol><li>Klik op het <strong>Wi-Fi icon</strong> in de menubalk</li><li>Klik om <strong>turn Wi-Fi off</strong></li><li>Koppel alle Ethernet-kabels los</li></ol>',
    guideWindowsChrome: '<strong>Installeer als offline app:</strong><ol><li>Open deze pagina in <strong>Chrome</strong></li><li>Klik op het <strong>install icon</strong> in de adresbalk (of three-dot menu &rarr; "Install BitClutch Signer")</li><li>Klik op <strong>"Install"</strong></li></ol><strong>Netwerk uitschakelen:</strong><ol><li>Klik op het <strong>Wi-Fi icon</strong> in de taakbalk (rechtsonder)</li><li>Klik om <strong>Wi-Fi te verbreken</strong></li><li>Koppel alle Ethernet-kabels los</li></ol>',
    guideWindowsEdge: '<strong>Installeer als offline app:</strong><ol><li>Open deze pagina in <strong>Edge</strong></li><li>Klik op het <strong>install icon</strong> in de adresbalk (of three-dot menu &rarr; "Apps" &rarr; "Install BitClutch Signer")</li><li>Klik op <strong>"Install"</strong></li></ol><strong>Netwerk uitschakelen:</strong><ol><li>Klik op het <strong>Wi-Fi icon</strong> in de taakbalk (rechtsonder)</li><li>Klik om <strong>Wi-Fi te verbreken</strong></li><li>Koppel alle Ethernet-kabels los</li></ol>',
    noMnemonic: 'Geen geheugensteuntje beschikbaar.', noTxData: 'Geen transactiegegevens.', noSignedData: 'Geen ondertekende gegevens.',
    noBmsRequest: 'Geen BMS-verzoek.', noSignature: 'Geen handtekening.', loading: 'Laden...',
    bannerWarn: 'NETWERK GEDETECTEERD \u2014 Verbreek alle netwerken voordat u sleutels genereert.',
    bannerOnline: 'NETWERK VERBONDEN \u2014 Verbreek NU en verbind dit apparaat NOOIT meer. Sleutels zijn mogelijk al blootgesteld.',
    bannerOffline: 'Geen draadloos netwerk gedetecteerd. Controleer of Bluetooth, NFC en USB-datakabels ook losgekoppeld zijn.',
  },
  hi: {
    unlocked: '\u0905\u0928\u0932\u0949\u0915', locked: '\u0932\u0949\u0915',
    tabKey: '\u0915\u0941\u0902\u091c\u0940', tabSign: '\u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930', tabSettings: '\u0938\u0947\u091f\u093f\u0902\u0917\u094d\u0938',
    createKeys: '\u0905\u092a\u0928\u0940 \u0915\u0941\u0902\u091c\u0940 \u092c\u0928\u093e\u090f\u0902',
    setupDesc: '\u092d\u094c\u0924\u093f\u0915 \u090f\u0902\u091f\u094d\u0930\u0949\u092a\u0940 \u0938\u0947 \u0928\u0908 \u0915\u0941\u0902\u091c\u0940 \u092c\u0928\u093e\u090f\u0902,<br>\u092f\u093e \u092e\u094c\u091c\u0942\u0926\u093e \u0938\u0940\u0921 \u0935\u093e\u0915\u094d\u092f\u093e\u0902\u0936 \u0906\u092f\u093e\u0924 \u0915\u0930\u0947\u0902\u0964',
    diceBtn: '\u092a\u093e\u0938\u093e (99 \u092c\u093e\u0930)', coinBtn: '\u0938\u093f\u0915\u094d\u0915\u093e (256 \u092c\u093e\u0930)', importBtn: '\u0938\u0940\u0921 \u0935\u093e\u0915\u094d\u092f\u093e\u0902\u0936 \u0906\u092f\u093e\u0924 \u0915\u0930\u0947\u0902',
    enterPassphrase: '\u0905\u0928\u0932\u0949\u0915 \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u092a\u093e\u0938\u0935\u0930\u094d\u0921 \u0926\u0930\u094d\u091c \u0915\u0930\u0947\u0902', passphrase: '\u092a\u093e\u0938\u0935\u0930\u094d\u0921', unlock: '\u0905\u0928\u0932\u0949\u0915', wrongPassphrase: '\u0917\u0932\u0924 \u092a\u093e\u0938\u0935\u0930\u094d\u0921\u0964',
    yourKey: '\u0906\u092a\u0915\u0940 \u0915\u0941\u0902\u091c\u0940', network: '\u0928\u0947\u091f\u0935\u0930\u094d\u0915', fingerprint: '\u092b\u093f\u0902\u0917\u0930\u092a\u094d\u0930\u093f\u0902\u091f', keyCreated: '\u092c\u0928\u093e\u092f\u093e \u0917\u092f\u093e', lastOnline: '\u0905\u0902\u0924\u093f\u092e \u0911\u0928\u0932\u093e\u0907\u0928', neverOnline: '\u0915\u092d\u0940 \u0928\u0939\u0940\u0902 (\u0938\u0941\u0930\u0915\u094d\u0937\u093f\u0924)', onlineAfterKey: '\u0915\u0941\u0902\u091c\u0940 \u092c\u0928\u093e\u0928\u0947 \u0915\u0947 \u092c\u093e\u0926 \u0911\u0928\u0932\u093e\u0907\u0928 \u092a\u0924\u093e \u091a\u0932\u093e', accountXpub: '\u0916\u093e\u0924\u093e xpub',
    showXpubQR: 'xpub QR \u0926\u093f\u0916\u093e\u090f\u0902', lockBtn: '\u0932\u0949\u0915', mainnet: '\u092e\u0947\u0928\u0928\u0947\u091f', testnet: '\u091f\u0947\u0938\u094d\u091f\u0928\u0947\u091f',
    diceTitle: '\u092a\u093e\u0938\u0947 \u0938\u0947 \u0915\u0941\u0902\u091c\u0940 \u092c\u0928\u093e\u0928\u093e', diceDesc: '\u0905\u0938\u0932\u0940 \u092a\u093e\u0938\u093e \u092b\u0947\u0902\u0915\u0947\u0902 \u0914\u0930 \u092a\u0930\u093f\u0923\u093e\u092e \u091f\u0948\u092a \u0915\u0930\u0947\u0902\u0964',
    progress: '\u092a\u094d\u0930\u0917\u0924\u093f', undoLast: '\u0935\u093e\u092a\u0938', cancel: '\u0930\u0926\u094d\u0926', ok: '\u0920\u0940\u0915',
    coinTitle: '\u0938\u093f\u0915\u094d\u0915\u0947 \u0938\u0947 \u0915\u0941\u0902\u091c\u0940 \u092c\u0928\u093e\u0928\u093e', coinDesc: '\u0905\u0938\u0932\u0940 \u0938\u093f\u0915\u094d\u0915\u093e \u0909\u091b\u093e\u0932\u0947\u0902 \u0914\u0930 \u092a\u0930\u093f\u0923\u093e\u092e \u091f\u0948\u092a \u0915\u0930\u0947\u0902\u0964',
    entropyWarning: '\u0905\u0938\u0932\u0940 \u092a\u093e\u0938\u093e/\u0938\u093f\u0915\u094d\u0915\u093e \u0907\u0938\u094d\u0924\u0947\u092e\u093e\u0932 \u0915\u0930\u0947\u0902 \u2014 \u0915\u092d\u0940 \u0928\u0902\u092c\u0930 \u0928 \u092c\u0928\u093e\u090f\u0902\u0964 \u092e\u093e\u0928\u0935\u0940\u092f \u091a\u092f\u0928 \u092a\u0942\u0930\u094d\u0935\u093e\u0928\u0941\u092e\u093e\u0928\u093f\u0924 \u0939\u094b\u0924\u0947 \u0939\u0948\u0902 \u0914\u0930 \u0915\u0941\u0902\u091c\u0940 \u0915\u092e\u091c\u094b\u0930 \u0915\u0930\u0924\u0947 \u0939\u0948\u0902\u0964 \u092a\u093e\u0938 \u092e\u0947\u0902 \u0915\u094b\u0908 \u0915\u0948\u092e\u0930\u093e \u092f\u093e \u092e\u093e\u0907\u0915\u094d\u0930\u094b\u092b\u094b\u0928 \u0928 \u0939\u094b \u2014 \u091c\u094b \u0906\u092a\u0915\u0947 \u092a\u0930\u093f\u0923\u093e\u092e \u0926\u0947\u0916\u0947 \u0935\u0939 \u0906\u092a\u0915\u093e Bitcoin \u091a\u0941\u0930\u093e \u0938\u0915\u0924\u093e \u0939\u0948\u0964',
    heads: 'H (\u091a\u093f\u0924)', tails: 'T (\u092a\u091f)',
    writeDown: '\u092f\u0947 \u0936\u092c\u094d\u0926 \u0932\u093f\u0916 \u0932\u0947\u0902!',
    mnemonicDesc: '\u092f\u0939 \u0906\u092a\u0915\u093e \u0938\u0940\u0921 \u0935\u093e\u0915\u094d\u092f\u093e\u0902\u0936 \u0939\u0948\u0964 \u0911\u092b\u0932\u093e\u0907\u0928 \u0938\u0941\u0930\u0915\u094d\u0937\u093f\u0924 \u0930\u0916\u0947\u0902\u0964 \u092b\u093f\u0930 \u0928\u0939\u0940\u0902 \u0926\u093f\u0916\u093e\u092f\u093e \u091c\u093e\u090f\u0917\u093e\u0964',
    stolenVsLost: '\u091a\u094b\u0930\u0940 vs. \u0916\u094b\u092f\u093e \u2014 \u0905\u0902\u0924\u0930 \u091c\u093e\u0928\u0947\u0902',
    theft: '\u091a\u094b\u0930\u0940:', theftDesc: '\u0905\u0917\u0930 \u0915\u093f\u0938\u0940 \u0915\u094b \u0906\u092a\u0915\u093e \u0938\u0940\u0921 \u092e\u093f\u0932 \u091c\u093e\u090f, \u0935\u0947 \u0924\u0941\u0930\u0902\u0924 Bitcoin \u091a\u0941\u0930\u093e \u0938\u0915\u0924\u0947 \u0939\u0948\u0902\u0964 \u0915\u094b\u0908 \u0907\u0938\u0947 \u0935\u093e\u092a\u0938 \u0928\u0939\u0940\u0902 \u0915\u0930 \u0938\u0915\u0924\u093e\u0964',
    loss: '\u0916\u094b\u092f\u093e:', lossDesc: '\u0905\u0917\u0930 \u0906\u092a \u0938\u0940\u0921 \u0916\u094b \u0926\u0947\u0902 \u0914\u0930 \u0921\u093f\u0935\u093e\u0907\u0938 \u0916\u0930\u093e\u092c \u0939\u094b \u091c\u093e\u090f, \u0924\u094b Bitcoin \u0939\u092e\u0947\u0936\u093e \u0915\u0947 \u0932\u093f\u090f \u0916\u094b \u091c\u093e\u090f\u0917\u093e \u2014 \u091c\u092c \u0924\u0915 \u0915\u093f \u0930\u093f\u0915\u0935\u0930\u0940 \u092a\u094d\u0932\u093e\u0928 \u0928 \u0939\u094b\u0964',
    bitclutchPromo: '<strong>BitClutch</strong> \u0916\u094b\u0928\u0947 \u0914\u0930 \u092e\u0943\u0924\u094d\u092f\u0941 \u0938\u0947 \u092c\u091a\u093e\u0924\u093e \u0939\u0948, \u091a\u094b\u0930\u0940 \u0938\u0947 \u0928\u0939\u0940\u0902\u0964 \u091f\u093e\u0907\u092e\u0932\u0949\u0915 \u0915\u0947 \u0938\u093e\u0925 <strong>\u0938\u0941\u0930\u0915\u094d\u0937\u093f\u0924 \u0935\u0949\u0932\u0947\u091f</strong> \u092c\u0928\u093e\u090f\u0902 \u2014 Bitcoin \u0906\u092a\u0915\u093e \u0930\u0939\u0924\u093e \u0939\u0948, \u0932\u0947\u0915\u093f\u0928 \u0909\u0924\u094d\u0924\u0930\u093e\u0927\u093f\u0915\u093e\u0930\u0940 \u0907\u0938\u0947 \u0930\u093f\u0915\u0935\u0930 \u0915\u0930 \u0938\u0915\u0924\u0947 \u0939\u0948\u0902\u0964',
    visitBitclutch: '\u0938\u0941\u0930\u0915\u094d\u0937\u093f\u0924 \u0935\u0949\u0932\u0947\u091f \u092c\u0928\u093e\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u0911\u0928\u0932\u093e\u0907\u0928 \u0921\u093f\u0935\u093e\u0907\u0938 \u092a\u0930 <strong>bitclutch.app</strong> \u092a\u0930 \u091c\u093e\u090f\u0902\u0964',
    confirmedWritten: '\u0932\u093f\u0916 \u0932\u093f\u092f\u093e',
    importTitle: '\u0938\u0940\u0921 \u0935\u093e\u0915\u094d\u092f\u093e\u0902\u0936 \u0906\u092f\u093e\u0924', importDesc: '\u0936\u092c\u094d\u0926 \u0938\u0902\u0916\u094d\u092f\u093e \u0914\u0930 \u092d\u093e\u0937\u093e \u091a\u0941\u0928\u0947\u0902, \u092b\u093f\u0930 \u092a\u094d\u0930\u0924\u094d\u092f\u0947\u0915 \u0936\u092c\u094d\u0926 \u0926\u0930\u094d\u091c \u0915\u0930\u0947\u0902\u0964',
    importPlaceholder: '\u0936\u092c\u094d\u09261 \u0936\u092c\u094d\u09262 \u0936\u092c\u094d\u09263 ...', importAction: '\u0906\u092f\u093e\u0924', words: '\u0936\u092c\u094d\u0926',
    fillAllWords: '\u0915\u0943\u092a\u092f\u093e \u0938\u092d\u0940 \u0936\u092c\u094d\u0926 \u092d\u0930\u0947\u0902\u0964', needWords: '12 \u092f\u093e 24 \u0936\u092c\u094d\u0926 \u091a\u093e\u0939\u093f\u090f', invalidMnemonic: '\u0905\u092e\u093e\u0928\u094d\u092f mnemonic',
    setPassTitle: '\u092a\u093e\u0938\u0935\u0930\u094d\u0921 \u0938\u0947\u091f \u0915\u0930\u0947\u0902', setPassDesc: '\u0905\u092a\u0928\u0940 \u0928\u093f\u091c\u0940 \u0915\u0941\u0902\u091c\u0940 \u0915\u094b \u090f\u0928\u094d\u0915\u094d\u0930\u093f\u092a\u094d\u091f \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u092e\u091c\u092c\u0942\u0924 \u092a\u093e\u0938\u0935\u0930\u094d\u0921 \u091a\u0941\u0928\u0947\u0902\u0964 \u0939\u0930 \u092c\u093e\u0930 \u0905\u0928\u0932\u0949\u0915 \u0915\u0930\u0924\u0947 \u0938\u092e\u092f \u091c\u0930\u0942\u0930\u0940 \u0939\u094b\u0917\u093e\u0964',
    confirmPass: '\u092a\u093e\u0938\u0935\u0930\u094d\u0921 \u0915\u0940 \u092a\u0941\u0937\u094d\u091f\u093f', enterPass: '\u092a\u093e\u0938\u0935\u0930\u094d\u0921 \u0926\u0930\u094d\u091c \u0915\u0930\u0947\u0902',
    passRequired: '\u092a\u093e\u0938\u0935\u0930\u094d\u0921 \u0906\u0935\u0936\u094d\u092f\u0915 \u0939\u0948\u0964', passTooShort: '\u092a\u093e\u0938\u0935\u0930\u094d\u0921 \u092c\u0939\u0941\u0924 \u091b\u094b\u091f\u093e (\u0928\u094d\u092f\u0942\u0928\u0924\u092e 4 \u0905\u0915\u094d\u0937\u0930)\u0964', passNoMatch: '\u092a\u093e\u0938\u0935\u0930\u094d\u0921 \u092e\u0947\u0932 \u0928\u0939\u0940\u0902 \u0916\u093e\u0924\u0947\u0964',
    noKeyToSave: '\u0938\u0939\u0947\u091c\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u0915\u094b\u0908 \u0915\u0941\u0902\u091c\u0940 \u0928\u0939\u0940\u0902\u0964 \u0926\u094b\u092c\u093e\u0930\u093e \u0936\u0941\u0930\u0942 \u0915\u0930\u0947\u0902\u0964', encryptSave: '\u090f\u0928\u094d\u0915\u094d\u0930\u093f\u092a\u094d\u091f \u0914\u0930 \u0938\u0939\u0947\u091c\u0947\u0902', encryptFailed: '\u090f\u0928\u094d\u0915\u094d\u0930\u093f\u092a\u094d\u0936\u0928 \u0935\u093f\u092b\u0932: ',
    scanTitle: 'QR \u0938\u094d\u0915\u0948\u0928', scanDesc: '\u0915\u0948\u092e\u0930\u093e BitClutch \u0910\u092a \u0915\u0947 QR \u0915\u094b\u0921 \u0915\u0940 \u0913\u0930 \u0930\u0916\u0947\u0902\u0964',
    startingCamera: '\u0915\u0948\u092e\u0930\u093e \u0936\u0941\u0930\u0942 \u0939\u094b \u0930\u0939\u093e...', scanning: '\u0938\u094d\u0915\u0948\u0928 \u0939\u094b \u0930\u0939\u093e... QR \u0915\u0940 \u0913\u0930 \u0930\u0916\u0947\u0902\u0964', cameraError: '\u0915\u0948\u092e\u0930\u093e \u0924\u094d\u0930\u0941\u091f\u093f: ',
    receivingFountain: 'Fountain \u0915\u094b\u0921 \u092a\u094d\u0930\u093e\u092a\u094d\u0924 \u0939\u094b \u0930\u0939\u093e...', urFailed: 'UR \u0921\u093f\u0915\u094b\u0921 \u0935\u093f\u092b\u0932\u0964 \u092b\u093f\u0930 \u092a\u094d\u0930\u092f\u093e\u0938 \u0915\u0930\u0947\u0902\u0964', psbtParseError: 'PSBT \u092a\u093e\u0930\u094d\u0938 \u0924\u094d\u0930\u0941\u091f\u093f: ',
    confirmTx: '\u0932\u0947\u0928\u0926\u0947\u0928 \u0915\u0940 \u092a\u0941\u0937\u094d\u091f\u093f', reviewBeforeSign: '\u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930 \u0915\u0930\u0928\u0947 \u0938\u0947 \u092a\u0939\u0932\u0947 \u0927\u094d\u092f\u093e\u0928 \u0938\u0947 \u091c\u093e\u0902\u091a\u0947\u0902\u0964',
    inputs: '\u0907\u0928\u092a\u0941\u091f', output: '\u0906\u0909\u091f\u092a\u0941\u091f', change: '(\u092c\u093e\u0915\u0940)', fee: '\u0936\u0941\u0932\u094d\u0915', reject: '\u0905\u0938\u094d\u0935\u0940\u0915\u093e\u0930', sign: '\u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930', signingFailed: '\u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930 \u0935\u093f\u092b\u0932: ',
    signedPsbt: '\u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930\u093f\u0924 PSBT', showQRDesc: '\u0932\u0947\u0928-\u0926\u0947\u0928 \u092a\u094d\u0930\u0938\u093e\u0930\u093f\u0924 \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f BitClutch \u0910\u092a \u0938\u0947 \u092f\u0939 QR \u0915\u094b\u0921 \u0938\u094d\u0915\u0948\u0928 \u0915\u0930\u0935\u093e\u090f\u0902\u0964', scanComplete: '\u0938\u094d\u0915\u0948\u0928 \u092a\u0942\u0930\u093e', scanSignatureDesc: '\u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930 \u092d\u0947\u091c\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f BitClutch \u0910\u092a \u0938\u0947 \u092f\u0939 QR \u0915\u094b\u0921 \u0938\u094d\u0915\u0948\u0928 \u0915\u0930\u0935\u093e\u090f\u0902\u0964',
    singleQR: '\u090f\u0915\u0932 QR', fountainKeepShowing: 'fountain \u0915\u094b\u0921 \u2014 \u0926\u093f\u0916\u093e\u0924\u0947 \u0930\u0939\u0947\u0902', frame: '\u092b\u094d\u0930\u0947\u092e',
    confirmBms: '\u0938\u0902\u0926\u0947\u0936 \u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930 \u0915\u0940 \u092a\u0941\u0937\u094d\u091f\u093f', reviewMessage: '\u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930 \u0938\u0947 \u092a\u0939\u0932\u0947 \u0938\u0902\u0926\u0947\u0936 \u091c\u093e\u0902\u091a\u0947\u0902\u0964',
    type: '\u092a\u094d\u0930\u0915\u093e\u0930', bmsType: 'BMS (Bitcoin \u0938\u0902\u0926\u0947\u0936)', index: '\u0907\u0902\u0921\u0947\u0915\u094d\u0938', address: '\u092a\u0924\u093e', message: '\u0938\u0902\u0926\u0947\u0936',
    bmsSignature: 'BMS \u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930', sigBase64: '\u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930 (base64)', tapToCopy: '\u0915\u0949\u092a\u0940 \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u091f\u0948\u092a \u0915\u0930\u0947\u0902', copySig: '\u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930 \u0915\u0949\u092a\u0940 \u0915\u0930\u0947\u0902', sha256: 'SHA-256',
    settings: '\u0938\u0947\u091f\u093f\u0902\u0917\u094d\u0938', version: '\u0938\u0902\u0938\u094d\u0915\u0930\u0923', language: '\u092d\u093e\u0937\u093e', seedLanguage: '\u0938\u0940\u0921 \u092d\u093e\u0937\u093e',
    onlineKeygenTitle: '\u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u0915\u0928\u0947\u0915\u094d\u091f\u0947\u0921!',
    onlineKeygenBody: '\u0906\u092a\u0915\u093e \u0921\u093f\u0935\u093e\u0907\u0938 \u0907\u0902\u091f\u0930\u0928\u0947\u091f \u0938\u0947 \u091c\u0941\u0921\u093c\u093e \u0939\u0948\u0964 \u0911\u0928\u0932\u093e\u0907\u0928 \u091c\u0947\u0928\u0930\u0947\u091f \u0915\u0940 \u0917\u0908 \u0915\u0941\u0902\u091c\u093f\u092f\u093e\u0901 \u092e\u0948\u0932\u0935\u0947\u092f\u0930 \u0926\u094d\u0935\u093e\u0930\u093e \u0907\u0902\u091f\u0930\u0938\u0947\u092a\u094d\u091f \u0939\u094b \u0938\u0915\u0924\u0940 \u0939\u0948\u0902\u0964 \u0906\u0917\u0947 \u092c\u0922\u093c\u0928\u0947 \u0938\u0947 \u092a\u0939\u0932\u0947 \u0938\u092d\u0940 \u0928\u0947\u091f\u0935\u0930\u094d\u0915 (WiFi, \u092e\u094b\u092c\u093e\u0907\u0932, Bluetooth, USB) \u0921\u093f\u0938\u094d\u0915\u0928\u0947\u0915\u094d\u091f \u0915\u0930\u0947\u0902\u0964',
    proceedAnyway: '\u092b\u093f\u0930 \u092d\u0940 \u0906\u0917\u0947 \u092c\u0922\u093c\u0947\u0902 (\u0905\u0938\u0941\u0930\u0915\u094d\u0937\u093f\u0924)',
    installGuide: '\u0938\u094d\u0925\u093e\u092a\u0928\u093e \u0917\u093e\u0907\u0921', viewSource: '\u0938\u094d\u0930\u094b\u0924 \u0915\u094b\u0921 \u0905\u0916\u0902\u0921\u0924\u093e \u0938\u0924\u094d\u092f\u093e\u092a\u093f\u0924 \u0915\u0930\u0947\u0902', securityInfo: '\u0938\u0941\u0930\u0915\u094d\u0937\u093e \u091c\u093e\u0928\u0915\u093e\u0930\u0940',
    deleteKey: '\u0915\u0941\u0902\u091c\u0940 \u0939\u091f\u093e\u090f\u0902', deleteConfirm1: '\u0915\u0941\u0902\u091c\u0940 \u0939\u091f\u093e\u090f\u0902? \u0935\u093e\u092a\u0938 \u0928\u0939\u0940\u0902 \u0939\u094b \u0938\u0915\u0924\u093e\u0964\n\u0938\u0941\u0928\u093f\u0936\u094d\u091a\u093f\u0924 \u0915\u0930\u0947\u0902 \u0915\u093f \u0938\u0940\u0921 \u092c\u0948\u0915\u0905\u092a \u0939\u0948!',
    deleteConfirm2: '\u0915\u094d\u092f\u093e \u0906\u092a \u092a\u0942\u0930\u0940 \u0924\u0930\u0939 \u0938\u0941\u0928\u093f\u0936\u094d\u091a\u093f\u0924 \u0939\u0948\u0902? \u092c\u0948\u0915\u0905\u092a \u0915\u0947 \u092c\u093f\u0928\u093e Bitcoin \u0916\u094b \u091c\u093e\u090f\u0917\u093e\u0964',
    verifyIntegrity: '\u0905\u0916\u0902\u0921\u0924\u093e \u0938\u0924\u094d\u092f\u093e\u092a\u093f\u0924 \u0915\u0930\u0947\u0902', verifyDesc: 'SHA-256 \u0939\u0948\u0936 \u0915\u094b GitHub \u0915\u0947 \u0906\u0927\u093f\u0915\u093e\u0930\u093f\u0915 \u0930\u093f\u0932\u0940\u091c \u0938\u0947 \u0924\u0941\u0932\u0928\u093e \u0915\u0930\u0947\u0902\u0964',
    computing: '\u0917\u0923\u0928\u093e \u0939\u094b \u0930\u0939\u093e...', fetchFailed: '(\u0921\u093e\u0909\u0928\u0932\u094b\u0921 \u0935\u093f\u092b\u0932)',
    verifyFile: '\u092f\u0939 \u092b\u093e\u0907\u0932 \u0938\u0924\u094d\u092f\u093e\u092a\u093f\u0924 \u0915\u0930\u0947\u0902', verifyFileDesc: '\u092f\u0939\u093e\u0902 \u091f\u0948\u092a \u0915\u0930\u0947\u0902 \u0914\u0930 \u0921\u093e\u0909\u0928\u0932\u094b\u0921 \u0915\u0940 <strong>bitclutch-signer.html</strong> \u092b\u093e\u0907\u0932 \u091a\u0941\u0928\u0947\u0902\u0964<br>SHA-256 \u0939\u0948\u0936 \u0938\u094d\u0925\u093e\u0928\u0940\u092f \u0930\u0942\u092a \u0938\u0947 \u0917\u0923\u0928\u093e \u0939\u094b\u0917\u093e\u0964',
    tapToSelect: '\u091a\u0941\u0928\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u091f\u0948\u092a \u0915\u0930\u0947\u0902', compareGithub: 'GitHub \u0930\u093f\u0932\u0940\u091c \u0915\u0947 <code>hashes.json</code> \u0938\u0947 \u0924\u0941\u0932\u0928\u093e \u0915\u0930\u0947\u0902\u0964',
    auditableSource: '\u0911\u0921\u093f\u091f \u092f\u094b\u0917\u094d\u092f \u0938\u094b\u0930\u094d\u0938', auditableDesc: '\u0907\u0938 \u0910\u092a \u0915\u093e \u0938\u092e\u094d\u092a\u0942\u0930\u094d\u0923 \u0924\u0930\u094d\u0915 \u090f\u0915 \u0911\u0921\u093f\u091f \u092f\u094b\u0917\u094d\u092f \u092b\u093e\u0907\u0932 \u092e\u0947\u0902 \u0939\u0948\u0964 \u0938\u094b\u0930\u094d\u0938 \u0915\u094b\u0921 \u0914\u0930 \u0906\u0927\u093f\u0915\u093e\u0930\u093f\u0915 \u0939\u0948\u0936 GitHub \u092a\u0930 \u092a\u094d\u0930\u0915\u093e\u0936\u093f\u0924 \u0939\u0948\u0902\u0964',
    back: '\u0935\u093e\u092a\u0938',
    securityTitle: '\u0938\u0941\u0930\u0915\u094d\u0937\u093e \u091c\u093e\u0928\u0915\u093e\u0930\u0940', securityLevel: '\u0938\u0941\u0930\u0915\u094d\u0937\u093e \u0938\u094d\u0924\u0930: \u0938\u0949\u092b\u094d\u091f\u0935\u0947\u092f\u0930 \u090f\u092f\u0930-\u0917\u0948\u092a',
    whatProvides: '\u092f\u0939 \u092a\u094d\u0930\u0926\u093e\u0928 \u0915\u0930\u0924\u093e \u0939\u0948:', secProvide1: '\u0928\u093f\u091c\u0940 \u0915\u0941\u0902\u091c\u0940 \u0915\u092d\u0940 \u0907\u0902\u091f\u0930\u0928\u0947\u091f \u0928\u0939\u0940\u0902 \u091b\u0942\u0924\u0940 (\u0938\u0947\u091f\u0905\u092a \u0915\u0947 \u092c\u093e\u0926)',
    secProvide2: '\u0915\u094b\u0921 \u0911\u0921\u093f\u091f \u092f\u094b\u0917\u094d\u092f (app.js \u090f\u0915 \u092b\u093e\u0907\u0932)', secProvide3: '\u0915\u0947\u0935\u0932 \u092d\u094c\u0924\u093f\u0915 \u0938\u094d\u0930\u094b\u0924 \u0938\u0947 \u090f\u0902\u091f\u094d\u0930\u0949\u092a\u0940 (\u092a\u093e\u0938\u093e/\u0938\u093f\u0915\u094d\u0915\u093e)',
    secProvide4: 'AES-256-GCM \u090f\u0928\u094d\u0915\u094d\u0930\u093f\u092a\u094d\u0936\u0928 + 600K PBKDF2 \u0907\u091f\u0930\u0947\u0936\u0928',
    whatNot: '\u092f\u0939 \u092a\u094d\u0930\u0926\u093e\u0928 \u0928\u0939\u0940\u0902 \u0915\u0930\u0924\u093e:', secNot1: 'Secure Element (\u0939\u093e\u0930\u094d\u0921\u0935\u0947\u092f\u0930 \u0935\u0949\u0932\u0947\u091f \u092e\u0947\u0902 \u0939\u094b\u0924\u093e \u0939\u0948)',
    secNot2: '\u0939\u093e\u0930\u094d\u0921\u0935\u0947\u092f\u0930 \u0938\u094d\u0924\u0930 \u090f\u092f\u0930 \u0917\u0948\u092a (WiFi \u091a\u093f\u092a \u0905\u092d\u0940 \u092d\u0940 \u092e\u094c\u091c\u0942\u0926)', secNot3: '\u0938\u093e\u0907\u0921 \u091a\u0948\u0928\u0932 \u0939\u092e\u0932\u0947 \u092a\u094d\u0930\u0924\u093f\u0930\u094b\u0927',
    keyStorage: '\u0915\u0941\u0902\u091c\u0940 \u0938\u0902\u0917\u094d\u0930\u0939\u0923', encryption: '\u090f\u0928\u094d\u0915\u094d\u0930\u093f\u092a\u094d\u0936\u0928:', encryptionDesc: 'AES-256-GCM + PBKDF2 (600,000 \u092c\u093e\u0930) + \u092f\u093e\u0926\u0943\u091a\u094d\u091b\u093f\u0915 salt/IV',
    warning: '\u091a\u0947\u0924\u093e\u0935\u0928\u0940:', clearDataWarning: '\u092c\u094d\u0930\u093e\u0909\u091c\u0930 \u0921\u0947\u091f\u093e \u0938\u093e\u092b \u0915\u0930\u0928\u0947 \u0938\u0947 \u090f\u0928\u094d\u0915\u094d\u0930\u093f\u092a\u094d\u091f\u0947\u0921 \u0915\u0941\u0902\u091c\u0940 \u0938\u094d\u0925\u093e\u092f\u0940 \u0930\u0942\u092a \u0938\u0947 \u0939\u091f \u091c\u093e\u090f\u0917\u0940\u0964 \u0938\u0940\u0921 \u0939\u092e\u0947\u0936\u093e \u0911\u092b\u0932\u093e\u0907\u0928 \u092c\u0948\u0915\u0905\u092a \u0930\u0916\u0947\u0902\u0964',
    autoLock: '\u0911\u091f\u094b \u0932\u0949\u0915:', autoLockDesc: '5 \u092e\u093f\u0928\u091f \u0928\u093f\u0937\u094d\u0915\u094d\u0930\u093f\u092f\u0924\u093e \u0915\u0947 \u092c\u093e\u0926 \u0915\u0941\u0902\u091c\u093f\u092f\u093e\u0902 \u092e\u0947\u092e\u094b\u0930\u0940 \u0938\u0947 \u0939\u091f\u093e \u0926\u0940 \u091c\u093e\u0924\u0940 \u0939\u0948\u0902\u0964',
    storageEncKey: '\u090f\u0928\u094d\u0915\u094d\u0930\u093f\u092a\u094d\u091f\u0947\u0921 \u0928\u093f\u091c\u0940 \u0915\u0941\u0902\u091c\u0940 (AES-256-GCM)', storageXpub: '\u0916\u093e\u0924\u093e \u0935\u093f\u0938\u094d\u0924\u093e\u0930\u093f\u0924 \u0938\u093e\u0930\u094d\u0935\u091c\u0928\u093f\u0915 \u0915\u0941\u0902\u091c\u0940', storageFp: 'BIP-32 \u092b\u093f\u0902\u0917\u0930\u092a\u094d\u0930\u093f\u0902\u091f',
    storageNet: '\u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u0938\u0947\u091f\u093f\u0902\u0917 (main/test)', storageLang: '\u0907\u0902\u091f\u0930\u092b\u0947\u0938 \u092d\u093e\u0937\u093e', storageSeedLang: '\u0938\u0940\u0921 \u092d\u093e\u0937\u093e', storageKeyCreated: '\u0915\u0941\u0902\u091c\u0940 \u0928\u093f\u0930\u094d\u092e\u093e\u0923 \u0924\u093f\u0925\u093f', storageLastOnline: '\u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u092a\u0924\u093e \u0924\u093f\u0925\u093f',
    guideTitle: '\u0938\u094d\u0925\u093e\u092a\u0928\u093e \u0917\u093e\u0907\u0921', guideDesc: 'BitClutch Signer \u0915\u094b \u0911\u092b\u0932\u093e\u0907\u0928 \u0910\u092a \u0915\u0947 \u0930\u0942\u092a \u092e\u0947\u0902 \u0907\u0902\u0938\u094d\u091f\u0949\u0932 \u0915\u0930\u0947\u0902, \u092b\u093f\u0930 \u0909\u092a\u092f\u094b\u0917 \u0938\u0947 \u092a\u0939\u0932\u0947 \u090f\u092f\u0930\u092a\u094d\u0932\u0947\u0928 \u092e\u094b\u0921 \u091a\u093e\u0932\u0942 \u0915\u0930\u0947\u0902\u0964',
    detected: '\u092a\u0939\u091a\u093e\u0928\u093e \u0917\u092f\u093e', accountXpubTitle: '\u0916\u093e\u0924\u093e xpub',
    guideIosSafari: '<strong>\u0911\u092b\u0932\u093e\u0907\u0928 \u0910\u092a \u0915\u0947 \u0930\u0942\u092a \u092e\u0947\u0902 \u0907\u0902\u0938\u094d\u091f\u0949\u0932 \u0915\u0930\u0947\u0902:</strong><ol><li>\u092f\u0939 \u092a\u0947\u091c <strong>Safari</strong> \u092e\u0947\u0902 \u0916\u094b\u0932\u0947\u0902</li><li><strong>Share</strong> \u092c\u091f\u0928 (\u0924\u0940\u0930 \u0935\u093e\u0932\u093e \u092c\u0949\u0915\u094d\u0938) \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902</li><li>\u0928\u0940\u091a\u0947 \u0938\u094d\u0915\u094d\u0930\u094b\u0932 \u0915\u0930\u0947\u0902 \u0914\u0930 <strong>"Add to Home Screen"</strong> \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902</li><li>\u0926\u093e\u0908\u0902 \u0913\u0930 \u090a\u092a\u0930 <strong>"Add"</strong> \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902</li></ol><strong>\u090f\u092f\u0930\u092a\u094d\u0932\u0947\u0928 \u092e\u094b\u0921 \u091a\u093e\u0932\u0942 \u0915\u0930\u0947\u0902:</strong><ol><li>\u0926\u093e\u0908\u0902 \u0913\u0930 \u0915\u094b\u0928\u0947 \u0938\u0947 \u0928\u0940\u091a\u0947 \u0938\u094d\u0935\u093e\u0907\u092a \u0915\u0930\u0947\u0902 (\u092f\u093e \u092a\u0941\u0930\u093e\u0928\u0947 iPhone \u092a\u0930 \u0928\u0940\u091a\u0947 \u0938\u0947 \u090a\u092a\u0930)</li><li>\u091a\u093e\u0932\u0942 \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f <strong>airplane icon</strong> \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902</li><li>\u0938\u0941\u0928\u093f\u0936\u094d\u091a\u093f\u0924 \u0915\u0930\u0947\u0902 \u0915\u093f Wi-Fi \u0914\u0930 Bluetooth \u092d\u0940 \u092c\u0902\u0926 \u0939\u0948\u0902</li></ol>',
    guideIosChrome: '<strong>\u092e\u0939\u0924\u094d\u0935\u092a\u0942\u0930\u094d\u0923:</strong> iOS \u092a\u0930 Chrome \u0911\u092b\u0932\u093e\u0907\u0928 \u0910\u092a \u0907\u0902\u0938\u094d\u091f\u0949\u0932 \u0928\u0939\u0940\u0902 \u0915\u0930 \u0938\u0915\u0924\u093e\u0964 \u0907\u0938\u0915\u0947 \u092c\u091c\u093e\u092f <strong>Safari</strong> \u0915\u093e \u0909\u092a\u092f\u094b\u0917 \u0915\u0930\u0947\u0902\u0964<ol><li>\u0907\u0938 \u092a\u0947\u091c \u0915\u093e URL \u0915\u0949\u092a\u0940 \u0915\u0930\u0947\u0902</li><li><strong>Safari</strong> \u0916\u094b\u0932\u0947\u0902 \u0914\u0930 URL \u092a\u0947\u0938\u094d\u091f \u0915\u0930\u0947\u0902</li><li>\u090a\u092a\u0930 \u0926\u093f\u090f \u0917\u090f <strong>iOS Safari</strong> \u0928\u093f\u0930\u094d\u0926\u0947\u0936\u094b\u0902 \u0915\u093e \u092a\u093e\u0932\u0928 \u0915\u0930\u0947\u0902</li></ol><strong>\u090f\u092f\u0930\u092a\u094d\u0932\u0947\u0928 \u092e\u094b\u0921 \u091a\u093e\u0932\u0942 \u0915\u0930\u0947\u0902:</strong><ol><li>\u0926\u093e\u0908\u0902 \u0913\u0930 \u0915\u094b\u0928\u0947 \u0938\u0947 \u0928\u0940\u091a\u0947 \u0938\u094d\u0935\u093e\u0907\u092a \u0915\u0930\u0947\u0902</li><li><strong>airplane icon</strong> \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902</li></ol>',
    guideAndroidChrome: '<strong>\u0911\u092b\u0932\u093e\u0907\u0928 \u0910\u092a \u0915\u0947 \u0930\u0942\u092a \u092e\u0947\u0902 \u0907\u0902\u0938\u094d\u091f\u0949\u0932 \u0915\u0930\u0947\u0902:</strong><ol><li>\u092f\u0939 \u092a\u0947\u091c <strong>Chrome</strong> \u092e\u0947\u0902 \u0916\u094b\u0932\u0947\u0902</li><li><strong>three-dot menu</strong> (\u0926\u093e\u0908\u0902 \u0913\u0930 \u090a\u092a\u0930) \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902</li><li><strong>"Install app"</strong> \u092f\u093e <strong>"Add to Home screen"</strong> \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902</li><li><strong>"Install"</strong> \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0915\u0947 \u092a\u0941\u0937\u094d\u091f\u093f \u0915\u0930\u0947\u0902</li></ol><strong>\u090f\u092f\u0930\u092a\u094d\u0932\u0947\u0928 \u092e\u094b\u0921 \u091a\u093e\u0932\u0942 \u0915\u0930\u0947\u0902:</strong><ol><li>\u0938\u094d\u0915\u094d\u0930\u0940\u0928 \u0915\u0947 \u090a\u092a\u0930 \u0938\u0947 \u0928\u0940\u091a\u0947 \u0938\u094d\u0935\u093e\u0907\u092a \u0915\u0930\u0947\u0902</li><li><strong>"Airplane mode"</strong> \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902</li><li>\u0938\u0941\u0928\u093f\u0936\u094d\u091a\u093f\u0924 \u0915\u0930\u0947\u0902 \u0915\u093f Wi-Fi \u0914\u0930 \u092e\u094b\u092c\u093e\u0907\u0932 \u0921\u0947\u091f\u093e \u092c\u0902\u0926 \u0939\u0948\u0902</li></ol>',
    guideAndroidSamsung: '<strong>\u0911\u092b\u0932\u093e\u0907\u0928 \u0910\u092a \u0915\u0947 \u0930\u0942\u092a \u092e\u0947\u0902 \u0907\u0902\u0938\u094d\u091f\u0949\u0932 \u0915\u0930\u0947\u0902:</strong><ol><li>\u092f\u0939 \u092a\u0947\u091c <strong>Samsung Internet</strong> \u092e\u0947\u0902 \u0916\u094b\u0932\u0947\u0902</li><li><strong>menu icon</strong> (\u0924\u0940\u0928 \u0932\u093e\u0907\u0928\u0947\u0902, \u0926\u093e\u0908\u0902 \u0928\u0940\u091a\u0947) \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902</li><li><strong>"Add page to"</strong> \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902 \u092b\u093f\u0930 <strong>"Home screen"</strong></li></ol><strong>\u090f\u092f\u0930\u092a\u094d\u0932\u0947\u0928 \u092e\u094b\u0921 \u091a\u093e\u0932\u0942 \u0915\u0930\u0947\u0902:</strong><ol><li>Quick Settings \u0916\u094b\u0932\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u090a\u092a\u0930 \u0938\u0947 \u0926\u094b \u092c\u093e\u0930 \u0928\u0940\u091a\u0947 \u0938\u094d\u0935\u093e\u0907\u092a \u0915\u0930\u0947\u0902</li><li><strong>"Airplane mode"</strong> \u092a\u0930 \u091f\u0948\u092a \u0915\u0930\u0947\u0902</li></ol>',
    guideMacosSafari: '<strong>\u0911\u092b\u0932\u093e\u0907\u0928 \u0910\u092a \u0915\u0947 \u0930\u0942\u092a \u092e\u0947\u0902 \u0907\u0902\u0938\u094d\u091f\u0949\u0932 \u0915\u0930\u0947\u0902 (macOS Sonoma+):</strong><ol><li>\u092f\u0939 \u092a\u0947\u091c <strong>Safari</strong> \u092e\u0947\u0902 \u0916\u094b\u0932\u0947\u0902</li><li><strong>File</strong> \u092e\u0947\u0928\u0942 \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902 \u092b\u093f\u0930 <strong>"Add to Dock"</strong></li><li><strong>"Add"</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li></ol><strong>\u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u092c\u0902\u0926 \u0915\u0930\u0947\u0902:</strong><ol><li>\u092e\u0947\u0928\u0942 \u092c\u093e\u0930 \u092e\u0947\u0902 <strong>Wi-Fi icon</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li><li><strong>turn Wi-Fi off</strong> \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li><li>\u0938\u092d\u0940 Ethernet \u0915\u0947\u092c\u0932 \u0928\u093f\u0915\u093e\u0932\u0947\u0902</li></ol>',
    guideMacosChrome: '<strong>\u0911\u092b\u0932\u093e\u0907\u0928 \u0910\u092a \u0915\u0947 \u0930\u0942\u092a \u092e\u0947\u0902 \u0907\u0902\u0938\u094d\u091f\u0949\u0932 \u0915\u0930\u0947\u0902:</strong><ol><li>\u092f\u0939 \u092a\u0947\u091c <strong>Chrome</strong> \u092e\u0947\u0902 \u0916\u094b\u0932\u0947\u0902</li><li>\u090f\u0921\u094d\u0930\u0947\u0938 \u092c\u093e\u0930 \u092e\u0947\u0902 <strong>install icon</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902 (\u092f\u093e three-dot menu &rarr; "Install BitClutch Signer")</li><li><strong>"Install"</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li></ol><strong>\u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u092c\u0902\u0926 \u0915\u0930\u0947\u0902:</strong><ol><li>\u092e\u0947\u0928\u0942 \u092c\u093e\u0930 \u092e\u0947\u0902 <strong>Wi-Fi icon</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li><li><strong>turn Wi-Fi off</strong> \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li><li>\u0938\u092d\u0940 Ethernet \u0915\u0947\u092c\u0932 \u0928\u093f\u0915\u093e\u0932\u0947\u0902</li></ol>',
    guideWindowsChrome: '<strong>\u0911\u092b\u0932\u093e\u0907\u0928 \u0910\u092a \u0915\u0947 \u0930\u0942\u092a \u092e\u0947\u0902 \u0907\u0902\u0938\u094d\u091f\u0949\u0932 \u0915\u0930\u0947\u0902:</strong><ol><li>\u092f\u0939 \u092a\u0947\u091c <strong>Chrome</strong> \u092e\u0947\u0902 \u0916\u094b\u0932\u0947\u0902</li><li>\u090f\u0921\u094d\u0930\u0947\u0938 \u092c\u093e\u0930 \u092e\u0947\u0902 <strong>install icon</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902 (\u092f\u093e three-dot menu &rarr; "Install BitClutch Signer")</li><li><strong>"Install"</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li></ol><strong>\u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u092c\u0902\u0926 \u0915\u0930\u0947\u0902:</strong><ol><li>\u091f\u093e\u0938\u094d\u0915\u092c\u093e\u0930 (\u0928\u0940\u091a\u0947 \u0926\u093e\u0908\u0902 \u0913\u0930) \u092e\u0947\u0902 <strong>Wi-Fi icon</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li><li><strong>Wi-Fi \u0921\u093f\u0938\u094d\u0915\u0928\u0947\u0915\u094d\u091f</strong> \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li><li>\u0938\u092d\u0940 Ethernet \u0915\u0947\u092c\u0932 \u0928\u093f\u0915\u093e\u0932\u0947\u0902</li></ol>',
    guideWindowsEdge: '<strong>\u0911\u092b\u0932\u093e\u0907\u0928 \u0910\u092a \u0915\u0947 \u0930\u0942\u092a \u092e\u0947\u0902 \u0907\u0902\u0938\u094d\u091f\u0949\u0932 \u0915\u0930\u0947\u0902:</strong><ol><li>\u092f\u0939 \u092a\u0947\u091c <strong>Edge</strong> \u092e\u0947\u0902 \u0916\u094b\u0932\u0947\u0902</li><li>\u090f\u0921\u094d\u0930\u0947\u0938 \u092c\u093e\u0930 \u092e\u0947\u0902 <strong>install icon</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902 (\u092f\u093e three-dot menu &rarr; "\u090f\u092a\u094d\u0938" &rarr; "Install BitClutch Signer")</li><li><strong>"Install"</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li></ol><strong>\u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u092c\u0902\u0926 \u0915\u0930\u0947\u0902:</strong><ol><li>\u091f\u093e\u0938\u094d\u0915\u092c\u093e\u0930 (\u0928\u0940\u091a\u0947 \u0926\u093e\u0908\u0902 \u0913\u0930) \u092e\u0947\u0902 <strong>Wi-Fi icon</strong> \u092a\u0930 \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li><li><strong>Wi-Fi \u0921\u093f\u0938\u094d\u0915\u0928\u0947\u0915\u094d\u091f</strong> \u0915\u0930\u0928\u0947 \u0915\u0947 \u0932\u093f\u090f \u0915\u094d\u0932\u093f\u0915 \u0915\u0930\u0947\u0902</li><li>\u0938\u092d\u0940 Ethernet \u0915\u0947\u092c\u0932 \u0928\u093f\u0915\u093e\u0932\u0947\u0902</li></ol>',
    noMnemonic: '\u0915\u094b\u0908 mnemonic \u0928\u0939\u0940\u0902\u0964', noTxData: '\u0915\u094b\u0908 \u0932\u0947\u0928\u0926\u0947\u0928 \u0921\u0947\u091f\u093e \u0928\u0939\u0940\u0902\u0964', noSignedData: '\u0915\u094b\u0908 \u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930\u093f\u0924 \u0921\u0947\u091f\u093e \u0928\u0939\u0940\u0902\u0964',
    noBmsRequest: '\u0915\u094b\u0908 BMS \u0905\u0928\u0941\u0930\u094b\u0927 \u0928\u0939\u0940\u0902\u0964', noSignature: '\u0915\u094b\u0908 \u0939\u0938\u094d\u0924\u093e\u0915\u094d\u0937\u0930 \u0928\u0939\u0940\u0902\u0964', loading: '\u0932\u094b\u0921 \u0939\u094b \u0930\u0939\u093e...',
    bannerWarn: '\u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u092e\u093f\u0932\u093e \u2014 \u0915\u0941\u0902\u091c\u0940 \u092c\u0928\u093e\u0928\u0947 \u0938\u0947 \u092a\u0939\u0932\u0947 \u0938\u092d\u0940 \u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u0921\u093f\u0938\u094d\u0915\u0928\u0947\u0915\u094d\u091f \u0915\u0930\u0947\u0902\u0964',
    bannerOnline: '\u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u0915\u0928\u0947\u0915\u094d\u091f\u0947\u0921 \u2014 \u0905\u092d\u0940 \u0921\u093f\u0938\u094d\u0915\u0928\u0947\u0915\u094d\u091f \u0915\u0930\u0947\u0902 \u0914\u0930 \u0907\u0938 \u0921\u093f\u0935\u093e\u0907\u0938 \u0915\u094b \u0915\u092d\u0940 \u0926\u094b\u092c\u093e\u0930\u093e \u0915\u0928\u0947\u0915\u094d\u091f \u0928 \u0915\u0930\u0947\u0902\u0964 \u0915\u0941\u0902\u091c\u093f\u092f\u093e\u0901 \u092a\u0939\u0932\u0947 \u0938\u0947 \u0909\u091c\u093e\u0917\u0930 \u0939\u094b \u0938\u0915\u0924\u0940 \u0939\u0948\u0902\u0964',
    bannerOffline: '\u0915\u094b\u0908 \u0935\u093e\u092f\u0930\u0932\u0947\u0938 \u0928\u0947\u091f\u0935\u0930\u094d\u0915 \u0928\u0939\u0940\u0902 \u092e\u093f\u0932\u093e\u0964 \u0938\u0941\u0928\u093f\u0936\u094d\u091a\u093f\u0924 \u0915\u0930\u0947\u0902 \u0915\u093f Bluetooth, NFC \u0914\u0930 USB \u0921\u0947\u091f\u093e \u0915\u0947\u092c\u0932 \u092d\u0940 \u0921\u093f\u0938\u094d\u0915\u0928\u0947\u0915\u094d\u091f \u0939\u0948\u0902\u0964',
  },
};

function t(key) { return (I18N[S.lang] || I18N.en)[key] || I18N.en[key] || key; }
function fmtDate(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleString(S.lang, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
const SEED_LANGS = [
  { id: 'en', label: 'English', wordlist: englishWordlist },
  { id: 'ko', label: '한국어', wordlist: koreanWordlist },
  { id: 'ja', label: '日本語', wordlist: japaneseWordlist },
  { id: 'es', label: 'Español', wordlist: spanishWordlist },
  { id: 'fr', label: 'Français', wordlist: frenchWordlist },
  { id: 'it', label: 'Italiano', wordlist: italianWordlist },
  { id: 'pt', label: 'Português', wordlist: portugueseWordlist },
  { id: 'cs', label: 'Čeština', wordlist: czechWordlist },
  { id: 'zh-s', label: '简体中文', wordlist: simplifiedChineseWordlist },
  { id: 'zh-t', label: '繁體中文', wordlist: traditionalChineseWordlist },
];
function getWordlist(lang) {
  const id = lang || S.seedLang;
  const entry = SEED_LANGS.find(l => l.id === id);
  return entry ? entry.wordlist : englishWordlist;
}
// Korean BIP-39 wordlist is NFD; browser input is NFC.
// getWordlistNFC() returns NFC-normalized copy for UI matching (autocomplete, validation display).
const _nfcCache = new Map();
function getWordlistNFC(lang) {
  const raw = getWordlist(lang);
  if (!_nfcCache.has(raw)) _nfcCache.set(raw, raw.map(w => w.normalize('NFC')));
  return _nfcCache.get(raw);
}
function getSeedLangLabel(id) {
  const entry = SEED_LANGS.find(l => l.id === (id || S.seedLang));
  return entry ? entry.label : 'English';
}
const UI_LANGS = [
  { id: 'en', label: 'English' },
  { id: 'ko', label: '\ud55c\uad6d\uc5b4' },
  { id: 'es', label: 'Espa\u00f1ol' },
  { id: 'ja', label: '\u65e5\u672c\u8a9e' },
  { id: 'pt', label: 'Portugu\u00eas' },
  { id: 'de', label: 'Deutsch' },
  { id: 'fr', label: 'Fran\u00e7ais' },
  { id: 'zh-s', label: '\u7b80\u4f53\u4e2d\u6587' },
  { id: 'zh-t', label: '\u7e41\u9ad4\u4e2d\u6587' },
  { id: 'tr', label: 'T\u00fcrk\u00e7e' },
  { id: 'it', label: 'Italiano' },
  { id: 'vi', label: 'Ti\u1ebfng Vi\u1ec7t' },
  { id: 'th', label: '\u0e44\u0e17\u0e22' },
  { id: 'id', label: 'Bahasa Indonesia' },
  { id: 'ar', label: '\u0627\u0644\u0639\u0631\u0628\u064a\u0629' },
  { id: 'nl', label: 'Nederlands' },
  { id: 'hi', label: '\u0939\u093f\u0928\u094d\u0926\u0940' },
];
function getUILangLabel(id) {
  const entry = UI_LANGS.find(l => l.id === (id || S.lang));
  return entry ? entry.label : 'English';
}
function renderUILangSelect() {
  const cur = UI_LANGS.find(l => l.id === S.lang) || UI_LANGS[0];
  const chevron = `<svg class="lang-dropdown-arrow" viewBox="0 0 16 16"><polyline points="4 6 8 10 12 6"/></svg>`;
  const check = `<svg class="check-icon" viewBox="0 0 16 16"><polyline points="3 8 7 12 13 4"/></svg>`;
  const items = UI_LANGS.map(l =>
    `<div class="lang-dropdown-item${l.id === S.lang ? ' selected' : ''}" data-action="pickUILang" data-arg="${l.id}">
      <span>${l.label}</span>${l.id === S.lang ? check : ''}
    </div>`
  ).join('');
  return `<div class="lang-dropdown">
    <div class="lang-dropdown-trigger" data-action="toggleLangDropdown">${cur.label} ${chevron}</div>
    <div class="lang-dropdown-menu">${items}</div>
  </div>`;
}
function renderSeedLangSelect(action) {
  const cur = SEED_LANGS.find(l => l.id === S.seedLang) || SEED_LANGS[0];
  const chevron = `<svg class="lang-dropdown-arrow" viewBox="0 0 16 16"><polyline points="4 6 8 10 12 6"/></svg>`;
  const check = `<svg class="check-icon" viewBox="0 0 16 16"><polyline points="3 8 7 12 13 4"/></svg>`;
  const items = SEED_LANGS.map(l =>
    `<div class="lang-dropdown-item${l.id === S.seedLang ? ' selected' : ''}" data-action="pickSeedLang" data-arg="${action}:${l.id}">
      <span>${l.label}</span>${l.id === S.seedLang ? check : ''}
    </div>`
  ).join('');
  return `<div class="lang-dropdown">
    <div class="lang-dropdown-trigger" data-action="toggleLangDropdown">${cur.label} ${chevron}</div>
    <div class="lang-dropdown-menu">${items}</div>
  </div>`;
}

// ── Init ───────────────────────────────────────────
async function init() {
  // Register service worker
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }

  // Try restoring from backup stores if localStorage was cleared
  await restoreFromBackupStores();

  // Check if keys exist
  S.screen = hasAnyKeys() ? 'home' : 'setup';
  render();

  // Activity tracker for auto-lock (clears xprv from memory)
  ['click', 'touchstart', 'keydown'].forEach((evt) =>
    document.addEventListener(evt, () => { S.lastActivity = Date.now(); }, true)
  );
  setInterval(checkAutoLock, 30000);

  // Request persistent storage (prevents browser from evicting our data)
  if (navigator.storage && navigator.storage.persist) {
    navigator.storage.persist().catch(() => {});
  }
}

function checkAutoLock() {
  if (S.xprv && Date.now() - S.lastActivity > LOCK_TIMEOUT) {
    lock();
  }
}

function lock() {
  S.xprv = null;
  S.tempMnemonic = null;
  S.tempEntropy = null;
  S.tempKeyResult = null;
  S.bmsRequest = null;
  S.bmsResult = null;
  S.parsedTx = null;
  S.signedPsbtBytes = null;
  S.pendingAction = null;
  stopCamera();
  // No screen change — home is always accessible. Only clear xprv.
  // If we were mid-signing, go back to scan
  if (S.screen === 'enter-pass' || S.screen === 'confirm-tx' || S.screen === 'confirm-bms') {
    S.screen = 'scan';
    S.tab = 'sign';
  }
}

function stopCamera() {
  if (S.scanAnimId) { cancelAnimationFrame(S.scanAnimId); S.scanAnimId = null; }
  if (S.scanStream) { S.scanStream.getTracks().forEach((t) => t.stop()); S.scanStream = null; }
  if (S.qrAnimId) { clearInterval(S.qrAnimId); S.qrAnimId = null; }
}

// ── Tab switching ──────────────────────────────────
function switchTab(tab) {
  if (tab === 'sign' && !hasAnyKeys()) return; // need at least one key to sign
  S.tab = tab;
  stopCamera();
  if (tab === 'key') S.screen = hasAnyKeys() ? 'home' : 'setup';
  else if (tab === 'sign') S.screen = 'scan';
  else if (tab === 'settings') S.screen = 'settings-main';
  render();
}

// ── Platform Detection ────────────────────────────
function detectPlatform() {
  const ua = navigator.userAgent;
  const p = navigator.platform;
  let os = 'unknown', browser = 'unknown';

  // OS detection
  if (/iPad|iPhone|iPod/.test(ua) || (p === 'MacIntel' && navigator.maxTouchPoints > 1)) {
    os = 'ios';
  } else if (/Android/i.test(ua)) {
    os = 'android';
  } else if (/Mac/i.test(p)) {
    os = 'macos';
  } else if (/Win/i.test(p)) {
    os = 'windows';
  } else if (/Linux/i.test(p)) {
    os = 'linux';
  }

  // Browser detection
  if (/CriOS/i.test(ua)) {
    browser = 'chrome-ios';
  } else if (/SamsungBrowser/i.test(ua)) {
    browser = 'samsung';
  } else if (/Firefox/i.test(ua)) {
    browser = 'firefox';
  } else if (/Edg/i.test(ua)) {
    browser = 'edge';
  } else if (/Chrome/i.test(ua) && !/Edg/i.test(ua)) {
    browser = 'chrome';
  } else if (/Safari/i.test(ua) && !/Chrome/i.test(ua)) {
    browser = 'safari';
  }

  return { os, browser };
}

// ── Event Delegation (no inline handlers) ─────────
const ACTIONS = {
  startDice, startCoin, startImport, showXpubQR,
  undoDice, undoCoin, cancelKeygen,
  confirmMnemonic, doImport, doSetPass,
  cancelScan, rejectTx, approveTx, finishSign,
  approveBms, rejectBms, copyBmsSig,
  toggleNetwork, downloadBackup, importBackupFile, cycleTheme,
  doSignWithPass, cancelEnterPass,
  addDice(arg) { addDice(parseInt(arg, 10)); },
  addCoin(arg) { addCoin(parseInt(arg, 10)); },
  goHome() { S.screen = 'home'; render(); },
  goViewSource() { S.screen = 'view-source'; render(); },
  goSecurity() { S.screen = 'security'; render(); },
  goGuide() { S.screen = 'guide'; render(); },
  goSettings() { S.screen = 'settings-main'; render(); },
  toggleGuide(id) {
    const header = document.querySelector(`[data-guide-id="${id}"]`);
    const body = document.getElementById('guide-body-' + id);
    if (!header || !body) return;
    const isOpen = header.classList.toggle('open');
    body.style.maxHeight = isOpen ? body.scrollHeight + 'px' : '0';
  },
  bmsDone() { S.bmsResult = null; S.screen = 'scan'; render(); },
  renameKey(id) { renameKey(id); },
  confirmDeleteKeyById(id) { confirmDeleteKeyById(id); },
  downloadBackupById(id) { downloadBackupById(id); },
  verifyPassById(id) { verifyPassphraseForKey(id); },
  toggleXpub(id) { S.expandedKeyId = S.expandedKeyId === id ? null : id; render(); },
  addNewKey() { warnIfOnline(() => { S.screen = 'setup'; render(); }); },
  setImportCount(arg) { S.importWordCount = parseInt(arg, 10); S.screen = 'import'; render(); },
  setImportLang(arg) { S.seedLang = arg; localStorage.setItem('signer-seed-lang', arg); S.screen = 'import'; render(); },
  switchMnemonicLang(arg) {
    S.seedLang = arg; localStorage.setItem('signer-seed-lang', arg);
    if (S.tempEntropy) {
      const result = entropyToKey(S.tempEntropy);
      S.tempMnemonic = result.mnemonic;
      S.tempKeyResult = result;
    }
    render();
  },
  toggleLangDropdown() {
    const trigger = document.querySelector('.lang-dropdown-trigger');
    const menu = document.querySelector('.lang-dropdown-menu');
    if (!trigger || !menu) return;
    const isOpen = menu.classList.contains('show');
    menu.classList.toggle('show');
    trigger.classList.toggle('open');
    if (!isOpen) {
      // Close on outside click
      const close = (e) => {
        if (!e.target.closest('.lang-dropdown')) {
          menu.classList.remove('show');
          trigger.classList.remove('open');
          document.removeEventListener('click', close);
        }
      };
      setTimeout(() => document.addEventListener('click', close), 0);
    }
  },
  pickSeedLang(arg) {
    // arg = "actionName:langId" — whitelist allowed actions
    const SEED_LANG_ACTIONS = new Set(['setImportLang', 'switchMnemonicLang']);
    const [action, langId] = arg.split(':');
    if (!SEED_LANG_ACTIONS.has(action)) return;
    const fn = ACTIONS[action];
    if (fn) fn(langId);
  },
  pickUILang(arg) {
    S.lang = arg;
    localStorage.setItem('signer-lang', arg);
    render();
  },
};

document.addEventListener('click', (e) => {
  // Tab bar delegation
  const tabBtn = e.target.closest('.tab-btn');
  if (tabBtn && tabBtn.dataset.tab) {
    switchTab(tabBtn.dataset.tab);
    return;
  }
  // Action delegation
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const action = el.dataset.action;
  const fn = ACTIONS[action];
  if (fn) fn(el.dataset.arg);
});

document.addEventListener('keydown', (e) => {
  // Dice: 1-6 keys
  if (S.screen === 'dice' && e.key >= '1' && e.key <= '6') {
    addDice(parseInt(e.key, 10));
    return;
  }
  // Coin: h/t keys
  if (S.screen === 'coin') {
    if (e.key === 'h' || e.key === 'H') { addCoin(1); return; }
    if (e.key === 't' || e.key === 'T') { addCoin(0); return; }
  }
  // Enter for form actions
  if (e.key !== 'Enter') return;
  const el = e.target.closest('[data-enter-action]');
  if (!el) return;
  const fn = ACTIONS[el.dataset.enterAction];
  if (fn) fn();
});

// ── Encryption (AES-256-GCM via SubtleCrypto) ─────
async function deriveAesKey(passphrase, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(plaintext, passphrase) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await deriveAesKey(passphrase, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(plaintext));
  const blob = new Uint8Array(16 + 12 + ct.byteLength);
  blob.set(salt, 0);
  blob.set(iv, 16);
  blob.set(new Uint8Array(ct), 28);
  return btoa(String.fromCharCode(...blob));
}

async function encryptAndStore(xprv, passphrase) {
  const encrypted = await encryptData(xprv, passphrase);
  localStorage.setItem('signer-key', encrypted);
  await persistToBackupStores(encrypted);
}

// ── Triple Storage (localStorage + IndexedDB + OPFS) ──
// Provides resilience against accidental browser data clearing.
// localStorage is primary; IndexedDB and OPFS are silent backup layers.

const IDB_NAME = 'bitclutch-signer';
const IDB_STORE = 'keys';

function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbSet(key, value) {
  try {
    const db = await idbOpen();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).put(value, key);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  } catch (_) { /* IndexedDB unavailable — ignore */ }
}

async function idbGet(key) {
  try {
    const db = await idbOpen();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readonly');
      const req = tx.objectStore(IDB_STORE).get(key);
      req.onsuccess = () => { db.close(); resolve(req.result); };
      req.onerror = () => { db.close(); reject(req.error); };
    });
  } catch (_) { return undefined; }
}

async function idbDel(key) {
  try {
    const db = await idbOpen();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).delete(key);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  } catch (_) { /* ignore */ }
}

async function opfsWrite(name, data) {
  try {
    if (!navigator.storage || !navigator.storage.getDirectory) return;
    const root = await navigator.storage.getDirectory();
    const fh = await root.getFileHandle(name, { create: true });
    const w = await fh.createWritable();
    await w.write(data);
    await w.close();
  } catch (_) { /* OPFS unavailable — ignore */ }
}

async function opfsRead(name) {
  try {
    if (!navigator.storage || !navigator.storage.getDirectory) return undefined;
    const root = await navigator.storage.getDirectory();
    const fh = await root.getFileHandle(name);
    const file = await fh.getFile();
    return await file.text();
  } catch (_) { return undefined; }
}

async function opfsDel(name) {
  try {
    if (!navigator.storage || !navigator.storage.getDirectory) return;
    const root = await navigator.storage.getDirectory();
    await root.removeEntry(name);
  } catch (_) { /* ignore */ }
}

// Write multi-key bundle to IndexedDB + OPFS (called after localStorage write)
async function persistMultiKeyBundle() {
  const keys = localStorage.getItem('signer-keys') || '[]';
  const bundle = JSON.stringify({ keys });
  await Promise.allSettled([
    idbSet('signer-bundle', bundle),
    opfsWrite('signer-bundle.json', bundle),
  ]);
}

// Legacy single-key backup store write (kept for migration support)
async function persistToBackupStores(encKey) {
  await persistMultiKeyBundle();
}

// On startup: if localStorage is empty, try restoring from IndexedDB or OPFS
async function restoreFromBackupStores() {
  // If we already have multi-key data, nothing to restore
  if (localStorage.getItem('signer-keys')) return false;
  // Also check legacy single-key format
  if (localStorage.getItem('signer-key')) return false;
  let bundle = await idbGet('signer-bundle');
  if (!bundle) bundle = await opfsRead('signer-bundle.json');
  if (!bundle) return false;
  try {
    const data = JSON.parse(bundle);
    // Multi-key format
    if (data.keys) {
      localStorage.setItem('signer-keys', data.keys);
      return true;
    }
    // Legacy single-key format
    if (data.encKey) {
      localStorage.setItem('signer-key', data.encKey);
      if (data.xpub) localStorage.setItem('signer-xpub', data.xpub);
      if (data.fp) localStorage.setItem('signer-fp', data.fp);
      if (data.net) localStorage.setItem('signer-network', data.net);
      return true;
    }
    return false;
  } catch (_) { return false; }
}

// Intentional delete: remove ALL data from ALL stores
async function removeFromAllStores() {
  localStorage.removeItem('signer-keys');
  // Also remove legacy keys if any
  localStorage.removeItem('signer-key');
  localStorage.removeItem('signer-xpub');
  localStorage.removeItem('signer-fp');
  localStorage.removeItem('signer-key-created');
  localStorage.removeItem('signer-last-online');
  await Promise.allSettled([
    idbDel('signer-bundle'),
    opfsDel('signer-bundle.json'),
  ]);
}


async function decryptData(storedBase64, passphrase) {
  if (!storedBase64) throw new Error('No data');
  const data = Uint8Array.from(atob(storedBase64), (c) => c.charCodeAt(0));
  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const ct = data.slice(28);
  const aesKey = await deriveAesKey(passphrase, salt);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return new TextDecoder().decode(plain);
}

async function decryptStored(passphrase) {
  return decryptData(localStorage.getItem('signer-key'), passphrase);
}

// ── Multi-Key Storage Helpers ─────────────────────
function generateKeyId() { return 'k_' + Date.now(); }

function getKeys() {
  try {
    const raw = localStorage.getItem('signer-keys');
    return raw ? JSON.parse(raw) : [];
  } catch (_) { return []; }
}

function setKeys(keys) {
  localStorage.setItem('signer-keys', JSON.stringify(keys));
}

// Get signing key: explicit signingKeyId, or first key as fallback
function getSigningKey() {
  const keys = getKeys();
  if (!keys.length) return null;
  if (S.signingKeyId) return keys.find(k => k.id === S.signingKeyId) || keys[0];
  return keys[0];
}

// Find key by fingerprint (for PSBT auto-matching)
function findKeyByFingerprint(fp) {
  return getKeys().find(k => k.fp === fp) || null;
}

function nextKeyNumber() {
  const keys = getKeys();
  // Find the highest existing "Key #N" number and increment
  let max = 0;
  const re = /^Key #(\d+)$/;
  for (const k of keys) {
    const m = k.name && k.name.match(re);
    if (m) max = Math.max(max, parseInt(m[1], 10));
  }
  return Math.max(max, keys.length) + 1;
}

function addKey(obj) {
  // Assign default name if empty
  if (!obj.name) obj.name = t('keyN') + nextKeyNumber();
  const keys = getKeys();
  keys.push(obj);
  setKeys(keys);
}

function removeKey(id) {
  let keys = getKeys();
  keys = keys.filter(k => k.id !== id);
  setKeys(keys);
  if (S.signingKeyId === id) S.signingKeyId = null;
}

function updateKey(id, patch) {
  const keys = getKeys();
  const idx = keys.findIndex(k => k.id === id);
  if (idx >= 0) Object.assign(keys[idx], patch);
  setKeys(keys);
}

function hasAnyKeys() { return getKeys().length > 0; }

// (Migration removed — no existing users with single-key format)

// ── Encrypted Backup ──────────────────────────────
function downloadBackup() {
  const keys = getKeys();
  if (keys.length === 1) downloadBackupById(keys[0].id);
}

function importBackupFile() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = () => {
    const file = input.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const backup = JSON.parse(reader.result);
        if (backup.type !== 'bitclutch-signer-backup' || !backup.encryptedKey) {
          alert(t('invalidBackup'));
          return;
        }
        const fp = backup.fingerprint ? parseInt(backup.fingerprint, 16) : 0;
        // Check for duplicate (same fingerprint + xpub)
        const existing = getKeys();
        if (existing.some(k => k.fp === fp && k.xpub === (backup.xpub || ''))) {
          alert(t('keyAlreadyExists'));
          return;
        }
        const id = generateKeyId();
        const keyObj = {
          id,
          name: backup.name || '',
          encryptedKey: backup.encryptedKey,
          xpub: backup.xpub || '',
          fp,
          network: backup.network || 'main',
          seedLang: backup.seedLang || 'en',
          createdAt: Date.now(),
          lastOnline: null,
        };
        addKey(keyObj);
        persistMultiKeyBundle();
        S.screen = 'home';
        render();
        alert(t('backupRestored'));
      } catch (e) {
        alert(t('invalidBackup'));
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

// ── Key Generation ─────────────────────────────────
function diceToEntropy(diceValues) {
  // 99 dice rolls → ~256 bits, SHA256 to normalize
  const raw = new Uint8Array(diceValues.length);
  for (let i = 0; i < diceValues.length; i++) raw[i] = diceValues[i] - 1; // 0-5
  return sha256(raw);
}

function coinToEntropy(coinFlips) {
  // 256 coin flips → 256 bits exactly, SHA256 for safety
  const raw = new Uint8Array(32);
  for (let i = 0; i < 256; i++) {
    if (coinFlips[i]) raw[i >> 3] |= 1 << (7 - (i & 7));
  }
  return sha256(raw);
}

function entropyToKey(entropy256) {
  const mnemonic = entropyToMnemonic(entropy256, getWordlist());
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const coinType = S.network === 'main' ? 0 : 1;
  const account = master.derive(`m/84'/${coinType}'/0'`);
  return {
    mnemonic,
    xprv: account.privateExtendedKey,
    xpub: account.publicExtendedKey,
    fingerprint: account.fingerprint,  // BIP-32 standard: uint32
  };
}

function importFromMnemonic(mnemonicStr) {
  const words = mnemonicStr.trim().toLowerCase().split(/\s+/);
  if (words.length !== 12 && words.length !== 24) throw new Error(t('needWords'));
  const joined = words.join(' ');
  // Try all wordlists: preferred first, then all others
  const valid = SEED_LANGS.some(l => validateMnemonic(joined, l.wordlist));
  if (!valid) throw new Error(t('invalidMnemonic'));
  const seed = mnemonicToSeedSync(joined);
  const master = HDKey.fromMasterSeed(seed);
  const coinType = S.network === 'main' ? 0 : 1;
  const account = master.derive(`m/84'/${coinType}'/0'`);
  return {
    mnemonic: joined,
    xprv: account.privateExtendedKey,
    xpub: account.publicExtendedKey,
    fingerprint: account.fingerprint,  // BIP-32 standard: uint32
  };
}

// ── QR Generation ──────────────────────────────────
function generateQRCanvas(data, size) {
  // Defense-in-depth: refuse to encode private keys in QR
  if (typeof data === 'string' && (/xprv/i.test(data) || /tprv/i.test(data))) {
    throw new Error('Refusing to encode private key in QR');
  }
  const qr = qrgen(0, 'M');
  qr.addData(data);
  qr.make();
  const mods = qr.getModuleCount();
  const cellSize = Math.floor(size / mods);
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = cellSize * mods;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#FFFFFF';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000000';
  for (let r = 0; r < mods; r++) {
    for (let c = 0; c < mods; c++) {
      if (qr.isDark(r, c)) ctx.fillRect(c * cellSize, r * cellSize, cellSize, cellSize);
    }
  }
  return canvas;
}

// ── Theme ──────────────────────────────────────────
function applyTheme() {
  const root = document.documentElement;
  root.classList.remove('dark', 'light');
  if (S.theme === 'dark') root.classList.add('dark');
  else if (S.theme === 'light') root.classList.add('light');
  // 'auto' = no class → falls back to prefers-color-scheme media query
}
function cycleTheme() {
  const order = ['auto', 'light', 'dark'];
  const idx = order.indexOf(S.theme);
  S.theme = order[(idx + 1) % 3];
  localStorage.setItem('signer-theme', S.theme);
  applyTheme();
  render();
}
// Apply theme on load
applyTheme();

// ── Render ─────────────────────────────────────────
// ── Network Banner ─────────────────────────────────
function updateBanner() {
  const banner = $('network-banner');
  const text = $('banner-text');
  if (!banner || !text) return;
  const online = navigator.onLine;
  const hasKeys = hasAnyKeys();
  // Three states: offline (green), online+noKey (yellow warn), online+hasKey (red danger)
  banner.classList.remove('online', 'offline', 'warn');
  if (!online) {
    banner.classList.add('offline');
    text.textContent = t('bannerOffline');
  } else if (!hasKeys) {
    banner.classList.add('warn');
    text.textContent = t('bannerWarn');
  } else {
    banner.classList.add('online');
    text.textContent = t('bannerOnline');
    // Update lastOnline for ALL keys
    const now = Date.now();
    const keys = getKeys();
    keys.forEach(k => { k.lastOnline = now; });
    setKeys(keys);
    // Re-render home to show updated timestamp & compromise warning
    if (S.screen === 'home') {
      const el = $screen();
      if (el) el.innerHTML = renderHome();
    }
  }
}
window.addEventListener('online', updateBanner);
window.addEventListener('offline', updateBanner);

function render() {
  const el = $screen();

  // Update banner (network status + language)
  updateBanner();

  // Update lock badge — show key count
  const badge = $('lock-badge');
  const keyCount = getKeys().length;
  if (keyCount > 0) {
    badge.textContent = `${keyCount} ${keyCount === 1 ? t('tabKey') : t('tabKey')}`;
    badge.style.color = 'var(--success)';
    badge.style.borderColor = 'var(--success)';
  } else {
    badge.textContent = t('locked');
    badge.style.color = '';
    badge.style.borderColor = '';
  }

  // Update tab active state and labels
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === S.tab);
    const span = btn.querySelector('span');
    if (span) {
      if (btn.dataset.tab === 'key') span.textContent = t('tabKey');
      else if (btn.dataset.tab === 'sign') span.textContent = t('tabSign');
      else if (btn.dataset.tab === 'settings') span.textContent = t('tabSettings');
    }
  });

  // Render screen
  switch (S.screen) {
    case 'setup': el.innerHTML = renderSetup(); break;
    case 'home': el.innerHTML = renderHome(); break;
    case 'dice': el.innerHTML = renderDice(); break;
    case 'coin': el.innerHTML = renderCoin(); break;
    case 'mnemonic': el.innerHTML = renderMnemonic(); break;
    case 'set-pass': el.innerHTML = renderSetPass(); break;
    case 'import': el.innerHTML = renderImport(); setupImportInputs(); break;
    case 'scan': el.innerHTML = renderScan(); startCamera(); break;
    case 'confirm-tx': el.innerHTML = renderConfirmTx(); break;
    case 'enter-pass': el.innerHTML = renderEnterPass(); break;
    case 'show-qr': el.innerHTML = renderShowQR(); break;
    case 'confirm-bms': el.innerHTML = renderConfirmBms(); break;
    case 'bms-result': el.innerHTML = renderBmsResult(); showBmsQR(); break;
    case 'settings-main': el.innerHTML = renderSettings(); break;
    case 'view-source': el.innerHTML = renderViewSource(); loadSourceAndHashes(); break;
    case 'security': el.innerHTML = renderSecurity(); break;
    case 'guide': el.innerHTML = renderGuide(); autoExpandGuide(); break;
    default: el.innerHTML = '<p class="text-muted text-center mt-20">Loading...</p>';
  }
}

// ── Screen Renderers ───────────────────────────────

function renderSetup() {
  return `
    <div class="text-center mt-20">
      <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5" style="margin: 0 auto 16px">
        <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/>
      </svg>
      <h2 style="font-size:20px; margin-bottom:8px">${t('createKeys')}</h2>
      <p class="text-muted mb-12">${t('setupDesc')}</p>
    </div>
    <div class="gap-12 mt-16">
      <button class="btn btn-primary" data-action="startDice">${t('diceBtn')}</button>
      <button class="btn btn-secondary" data-action="startCoin">${t('coinBtn')}</button>
      <button class="btn btn-secondary" data-action="startImport">${t('importBtn')}</button>
      <button class="btn btn-secondary" data-action="importBackupFile">${t('restoreBackup')}</button>
    </div>
    `;
}

function renderHome() {
  const keys = getKeys();
  if (!keys.length) {
    return `
      <div class="text-center mt-20">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin: 0 auto 16px">
          <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/>
        </svg>
        <p class="text-muted">${t('noKeysYet')}</p>
      </div>
      <div class="gap-12 mt-16">
        <button class="btn btn-primary" data-action="addNewKey">${t('addNewKey')}</button>
        <button class="btn btn-secondary" data-action="importBackupFile">${t('restoreBackup')}</button>
      </div>`;
  }

  let html = '';
  keys.forEach((k, idx) => {
    const fpHex = k.fp ? k.fp.toString(16).padStart(8, '0') : '?';
    const net = k.network === 'main' ? t('mainnet') : t('testnet');
    const createdStr = fmtDate(k.createdAt);
    const compromised = k.createdAt && k.lastOnline && k.lastOnline > k.createdAt;
    const expanded = S.expandedKeyId === k.id;
    const displayName = k.name || (t('keyN') + '?');

    let lastOnlineStr = '';
    if (!k.lastOnline || (k.createdAt && k.lastOnline <= k.createdAt)) {
      lastOnlineStr = `<span style="color:var(--success)">${t('neverOnline')}</span>`;
    } else {
      lastOnlineStr = `<span style="color:var(--danger)">${fmtDate(k.lastOnline)}</span>`;
    }

    html += `
      <div class="card">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
          <div class="card-title" style="margin:0;flex:1">${escapeHtml(displayName)}</div>
          <button class="btn btn-secondary" style="width:auto;min-height:28px;padding:2px 8px;font-size:11px" data-action="renameKey" data-arg="${k.id}">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px"><path d="M17 3a2.85 2.83 0 114 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
          </button>
        </div>
        <div class="tx-row"><span class="tx-label">${t('network')}</span><span class="tx-value">${net}</span></div>
        <div class="tx-row"><span class="tx-label">${t('fingerprint')}</span><span class="tx-value" style="font-family:var(--mono)">${fpHex}</span></div>
        ${createdStr ? `<div class="tx-row"><span class="tx-label">${t('keyCreated')}</span><span class="tx-value" style="font-size:12px">${createdStr}</span></div>` : ''}
        <div class="tx-row"><span class="tx-label">${t('lastOnline')}</span><span class="tx-value" style="font-size:12px">${lastOnlineStr}</span></div>
        ${compromised ? `<div class="security-banner" style="border-left-color:var(--danger);margin-top:8px"><strong style="color:var(--danger)">${t('onlineAfterKey')}</strong></div>` : ''}
        <div style="margin-top:12px">
          <button class="btn btn-secondary" style="width:100%;min-height:44px" data-action="showXpubQR" data-arg="${k.id}">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-3px;margin-right:6px"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="3" height="3"/><rect x="19" y="14" width="2" height="2"/><rect x="14" y="19" width="2" height="2"/><rect x="19" y="19" width="2" height="2"/></svg>
            ${t('accountXpub')}
          </button>
        </div>
        ${expanded ? `<div style="margin-top:8px"><div class="tx-address">${escapeHtml(k.xpub || '')}</div></div>` : ''}
        <div style="display:flex;gap:8px;margin-top:8px">
          <button class="btn btn-secondary" style="flex:1;min-height:40px;font-size:13px" data-action="downloadBackupById" data-arg="${k.id}">${t('exportBackup')}</button>
          <button class="btn btn-secondary" style="flex:1;min-height:40px;font-size:13px" data-action="verifyPassById" data-arg="${k.id}">${t('verifyPass')}</button>
        </div>
        <div style="margin-top:8px">
          <button class="btn btn-secondary" style="width:100%;min-height:40px;font-size:13px;color:var(--danger);border-color:var(--danger)" data-action="confirmDeleteKeyById" data-arg="${k.id}">${t('deleteKey')}</button>
        </div>
      </div>`;
  });

  html += `
    <div class="gap-12">
      <button class="btn btn-primary" data-action="addNewKey">${t('addNewKey')}</button>
      <button class="btn btn-secondary" data-action="importBackupFile">${t('restoreBackup')}</button>
    </div>`;

  return html;
}

function renderDice() {
  const count = S.diceEntropy.length;
  const pct = Math.round((count / DICE_REQUIRED) * 100);
  const display = S.diceEntropy.join(' ');
  return `
    <div class="card">
      <div class="card-title">${t('diceTitle')}</div>
      <p class="text-muted">${t('diceDesc')}</p>
      <div class="security-banner" style="font-size:11px;line-height:1.5;margin-top:8px">${t('entropyWarning')}</div>
      <div style="display:flex; justify-content:space-between; margin-top:12px">
        <span class="text-muted">${t('progress')}</span>
        <span style="font-weight:600">${count} / ${DICE_REQUIRED}</span>
      </div>
      <div class="progress-bar"><div class="progress-fill" style="width:${pct}%"></div></div>
      <div class="dice-grid">
        ${[1,2,3,4,5,6].map((n) => `<button class="dice-btn" data-action="addDice" data-arg="${n}">${n}</button>`).join('')}
      </div>
      ${count > 0 ? `<div class="entropy-display">${display}</div>` : ''}
      <div class="gap-12 mt-12">
        ${count > 0 ? `<button class="btn btn-secondary" data-action="undoDice">${t('undoLast')}</button>` : ''}
        <button class="btn btn-secondary" data-action="cancelKeygen">${t('cancel')}</button>
      </div>
    </div>`;
}

function renderCoin() {
  const count = S.coinEntropy.length;
  const pct = Math.round((count / COIN_REQUIRED) * 100);
  const display = S.coinEntropy.map((v) => v ? 'H' : 'T').join('');
  return `
    <div class="card">
      <div class="card-title">${t('coinTitle')}</div>
      <p class="text-muted">${t('coinDesc')}</p>
      <div class="security-banner" style="font-size:11px;line-height:1.5;margin-top:8px">${t('entropyWarning')}</div>
      <div style="display:flex; justify-content:space-between; margin-top:12px">
        <span class="text-muted">${t('progress')}</span>
        <span style="font-weight:600">${count} / ${COIN_REQUIRED}</span>
      </div>
      <div class="progress-bar"><div class="progress-fill" style="width:${pct}%"></div></div>
      <div class="coin-grid">
        <button class="coin-btn" data-action="addCoin" data-arg="1">${t('heads')}</button>
        <button class="coin-btn" data-action="addCoin" data-arg="0">${t('tails')}</button>
      </div>
      ${count > 0 ? `<div class="entropy-display">${display}</div>` : ''}
      <div class="gap-12 mt-12">
        ${count > 0 ? `<button class="btn btn-secondary" data-action="undoCoin">${t('undoLast')}</button>` : ''}
        <button class="btn btn-secondary" data-action="cancelKeygen">${t('cancel')}</button>
      </div>
    </div>`;
}

function renderMnemonic() {
  if (!S.tempMnemonic) return `<p class="text-muted text-center mt-20">${t('noMnemonic')}</p>`;
  const sl = S.seedLang;
  const words = S.tempMnemonic.normalize('NFC').split(' ');
  return `
    <div class="card">
      <div class="card-title" style="color:var(--danger)">${t('writeDown')}</div>
      <p class="text-muted mb-12">${t('mnemonicDesc')}</p>
      ${S.tempEntropy ? `<div class="import-toggle">${renderSeedLangSelect('switchMnemonicLang')}</div>` : ''}
      <div class="mnemonic-grid">
        ${words.map((w, i) => `<div class="mnemonic-word"><span class="num">${i + 1}.</span>${w}</div>`).join('')}
      </div>
    </div>
    <div class="card" style="border-left:3px solid var(--accent)">
      <div class="card-title" style="font-size:13px">${t('stolenVsLost')}</div>
      <p class="text-muted" style="font-size:12px; line-height:1.5">
        <strong style="color:var(--danger)">${t('theft')}</strong> ${t('theftDesc')}<br><br>
        <strong style="color:var(--text-secondary)">${t('loss')}</strong> ${t('lossDesc')}<br><br>
        ${t('bitclutchPromo')}
      </p>
      <p style="margin-top:8px; font-size:12px; color:var(--accent)">${t('visitBitclutch')}</p>
    </div>
    <div class="gap-12">
      <button class="btn btn-primary" data-action="confirmMnemonic">${t('confirmedWritten')}</button>
    </div>`;
}

function renderImport() {
  const wc = S.importWordCount;
  const sl = S.seedLang;
  const cells = [];
  for (let i = 0; i < wc; i++) {
    cells.push(`<div class="import-cell">
        <label><span class="import-num">${i + 1}.</span>
          <input type="text" class="import-word" data-idx="${i}"
            autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
        </label>
        <div class="import-suggest" data-for="${i}"></div>
      </div>`);
  }
  return `
    <div class="card">
      <div class="card-title">${t('importTitle')}</div>
      <p class="text-muted mb-12">${t('importDesc')}</p>
      <div class="import-toggle">
        <button class="toggle-btn ${wc === 12 ? 'active' : ''}" data-action="setImportCount" data-arg="12">12 ${t('words')}</button>
        <button class="toggle-btn ${wc === 24 ? 'active' : ''}" data-action="setImportCount" data-arg="24">24 ${t('words')}</button>
      </div>
      <div class="import-toggle">${renderSeedLangSelect('setImportLang')}</div>
      <div class="import-grid" id="import-grid">${cells.join('')}</div>
      <p id="import-error" class="text-muted mt-12" style="color:var(--danger)"></p>
    </div>
    <div class="gap-12">
      <button class="btn btn-primary" data-action="doImport">${t('importAction')}</button>
      <button class="btn btn-secondary" data-action="cancelKeygen">${t('cancel')}</button>
    </div>`;
}

function setupImportInputs() {
  const grid = $('import-grid');
  if (!grid) return;
  const wl = getWordlistNFC();
  let activeSugIdx = -1;

  // Hangul composition-aware autocomplete.
  // 받침(final consonant) can split to become next syllable's initial:
  // "각" = 가+ㄱ받침 → could become "가" + "ㄱ초성..." (e.g. 가격)
  // "가겨" → 겨 could gain 받침 (e.g. 가격)
  // Map: 받침 index → initial consonant index it becomes when split
  // Includes compound 받침 (ㄳ→ㅅ, ㄵ→ㅈ, ㄺ→ㄱ, etc.)
  const FI = [-1,0,1,9,2,12,18,3,5,0,6,7,9,16,17,18,6,7,9,9,10,11,12,14,15,16,17,18];

  function updateSuggestions(inp) {
    const val = inp.value.trim().toLowerCase();
    const idx = inp.dataset.idx;
    const sugDiv = grid.querySelector(`.import-suggest[data-for="${idx}"]`);
    activeSugIdx = -1;
    if (val.length < 1) {
      sugDiv.classList.remove('show'); sugDiv.innerHTML = '';
      inp.classList.remove('valid'); return;
    }
    if (wl.includes(val)) {
      inp.classList.add('valid');
      sugDiv.classList.remove('show'); sugDiv.innerHTML = ''; return;
    }
    inp.classList.remove('valid');

    const seen = new Set();
    // 1. Exact prefix
    for (const w of wl) { if (w.startsWith(val)) seen.add(w); }

    // 2. Hangul-aware fallback for last character
    const lc = val.charCodeAt(val.length - 1);
    if (lc >= 0xAC00 && lc <= 0xD7AF) {
      const fi = (lc - 0xAC00) % 28;           // final consonant index
      const base = val.slice(0, -1);            // chars before last
      if (fi > 0) {
        // Case A: 받침 exists (e.g. "각")
        // → strip 받침 ("가"), next char must start with that consonant
        const stripped = String.fromCharCode(lc - fi);
        const prefix = base + stripped;
        const need = FI[fi]; // required initial of next char
        for (const w of wl) {
          if (seen.has(w) || !w.startsWith(prefix) || w.length <= prefix.length) continue;
          const nc = w.charCodeAt(prefix.length);
          if (nc >= 0xAC00 && nc <= 0xD7AF &&
              Math.floor((nc - 0xAC00) / 588) === need) seen.add(w);
        }
      } else {
        // Case B: no 받침 (e.g. "가겨")
        // → match words where this position has same base + any 받침 (겨→격,겸...)
        for (const w of wl) {
          if (seen.has(w) || w.length < val.length) continue;
          if (base && !w.startsWith(base)) continue;
          const wc = w.charCodeAt(val.length - 1);
          if (wc >= 0xAC00 && wc <= 0xD7AF &&
              wc - ((wc - 0xAC00) % 28) === lc) seen.add(w);
        }
      }
    }

    const matches = [...seen].sort().slice(0, 6);
    if (matches.length === 0) { sugDiv.classList.remove('show'); sugDiv.innerHTML = ''; return; }
    if (matches.length === 1 && matches[0] === val) {
      inp.classList.add('valid');
      sugDiv.classList.remove('show'); sugDiv.innerHTML = ''; return;
    }
    sugDiv.innerHTML = matches.map((w) =>
      `<div class="import-suggest-item" data-word="${w}" data-idx="${idx}">${w}</div>`
    ).join('');
    sugDiv.classList.add('show');
  }

  // Autocomplete on every input (works for all languages including CJK IME)
  grid.addEventListener('input', (e) => {
    const inp = e.target;
    if (!inp.classList.contains('import-word')) return;
    updateSuggestions(inp);
  });

  // Also trigger on compositionend as safety net (some browsers
  // don't fire a final input event after IME commit)
  grid.addEventListener('compositionend', (e) => {
    const inp = e.target;
    if (!inp.classList.contains('import-word')) return;
    // Small delay: some browsers fire input AFTER compositionend
    setTimeout(() => updateSuggestions(inp), 0);
  });

  // Click suggestion
  grid.addEventListener('mousedown', (e) => {
    const item = e.target.closest('.import-suggest-item');
    if (!item) return;
    e.preventDefault(); // prevent blur before we can read the item
    const idx = parseInt(item.dataset.idx, 10);
    const word = item.dataset.word;
    const inp = grid.querySelector(`.import-word[data-idx="${idx}"]`);
    if (inp) { inp.value = word; inp.classList.add('valid'); }
    const sugDiv = grid.querySelector(`.import-suggest[data-for="${idx}"]`);
    if (sugDiv) { sugDiv.classList.remove('show'); sugDiv.innerHTML = ''; }
    const next = grid.querySelector(`.import-word[data-idx="${idx + 1}"]`);
    if (next) next.focus();
  });

  // Keyboard navigation (skip during IME composition to avoid
  // intercepting Enter/Space used for character selection)
  grid.addEventListener('keydown', (e) => {
    if (e.isComposing || e.keyCode === 229) return;
    const inp = e.target;
    if (!inp.classList.contains('import-word')) return;
    const idx = inp.dataset.idx;
    const sugDiv = grid.querySelector(`.import-suggest[data-for="${idx}"]`);
    const items = sugDiv ? sugDiv.querySelectorAll('.import-suggest-item') : [];
    const hasSuggestions = sugDiv.classList.contains('show') && items.length > 0;

    if (e.key === 'ArrowDown' && hasSuggestions) {
      e.preventDefault();
      activeSugIdx = Math.min(activeSugIdx + 1, items.length - 1);
      items.forEach((it, i) => it.classList.toggle('active', i === activeSugIdx));
    } else if (e.key === 'ArrowUp' && hasSuggestions) {
      e.preventDefault();
      activeSugIdx = Math.max(activeSugIdx - 1, 0);
      items.forEach((it, i) => it.classList.toggle('active', i === activeSugIdx));
    } else if (e.key === 'Enter' && hasSuggestions) {
      e.preventDefault();
      const selected = activeSugIdx >= 0 ? items[activeSugIdx] : items[0];
      inp.value = selected.dataset.word;
      inp.classList.add('valid');
      sugDiv.classList.remove('show'); sugDiv.innerHTML = '';
      activeSugIdx = -1;
      const next = grid.querySelector(`.import-word[data-idx="${parseInt(idx, 10) + 1}"]`);
      if (next) next.focus();
    } else if (e.key === 'Tab') {
      // Accept first suggestion if open, or advance
      if (hasSuggestions) {
        e.preventDefault();
        const selected = activeSugIdx >= 0 ? items[activeSugIdx] : items[0];
        inp.value = selected.dataset.word;
        inp.classList.add('valid');
        sugDiv.classList.remove('show'); sugDiv.innerHTML = '';
        activeSugIdx = -1;
        const next = grid.querySelector(`.import-word[data-idx="${parseInt(idx, 10) + 1}"]`);
        if (next) next.focus();
      }
    } else if (e.key === ' ') {
      const val = inp.value.trim().toLowerCase();
      if (wl.includes(val) || (hasSuggestions && items.length === 1)) {
        e.preventDefault();
        if (!wl.includes(val)) inp.value = items[0].dataset.word;
        inp.classList.add('valid');
        sugDiv.classList.remove('show'); sugDiv.innerHTML = '';
        const next = grid.querySelector(`.import-word[data-idx="${parseInt(idx, 10) + 1}"]`);
        if (next) next.focus();
      }
    }
  });

  // Hide suggestions on blur
  grid.addEventListener('focusout', (e) => {
    if (!e.target.classList.contains('import-word')) return;
    setTimeout(() => {
      const idx = e.target.dataset.idx;
      const sugDiv = grid.querySelector(`.import-suggest[data-for="${idx}"]`);
      if (sugDiv) sugDiv.classList.remove('show');
      activeSugIdx = -1;
    }, 150);
  });

  // Paste: distribute words across inputs
  grid.addEventListener('paste', (e) => {
    const inp = e.target;
    if (!inp.classList.contains('import-word')) return;
    const text = (e.clipboardData || window.clipboardData).getData('text');
    const words = text.trim().split(/\s+/);
    if (words.length > 1) {
      e.preventDefault();
      const startIdx = parseInt(inp.dataset.idx, 10);
      const inputs = grid.querySelectorAll('.import-word');
      words.forEach((w, i) => {
        const target = inputs[startIdx + i];
        if (target) {
          target.value = w.toLowerCase();
          if (wl.includes(w.toLowerCase())) target.classList.add('valid');
        }
      });
      const nextEmpty = Array.from(inputs).find((input) => !input.value);
      if (nextEmpty) nextEmpty.focus();
      else inputs[inputs.length - 1].focus();
    }
  });

  // Focus first input
  const first = grid.querySelector('.import-word[data-idx="0"]');
  if (first) setTimeout(() => first.focus(), 50);
}

function renderSetPass() {
  return `
    <div class="card">
      <div class="card-title">${t('setPassTitle')}</div>
      <p class="text-muted mb-12">${t('setPassDesc')}</p>
      <label class="label">${t('passphrase')}</label>
      <input type="password" id="new-pass" class="input mb-12" placeholder="${t('enterPass')}" autocomplete="off">
      <label class="label">${t('confirmPass')}</label>
      <input type="password" id="new-pass2" class="input" placeholder="${t('confirmPass')}" autocomplete="off"
        data-enter-action="doSetPass">
      <p id="setpass-error" class="text-muted mt-12" style="color:var(--danger)"></p>
    </div>
    <div class="gap-12">
      <button class="btn btn-primary" data-action="doSetPass">${t('encryptSave')}</button>
      <button class="btn btn-secondary" data-action="cancelKeygen">${t('cancel')}</button>
    </div>`;
}

// (viewMnemonic removed — mnemonic shown once during keygen, not stored)

function renderScan() {
  return `
    <div class="card">
      <div class="card-title">${t('scanTitle')}</div>
      <p class="text-muted mb-12">${t('scanDesc')}</p>
      <div class="camera-container">
        <video id="qr-video" playsinline autoplay muted></video>
      </div>
      <p id="scan-status" class="text-muted text-center mt-12">${S.urProgress || t('startingCamera')}</p>
      <button class="btn btn-secondary mt-16" data-action="cancelScan">${t('cancel')}</button>
    </div>`;
}

function renderConfirmTx() {
  const tx = S.parsedTx;
  if (!tx) return `<p class="text-muted text-center mt-20">${t('noTxData')}</p>`;
  const fmt = (sats) => {
    const btc = (sats / 1e8).toFixed(8).replace(/0+$/, '').replace(/\.$/, '');
    return btc + ' BTC';
  };
  const fmtSats = (sats) => sats.toLocaleString(S.lang) + ' sat';

  let outputsHtml = '';
  for (const o of tx.outputs) {
    const isChange = o.isChange ? ` <span style="color:var(--text-muted)">${t('change')}</span>` : '';
    outputsHtml += `
      <div style="padding:10px 0; border-bottom:1px solid var(--border-light)">
        <div style="display:flex; justify-content:space-between">
          <span class="tx-label">${t('output')}${isChange}</span>
          <span class="tx-value">${fmt(o.amount)}</span>
        </div>
        <div class="tx-address">${escapeHtml(o.address || 'Unknown')}</div>
      </div>`;
  }

  return `
    <div class="card">
      <div class="card-title">${t('confirmTx')}</div>
      <div class="security-banner mb-12">${t('reviewBeforeSign')}</div>
      <div class="tx-row">
        <span class="tx-label">${t('inputs')}</span>
        <span class="tx-value">${tx.inputs.length} (${fmt(tx.inputTotal)})</span>
      </div>
      ${outputsHtml}
      <div class="tx-row" style="border-bottom:none">
        <span class="tx-label" style="font-weight:600">${t('fee')}</span>
        <span class="tx-value" style="color:var(--danger)">${fmt(tx.fee)} (${fmtSats(tx.fee)})</span>
      </div>
    </div>
    <div style="display:flex; gap:12px">
      <button class="btn btn-secondary" style="flex:1" data-action="rejectTx">${t('reject')}</button>
      <button class="btn btn-success" style="flex:1" data-action="approveTx">${t('sign')}</button>
    </div>`;
}

function renderEnterPass() {
  const ak = getSigningKey();
  if (!ak) return `<p class="text-muted text-center mt-20">${t('noKeyToSave')}</p>`;
  const fpHex = ak.fp ? ak.fp.toString(16).padStart(8, '0') : '?';
  const displayName = ak.name || t('keyN') + '?';
  return `
    <div class="card">
      <div class="card-title">${t('enterPassToSign')}</div>
      <div class="tx-row"><span class="tx-label">${t('tabKey')}</span><span class="tx-value">${escapeHtml(displayName)}</span></div>
      <div class="tx-row"><span class="tx-label">${t('fingerprint')}</span><span class="tx-value">${fpHex}</span></div>
      <div class="gap-12 mt-16">
        <input type="password" id="sign-pass" class="input" placeholder="${t('passphrase')}" autocomplete="off"
          data-enter-action="doSignWithPass">
        <p id="sign-pass-error" class="text-muted text-center" style="color:var(--danger)"></p>
      </div>
    </div>
    <div style="display:flex; gap:12px">
      <button class="btn btn-secondary" style="flex:1" data-action="cancelEnterPass">${t('cancel')}</button>
      <button class="btn btn-success" style="flex:1" data-action="doSignWithPass">${t('sign')}</button>
    </div>`;
}

function renderShowQR() {
  if (!S.signedPsbtBytes) return `<p class="text-muted text-center mt-20">${t('noSignedData')}</p>`;
  return `
    <div class="card text-center">
      <div class="card-title">${t('signedPsbt')}</div>
      <p class="text-muted mb-12">${t('showQRDesc')}</p>
      <div class="qr-container" id="signed-qr"></div>
      <p id="qr-frame-info" class="text-muted mt-12"></p>
    </div>
    <button class="btn btn-primary" data-action="finishSign">${t('scanComplete')}</button>`;
}

function renderConfirmBms() {
  const req = S.bmsRequest;
  if (!req) return `<p class="text-muted text-center mt-20">${t('noBmsRequest')}</p>`;
  // Preview: show addresses for all keys (user will pick at signing time)
  const keys = getKeys();
  let addrPreview = '';
  if (keys.length === 1 && keys[0].xpub) {
    try {
      const hdkey = HDKey.fromExtendedKey(keys[0].xpub);
      const child = hdkey.deriveChild(0).deriveChild(req.index || 0);
      addrPreview = p2wpkh(child.publicKey).address;
    } catch { addrPreview = '?'; }
  } else {
    addrPreview = t('selectKeyAtSign');
  }
  return `
    <div class="card">
      <div class="card-title">${t('confirmBms')}</div>
      <div class="security-banner mb-12">${t('reviewMessage')}</div>
      <div class="tx-row"><span class="tx-label">${t('type')}</span><span class="tx-value">${t('bmsType')}</span></div>
      <div class="tx-row"><span class="tx-label">${t('index')}</span><span class="tx-value">${req.index || 0}</span></div>
      <div class="tx-row"><span class="tx-label">${t('address')}</span><span class="tx-value" style="font-size:11px;word-break:break-all">${escapeHtml(addrPreview)}</span></div>
      <div style="margin-top:12px">
        <span class="label">${t('message')}</span>
        <div class="tx-address" style="padding:10px;background:var(--surface-hover);border-radius:8px;white-space:pre-wrap;max-height:200px;overflow-y:auto">${escapeHtml(req.message)}</div>
      </div>
      <div class="tx-row" style="margin-top:8px"><span class="tx-label">${t('sha256')}</span><span class="tx-value" style="font-size:10px;word-break:break-all;font-family:monospace">${bytesToHex(sha256(utf8ToBytes(req.message)))}</span></div>
    </div>
    <div style="display:flex; gap:12px">
      <button class="btn btn-secondary" style="flex:1" data-action="rejectBms">${t('reject')}</button>
      <button class="btn btn-success" style="flex:1" data-action="approveBms">${t('sign')}</button>
    </div>`;
}

function renderBmsResult() {
  const r = S.bmsResult;
  if (!r) return `<p class="text-muted text-center mt-20">${t('noSignature')}</p>`;
  return `
    <div class="card">
      <div class="card-title">${t('bmsSignature')}</div>
      <div class="tx-row"><span class="tx-label">${t('address')}</span><span class="tx-value" style="font-size:11px">${escapeHtml(r.address)}</span></div>
      <div style="margin-top:12px">
        <span class="label">${t('message')}</span>
        <div class="tx-address" style="white-space:pre-wrap;max-height:120px;overflow-y:auto">${escapeHtml(r.message)}</div>
      </div>
      <div style="margin-top:12px">
        <span class="label">${t('sigBase64')}</span>
        <div class="tx-address" id="bms-sig-text" style="cursor:pointer" data-action="copyBmsSig" title="${t('tapToCopy')}">${escapeHtml(r.signature)}</div>
      </div>
      <div class="qr-container mt-12" id="bms-qr"></div>
      <p class="text-muted mt-12" style="text-align:center;font-size:12px">${t('scanSignatureDesc')}</p>
    </div>
    <div class="gap-12">
      <button class="btn btn-secondary" data-action="copyBmsSig">${t('copySig')}</button>
      <button class="btn btn-primary" data-action="bmsDone">${t('scanComplete')}</button>
    </div>`;
}

function renderSettings() {
  const net = S.network === 'main' ? t('mainnet') : t('testnet');
  const themeLabel = S.theme === 'dark' ? t('themeDark') : S.theme === 'light' ? t('themeLight') : t('themeAuto');
  const themeIcon = S.theme === 'dark'
    ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-2px"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"/></svg>'
    : S.theme === 'light'
    ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
    : '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-2px"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 18V4a8 8 0 0 1 0 16z"/></svg>';
  return `
    <div class="card">
      <div class="card-title">${t('settings')}</div>
      <div class="tx-row">
        <span class="tx-label">${t('version')}</span>
        <span class="tx-value">v${APP_VERSION}</span>
      </div>
      <div class="tx-row">
        <span class="tx-label">${t('network')}</span>
        <button class="btn btn-secondary" style="width:auto;min-height:36px;padding:6px 16px;font-size:13px" data-action="toggleNetwork">${net}</button>
      </div>
      <div class="tx-row">
        <span class="tx-label">${t('language')}</span>
        ${renderUILangSelect()}
      </div>
      <div class="tx-row" style="border-bottom:none">
        <span class="tx-label">${t('theme')}</span>
        <button class="btn btn-secondary" style="width:auto;min-height:36px;padding:6px 16px;font-size:13px" data-action="cycleTheme">${themeIcon} ${themeLabel}</button>
      </div>
    </div>
    <div class="gap-12">
      <button class="btn btn-secondary" data-action="goGuide">${t('installGuide')}</button>
      <button class="btn btn-secondary" data-action="goViewSource">${t('viewSource')}</button>
      <button class="btn btn-secondary" data-action="goSecurity">${t('securityInfo')}</button>
    </div>
`;
}

function renderViewSource() {
  return `
    <div class="card">
      <div class="card-title">${t('verifyIntegrity')}</div>
      <p class="text-muted mb-12">${t('verifyDesc')}</p>
      <div style="margin-bottom:12px">
        <span class="label">${t('version')}</span>
        <div class="tx-address" style="font-size:13px; font-weight:600; color:var(--text)">v${APP_VERSION}</div>
      </div>
      <div style="margin-bottom:12px">
        <span class="label">app.js SHA-256 <span class="text-muted">(live)</span></span>
        <div class="tx-address" id="hash-app" style="font-size:11px">${t('computing')}</div>
      </div>
      <div style="margin-bottom:12px">
        <span class="label">lib/bundle.js SHA-256 <span class="text-muted">(live)</span></span>
        <div class="tx-address" id="hash-lib" style="font-size:11px">${t('computing')}</div>
      </div>
      <div id="hash-drop" class="hidden" style="border:2px dashed var(--border);border-radius:12px;padding:20px;text-align:center;cursor:pointer;transition:border-color 0.2s;margin-bottom:12px">
        <input type="file" style="display:none" accept=".html">
        <div style="font-size:13px;color:var(--text);font-weight:600;margin-bottom:6px">${t('verifyFile')}</div>
        <div style="font-size:12px;color:var(--text-secondary);line-height:1.5;margin-bottom:10px">
          ${t('verifyFileDesc')}
        </div>
        <div class="drop-label" style="font-size:12px;color:var(--accent);margin-bottom:8px">${t('tapToSelect')}</div>
        <div class="drop-result" style="font-size:13px;font-family:var(--mono);font-weight:600;word-break:break-all;min-height:20px;padding:10px;background:var(--surface-hover);border-radius:8px;color:var(--text-muted)"></div>
      </div>
      <div class="security-banner">
        ${t('compareGithub')}
      </div>
    </div>
    <div class="card">
      <div class="card-title">${t('auditableSource')}</div>
      <p class="text-muted mb-12">${t('auditableDesc')}</p>
      <p style="font-size:13px;font-family:var(--mono);color:var(--accent);word-break:break-all">github.com/bitclutch/signer</p>
    </div>
    <button class="btn btn-secondary" data-action="goSettings">${t('back')}</button>`;
}

async function loadSourceAndHashes() {
  const hashLib = $('hash-lib');
  const hashApp = $('hash-app');
  const dropZone = $('hash-drop');
  const isStandalone = location.protocol === 'file:' || !document.querySelector('script[src="app.js"]');

  if (isStandalone) {
    // Standalone: hide individual file hashes, show drop zone
    if (hashLib) hashLib.parentElement.style.display = 'none';
    if (hashApp) hashApp.parentElement.style.display = 'none';
    if (dropZone) {
      dropZone.classList.remove('hidden');
      setupDropVerify(dropZone);
    }
  } else {
    // PWA: hash individual files live
    if (dropZone) dropZone.classList.add('hidden');
    if (hashApp) {
      try {
        const resp = await fetch('/app.js', { cache: 'force-cache' });
        const bytes = new Uint8Array(await resp.arrayBuffer());
        hashApp.textContent = bytesToHex(sha256(bytes));
      } catch {
        hashApp.textContent = t('fetchFailed');
      }
    }
    if (hashLib) {
      try {
        const resp = await fetch('/lib/bundle.js', { cache: 'force-cache' });
        const bytes = new Uint8Array(await resp.arrayBuffer());
        hashLib.textContent = bytesToHex(sha256(bytes));
      } catch {
        hashLib.textContent = BUILD_LIB_HASH;
      }
    }
  }
}

function setupDropVerify(zone) {
  const label = zone.querySelector('.drop-label');
  const result = zone.querySelector('.drop-result');
  const fileInput = zone.querySelector('input[type="file"]');

  function hashFile(file) {
    const reader = new FileReader();
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result);
      const hash = bytesToHex(sha256(bytes));
      result.textContent = hash;
      result.style.color = 'var(--text)';
      result.style.background = 'var(--surface-hover)';
      result.style.border = '1px solid var(--border)';
      label.textContent = file.name + ' (' + (bytes.length / 1024).toFixed(0) + ' KB)';
    };
    reader.readAsArrayBuffer(file);
  }

  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.style.borderColor = 'var(--accent)'; });
  zone.addEventListener('dragleave', () => { zone.style.borderColor = ''; });
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.style.borderColor = '';
    if (e.dataTransfer.files[0]) hashFile(e.dataTransfer.files[0]);
  });
  zone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) hashFile(fileInput.files[0]);
  });
}

function renderSecurity() {
  const keys = [
    { key: 'signer-keys', descKey: 'storageKeys' },
    { key: 'signer-network', descKey: 'storageNet' },
    { key: 'signer-lang', descKey: 'storageLang' },
    { key: 'signer-seed-lang', descKey: 'storageSeedLang' },
  ];
  const storageRows = keys.map((k) => {
    const exists = localStorage.getItem(k.key) !== null;
    const dot = exists ? '<span style="color:var(--success)">&#9679;</span>' : '<span style="color:var(--text-muted)">&#9675;</span>';
    return `<div class="tx-row"><span class="tx-label">${dot} <code style="background:var(--surface-hover);padding:1px 5px;border-radius:4px;font-family:var(--mono);font-size:12px">${k.key}</code></span><span class="text-muted" style="font-size:11px;text-align:right;max-width:50%">${t(k.descKey)}</span></div>`;
  }).join('');

  return `
    <div class="card">
      <div class="card-title">${t('securityTitle')}</div>
      <div class="security-banner mb-12">
        <strong>${t('securityLevel')}</strong><br><br>
        ${t('whatProvides')}<br>
        - ${t('secProvide1')}<br>
        - ${t('secProvide2')}<br>
        - ${t('secProvide3')}<br>
        - ${t('secProvide4')}<br><br>
        ${t('whatNot')}<br>
        - ${t('secNot1')}<br>
        - ${t('secNot2')}<br>
        - ${t('secNot3')}
      </div>
    </div>
    <div class="card">
      <div class="card-title">${t('keyStorage')}</div>
      ${storageRows}
      <div class="security-banner mt-12">
        <strong>${t('encryption')}</strong> ${t('encryptionDesc')}<br><br>
        <strong style="color:var(--danger)">${t('warning')}</strong> ${t('clearDataWarning')}<br><br>
        <strong>${t('autoLock')}</strong> ${t('autoLockDesc')}
      </div>
    </div>
    <button class="btn btn-secondary" data-action="goSettings">${t('back')}</button>`;
}

function renderGuide() {
  const { os, browser } = detectPlatform();

  const sections = [
    { id: 'ios-safari', label: 'iOS — Safari', key: 'guideIosSafari', match: os === 'ios' && browser === 'safari' },
    { id: 'ios-chrome', label: 'iOS — Chrome', key: 'guideIosChrome', match: os === 'ios' && browser === 'chrome-ios' },
    { id: 'android-chrome', label: 'Android — Chrome', key: 'guideAndroidChrome', match: os === 'android' && browser === 'chrome' },
    { id: 'android-samsung', label: 'Android — Samsung Internet', key: 'guideAndroidSamsung', match: os === 'android' && browser === 'samsung' },
    { id: 'macos-safari', label: 'macOS — Safari', key: 'guideMacosSafari', match: os === 'macos' && browser === 'safari' },
    { id: 'macos-chrome', label: 'macOS — Chrome', key: 'guideMacosChrome', match: os === 'macos' && browser === 'chrome' },
    { id: 'windows-chrome', label: 'Windows — Chrome', key: 'guideWindowsChrome', match: os === 'windows' && browser === 'chrome' },
    { id: 'windows-edge', label: 'Windows — Edge', key: 'guideWindowsEdge', match: os === 'windows' && browser === 'edge' },
  ];

  const chevronSvg = '<svg class="chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5"/></svg>';

  let html = `
    <div class="card">
      <div class="card-title">${t('guideTitle')}</div>
      <p class="text-muted mb-12">${t('guideDesc')}</p>
    </div>`;

  for (const s of sections) {
    const detectedBadge = s.match ? `<span class="badge-detected">${t('detected')}</span>` : '';
    html += `
      <div class="guide-section">
        <div class="guide-header" data-guide-id="${s.id}" data-action="toggleGuide" data-arg="${s.id}">
          <span>${s.label} ${detectedBadge}</span>
          ${chevronSvg}
        </div>
        <div class="guide-body" id="guide-body-${s.id}">
          <div class="guide-body-inner">${t(s.key)}</div>
        </div>
      </div>`;
  }

  html += `<button class="btn btn-secondary mt-16" data-action="goSettings">${t('back')}</button>`;
  return html;
}

function autoExpandGuide() {
  const { os, browser } = detectPlatform();
  const sections = document.querySelectorAll('.guide-header');
  for (const header of sections) {
    const id = header.dataset.guideId;
    const body = document.getElementById('guide-body-' + id);
    if (!body) continue;
    // Auto-expand matching section
    let match = false;
    if (id === 'ios-safari' && os === 'ios' && browser === 'safari') match = true;
    if (id === 'ios-chrome' && os === 'ios' && browser === 'chrome-ios') match = true;
    if (id === 'android-chrome' && os === 'android' && browser === 'chrome') match = true;
    if (id === 'android-samsung' && os === 'android' && browser === 'samsung') match = true;
    if (id === 'macos-safari' && os === 'macos' && browser === 'safari') match = true;
    if (id === 'macos-chrome' && os === 'macos' && browser === 'chrome') match = true;
    if (match) {
      header.classList.add('open');
      body.style.maxHeight = body.scrollHeight + 'px';
    }
  }
}

// ── Actions ────────────────────────────────────────

function warnIfOnline(proceed) {
  if (!navigator.onLine) { proceed(); return; }
  const warnIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  showModal({
    icon: warnIcon,
    title: t('onlineKeygenTitle'),
    body: t('onlineKeygenBody'),
    buttons: [
      { text: t('cancel'), cls: 'btn-secondary' },
      { text: t('proceedAnyway'), cls: 'btn-danger', action: proceed },
    ],
  });
}
function startDice() { warnIfOnline(() => { S.diceEntropy = []; S.screen = 'dice'; render(); }); }
function startCoin() { warnIfOnline(() => { S.coinEntropy = []; S.screen = 'coin'; render(); }); }
function startImport() { warnIfOnline(() => { S.screen = 'import'; render(); }); }
function cancelKeygen() { S.diceEntropy = []; S.coinEntropy = []; S.screen = hasAnyKeys() ? 'home' : 'setup'; render(); }

function addDice(n) {
  S.diceEntropy.push(n);
  if (S.diceEntropy.length >= DICE_REQUIRED) {
    finishEntropy(diceToEntropy(S.diceEntropy));
  } else {
    render();
  }
}
function undoDice() { S.diceEntropy.pop(); render(); }

function addCoin(v) {
  S.coinEntropy.push(v);
  if (S.coinEntropy.length >= COIN_REQUIRED) {
    finishEntropy(coinToEntropy(S.coinEntropy));
  } else {
    render();
  }
}
function undoCoin() { S.coinEntropy.pop(); render(); }

function finishEntropy(entropy) {
  S.tempEntropy = entropy;
  const result = entropyToKey(entropy);
  S.tempMnemonic = result.mnemonic;
  S.tempKeyResult = result;
  S.diceEntropy = [];
  S.coinEntropy = [];
  S.screen = 'mnemonic';
  render();
}

function confirmMnemonic() {
  // After user has written down mnemonic, go to passphrase screen
  S.screen = 'set-pass';
  render();
}

async function doSetPass() {
  const p1 = $('new-pass');
  const p2 = $('new-pass2');
  const errEl = $('setpass-error');
  if (!p1 || !p2) return;
  if (!p1.value) { errEl.textContent = t('passRequired'); return; }
  if (p1.value.length < 4) { errEl.textContent = t('passTooShort'); return; }
  if (p1.value !== p2.value) { errEl.textContent = t('passNoMatch'); p2.value = ''; p2.focus(); return; }

  const result = S.tempKeyResult;
  if (!result) { errEl.textContent = t('noKeyToSave'); return; }

  try {
    const encrypted = await encryptData(result.xprv, p1.value);
    const id = generateKeyId();
    const keyObj = {
      id,
      name: '',
      encryptedKey: encrypted,
      xpub: result.xpub,
      fp: result.fingerprint,
      network: S.network,
      seedLang: S.seedLang,
      createdAt: Date.now(),
      lastOnline: null,
    };
    addKey(keyObj);
    await persistMultiKeyBundle();
    S.xprv = null; // don't keep xprv in memory
    S.tempMnemonic = null;
    S.tempEntropy = null;
    S.tempKeyResult = null;
    S.screen = 'home';
    render();
  } catch (e) {
    errEl.textContent = t('encryptFailed') + e.message;
  }
}

async function doImport() {
  const errEl = $('import-error');
  const inputs = document.querySelectorAll('.import-word');
  if (!inputs.length) return;
  const words = Array.from(inputs).map((inp) => inp.value.trim().toLowerCase());
  const emptyIdx = words.findIndex((w) => !w);
  if (emptyIdx >= 0) {
    if (errEl) errEl.textContent = t('fillAllWords');
    inputs[emptyIdx].focus();
    return;
  }
  try {
    const result = importFromMnemonic(words.join(' '));
    S.tempKeyResult = result;
    S.screen = 'set-pass';
    render();
  } catch (e) {
    if (errEl) errEl.textContent = e.message;
  }
}

// (doUnlock removed — passphrase is now requested at signing time only)

// ── Camera Scanning ────────────────────────────────

function startCamera() {
  if (S.scanStream) return; // already running
  S.urDecoder = new URDecoder();
  S.urProgress = t('startingCamera');

  navigator.mediaDevices.getUserMedia({
    video: { facingMode: 'environment', width: { ideal: 720 }, height: { ideal: 720 } }
  }).then((stream) => {
    S.scanStream = stream;
    const video = $('qr-video');
    if (!video) { stopCamera(); return; }
    video.srcObject = stream;
    video.play();
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    function tick() {
      if (!S.scanStream || S.screen !== 'scan') { return; }
      if (video.readyState >= video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0);
        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
        if (code && code.data) {
          handleQRData(code.data);
        }
      }
      S.scanAnimId = requestAnimationFrame(tick);
    }
    S.scanAnimId = requestAnimationFrame(tick);
    updateScanStatus(t('scanning'));
  }).catch((err) => {
    updateScanStatus(t('cameraError') + err.message);
  });
}

function updateScanStatus(text) {
  S.urProgress = text;
  const el = $('scan-status');
  if (el) el.textContent = text;
}

function handleQRData(data) {
  const lower = data.toLowerCase();

  if (lower.startsWith('ur:')) {
    // Skip duplicate frames (same part scanned consecutively)
    if (S._lastURPart === lower) return;
    S._lastURPart = lower;

    // BC-UR (single or multi-part)
    let accepted = false;
    try {
      accepted = S.urDecoder.receivePart(lower);
    } catch (e) {
      stopCamera();
      updateScanStatus('UR part error: ' + (e.message || e));
      return;
    }

    if (S.urDecoder.isComplete()) {
      if (S.urDecoder.isSuccess()) {
        try {
          const ur = S.urDecoder.resultUR();
          const payload = ur.decodeCBOR();
          stopCamera();
          handleURPayload(payload);
        } catch (e) {
          stopCamera();
          updateScanStatus('CBOR error: ' + (e.message || e));
        }
      } else {
        stopCamera();
        updateScanStatus('UR decode failed: ' + S.urDecoder.resultError());
      }
    } else {
      // Show progress for multi-part
      const pct = Math.round(S.urDecoder.estimatedPercentComplete() * 100);
      const parts = S.urDecoder.expectedPartCount();
      const received = S.urDecoder.receivedPartIndexes().length;
      updateScanStatus(`${t('receivingFountain')} ${pct}% (${received}/${parts}${accepted ? '' : ' dup'})`);
    }
  } else {
    // Try BMS JSON: {"type":"bms","message":"...","index":0}
    if (data.startsWith('{')) {
      try {
        const json = JSON.parse(data);
        if (json.type === 'bms' && typeof json.message === 'string') {
          stopCamera();
          onBmsReceived(json);
          return;
        }
      } catch { /* not valid JSON */ }
    }

    // Try raw base64 PSBT
    try {
      const bytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
      // Validate PSBT magic bytes: 0x70736274ff
      if (bytes[0] === 0x70 && bytes[1] === 0x73 && bytes[2] === 0x62 && bytes[3] === 0x74 && bytes[4] === 0xff) {
        stopCamera();
        onPsbtReceived(bytes);
        return;
      }
    } catch { /* not base64 */ }

    // Try hex
    if (/^[0-9a-fA-F]+$/.test(data) && data.length > 10) {
      try {
        const bytes = hexToBytes(data);
        if (bytes[0] === 0x70 && bytes[1] === 0x73) {
          stopCamera();
          onPsbtReceived(bytes);
          return;
        }
      } catch { /* not valid hex */ }
    }
  }
}

function cancelScan() {
  stopCamera();
  S.urDecoder = null;
  S.urProgress = '';
  S.screen = 'home';
  S.tab = 'key';
  render();
}

// ── UR Payload Router ──────────────────────────────

function handleURPayload(payload) {
  const bytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);

  // PSBT magic: 0x70736274ff ("psbt" + 0xff)
  if (bytes.length >= 5 && bytes[0] === 0x70 && bytes[1] === 0x73 && bytes[2] === 0x62 && bytes[3] === 0x74 && bytes[4] === 0xff) {
    onPsbtReceived(bytes);
    return;
  }

  // Try UTF-8 text → BMS JSON wrapper or plain text message
  try {
    const text = new TextDecoder().decode(bytes);
    // Try JSON wrapper: {"type":"bms","message":"...","index":0}
    try {
      const json = JSON.parse(text);
      if (json.type === 'bms' && typeof json.message === 'string') {
        onBmsReceived(json);
        return;
      }
    } catch { /* not JSON — treat as plain text BMS */ }
    // Plain text from frontend (planDoc sent via encodeTextToUR)
    if (text.length > 0) {
      onBmsReceived({ message: text, index: 0 });
      return;
    }
  } catch { /* not valid UTF-8 */ }

  showAlert(t('psbtParseError'), 'Unknown UR payload format');
}

// ── PSBT Parsing ───────────────────────────────────

function onPsbtReceived(psbtBytes) {
  try {
    // Ensure Uint8Array (decodeCBOR may return Buffer)
    const bytes = psbtBytes instanceof Uint8Array ? psbtBytes : new Uint8Array(psbtBytes);
    const tx = Transaction.fromPSBT(bytes);
    const parsed = parseTxDetails(tx, bytes);
    S.parsedTx = parsed;
    S.screen = 'confirm-tx';
    S.tab = 'sign';
    render();
  } catch (e) {
    // Show error without restarting camera (scan screen auto-starts camera)
    S.screen = 'home';
    S.tab = 'sign';
    showAlert(t('psbtParseError'), e.message);
  }
}

function parseTxDetails(tx, psbtBytes) {
  // Extract fingerprints from BIP32 derivation in inputs
  const fpSet = new Set();
  const inputs = [];
  let inputTotal = 0;

  for (let i = 0; i < tx.inputsLength; i++) {
    const inp = tx.getInput(i);
    const amount = Number(inp.witnessUtxo?.amount || 0n);
    inputTotal += amount;
    if (inp.bip32Derivation) {
      for (const [, deriv] of inp.bip32Derivation) {
        if (deriv.fingerprint) fpSet.add(deriv.fingerprint);
      }
    }
    inputs.push({
      index: i,
      txid: inp.txid ? bytesToHex(inp.txid) : '?',
      vout: inp.index ?? 0,
      amount,
    });
  }

  // Auto-match key by fingerprint
  let matchedKey = null;
  for (const fp of fpSet) {
    matchedKey = findKeyByFingerprint(fp);
    if (matchedKey) break;
  }
  const myFp = matchedKey ? matchedKey.fp : 0;
  // Set signingKeyId for this PSBT session
  if (matchedKey) S.signingKeyId = matchedKey.id;

  const outputs = [];
  let outputTotal = 0;

  for (let i = 0; i < tx.outputsLength; i++) {
    const out = tx.getOutput(i);
    const amount = Number(out.amount || 0n);
    outputTotal += amount;
    const address = tx.getOutputAddress(i) || 'Unknown';

    // Detect change output by checking bip32 derivation
    let isChange = false;
    if (out.bip32Derivation) {
      for (const [, deriv] of out.bip32Derivation) {
        if (deriv.fingerprint === myFp && deriv.path && deriv.path[0] === 1) {
          isChange = true; // chain=1 means change
        }
      }
    }

    outputs.push({ index: i, address, amount, isChange });
  }

  const fee = inputTotal - outputTotal;
  return { psbtBytes, inputs, outputs, fee, inputTotal, outputTotal };
}

// ── PSBT Signing ───────────────────────────────────

function rejectTx() {
  S.parsedTx = null;
  S.screen = 'scan';
  S.tab = 'sign';
  render();
}

function approveTx() {
  if (!S.parsedTx) return;
  if (!hasAnyKeys()) return;
  S.pendingAction = 'sign-tx';
  S.screen = 'enter-pass';
  render();
}

function signPsbt(psbtBytes, xprv) {
  const tx = Transaction.fromPSBT(psbtBytes);
  const hdkey = HDKey.fromExtendedKey(xprv);
  let signed = 0;

  for (let i = 0; i < tx.inputsLength; i++) {
    const inp = tx.getInput(i);
    if (!inp.bip32Derivation) continue;

    for (const [pubkeyBytes, deriv] of inp.bip32Derivation) {
      const path = deriv.path; // [chain, addr_index]
      if (!path || path.length < 2) continue;

      try {
        const chainNode = hdkey.deriveChild(path[0]);
        const child = chainNode.deriveChild(path[1]);
        if (child.publicKey) {
          // Compare public keys to find ours
          const childPub = child.publicKey;
          const targetPub = pubkeyBytes instanceof Uint8Array ? pubkeyBytes : new Uint8Array(pubkeyBytes);
          if (childPub.length === targetPub.length && childPub.every((b, j) => b === targetPub[j])) {
            tx.signIdx(child.privateKey, i);
            signed++;
            if (child.privateKey) child.privateKey.fill(0);
            if (chainNode.privateKey) chainNode.privateKey.fill(0);
            break;
          }
        }
        if (child.privateKey) child.privateKey.fill(0);
        if (chainNode.privateKey) chainNode.privateKey.fill(0);
      } catch { /* skip non-matching derivation */ }
    }
  }

  if (signed === 0) throw new Error('No matching key found in PSBT');

  // Return partially-signed PSBT (do NOT finalize here).
  // Server-side finalize handles Miniscript witness construction.
  return tx.toPSBT();
}

// ── Signed QR Display ──────────────────────────────

function displaySignedQR() {
  const container = $('signed-qr');
  const info = $('qr-frame-info');
  if (!container || !S.signedPsbtBytes) return;

  const psbtB64 = btoa(String.fromCharCode(...S.signedPsbtBytes));
  const SINGLE_QR_LIMIT = 400; // bytes threshold for single vs animated

  if (S.signedPsbtBytes.length <= SINGLE_QR_LIMIT) {
    // Single QR — base64 encoded PSBT
    container.appendChild(generateQRCanvas(psbtB64, 280));
    if (info) info.textContent = `${psbtB64.length} chars (${t('singleQR')})`;
  } else {
    // Animated fountain QR — BC-UR
    try {
      const ur = UR.fromBuffer(S.signedPsbtBytes);
      const encoder = new UREncoder(ur, 100); // 100 bytes per fragment
      S.qrEncoder = encoder;
      const totalParts = encoder.fragmentsLength;

      let frameNum = 0;
      function showNextFrame() {
        const part = encoder.nextPart();
        container.innerHTML = '';
        container.appendChild(generateQRCanvas(part.toUpperCase(), 280));
        frameNum++;
        const cyclePos = ((frameNum - 1) % totalParts) + 1;
        if (info) info.textContent = `${t('frame')} ${cyclePos} / ${totalParts}`;
      }
      showNextFrame();
      S.qrAnimId = setInterval(showNextFrame, 300);
    } catch (e) {
      // Fallback to single large QR
      container.appendChild(generateQRCanvas(psbtB64, 280));
      if (info) info.textContent = `${psbtB64.length} chars (single QR, BC-UR failed)`;
    }
  }
}

function finishSign() {
  stopCamera();
  S.signedPsbtBytes = null;
  S.qrEncoder = null;
  S.screen = 'scan';
  S.tab = 'sign';
  render();
}

// ── Bitcoin Message Signing (BMS) ─────────────────

function encodeVarint(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
  return new Uint8Array([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
}

function bmsHash(message) {
  const prefix = utf8ToBytes('\x18Bitcoin Signed Message:\n');
  const msgBytes = utf8ToBytes(message);
  const varint = encodeVarint(msgBytes.length);
  const full = concatBytes(prefix, varint, msgBytes);
  return sha256(sha256(full));
}

function signBms(message, xprv, derivIndex) {
  const hdkey = HDKey.fromExtendedKey(xprv);
  const chainNode = hdkey.deriveChild(0);
  const child = chainNode.deriveChild(derivIndex);

  const hash = bmsHash(message);
  const sig = secp256k1.sign(hash, child.privateKey);
  const recid = sig.recovery;
  const flag = 31 + recid; // compressed key
  const compact = sig.toCompactRawBytes(); // 64 bytes r||s

  // BMS format: [flag(1)] + [compact(64)] = 65 bytes
  const bmsSig = new Uint8Array(65);
  bmsSig[0] = flag;
  bmsSig.set(compact, 1);

  // Derive address for display
  const addr = p2wpkh(child.publicKey).address;
  if (child.privateKey) child.privateKey.fill(0);
  if (chainNode.privateKey) chainNode.privateKey.fill(0);

  return {
    signature: btoa(String.fromCharCode(...bmsSig)),
    address: addr,
  };
}

function onBmsReceived(json) {
  const index = typeof json.index === 'number' ? Math.floor(json.index) : 0;
  if (index < 0 || index > 0x7FFFFFFF) return;
  S.bmsRequest = { message: json.message, index };
  S.screen = 'confirm-bms';
  S.tab = 'sign';
  render();
}

function approveBms() {
  if (!S.bmsRequest) return;
  if (!hasAnyKeys()) return;
  const keys = getKeys();
  if (keys.length === 1) {
    // Single key: auto-select
    S.signingKeyId = keys[0].id;
    S.pendingAction = 'sign-bms';
    S.screen = 'enter-pass';
    render();
  } else {
    // Multiple keys: show picker modal
    showBmsKeyPicker(keys);
  }
}

function showBmsKeyPicker(keys) {
  const keyIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/></svg>`;
  const bodyHtml = keys.map((k, idx) => {
    const fpHex = k.fp ? k.fp.toString(16).padStart(8, '0') : '?';
    const name = k.name || (t('keyN') + '?');
    return `<button class="btn btn-secondary" style="width:100%;min-height:48px;text-align:left;padding:10px 14px;margin-bottom:6px;font-size:13px" data-bms-key-id="${k.id}"><strong>${escapeHtml(name)}</strong><br><span class="text-muted" style="font-size:11px">${fpHex}</span></button>`;
  }).join('');
  showModal({
    icon: keyIcon,
    title: t('selectKeyForBms'),
    body: bodyHtml,
    buttons: [{ text: t('cancel'), cls: 'btn-secondary' }],
  });
  // Attach click handlers to key buttons
  setTimeout(() => {
    document.querySelectorAll('[data-bms-key-id]').forEach(btn => {
      btn.addEventListener('click', () => {
        S.signingKeyId = btn.dataset.bmsKeyId;
        S.pendingAction = 'sign-bms';
        document.getElementById('modal-overlay').classList.remove('show');
        S.screen = 'enter-pass';
        render();
      });
    });
  }, 50);
}

function rejectBms() {
  S.bmsRequest = null;
  S.screen = 'scan';
  S.tab = 'sign';
  render();
}

function showBmsQR() {
  const container = $('bms-qr');
  if (!container || !S.bmsResult) return;
  container.appendChild(generateQRCanvas(S.bmsResult.signature, 220));
}

function copyBmsSig() {
  if (!S.bmsResult) return;
  navigator.clipboard.writeText(S.bmsResult.signature).then(() => {
    const el = $('bms-sig-text');
    if (el) { el.style.color = 'var(--success)'; setTimeout(() => { el.style.color = ''; }, 1000); }
  }).catch(() => {});
}

// ── Multi-key signing flow ────────────────────────

async function doSignWithPass() {
  const passEl = $('sign-pass');
  const errEl = $('sign-pass-error');
  if (!passEl) return;
  const ak = getSigningKey();
  if (!ak) { if (errEl) errEl.textContent = t('noKeyToSave'); return; }

  // Step 1: Decrypt — passphrase error if this fails
  console.log('[doSignWithPass] key:', ak.id, 'enc prefix:', ak.encryptedKey?.slice(0,12), 'signingKeyId:', S.signingKeyId);
  let xprv;
  try {
    xprv = await decryptData(ak.encryptedKey, passEl.value);
  } catch (e) {
    console.error('[doSignWithPass] decrypt failed:', ak.id, e);
    if (errEl) errEl.textContent = t('passWrong') + ` [${ak.id}]`;
    passEl.value = '';
    passEl.focus();
    return;
  }

  // Step 2: Sign — show actual error if signing fails
  try {
    if (S.pendingAction === 'sign-tx' && S.parsedTx) {
      const signed = signPsbt(S.parsedTx.psbtBytes, xprv);
      // Zero xprv immediately
      S.xprv = null;
      S.signedPsbtBytes = signed;
      S.parsedTx = null;
      S.pendingAction = null;
      S.screen = 'show-qr';
      render();
      displaySignedQR();
    } else if (S.pendingAction === 'sign-bms' && S.bmsRequest) {
      const { message, index } = S.bmsRequest;
      const result = signBms(message, xprv, index);
      S.xprv = null;
      S.bmsResult = { message, signature: result.signature, address: result.address };
      S.bmsRequest = null;
      S.pendingAction = null;
      S.screen = 'bms-result';
      render();
    }
  } catch (e) {
    S.xprv = null;
    if (errEl) errEl.textContent = t('signFailed') + ': ' + (e.message || e);
  }
}

function cancelEnterPass() {
  S.pendingAction = null;
  // Go back to the previous screen
  if (S.parsedTx) { S.screen = 'confirm-tx'; }
  else if (S.bmsRequest) { S.screen = 'confirm-bms'; }
  else { S.screen = 'scan'; }
  render();
}

function renameKey(keyId) {
  const keys = getKeys();
  const k = keys.find(k => k.id === keyId);
  if (!k) return;
  const currentName = k.name || '';

  const editIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.83 0 114 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>`;
  showModal({
    icon: editIcon,
    title: t('renameKeyTitle'),
    body: `<input type="text" id="rename-input" class="input" value="${escapeHtml(currentName)}" placeholder="${t('keyN')}..." autocomplete="off" style="margin-top:8px">`,
    buttons: [
      { text: t('cancel'), cls: 'btn-secondary' },
      { text: t('save'), cls: 'btn-primary', action: () => {
        const inp = document.getElementById('rename-input');
        const newName = inp ? inp.value.trim() : '';
        updateKey(keyId, { name: newName });
        persistMultiKeyBundle();
        render();
      }},
    ],
  });
  // Focus input and select all
  setTimeout(() => {
    const inp = document.getElementById('rename-input');
    if (inp) { inp.focus(); inp.select(); }
  }, 50);
}

async function verifyPassphraseForKey(keyId) {
  const keys = getKeys();
  const k = keys.find(k => k.id === keyId);
  if (!k) return;
  const fpHex = k.fp ? k.fp.toString(16).padStart(8, '0') : '?';
  const displayName = k.name || t('keyN') + '?';

  showModal({
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`,
    title: `${t('verifyPass')} — ${escapeHtml(displayName)}`,
    body: '',
    buttons: [{ text: t('cancel'), cls: 'btn-secondary' }],
  });

  // Inject passphrase input into modal body
  const bodyEl = document.getElementById('modal-body');
  bodyEl.innerHTML = `
    <input type="password" id="verify-pass-input" class="input" placeholder="${t('passphrase')}" autocomplete="off" style="margin-top:12px">
    <p id="verify-pass-result" style="margin-top:8px;text-align:center"></p>
    <button class="btn btn-primary" id="verify-pass-btn" style="margin-top:8px">${t('verifyPass')}</button>
  `;
  const inp = document.getElementById('verify-pass-input');
  const btn = document.getElementById('verify-pass-btn');
  const res = document.getElementById('verify-pass-result');
  inp.focus();
  const doVerify = async () => {
    try {
      console.log('[verifyPass] key:', k.id, 'enc prefix:', k.encryptedKey?.slice(0,12));
      await decryptData(k.encryptedKey, inp.value);
      res.style.color = 'var(--success)';
      res.textContent = t('passCorrect') + ` [${k.id}]`;
    } catch {
      res.style.color = 'var(--danger)';
      res.textContent = t('passWrong');
      inp.value = '';
      inp.focus();
    }
  };
  btn.addEventListener('click', doVerify);
  inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') doVerify(); });
}

function confirmDeleteKeyById(keyId) {
  const warnIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  showModal({
    icon: warnIcon,
    title: t('deleteKeyConfirm1'),
    body: '',
    buttons: [
      { text: t('cancel'), cls: 'btn-secondary' },
      { text: t('deleteKey'), cls: 'btn-danger', action: () => {
        showModal({
          icon: warnIcon,
          title: t('deleteKeyConfirm2'),
          body: '',
          buttons: [
            { text: t('cancel'), cls: 'btn-secondary' },
            { text: t('deleteKey'), cls: 'btn-danger', action: async () => {
              removeKey(keyId);
              await persistMultiKeyBundle();
              S.screen = hasAnyKeys() ? 'home' : 'setup';
              render();
            }},
          ],
        });
      }},
    ],
  });
}

function downloadBackupById(keyId) {
  const keys = getKeys();
  const k = keys.find(k => k.id === keyId);
  if (!k) return;
  const fpHex = k.fp ? k.fp.toString(16).padStart(8, '0') : '????????';
  const backup = {
    type: 'bitclutch-signer-backup',
    version: APP_VERSION,
    created: new Date().toISOString(),
    fingerprint: fpHex,
    network: k.network || 'main',
    encryptedKey: k.encryptedKey,
    xpub: k.xpub || '',
    name: k.name || '',
    seedLang: k.seedLang || 'en',
  };
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `bitclutch-backup-${fpHex}.json`;
  a.click();
  URL.revokeObjectURL(url);
  alert(t('backupSaved'));
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── xpub QR ────────────────────────────────────────

function showXpubQR(keyId) {
  // If called with a keyId argument, use that key; otherwise use first key
  let xpub;
  const keys = getKeys();
  if (keyId) {
    const k = keys.find(k => k.id === keyId);
    xpub = k ? k.xpub : null;
  } else {
    xpub = keys.length ? keys[0].xpub : null;
  }
  if (!xpub) return;
  const el = $screen();
  el.innerHTML = `
    <div class="card text-center">
      <div class="card-title">${t('accountXpubTitle')}</div>
      <div class="qr-container" id="xpub-qr"></div>
      <div class="tx-address mt-12">${escapeHtml(xpub)}</div>
    </div>
    <button class="btn btn-secondary" data-action="goHome">${t('back')}</button>`;
  const container = $('xpub-qr');
  container.appendChild(generateQRCanvas(xpub, 300));
}

function toggleNetwork() {
  if (S.network === 'main') {
    // Switching to testnet — show warning
    const warnIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="var(--gold)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    showModal({
      icon: warnIcon,
      title: t('testnetWarningTitle'),
      body: t('testnetWarningBody'),
      buttons: [
        { text: t('cancel'), cls: 'btn-secondary' },
        { text: t('switchTestnet'), cls: 'btn-primary', action: () => {
          S.network = 'test';
          localStorage.setItem('signer-network', 'test');
          render();
        }},
      ],
    });
  } else {
    S.network = 'main';
    localStorage.setItem('signer-network', 'main');
    render();
  }
}



// ── Custom Modal ──────────────────────────────────
function showModal({ icon, title, body, buttons }) {
  const overlay = document.getElementById('modal-overlay');
  document.getElementById('modal-icon').innerHTML = icon || '';
  document.getElementById('modal-title').textContent = title || '';
  document.getElementById('modal-body').innerHTML = body || '';
  const actDiv = document.getElementById('modal-actions');
  actDiv.innerHTML = '';
  buttons.forEach(b => {
    const btn = document.createElement('button');
    btn.className = `btn ${b.cls || 'btn-secondary'}`;
    btn.textContent = b.text;
    btn.onclick = () => { overlay.classList.remove('show'); if (b.action) b.action(); };
    actDiv.appendChild(btn);
  });
  overlay.classList.add('show');
  // Close on overlay click (outside box)
  overlay.onclick = (e) => { if (e.target === overlay) overlay.classList.remove('show'); };
}

function showAlert(title, body) {
  const warnIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
  showModal({ icon: warnIcon, title, body, buttons: [{ text: t('ok'), cls: 'btn-primary' }] });
}

function confirmDeleteKey() {
  const warnIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  showModal({
    icon: warnIcon,
    title: t('deleteConfirm1'),
    body: '',
    buttons: [
      { text: t('cancel'), cls: 'btn-secondary' },
      { text: t('deleteKey'), cls: 'btn-danger', action: () => {
        // Second confirmation
        showModal({
          icon: warnIcon,
          title: t('deleteConfirm2'),
          body: '',
          buttons: [
            { text: t('cancel'), cls: 'btn-secondary' },
            { text: t('deleteKey'), cls: 'btn-danger', action: async () => {
              await removeFromAllStores();
              lock();
            }},
          ],
        });
      }},
    ],
  });
}

// ── Start ──────────────────────────────────────────
console.log('[Signer] app.js loaded — v2026-02-27-multikey');
init();
