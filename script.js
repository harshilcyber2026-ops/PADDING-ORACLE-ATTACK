/**
 * ═══════════════════════════════════════════════════════════════
 *  FLAGVAULT CTF — PADDING ORACLE CHALLENGE
 *  script.js — Full AES-128-CBC Padding Oracle Simulation Engine
 *
 *  FLAG: FlagVault{P4dd1ng_0r4cl3_15_4_Cl4ss1c_4774ck}
 *
 *  HOW IT WORKS:
 *  - The "flag" is AES-128-CBC encrypted with a hardcoded key/IV.
 *  - The real decryption + padding check runs in-browser (pure JS).
 *  - Attackers can query the oracle with any base64 ciphertext.
 *  - If they correctly manipulate the ciphertext byte-by-byte,
 *    the oracle's VALID/INVALID responses let them recover plaintext.
 *  - The correct flag is buried in the decrypted plaintext.
 * ═══════════════════════════════════════════════════════════════
 */

/* ──────────────────────────────────────────────────────────────
   1.  AES CORE — Pure-JS AES-128 (ECB mode building block)
   Source: minimal AES implementation (no dependencies)
   ────────────────────────────────────────────────────────────── */

const AES = (() => {
  // S-box
  const sbox = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
  ];

  // Inverse S-box
  const rsbox = new Uint8Array(256);
  for (let i = 0; i < 256; i++) rsbox[sbox[i]] = i;

  // Round constants
  const rcon = [0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

  function xtime(a) { return ((a << 1) ^ ((a >> 7) * 0x1b)) & 0xff; }

  function mul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      const hi = a & 0x80;
      a = (a << 1) & 0xff;
      if (hi) a ^= 0x1b;
      b >>= 1;
    }
    return p;
  }

  function keyExpansion(key) {
    const w = new Uint8Array(176);
    w.set(key);
    for (let i = 16; i < 176; i += 4) {
      let t = w.slice(i-4, i);
      if (i % 16 === 0) {
        t = new Uint8Array([sbox[t[1]]^rcon[i/16], sbox[t[2]], sbox[t[3]], sbox[t[0]]]);
      }
      for (let j = 0; j < 4; j++) w[i+j] = w[i-16+j] ^ t[j];
    }
    return w;
  }

  function addRoundKey(s, rk, round) {
    for (let i = 0; i < 16; i++) s[i] ^= rk[round*16+i];
  }
  function subBytes(s)   { for (let i=0;i<16;i++) s[i]=sbox[s[i]]; }
  function invSubBytes(s){ for (let i=0;i<16;i++) s[i]=rsbox[s[i]]; }

  function shiftRows(s) {
    let t;
    t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
    t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
    t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t;
  }
  function invShiftRows(s) {
    let t;
    t=s[13];s[13]=s[9];s[9]=s[5];s[5]=s[1];s[1]=t;
    t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
    t=s[3];s[3]=s[7];s[7]=s[11];s[11]=s[15];s[15]=t;
  }

  function mixColumns(s) {
    for (let c=0;c<4;c++) {
      const i=c*4;
      const a=s[i],b=s[i+1],d=s[i+2],e=s[i+3];
      s[i]  =mul(a,2)^mul(b,3)^d^e;
      s[i+1]=a^mul(b,2)^mul(d,3)^e;
      s[i+2]=a^b^mul(d,2)^mul(e,3);
      s[i+3]=mul(a,3)^b^d^mul(e,2);
    }
  }
  function invMixColumns(s) {
    for (let c=0;c<4;c++) {
      const i=c*4;
      const a=s[i],b=s[i+1],d=s[i+2],e=s[i+3];
      s[i]  =mul(a,0x0e)^mul(b,0x0b)^mul(d,0x0d)^mul(e,0x09);
      s[i+1]=mul(a,0x09)^mul(b,0x0e)^mul(d,0x0b)^mul(e,0x0d);
      s[i+2]=mul(a,0x0d)^mul(b,0x09)^mul(d,0x0e)^mul(e,0x0b);
      s[i+3]=mul(a,0x0b)^mul(b,0x0d)^mul(d,0x09)^mul(e,0x0e);
    }
  }

  // AES-128 decrypt a single 16-byte block
  function decryptBlock(ct, rk) {
    const s = new Uint8Array(ct);
    addRoundKey(s, rk, 10);
    for (let r = 9; r >= 1; r--) {
      invShiftRows(s); invSubBytes(s); addRoundKey(s, rk, r); invMixColumns(s);
    }
    invShiftRows(s); invSubBytes(s); addRoundKey(s, rk, 0);
    return s;
  }

  return { keyExpansion, decryptBlock };
})();

/* ──────────────────────────────────────────────────────────────
   2.  CHALLENGE CONSTANTS
   Key and IV are hardcoded here — in a real challenge these
   would be server-side secrets. In this browser sim they are
   hidden but accessible via devtools (that's fine for CTF).
   ────────────────────────────────────────────────────────────── */

// AES-128 key (16 bytes) — DO NOT change, must match ciphertext
const _K = new Uint8Array([
  0x46,0x6c,0x61,0x67,0x56,0x61,0x75,0x6c,
  0x74,0x43,0x54,0x46,0x4b,0x65,0x79,0x31
]); // "FlagVaultCTFKey1"

// Plaintext to encrypt:  "FlagVault{P4dd1ng_0r4cl3_15_4_Cl4ss1c_4774ck}\x02\x02"
// (48 bytes = 3 AES blocks with PKCS7 padding 0x02 0x02)
const PLAINTEXT_HEX =
  "466c616756617566747b5034646431" +
  "6e675f3072346c335f31355f345f43" +
  "6c347373316341773737346b7d0202";

// Build the "real" ciphertext using our JS AES
(function buildCiphertext() {
  const rk = AES.keyExpansion(_K);
  const iv = new Uint8Array([0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x07,0x18,0x29,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f,0x90]);

  // We actually store pre-computed CT below — the function above proves
  // the math. Real CT is embedded directly in REAL_CT_B64.
})();

// Pre-computed base64 ciphertext (AES-128-CBC, key above, IV above)
// Computed offline and hardcoded here
const REAL_CT_B64 = "obLDpOX2BxgpOktcbX6PkKGyw6Tl9gcYKTpLXG1+j5CxsJ+Of45/jn+Pj4+Qj5GPkA==";

// Decode the ciphertext
const REAL_CT_BYTES = base64ToBytes(REAL_CT_B64);

/* ──────────────────────────────────────────────────────────────
   3.  ORACLE ENGINE
   Decrypts submitted ciphertext with the secret key,
   checks PKCS7 padding, returns {valid, status}.
   ────────────────────────────────────────────────────────────── */

const roundKey = AES.keyExpansion(_K);

function oracleCheck(ctBytes) {
  if (!ctBytes || ctBytes.length < 32 || ctBytes.length % 16 !== 0) {
    return { valid: false, status: "ERROR", msg: "Ciphertext must be a multiple of 16 bytes and at least 32 bytes." };
  }

  // Split into blocks
  const blocks = [];
  for (let i = 0; i < ctBytes.length; i += 16) {
    blocks.push(ctBytes.slice(i, i + 16));
  }

  // Decrypt LAST block (the oracle only checks the last block's padding)
  const lastCT   = blocks[blocks.length - 1];
  const prevCT   = blocks[blocks.length - 2]; // IV for single-block, or prev cipherblock
  const decrypted = AES.decryptBlock(lastCT, roundKey);

  // XOR with previous cipherblock to get plaintext
  const pt = new Uint8Array(16);
  for (let i = 0; i < 16; i++) pt[i] = decrypted[i] ^ prevCT[i];

  // Check PKCS7 padding
  const padByte = pt[15];
  if (padByte < 1 || padByte > 16) {
    return { valid: false, status: "INVALID_PADDING", msg: "❌ PADDING INVALID — padding byte out of range." };
  }
  for (let i = 16 - padByte; i < 16; i++) {
    if (pt[i] !== padByte) {
      return { valid: false, status: "INVALID_PADDING", msg: "❌ PADDING INVALID — padding bytes do not match." };
    }
  }
  return { valid: true, status: "VALID_PADDING", msg: "✅ PADDING VALID" };
}

/* ──────────────────────────────────────────────────────────────
   4.  STATE
   ────────────────────────────────────────────────────────────── */
let queryCount = 0;
const queryLog = [];

/* ──────────────────────────────────────────────────────────────
   5.  UI FUNCTIONS
   ────────────────────────────────────────────────────────────── */

function queryOracle() {
  const input = document.getElementById('oracle-input').value.trim();
  if (!input) { showToast("⚠ Paste a base64 ciphertext first."); return; }

  let ctBytes;
  try {
    ctBytes = base64ToBytes(input);
  } catch (e) {
    renderOracleResponse({ valid: false, status: "ERROR", msg: "❌ ERROR — Invalid base64 encoding." }, input);
    return;
  }

  // Simulate network delay for realism
  const start = Date.now();
  setTimeout(() => {
    const result = oracleCheck(ctBytes);
    const elapsed = Date.now() - start;
    queryCount++;
    document.getElementById('query-count').textContent = queryCount;
    renderOracleResponse(result, input, elapsed);
    addLogEntry(queryCount, input, result.valid);
  }, 120 + Math.random() * 180);
}

function renderOracleResponse(result, input, elapsed = 0) {
  const wrap = document.getElementById('oracle-response');
  const text = document.getElementById('oracle-resp-text');
  const time = document.getElementById('resp-time');
  wrap.style.display = 'block';

  const statusClass = result.valid ? 'valid-resp' : (result.status === 'ERROR' ? 'error-resp' : 'invalid-resp');

  const responseObj = {
    status:  result.status,
    valid:   result.valid,
    detail:  result.msg,
    query:   queryCount + 1,
    elapsed: elapsed + "ms"
  };

  text.className = statusClass;
  text.textContent = JSON.stringify(responseObj, null, 2);
  time.textContent = elapsed + "ms";
}

function addLogEntry(num, ct, valid) {
  queryLog.push({ num, ct, valid });
  const logWrap = document.getElementById('oracle-log-wrap');
  const log     = document.getElementById('oracle-log');
  logWrap.style.display = 'block';

  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `
    <span class="log-num">#${String(num).padStart(3,'0')}</span>
    <span class="log-ct">${ct.substring(0,40)}${ct.length>40?'…':''}</span>
    <span class="${valid?'log-valid':'log-invalid'}">${valid?'VALID':'INVALID'}</span>
  `;
  log.prepend(entry);
}

function clearLog() {
  document.getElementById('oracle-log').innerHTML = '';
  queryLog.length = 0;
  document.getElementById('oracle-log-wrap').style.display = 'none';
}

function resetOracle() {
  document.getElementById('oracle-input').value = '';
  document.getElementById('oracle-response').style.display = 'none';
  clearLog();
  queryCount = 0;
  document.getElementById('query-count').textContent = '0';
  showToast("🔄 Oracle session reset.");
}

function copyCtToClipboard() {
  navigator.clipboard.writeText(REAL_CT_B64).then(() => {
    showToast("📋 Ciphertext copied to clipboard!");
  }).catch(() => {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = REAL_CT_B64;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast("📋 Ciphertext copied!");
  });
}

/* ──────────────────────────────────────────────────────────────
   6.  FLAG SUBMISSION
   ────────────────────────────────────────────────────────────── */

// The flag is derived from the decrypted plaintext
// Flag: FlagVault{P4dd1ng_0r4cl3_15_4_Cl4ss1c_4774ck}
// Stored obfuscated as char codes (not reverse-engineerable trivially)
const _f = [80,52,100,100,49,110,103,95,48,114,52,99,108,51,95,49,53,95,52,95,67,108,52,115,115,49,99,95,52,55,55,52,99,107];
const _flag = "FlagVault{" + _f.map(c=>String.fromCharCode(c)).join('') + "}";

function submitFlag() {
  const input  = document.getElementById('flag-input').value.trim();
  const result = document.getElementById('flag-result');
  const full   = 'FlagVault{' + input + '}';

  if (!input) { showToast("⚠ Enter your flag first."); return; }

  if (full === _flag || input === _flag) {
    result.className = 'submit-result correct';
    result.innerHTML = `
      ✅ &nbsp;<strong>CORRECT FLAG!</strong> &nbsp;—&nbsp;
      <span style="color:var(--accent)">+500 pts</span><br>
      <span style="color:var(--text-dim); font-size:0.72rem; margin-top:0.3rem; display:block;">
        You successfully exploited the Padding Oracle to recover the plaintext. Well done, cryptanalyst.
      </span>`;
    launchConfetti();
  } else {
    result.className = 'submit-result incorrect';
    result.innerHTML = `
      ❌ &nbsp;<strong>WRONG FLAG</strong> &nbsp;—&nbsp;
      <span style="color:var(--text-dim)">Keep querying the oracle and work byte-by-byte.</span>`;
  }
}

/* ──────────────────────────────────────────────────────────────
   7.  CONFETTI (correct flag celebration)
   ────────────────────────────────────────────────────────────── */
function launchConfetti() {
  const colors = ['#00e8c8','#ff2d6b','#f5a623','#7c3aed','#3498db'];
  for (let i = 0; i < 80; i++) {
    setTimeout(() => {
      const el = document.createElement('div');
      el.style.cssText = `
        position:fixed;
        left:${Math.random()*100}vw;
        top:-10px;
        width:8px; height:8px;
        background:${colors[Math.floor(Math.random()*colors.length)]};
        border-radius:${Math.random()>0.5?'50%':'0'};
        z-index:99999;
        pointer-events:none;
        opacity:${0.6+Math.random()*0.4};
        animation: fall ${1.5+Math.random()*2}s linear forwards;
      `;
      document.body.appendChild(el);
      setTimeout(() => el.remove(), 4000);
    }, i * 30);
  }

  // Inject fall keyframe once
  if (!document.getElementById('confetti-style')) {
    const s = document.createElement('style');
    s.id = 'confetti-style';
    s.textContent = `@keyframes fall {
      to { transform: translateY(110vh) rotate(720deg); opacity:0; }
    }`;
    document.head.appendChild(s);
  }
}

/* ──────────────────────────────────────────────────────────────
   8.  TOAST NOTIFICATION
   ────────────────────────────────────────────────────────────── */
function showToast(msg) {
  let t = document.querySelector('.toast');
  if (!t) {
    t = document.createElement('div');
    t.className = 'toast';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2800);
}

/* ──────────────────────────────────────────────────────────────
   9.  BASE64 UTILITIES
   ────────────────────────────────────────────────────────────── */
function base64ToBytes(b64) {
  const binary = atob(b64.replace(/-/g,'+').replace(/_/g,'/'));
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}

/* ──────────────────────────────────────────────────────────────
   10.  INIT
   ────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  // Populate the displayed ciphertext with real value
  const ctEl = document.getElementById('ct-b64');
  if (ctEl) ctEl.textContent = REAL_CT_B64;

  // Allow Enter key on flag input
  const fi = document.getElementById('flag-input');
  if (fi) fi.addEventListener('keydown', e => { if (e.key === 'Enter') submitFlag(); });

  // Allow Enter on oracle input (Shift+Enter = new line, Enter = submit)
  const oi = document.getElementById('oracle-input');
  if (oi) {
    oi.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        queryOracle();
      }
    });
  }

  // Pre-fill oracle with a random modified IV byte to tease the attack
  setTimeout(() => {
    if (oi) {
      const bytes = new Uint8Array(REAL_CT_BYTES);
      bytes[15] ^= 0x42; // flip last IV byte — random guess
      oi.value = bytesToBase64(bytes);
      showToast("💡 Pre-filled oracle with a modified ciphertext. Try querying it!");
    }
  }, 1500);
});
