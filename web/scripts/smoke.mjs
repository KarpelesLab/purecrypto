// Validates the JS<->wasm bridge against the real purecrypto.wasm, headless.
// Run: node web/scripts/smoke.mjs
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const here = path.dirname(fileURLToPath(import.meta.url));
const wasmPath = path.join(here, '..', 'public', 'purecrypto.wasm');

// Shim fetch(url) -> the local wasm bytes so lib/purecrypto.js loads unchanged.
const bytes = readFileSync(wasmPath);
globalThis.fetch = async () => ({ arrayBuffer: async () => bytes });
if (!globalThis.atob) globalThis.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');

const pc = await import('../src/lib/purecrypto.js');
await pc.load('purecrypto.wasm');

let pass = 0, fail = 0;
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${detail}`); }
}

// SHA-256("abc") known-answer.
const sha = pc.toHex(pc.digest(pc.HASH.SHA256, pc.utf8('abc')));
check('SHA-256("abc")', sha === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', sha);

// SHA3-256 length + BLAKE3 sanity.
check('SHA3-256 len', pc.digest(pc.HASH.SHA3_256, pc.utf8('x')).length === 32);
check('BLAKE3 len', pc.digest(pc.HASH.BLAKE3, pc.utf8('x')).length === 32);

// AES-256-GCM round-trip.
const key = new Uint8Array(32); crypto.getRandomValues(key);
const nonce = new Uint8Array(12); crypto.getRandomValues(nonce);
const aad = pc.utf8('header');
const pt = pc.utf8('the quick brown fox');
const ctTag = pc.aeadEncrypt(pc.AEAD.AES256_GCM, key, nonce, aad, pt);
check('AES-256-GCM ct grows by tag', ctTag.length === pt.length + 16);
const back = pc.aeadDecrypt(pc.AEAD.AES256_GCM, key, nonce, aad, ctTag);
check('AES-256-GCM round-trip', eq(back, pt));
// tampering is rejected
let rejected = false;
try { const bad = ctTag.slice(); bad[0] ^= 1; pc.aeadDecrypt(pc.AEAD.AES256_GCM, key, nonce, aad, bad); }
catch { rejected = true; }
check('AES-256-GCM rejects tamper', rejected);

// ChaCha20-Poly1305 round-trip.
const c2 = pc.aeadEncrypt(pc.AEAD.CHACHA20_POLY1305, key, nonce, aad, pt);
check('ChaCha20-Poly1305 round-trip', eq(pc.aeadDecrypt(pc.AEAD.CHACHA20_POLY1305, key, nonce, aad, c2), pt));

// Ed25519 sign / verify.
const k = pc.ed25519();
const pub = k.publicPem();
const msg = pc.utf8('sign me');
const sig = k.sign(msg);
check('Ed25519 sig is 64 bytes', sig.length === 64);
check('Ed25519 verify ok', pc.ed25519Verify(pub, msg, sig) === true);
check('Ed25519 verify rejects wrong msg', pc.ed25519Verify(pub, pc.utf8('other'), sig) === false);
k.free();

// ML-KEM-768 encapsulate / decapsulate.
const kem = pc.mlkem(pc.MLKEM.K768);
const ek = kem.publicDer();
const { ct, ss } = pc.mlkemEncaps(pc.MLKEM.K768, ek);
const ss2 = kem.decaps(ct);
check('ML-KEM-768 shared secret is 32 bytes', ss.length === 32);
check('ML-KEM-768 secrets agree', eq(ss, ss2));
kem.free();

// ML-DSA-65 sign / verify.
const d = pc.mldsa(pc.MLDSA.D65);
const dpub = d.publicPem();
const dsig = d.sign(msg);
check('ML-DSA-65 verify ok', pc.mldsaVerify(pc.MLDSA.D65, dpub, msg, dsig) === true);
check('ML-DSA-65 verify rejects wrong msg', pc.mldsaVerify(pc.MLDSA.D65, dpub, pc.utf8('other'), dsig) === false);
d.free();

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
