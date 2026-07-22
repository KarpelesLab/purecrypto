// Thin, dependency-free bridge over the purecrypto C ABI compiled to
// WebAssembly (the `ffi` feature, built as a `cdylib`). Every function here
// marshals bytes through the module's linear memory using the exported
// `pc_malloc` / `pc_free` allocator, then calls a `pc_*` entry point.
//
// The whole surface is real cryptography executing in the browser — no shims,
// no polyfills. Entropy is drawn from the host's CSPRNG via the imported
// `purecrypto.random_get`, wired to `crypto.getRandomValues` below.

let wasm = null; // instance.exports once initialized

// Views must be re-read after any call that may have grown linear memory
// (growth detaches existing ArrayBuffers), so these are always fresh.
const u8 = () => new Uint8Array(wasm.memory.buffer);
const dv = () => new DataView(wasm.memory.buffer);

// PcStatus (src/ffi/common.rs)
const OK = 0;
const BUFFER_TOO_SMALL = -2;
const STATUS = {
  '-1': 'null pointer',
  '-2': 'buffer too small',
  '-3': 'bad encoding',
  '-4': 'verification failed',
  '-5': 'unsupported',
  '-6': 'internal error',
};

export class PcError extends Error {
  constructor(status) {
    super(`purecrypto: ${STATUS[status] || 'error'} (${status})`);
    this.status = status;
  }
}

function malloc(size) {
  const p = wasm.pc_malloc(size || 1);
  if (!p) throw new Error('purecrypto: out of memory');
  return p;
}
const free = (ptr, size) => wasm.pc_free(ptr, size || 1);

// Copy `bytes` into a fresh linear-memory allocation; returns [ptr, len].
function put(bytes) {
  const len = bytes.length;
  const ptr = malloc(len);
  u8().set(bytes, ptr);
  return [ptr, len];
}

// Call an out-buffer entry point following the capacity-in / length-out
// convention. `call(outPtr, lenPtr)` returns a PcStatus; on BufferTooSmall we
// grow to the required size and retry once. Returns a copy of the output.
function withOutput(cap, call) {
  let capacity = cap;
  for (;;) {
    const outPtr = malloc(capacity);
    const lenPtr = malloc(4);
    dv().setUint32(lenPtr, capacity, true);
    const status = call(outPtr, lenPtr);
    const need = dv().getUint32(lenPtr, true);
    if (status === BUFFER_TOO_SMALL) {
      free(outPtr, capacity);
      free(lenPtr, 4);
      capacity = need;
      continue;
    }
    if (status !== OK) {
      free(outPtr, capacity);
      free(lenPtr, 4);
      throw new PcError(status);
    }
    const out = u8().slice(outPtr, outPtr + need);
    free(outPtr, capacity);
    free(lenPtr, 4);
    return out;
  }
}

// ---- lifecycle -----------------------------------------------------------

let loading = null;

/** Fetch, compile and instantiate the wasm module. Idempotent. */
export function load(url) {
  if (wasm) return Promise.resolve();
  if (loading) return loading;
  const imports = {
    purecrypto: {
      // The crate's entropy backend for wasm32-unknown-unknown: fill `len`
      // bytes at `ptr` from the host CSPRNG. getRandomValues caps at 65536
      // bytes per call, so chunk larger draws.
      random_get(ptr, len) {
        const buf = new Uint8Array(wasm.memory.buffer, ptr, len);
        for (let off = 0; off < len; off += 65536) {
          crypto.getRandomValues(buf.subarray(off, Math.min(off + 65536, len)));
        }
      },
    },
  };
  loading = fetch(url)
    .then((r) => r.arrayBuffer())
    .then((buf) => WebAssembly.instantiate(buf, imports))
    .then((res) => {
      wasm = res.instance.exports;
    });
  return loading;
}

export const ready = () => wasm !== null;

// ---- helpers -------------------------------------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();
export const utf8 = (s) => enc.encode(s);
export const fromUtf8 = (b) => dec.decode(b);
export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// Strip a PEM envelope to its raw DER bytes.
function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- algorithm ids (mirror src/ffi/*.rs) --------------------------------

export const HASH = {
  SHA256: 2, SHA384: 3, SHA512: 4, SHA3_256: 8, SHA3_512: 10,
  KECCAK256: 11, BLAKE2B512: 13, BLAKE3: 15,
};
export const AEAD = { AES128_GCM: 1, AES256_GCM: 2, CHACHA20_POLY1305: 3, XCHACHA20_POLY1305: 10 };
export const MLKEM = { K512: 1, K768: 2, K1024: 3 };
export const MLDSA = { D44: 1, D65: 2, D87: 3 };

// ---- hashing -------------------------------------------------------------

export function digest(alg, data) {
  const [dp, dl] = put(data);
  try {
    return withOutput(64, (o, l) => wasm.pc_digest(alg, dp, dl, o, l));
  } finally {
    free(dp, dl);
  }
}

// ---- AEAD ----------------------------------------------------------------

export function aeadEncrypt(alg, key, nonce, aad, pt) {
  const [kp, kl] = put(key), [np, nl] = put(nonce), [ap, al] = put(aad), [pp, pl] = put(pt);
  try {
    return withOutput(pl + 16, (o, l) =>
      wasm.pc_aead_encrypt(alg, kp, kl, np, nl, ap, al, pp, pl, o, l));
  } finally {
    free(kp, kl); free(np, nl); free(ap, al); free(pp, pl);
  }
}

export function aeadDecrypt(alg, key, nonce, aad, ctAndTag) {
  const [kp, kl] = put(key), [np, nl] = put(nonce), [ap, al] = put(aad), [cp, cl] = put(ctAndTag);
  try {
    return withOutput(Math.max(cl - 16, 1), (o, l) =>
      wasm.pc_aead_decrypt(alg, kp, kl, np, nl, ap, al, cp, cl, o, l));
  } finally {
    free(kp, kl); free(np, nl); free(ap, al); free(cp, cl);
  }
}

// ---- Ed25519 (generate / sign / verify) ----------------------------------

export function ed25519() {
  const h = wasm.pc_ed25519_generate();
  if (!h) throw new Error('purecrypto: Ed25519 keygen failed');
  return {
    publicPem: () => fromUtf8(withOutput(256, (o, l) => wasm.pc_ed25519_public_to_pem(h, o, l))),
    privatePem: () => fromUtf8(withOutput(256, (o, l) => wasm.pc_ed25519_private_to_pem(h, o, l))),
    sign(msg) {
      const [mp, ml] = put(msg);
      try { return withOutput(64, (o, l) => wasm.pc_ed25519_sign(h, mp, ml, o, l)); }
      finally { free(mp, ml); }
    },
    free: () => wasm.pc_ed25519_free(h),
  };
}

export function ed25519Verify(publicPem, msg, sig) {
  const der = pemToDer(publicPem);
  const [sp, sl] = put(der), [mp, ml] = put(msg), [gp, gl] = put(sig);
  try {
    return wasm.pc_ed25519_verify(sp, sl, mp, ml, gp, gl) === OK;
  } finally {
    free(sp, sl); free(mp, ml); free(gp, gl);
  }
}

// ---- ML-KEM (post-quantum KEM) -------------------------------------------

export function mlkem(set) {
  const h = wasm.pc_mlkem_generate(set);
  if (!h) throw new Error('purecrypto: ML-KEM keygen failed');
  return {
    publicDer: () => withOutput(1600, (o, l) => wasm.pc_mlkem_public_to_der(h, o, l)),
    // Decapsulate a ciphertext to the 32-byte shared secret.
    decaps(ct) {
      const [cp, cl] = put(ct);
      const ssPtr = malloc(32);
      try {
        const st = wasm.pc_mlkem_decaps(h, cp, cl, ssPtr);
        if (st !== OK) throw new PcError(st);
        return u8().slice(ssPtr, ssPtr + 32);
      } finally { free(cp, cl); free(ssPtr, 32); }
    },
    free: () => wasm.pc_mlkem_free(h),
  };
}

// Encapsulate to a public key (DER); returns { ct, ss } (ss is 32 bytes).
export function mlkemEncaps(set, ekDer) {
  const [ep, el] = put(ekDer);
  const ssPtr = malloc(32);
  try {
    const ct = withOutput(1600, (o, l) => wasm.pc_mlkem_encaps(set, ep, el, o, l, ssPtr));
    const ss = u8().slice(ssPtr, ssPtr + 32);
    return { ct, ss };
  } finally { free(ep, el); free(ssPtr, 32); }
}

// ---- ML-DSA (post-quantum signature) -------------------------------------

export function mldsa(set) {
  const h = wasm.pc_mldsa_generate(set);
  if (!h) throw new Error('purecrypto: ML-DSA keygen failed');
  return {
    set,
    publicPem: () => fromUtf8(withOutput(3072, (o, l) => wasm.pc_mldsa_public_to_pem(h, o, l))),
    sign(msg) {
      const [mp, ml] = put(msg);
      try { return withOutput(5000, (o, l) => wasm.pc_mldsa_sign(h, mp, ml, o, l)); }
      finally { free(mp, ml); }
    },
    free: () => wasm.pc_mldsa_free(h),
  };
}

export function mldsaVerify(set, publicPem, msg, sig) {
  const der = pemToDer(publicPem);
  const [sp, sl] = put(der), [mp, ml] = put(msg), [gp, gl] = put(sig);
  try {
    return wasm.pc_mldsa_verify(set, sp, sl, mp, ml, gp, gl) === OK;
  } finally {
    free(sp, sl); free(mp, ml); free(gp, gl);
  }
}

// ---- full hash catalogue (mirrors src/ffi/hash.rs `id`) -------------------

export const HASHES = [
  { id: 2, name: 'SHA-256' }, { id: 3, name: 'SHA-384' }, { id: 4, name: 'SHA-512' },
  { id: 5, name: 'SHA-512/224' }, { id: 6, name: 'SHA-512/256' },
  { id: 7, name: 'SHA3-224' }, { id: 8, name: 'SHA3-256' }, { id: 9, name: 'SHA3-384' },
  { id: 10, name: 'SHA3-512' }, { id: 11, name: 'Keccak-256' },
  { id: 12, name: 'BLAKE2b-256' }, { id: 13, name: 'BLAKE2b-512' }, { id: 14, name: 'BLAKE2s-256' },
  { id: 15, name: 'BLAKE3' }, { id: 16, name: 'SM3' }, { id: 1, name: 'SHA-224' },
  { id: 17, name: 'SHA-1' }, { id: 18, name: 'MD5' }, { id: 19, name: 'RIPEMD-160' },
  { id: 20, name: 'Ascon-Hash256' }, { id: 21, name: 'MD2' }, { id: 22, name: 'Whirlpool' },
  { id: 23, name: 'Streebog-256' }, { id: 24, name: 'Streebog-512' },
];

// The subset actually wired in the ffi build (probe once).
let _supported = null;
export function supportedHashes() {
  if (_supported) return _supported;
  _supported = HASHES.filter((h) => {
    const p = wasm.pc_hash_new(h.id);
    if (!p) return false;
    wasm.pc_hash_free(p);
    return true;
  });
  return _supported;
}

// ---- streaming multi-hash (one pass over the input) ----------------------

// Hash a stream of chunks under every algorithm in `algs` simultaneously,
// copying each chunk into linear memory once. Returns { updateChunk, finish }.
export function multiHash(algs) {
  const hs = algs.map((a) => ({ a, h: wasm.pc_hash_new(a.id) })).filter((x) => x.h);
  return {
    updateChunk(chunk) {
      if (!chunk.length) return;
      const [p, l] = put(chunk);
      try {
        for (const x of hs) wasm.pc_hash_update(x.h, p, l);
      } finally {
        free(p, l);
      }
    },
    finish() {
      return hs.map((x) => {
        const digest = withOutput(64, (o, l) => wasm.pc_hash_finish(x.h, o, l));
        wasm.pc_hash_free(x.h);
        return { name: x.a.name, hex: toHex(digest), bits: digest.length * 8 };
      });
    },
  };
}

// ---- key generation ------------------------------------------------------

// Each entry: how to generate + serialize a private key, and whether the ffi
// can build a CSR for it (rsa / ec / ed25519 have PEM CSR wrappers).
const KEY_IMPL = {
  ed25519: { gen: () => wasm.pc_ed25519_generate(), pr: (h, o, l) => wasm.pc_ed25519_private_to_pem(h, o, l), pu: (h, o, l) => wasm.pc_ed25519_public_to_pem(h, o, l), fr: (h) => wasm.pc_ed25519_free(h), csr: 'ed25519' },
  ed448: { gen: () => wasm.pc_ed448_generate(), pr: (h, o, l) => wasm.pc_ed448_private_to_pem(h, o, l), pu: (h, o, l) => wasm.pc_ed448_public_to_pem(h, o, l), fr: (h) => wasm.pc_ed448_free(h), csr: null },
  ecdsa: { gen: (p) => wasm.pc_ec_generate(p), pr: (h, o, l) => wasm.pc_ec_private_to_pem(h, o, l), pu: (h, o, l) => wasm.pc_ec_public_to_pem(h, o, l), fr: (h) => wasm.pc_ec_free(h), csr: 'ec' },
  rsa: { gen: (p) => wasm.pc_rsa_generate(p), pr: (h, o, l) => wasm.pc_rsa_private_to_pem(h, o, l), pu: (h, o, l) => wasm.pc_rsa_public_to_pem(h, o, l), fr: (h) => wasm.pc_rsa_free(h), csr: 'rsa' },
  mldsa: { gen: (p) => wasm.pc_mldsa_generate(p), pr: (h, o, l) => wasm.pc_mldsa_private_to_pem(h, o, l), pu: (h, o, l) => wasm.pc_mldsa_public_to_pem(h, o, l), fr: (h) => wasm.pc_mldsa_free(h), csr: null },
  slhdsa: { gen: (p) => wasm.pc_slhdsa_generate(p), pr: (h, o, l) => wasm.pc_slhdsa_private_to_pem(h, o, l), pu: (h, o, l) => wasm.pc_slhdsa_public_to_pem(h, o, l), fr: (h) => wasm.pc_slhdsa_free(h), csr: null },
  sm2: { gen: () => wasm.pc_sm2_generate(), pr: (h, o, l) => wasm.pc_sm2_private_to_pem(h, o, l), pu: (h, o, l) => wasm.pc_sm2_public_to_pem(h, o, l), fr: (h) => wasm.pc_sm2_free(h), csr: null },
};

// Generate a private key. `kind` keys KEY_IMPL; `param` is the curve/bits/set.
export function generateKey(kind, param = 0) {
  const impl = KEY_IMPL[kind];
  if (!impl) throw new Error(`unknown key kind: ${kind}`);
  const h = impl.gen(param | 0);
  if (!h) throw new Error(`${kind} key generation failed`);
  return {
    kind,
    csrType: impl.csr,
    handle: h,
    privatePem: () => fromUtf8(withOutput(6144, (o, l) => impl.pr(h, o, l))),
    publicPem: () => fromUtf8(withOutput(6144, (o, l) => impl.pu(h, o, l))),
    free: () => impl.fr(h),
  };
}

// Load a private key PEM into a handle for CSR signing (rsa / ec / ed25519).
const FROM_PEM = {
  rsa: (p, l) => wasm.pc_rsa_from_pem(p, l),
  ec: (p, l) => wasm.pc_ec_from_pem(p, l),
  ed25519: (p, l) => wasm.pc_ed25519_from_pem(p, l),
};
const FREE_BY = {
  rsa: (h) => wasm.pc_rsa_free(h),
  ec: (h) => wasm.pc_ec_free(h),
  ed25519: (h) => wasm.pc_ed25519_free(h),
};
export function loadPrivatePem(csrType, pem) {
  const [p, l] = put(utf8(pem));
  try {
    const h = FROM_PEM[csrType](p, l);
    if (!h) throw new Error(`could not parse a ${csrType} private key from that PEM`);
    return { handle: h, free: () => FREE_BY[csrType](h) };
  } finally {
    free(p, l);
  }
}

// ---- CSR (PKCS#10) -------------------------------------------------------

const CSR_FN = {
  rsa: (h, cp, cl, sp, sl, o, ol) => wasm.pc_csr_create_rsa_pem(h, cp, cl, sp, sl, o, ol),
  ec: (h, cp, cl, sp, sl, o, ol) => wasm.pc_csr_create_ec_pem(h, cp, cl, sp, sl, o, ol),
  ed25519: (h, cp, cl, sp, sl, o, ol) => wasm.pc_csr_create_ed25519_pem(h, cp, cl, sp, sl, o, ol),
};
export function csrPem(csrType, handle, cn, sans = []) {
  const [cp, cl] = put(utf8(cn));
  const [sp, sl] = put(utf8(sans.join('\n')));
  try {
    return fromUtf8(withOutput(4096, (o, l) => CSR_FN[csrType](handle, cp, cl, sp, sl, o, l)));
  } finally {
    free(cp, cl); free(sp, sl);
  }
}

// ---- X.509 analysis ------------------------------------------------------

// Parse a certificate (PEM string or DER bytes) and return a structured
// summary: subject/issuer, validity, serial, key, SANs, constraints, usages,
// fingerprints, and whether it is self-signed.
export function analyzeCert(input) {
  let handle;
  if (typeof input === 'string') {
    const [p, l] = put(utf8(input));
    try { handle = wasm.pc_cert_from_pem(p, l); } finally { free(p, l); }
  } else {
    const [p, l] = put(input);
    try { handle = wasm.pc_cert_from_der(p, l); } finally { free(p, l); }
  }
  if (!handle) throw new Error('could not parse an X.509 certificate from that input');
  try {
    const info = JSON.parse(fromUtf8(withOutput(8192, (o, l) => wasm.pc_cert_analyze(handle, o, l))));
    // from_der is lazy, so structurally-broken input parses to a shell with no
    // fields. A real certificate always has a decodable public key.
    if (!info.key) throw new Error('that does not appear to be a valid X.509 certificate');
    const der = withOutput(8192, (o, l) => wasm.pc_cert_to_der(handle, o, l));
    info.der_bytes = der.length;
    info.fingerprints = {
      sha256: toHex(digest(HASH.SHA256, der)),
      sha1: toHex(digest(17 /* SHA-1 */, der)),
    };
    info.self_signed = wasm.pc_cert_verify(handle, handle) === OK;
    return info;
  } finally {
    wasm.pc_cert_free(handle);
  }
}
