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
