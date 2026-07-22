<script setup>
const families = [
  {
    n: '01',
    title: 'Hashes & XOFs',
    desc: 'The full digest zoo, plus extendable-output functions.',
    items: ['SHA-2', 'SHA-3 / SHAKE', 'Keccak', 'BLAKE2', 'BLAKE3', 'Ascon-Hash', 'SM3', 'RIPEMD-160', 'Whirlpool', 'Streebog'],
  },
  {
    n: '02',
    title: 'MAC & KDF',
    desc: 'Message authentication and key derivation.',
    items: ['HMAC', 'CMAC', 'GMAC', 'Poly1305', 'UMAC', 'HKDF', 'PBKDF2', 'scrypt', 'Argon2'],
  },
  {
    n: '03',
    title: 'AEAD & ciphers',
    desc: 'Authenticated encryption, key wrap, block modes.',
    items: ['AES-GCM', 'AES-GCM-SIV', 'AES-CCM', 'ChaCha20-Poly1305', 'XChaCha20', 'AEGIS', 'Ascon-AEAD', 'AES-KW', 'Camellia', 'ARIA'],
  },
  {
    n: '04',
    title: 'Elliptic curves',
    desc: 'ECDSA, EdDSA, ECDH across the standard curves.',
    items: ['P-256 / 384 / 521', 'X25519', 'Ed25519', 'X448 / Ed448', 'secp256k1', 'Brainpool', 'SM2', 'ristretto255'],
  },
  {
    n: '05',
    title: 'RSA & finite-field DH',
    desc: 'Classic public-key, with CRT acceleration.',
    items: ['PKCS#1 v1.5', 'RSA-PSS', 'RSA-OAEP', 'MODP DH (RFC 3526)'],
  },
  {
    n: '06',
    title: 'Post-quantum',
    desc: 'The NIST PQC standards and stateful hash signatures.',
    pq: true,
    items: ['ML-KEM (FIPS 203)', 'ML-DSA (FIPS 204)', 'SLH-DSA (FIPS 205)', 'Falcon', 'LMS / HSS', 'XMSS'],
  },
  {
    n: '07',
    title: 'X.509 & PKI',
    desc: 'Certificates end to end — parse, build, validate.',
    items: ['Cert parse / build', 'CSR', 'CRL', 'OCSP', 'Path validation', 'Policy tree', 'SCT / CT', 'PKCS#8 / #12'],
  },
  {
    n: '08',
    title: 'Secure transport',
    desc: 'Full sans-I/O protocol stacks on top of the primitives.',
    items: ['TLS 1.2 / 1.3', 'DTLS 1.2 / 1.3', 'QUIC v1 (RFC 9000)', 'Encrypted ClientHello', 'Hybrid X25519MLKEM768'],
  },
  {
    n: '09',
    title: 'Randomness',
    desc: 'CSPRNGs seeded from the platform, wasm included.',
    items: ['OS entropy', 'HMAC-DRBG', 'getrandom(2)', 'WASI random_get', 'browser crypto'],
  },
];
</script>

<template>
  <section id="capabilities" class="section">
    <div class="wrap">
      <div class="section-head">
        <p class="eyebrow">The catalogue</p>
        <h2>One library, the whole stack.</h2>
        <p>
          purecrypto spans constant-time primitives all the way up to complete
          TLS, DTLS and QUIC engines — every layer implemented in safe Rust, with
          hardware backends where the CPU offers them. Here is what ships today.
        </p>
      </div>

      <div class="grid">
        <article v-for="f in families" :key="f.n" class="card panel">
          <div class="card-top">
            <span class="num mono">{{ f.n }}</span>
            <span v-if="f.pq" class="tag pq">post-quantum</span>
          </div>
          <h3>{{ f.title }}</h3>
          <p class="desc">{{ f.desc }}</p>
          <ul class="chips">
            <li v-for="it in f.items" :key="it" class="mono">{{ it }}</li>
          </ul>
        </article>
      </div>
    </div>
  </section>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 18px;
}
.card {
  padding: 24px;
  transition:
    border-color 0.2s ease,
    transform 0.2s ease;
}
.card:hover {
  border-color: var(--line);
  transform: translateY(-3px);
}
.card-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.num {
  font-size: 0.8rem;
  color: var(--violet-2);
  letter-spacing: 0.1em;
}
.card h3 {
  font-size: 1.22rem;
  margin-bottom: 8px;
}
.desc {
  color: var(--muted);
  font-size: 0.92rem;
  margin: 0 0 18px;
}
.chips {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
}
.chips li {
  font-size: 0.74rem;
  color: var(--dim);
  padding: 4px 9px;
  border: 1px solid var(--line-soft);
  border-radius: 6px;
  background: var(--ink-2);
}
@media (max-width: 900px) {
  .grid {
    grid-template-columns: repeat(2, 1fr);
  }
}
@media (max-width: 600px) {
  .grid {
    grid-template-columns: 1fr;
  }
}
</style>
