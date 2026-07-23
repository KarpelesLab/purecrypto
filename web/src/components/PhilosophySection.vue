<script setup>
// Pillars of the project. The mono keyword encodes each pillar's theme rather
// than a sequence number — these are facets, not steps.
const pillars = [
  {
    key: 'trust',
    title: 'No foreign code',
    body: 'Not a binding around OpenSSL or BoringSSL. purecrypto links no C, no system crypto library, no opaque assembler blobs — the dependency tree is Rust the whole way down. There is no separate toolchain to trust and nothing that falls outside `cargo audit`.',
  },
  {
    key: 'safety',
    title: 'Safe by construction',
    body: 'The memory-corruption class behind Heartbleed and a long line of CVEs simply does not compile. `unsafe` is denied crate-wide; the few exceptions that remain — a raw syscall, a CPU intrinsic, the C ABI — are named, isolated, and audited, never scattered through the algorithms.',
  },
  {
    key: 'timing',
    title: 'Constant-time by discipline',
    body: 'Secrets do not branch and do not index tables. Field arithmetic, scalar multiplication and padding checks are written to run in time independent of the key material they touch — the property that stops a correct algorithm from leaking through the clock.',
  },
  {
    key: 'reach',
    title: 'Runs where Rust runs',
    body: 'A `no_std`, no-alloc core compiles for a datacenter, a microcontroller with kilobytes of RAM, and a browser sandbox from one source tree. The demos and tools on this page are that exact library, compiled to WebAssembly — write once, run to the edge and back.',
  },
  {
    key: 'speed',
    title: 'Fast without hand-porting',
    body: 'Portable Rust is the floor, not the ceiling. Where the CPU offers AES-NI, PCLMULQDQ, SHA extensions or their ARM equivalents, purecrypto uses them automatically, and its pure paths are genuinely optimized — SIMD, specialized field backends — not reference code, with the fallback always intact.',
  },
  {
    key: 'scope',
    title: 'A framework, not a box of parts',
    body: 'Everything you would reach OpenSSL or GnuTLS for: hashes and AEADs, RSA and elliptic curves, X.509 and PKI, TLS 1.3, DTLS and QUIC — plus the post-quantum standards most toolkits still lack. Feature-gated, so you compile only the layers you ship.',
  },
];

const targets = [
  'Linux · macOS · Windows',
  'x86-64 · ARM64 · RISC-V',
  'no_std microcontrollers',
  'WebAssembly · browser',
  'WASI',
];

// Render `code spans` inside body text without a markdown dep.
const fmt = (s) => s.replace(/`([^`]+)`/g, '<code>$1</code>');
</script>

<template>
  <section id="philosophy" class="section">
    <div class="wrap">
      <div class="lead">
        <p class="eyebrow">Philosophy</p>
        <h2>Nothing foreign to trust.</h2>
        <p class="manifesto">
          A cryptography library is a strange thing to trust. Most of what runs
          in production is C wearing a Rust coat — a thin binding over OpenSSL or
          BoringSSL, carrying a C toolchain, a decades-deep CVE history, and an
          unsafe FFI seam you can't see past. purecrypto takes the harder path:
          every algorithm, from a constant-time field multiply to a full TLS 1.3
          handshake, is written in safe Rust in <em>this one crate</em>. What you
          audit is what runs.
        </p>
      </div>

      <div class="pillars">
        <article v-for="p in pillars" :key="p.key" class="pillar">
          <span class="pkey mono">{{ p.key }}</span>
          <h3>{{ p.title }}</h3>
          <p v-html="fmt(p.body)"></p>
        </article>
      </div>

      <div class="everywhere">
        <div class="ev-lead">
          <span class="mono ev-eye">One source tree</span>
          <p>The same code, every target — no per-platform fork, no C cross-build.</p>
        </div>
        <ul class="targets">
          <li v-for="t in targets" :key="t" class="mono">{{ t }}</li>
        </ul>
      </div>

      <div class="facts mono">
        <span>MIT licensed</span>
        <span>MSRV Rust 1.88</span>
        <span>unsafe denied crate-wide</span>
        <span>#![no_std] + alloc</span>
      </div>
    </div>
  </section>
</template>

<style scoped>
.lead {
  max-width: 760px;
  margin-bottom: 52px;
}
.lead h2 {
  font-size: clamp(2rem, 4.4vw, 3.1rem);
  margin: 14px 0 22px;
}
.manifesto {
  font-size: 1.15rem;
  line-height: 1.7;
  color: var(--dim);
  margin: 0;
}
.manifesto em {
  color: var(--paper);
  font-style: normal;
  font-weight: 600;
}

.pillars {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1px;
  background: var(--line-soft);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius);
  overflow: hidden;
}
.pillar {
  padding: 28px;
  background: var(--ink-1);
  transition: background 0.2s ease;
}
.pillar:hover {
  background: var(--ink-2);
}
.pkey {
  font-size: 0.7rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--violet-2);
}
.pillar h3 {
  font-size: 1.24rem;
  margin: 12px 0 12px;
}
.pillar p {
  font-size: 0.94rem;
  line-height: 1.65;
  color: var(--muted);
  margin: 0;
}
.pillar :deep(code) {
  font-family: var(--font-mono);
  font-size: 0.84em;
  color: var(--teal-2);
  background: var(--ink-3);
  padding: 1px 5px;
  border-radius: 4px;
}

.everywhere {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 28px;
  flex-wrap: wrap;
  margin-top: 22px;
  padding: 26px 28px;
  border: 1px solid var(--line-soft);
  border-radius: var(--radius);
  background:
    radial-gradient(500px 220px at 12% 0%, var(--teal-glow), transparent 70%),
    var(--ink-1);
}
.ev-eye {
  font-size: 0.72rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--teal-2);
}
.ev-lead p {
  margin: 8px 0 0;
  color: var(--dim);
  font-size: 0.98rem;
  max-width: 30ch;
}
.targets {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  list-style: none;
  margin: 0;
  padding: 0;
  justify-content: flex-end;
}
.targets li {
  font-size: 0.76rem;
  color: var(--dim);
  padding: 7px 12px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--ink-2);
}

.facts {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 26px;
  margin-top: 34px;
  font-size: 0.82rem;
  color: var(--teal-2);
}
.facts span::before {
  content: '› ';
  color: var(--violet-2);
}

@media (max-width: 880px) {
  .pillars {
    grid-template-columns: repeat(2, 1fr);
  }
}
@media (max-width: 560px) {
  .pillars {
    grid-template-columns: 1fr;
  }
  .everywhere {
    flex-direction: column;
    align-items: flex-start;
  }
  .targets {
    justify-content: flex-start;
  }
}
</style>
