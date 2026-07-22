<script setup>
const principles = [
  {
    k: 'No foreign code',
    d: 'Not a wrapper around OpenSSL or BoringSSL. Every algorithm is implemented in Rust in this one crate — the whole tree is auditable in one language, and there is no C build to trust.',
  },
  {
    k: 'Constant-time by discipline',
    d: 'Secret-dependent branches and table lookups are treated as bugs. Field arithmetic, scalar multiplication and padding checks are written to run in time independent of the secrets they touch.',
  },
  {
    k: 'no_std, no_alloc core',
    d: 'The primitives build without the standard library and, where possible, without a heap — the same code runs on a server, a microcontroller, or (as here) in a browser sandbox.',
  },
  {
    k: 'Hardware where it counts',
    d: 'Portable by default, accelerated when the CPU offers it: AES-NI, PCLMULQDQ, SHA-NI and their ARM equivalents are used automatically, with the pure-Rust path always available as fallback.',
  },
];
</script>

<template>
  <section id="principles" class="section">
    <div class="wrap">
      <div class="split">
        <div class="lead">
          <p class="eyebrow">Why it's built this way</p>
          <h2>Correctness you can read, top to bottom.</h2>
          <p class="body">
            A cryptography library earns trust by being legible. purecrypto keeps
            the entire stack — from a field multiply to a TLS 1.3 handshake — in
            safe, dependency-free Rust, so the thing you audit is the thing that
            runs.
          </p>
          <div class="facts mono">
            <span>MIT licensed</span>
            <span>MSRV 1.88</span>
            <span>#![forbid(unsafe)] core</span>
          </div>
        </div>
        <ul class="principles">
          <li v-for="p in principles" :key="p.k">
            <h3>{{ p.k }}</h3>
            <p>{{ p.d }}</p>
          </li>
        </ul>
      </div>
    </div>
  </section>
</template>

<style scoped>
.split {
  display: grid;
  grid-template-columns: 0.85fr 1.15fr;
  gap: clamp(32px, 5vw, 72px);
  align-items: start;
}
.lead {
  position: sticky;
  top: 96px;
}
.lead h2 {
  font-size: clamp(1.8rem, 3.6vw, 2.6rem);
  margin: 14px 0 18px;
}
.body {
  color: var(--dim);
  margin: 0 0 24px;
}
.facts {
  display: flex;
  flex-direction: column;
  gap: 8px;
  font-size: 0.8rem;
  color: var(--teal-2);
}
.facts span::before {
  content: '› ';
  color: var(--violet-2);
}
.principles {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 2px;
}
.principles li {
  padding: 24px;
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
  background: var(--ink-1);
  transition: border-color 0.2s ease;
}
.principles li:hover {
  border-color: var(--line);
}
.principles h3 {
  font-size: 1.15rem;
  margin-bottom: 8px;
}
.principles p {
  color: var(--muted);
  font-size: 0.94rem;
  margin: 0;
}
@media (max-width: 860px) {
  .split {
    grid-template-columns: 1fr;
  }
  .lead {
    position: static;
  }
}
</style>
