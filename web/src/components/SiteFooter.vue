<script setup>
import CopyChip from './ui/CopyChip.vue';
</script>

<template>
  <footer class="footer">
    <div class="wrap">
      <div class="cta panel">
        <div>
          <h2>Add it to your Cargo.toml.</h2>
          <p>Pull in only the modules you need — features gate every layer.</p>
        </div>
        <div class="cta-actions">
          <CopyChip text="cargo add purecrypto" />
          <a
            class="btn btn-primary"
            href="https://github.com/KarpelesLab/purecrypto"
            target="_blank"
            rel="noopener"
            >View on GitHub ↗</a
          >
        </div>
      </div>

      <div class="foot-bottom">
        <div class="brand">
          <span class="mark" aria-hidden="true"></span>
          <span class="mono">purecrypto</span>
        </div>
        <nav class="foot-links">
          <a href="https://github.com/KarpelesLab/purecrypto" target="_blank" rel="noopener">Source</a>
          <a href="https://docs.rs/purecrypto" target="_blank" rel="noopener">docs.rs</a>
          <a href="https://crates.io/crates/purecrypto" target="_blank" rel="noopener">crates.io</a>
        </nav>
        <p class="fine mono">
          Pure-Rust cryptography · MIT · demos computed locally via WebAssembly
        </p>
      </div>
    </div>
  </footer>
</template>

<style scoped>
.footer {
  border-top: 1px solid var(--line-soft);
  padding: clamp(48px, 7vw, 88px) 0 40px;
}
.cta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  flex-wrap: wrap;
  padding: 36px;
  background:
    radial-gradient(600px 300px at 90% 0%, var(--violet-glow), transparent 70%),
    var(--ink-1);
}
.cta h2 {
  font-size: clamp(1.5rem, 3vw, 2.1rem);
  margin-bottom: 8px;
}
.cta p {
  color: var(--muted);
  margin: 0;
}
.cta-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  align-items: center;
}
.foot-bottom {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  flex-wrap: wrap;
  margin-top: 40px;
  padding-top: 26px;
  border-top: 1px solid var(--line-soft);
}
.brand {
  display: flex;
  align-items: center;
  gap: 9px;
}
.mark {
  width: 16px;
  height: 16px;
  border-radius: 5px;
  background: linear-gradient(135deg, var(--violet), var(--teal));
}
.foot-links {
  display: flex;
  gap: 22px;
  font-size: 0.88rem;
  color: var(--dim);
}
.foot-links a:hover {
  color: var(--paper);
}
.fine {
  font-size: 0.74rem;
  color: var(--muted);
  margin: 0;
}
@media (max-width: 640px) {
  .cta {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
