<script setup>
import { state } from '../store.js';
import DemoAead from './DemoAead.vue';
import DemoSign from './DemoSign.vue';
import DemoKem from './DemoKem.vue';
import DemoDsa from './DemoDsa.vue';
</script>

<template>
  <section id="demos" class="section">
    <div class="wrap">
      <div class="section-head">
        <p class="eyebrow">Live · computed in your browser</p>
        <h2>Real primitives, real inputs.</h2>
        <p>
          Each panel calls the purecrypto WebAssembly build directly. Type,
          re-key, tamper — the results update instantly and never leave your
          device. <span class="semantic"><b class="v">Violet</b> marks secret
          material; <b class="t">teal</b> marks public or verified values.</span>
        </p>
      </div>

      <div v-if="state.status === 'error'" class="banner err">
        Couldn't load the WebAssembly module: {{ state.error }}
      </div>
      <div v-else-if="state.status !== 'ready'" class="banner">
        <span class="spinner"></span> Loading the purecrypto wasm build…
      </div>

      <div class="demo-grid">
        <DemoAead />
        <DemoSign />
        <DemoKem />
        <DemoDsa />
      </div>
    </div>
  </section>
</template>

<style scoped>
.semantic {
  display: block;
  margin-top: 8px;
  font-size: 0.95rem;
}
.semantic .v {
  color: var(--violet-2);
}
.semantic .t {
  color: var(--teal-2);
}
.banner {
  display: flex;
  align-items: center;
  gap: 12px;
  font-family: var(--font-mono);
  font-size: 0.84rem;
  color: var(--dim);
  padding: 14px 18px;
  margin-bottom: 22px;
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
  background: var(--ink-1);
}
.banner.err {
  color: #ff9c9c;
  border-color: rgba(255, 90, 90, 0.4);
}
.spinner {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  border: 2px solid var(--line);
  border-top-color: var(--violet);
  animation: spin 0.8s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.demo-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 18px;
}
@media (max-width: 940px) {
  .demo-grid {
    grid-template-columns: 1fr;
  }
}
</style>
