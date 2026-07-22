<script setup>
import { ref } from 'vue';
import { state } from '../store.js';
import ToolHash from './tools/ToolHash.vue';
import ToolHashFile from './tools/ToolHashFile.vue';
import ToolKeygen from './tools/ToolKeygen.vue';
import ToolCsr from './tools/ToolCsr.vue';
import ToolCert from './tools/ToolCert.vue';

const tabs = [
  { id: 'hash', label: 'Hash', desc: 'Digest any input under any algorithm.', comp: ToolHash },
  { id: 'file', label: 'Hash a file', desc: 'One read, every algorithm at once.', comp: ToolHashFile },
  { id: 'keygen', label: 'Key generator', desc: 'Generate a private key in any scheme.', comp: ToolKeygen },
  { id: 'csr', label: 'CSR', desc: 'Build a PKCS#10 certificate request.', comp: ToolCsr },
  { id: 'cert', label: 'X.509 analyzer', desc: 'Inspect any certificate in detail.', comp: ToolCert },
];
const active = ref('hash');
</script>

<template>
  <section id="tools" class="section">
    <div class="wrap">
      <div class="section-head">
        <p class="eyebrow">Utilities · nothing leaves your device</p>
        <h2>Tools you'd actually use.</h2>
        <p>
          Real crypto utilities backed by the same WebAssembly build — hash
          anything, generate keys in any scheme (classical or post-quantum), and
          issue certificate requests. All of it runs locally in your browser.
        </p>
      </div>

      <div class="tabs" role="tablist">
        <button
          v-for="t in tabs"
          :key="t.id"
          class="tab"
          :class="{ on: active === t.id }"
          role="tab"
          :aria-selected="active === t.id"
          @click="active = t.id"
        >
          <span class="tl">{{ t.label }}</span>
          <span class="td">{{ t.desc }}</span>
        </button>
      </div>

      <div class="panel toolwrap">
        <div v-if="state.status === 'error'" class="notice err">
          The WebAssembly module failed to load, so the tools are unavailable.
        </div>
        <div v-else-if="state.status !== 'ready'" class="notice">
          <span class="spinner"></span> Loading the purecrypto wasm build…
        </div>
        <component v-else :is="tabs.find((t) => t.id === active).comp" :key="active" />
      </div>
    </div>
  </section>
</template>

<style scoped>
.tabs {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 10px;
  margin-bottom: 20px;
}
.tab {
  display: flex;
  flex-direction: column;
  gap: 4px;
  text-align: left;
  padding: 14px 16px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--line-soft);
  background: var(--ink-1);
  cursor: pointer;
  transition:
    border-color 0.16s ease,
    transform 0.16s ease;
}
.tab:hover {
  transform: translateY(-2px);
}
.tab.on {
  border-color: var(--violet);
  background: var(--violet-glow);
}
.tl {
  font-family: var(--font-display);
  font-weight: 600;
  font-size: 1.02rem;
  color: var(--paper);
}
.td {
  font-size: 0.78rem;
  color: var(--muted);
}
.toolwrap {
  padding: 26px;
}
.notice {
  display: flex;
  align-items: center;
  gap: 12px;
  font-family: var(--font-mono);
  font-size: 0.85rem;
  color: var(--dim);
  padding: 30px;
  justify-content: center;
}
.notice.err {
  color: #ff9c9c;
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
@media (max-width: 760px) {
  .tabs {
    grid-template-columns: repeat(2, 1fr);
  }
}
@media (max-width: 420px) {
  .tabs {
    grid-template-columns: 1fr;
  }
  .td {
    display: none;
  }
}
</style>
