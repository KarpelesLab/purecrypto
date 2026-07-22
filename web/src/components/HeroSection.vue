<script setup>
import { ref, computed, watch } from 'vue';
import { state, pc } from '../store.js';
import CopyChip from './ui/CopyChip.vue';

const input = ref('The quick brown fox jumps over the lazy dog');
const algo = ref('SHA256');
const algos = [
  ['SHA256', 'SHA-256'],
  ['SHA3_256', 'SHA3-256'],
  ['SHA512', 'SHA-512'],
  ['BLAKE3', 'BLAKE3'],
  ['KECCAK256', 'Keccak-256'],
];

const digestHex = ref('');
const elapsed = ref(0);

function recompute() {
  if (state.status !== 'ready') return;
  const t = performance.now();
  const out = pc.digest(pc.HASH[algo.value], pc.utf8(input.value));
  elapsed.value = performance.now() - t;
  digestHex.value = pc.toHex(out);
}

watch([input, algo, () => state.status], recompute, { immediate: true });

// group the hex into readable byte-pair columns
const grouped = computed(() =>
  (digestHex.value.match(/.{1,2}/g) || []).map((b, i) => ({ b, i })),
);
</script>

<template>
  <section id="top" class="hero">
    <div class="wrap hero-grid">
      <div class="hero-copy">
        <p class="eyebrow">Pure-Rust cryptography · running in this tab</p>
        <h1>
          Watch a crypto library<br />
          work — <span class="grad">live in your browser.</span>
        </h1>
        <p class="lede">
          purecrypto is a from-scratch, constant-time toolkit with
          <strong>no OpenSSL, no C, no foreign-code dependencies</strong>. Every
          byte on this page is computed by the real library, compiled to
          WebAssembly and running on your machine — nothing is sent anywhere.
        </p>
        <div class="cta-row">
          <a href="#demos" class="btn btn-primary">Run the demos ↓</a>
          <CopyChip text="cargo add purecrypto" />
          <a
            class="btn"
            href="https://github.com/KarpelesLab/purecrypto"
            target="_blank"
            rel="noopener"
            >GitHub ↗</a
          >
        </div>
      </div>

      <!-- Live instrument: the hero's proof-of-work -->
      <div class="instrument panel">
        <div class="inst-head">
          <span class="tag public">live · wasm</span>
          <select v-model="algo" aria-label="Hash algorithm">
            <option v-for="[k, label] in algos" :key="k" :value="k">{{ label }}</option>
          </select>
        </div>
        <label for="hero-in">Input</label>
        <textarea id="hero-in" v-model="input" rows="2" spellcheck="false"></textarea>

        <div class="readout">
          <div class="readout-head">
            <span class="mono">digest</span>
            <span class="mono meta" v-if="state.status === 'ready'">
              {{ (digestHex.length * 4) }} bits · {{ elapsed.toFixed(3) }} ms
            </span>
            <span class="mono meta" v-else>warming up…</span>
          </div>
          <div class="bytes" v-if="digestHex">
            <span v-for="g in grouped" :key="g.i" class="byte">{{ g.b }}</span>
          </div>
          <div class="bytes skeleton" v-else>
            <span v-for="n in 32" :key="n" class="byte">··</span>
          </div>
        </div>
        <p class="inst-foot mono">
          purecrypto::hash → {{ algo.replace('_', '-') }}
        </p>
      </div>
    </div>
  </section>
</template>

<style scoped>
.hero {
  padding: clamp(56px, 9vw, 116px) 0 clamp(48px, 7vw, 92px);
}
.hero-grid {
  display: grid;
  grid-template-columns: 1.05fr 0.95fr;
  gap: clamp(32px, 5vw, 68px);
  align-items: center;
}
.hero-copy h1 {
  font-size: clamp(2.3rem, 5.4vw, 4rem);
  margin: 20px 0 22px;
}
.grad {
  background: linear-gradient(100deg, var(--violet-2), var(--teal-2));
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
.lede {
  font-size: 1.1rem;
  color: var(--dim);
  max-width: 34em;
  margin: 0 0 32px;
}
.lede strong {
  color: var(--paper);
  font-weight: 600;
}
.cta-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
}

.instrument {
  padding: 20px;
  box-shadow: 0 40px 80px -50px rgba(0, 0, 0, 0.9);
}
.inst-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.inst-head select {
  width: auto;
  padding: 7px 10px;
  font-size: 0.78rem;
}
.readout {
  margin-top: 16px;
  background: var(--ink);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
  padding: 14px;
}
.readout-head {
  display: flex;
  justify-content: space-between;
  font-size: 0.72rem;
  color: var(--muted);
  margin-bottom: 12px;
}
.meta {
  color: var(--teal);
}
.bytes {
  display: grid;
  grid-template-columns: repeat(8, 1fr);
  gap: 6px;
}
.byte {
  font-family: var(--font-mono);
  font-size: 0.78rem;
  text-align: center;
  padding: 5px 0;
  border-radius: 5px;
  background: var(--ink-2);
  color: var(--teal-2);
  transition: background 0.2s ease;
}
.skeleton .byte {
  color: var(--muted);
  opacity: 0.4;
}
.inst-foot {
  margin: 14px 0 0;
  font-size: 0.72rem;
  color: var(--muted);
}

@media (max-width: 900px) {
  .hero-grid {
    grid-template-columns: 1fr;
  }
  .bytes {
    grid-template-columns: repeat(8, 1fr);
  }
}
@media (max-width: 460px) {
  .bytes {
    grid-template-columns: repeat(6, 1fr);
  }
}
</style>
