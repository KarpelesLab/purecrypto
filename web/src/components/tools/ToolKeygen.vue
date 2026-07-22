<script setup>
import { ref, computed, nextTick } from 'vue';
import { state, pc } from '../../store.js';
import OutputBlock from '../ui/OutputBlock.vue';

const ALGOS = [
  { kind: 'ed25519', name: 'Ed25519', params: null },
  { kind: 'ecdsa', name: 'ECDSA', params: [[1, 'P-256'], [2, 'P-384'], [3, 'P-521'], [4, 'secp256k1']] },
  { kind: 'ed448', name: 'Ed448', params: null },
  { kind: 'rsa', name: 'RSA', params: [[2048, '2048-bit'], [3072, '3072-bit'], [4096, '4096-bit']], slow: true },
  { kind: 'mldsa', name: 'ML-DSA', params: [[1, 'ML-DSA-44'], [2, 'ML-DSA-65'], [3, 'ML-DSA-87']], pq: true },
  { kind: 'slhdsa', name: 'SLH-DSA', params: [[2, 'SHA2-128f'], [4, 'SHA2-192f'], [6, 'SHA2-256f'], [8, 'SHAKE-128f']], pq: true },
  { kind: 'sm2', name: 'SM2', params: null },
];

const kind = ref('ed25519');
const param = ref(0);
const busy = ref(false);
const out = ref(null); // { priv, pub, label }
const error = ref('');

const current = computed(() => ALGOS.find((a) => a.kind === kind.value));
function pickAlgo(a) {
  kind.value = a.kind;
  param.value = a.params ? a.params[0][0] : 0;
}
const label = computed(() => {
  const a = current.value;
  if (!a.params) return a.name;
  return a.params.find((p) => p[0] === param.value)?.[1] || a.name;
});

async function generate() {
  if (state.status !== 'ready') return;
  error.value = '';
  busy.value = true;
  // Let the spinner paint before a potentially slow (RSA) blocking keygen.
  await nextTick();
  await new Promise((r) => setTimeout(r, 20));
  try {
    const k = pc.generateKey(kind.value, param.value);
    out.value = { priv: k.privatePem(), pub: k.publicPem(), label: label.value };
    k.free();
  } catch (e) {
    error.value = String(e.message || e);
    out.value = null;
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="tool">
    <div class="algos">
      <button
        v-for="a in ALGOS"
        :key="a.kind"
        class="algo"
        :class="{ active: kind === a.kind }"
        @click="pickAlgo(a)"
      >
        {{ a.name }}
        <span v-if="a.pq" class="pqdot" title="post-quantum"></span>
      </button>
    </div>

    <div class="run">
      <div v-if="current.params" class="ctl">
        <label>Parameters</label>
        <select v-model.number="param">
          <option v-for="p in current.params" :key="p[0]" :value="p[0]">{{ p[1] }}</option>
        </select>
      </div>
      <button class="btn btn-primary gen" :disabled="busy" @click="generate">
        <span v-if="busy" class="spinner"></span>
        {{ busy ? 'Generating…' : 'Generate keypair' }}
      </button>
    </div>

    <p v-if="current.slow" class="note mono">
      RSA key generation runs in wasm on the main thread — it can take several
      seconds and will briefly freeze this tab. Ed25519 and ECDSA are instant.
    </p>
    <p v-if="error" class="err mono">{{ error }}</p>

    <div v-if="out" class="results">
      <OutputBlock label="private key" tone="secret" :value="out.priv" :filename="`${out.label}-private.pem`" />
      <OutputBlock label="public key" tone="public" :value="out.pub" :filename="`${out.label}-public.pem`" />
    </div>
  </div>
</template>

<style scoped>
.tool {
  display: flex;
  flex-direction: column;
  gap: 18px;
}
.algos {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.algo {
  position: relative;
  font-family: var(--font-mono);
  font-size: 0.82rem;
  padding: 9px 15px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--line);
  background: var(--ink-2);
  color: var(--dim);
  cursor: pointer;
  transition:
    border-color 0.16s ease,
    color 0.16s ease;
}
.algo:hover {
  color: var(--paper);
}
.algo.active {
  color: var(--paper);
  border-color: var(--violet);
  background: var(--violet-glow);
}
.pqdot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--amber);
  margin-left: 6px;
  vertical-align: middle;
}
.run {
  display: flex;
  gap: 14px;
  align-items: flex-end;
  flex-wrap: wrap;
}
.ctl {
  min-width: 180px;
}
.gen {
  min-height: 44px;
}
.gen:disabled {
  opacity: 0.7;
  cursor: default;
}
.spinner {
  width: 13px;
  height: 13px;
  border-radius: 50%;
  border: 2px solid rgba(255, 255, 255, 0.4);
  border-top-color: #fff;
  animation: spin 0.7s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.note {
  font-size: 0.76rem;
  color: var(--amber);
  margin: 0;
  padding: 10px 13px;
  border: 1px solid rgba(255, 180, 84, 0.25);
  border-radius: var(--radius-sm);
  background: rgba(255, 180, 84, 0.07);
}
.err {
  color: #ff9c9c;
  font-size: 0.82rem;
  margin: 0;
}
.results {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
</style>
