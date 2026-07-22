<script setup>
import { ref, computed, watch } from 'vue';
import { state, pc } from '../../store.js';

const algos = computed(() => (state.status === 'ready' ? pc.supportedHashes() : []));
const alg = ref(2); // SHA-256
const encoding = ref('utf8');
const input = ref('The quick brown fox jumps over the lazy dog');
const upper = ref(false);
const error = ref('');

function parse() {
  const s = input.value;
  if (encoding.value === 'utf8') return pc.utf8(s);
  if (encoding.value === 'hex') {
    const clean = s.replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2) throw new Error('hex input has an odd number of digits');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }
  // base64
  const bin = atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const result = ref({ hex: '', bits: 0, len: 0 });
function recompute() {
  if (state.status !== 'ready') return;
  error.value = '';
  try {
    const data = parse();
    const out = pc.digest(alg.value, data);
    result.value = { hex: pc.toHex(out), bits: out.length * 8, len: out.length };
  } catch (e) {
    error.value = String(e.message || e);
    result.value = { hex: '', bits: 0, len: 0 };
  }
}
const shown = computed(() => (upper.value ? result.value.hex.toUpperCase() : result.value.hex));
watch([alg, encoding, input, () => state.status], recompute, { immediate: true });

const copied = ref(false);
function copy() {
  navigator.clipboard?.writeText(shown.value).then(() => {
    copied.value = true;
    setTimeout(() => (copied.value = false), 1200);
  });
}
</script>

<template>
  <div class="tool">
    <div class="controls">
      <div class="ctl">
        <label>Algorithm</label>
        <select v-model.number="alg">
          <option v-for="h in algos" :key="h.id" :value="h.id">{{ h.name }}</option>
        </select>
      </div>
      <div class="ctl">
        <label>Input as</label>
        <select v-model="encoding">
          <option value="utf8">UTF-8 text</option>
          <option value="hex">Hex</option>
          <option value="base64">Base64</option>
        </select>
      </div>
    </div>

    <div>
      <label>Input</label>
      <textarea v-model="input" rows="4" spellcheck="false"></textarea>
    </div>

    <div class="result">
      <div class="result-head">
        <span class="tag public">digest</span>
        <div class="meta mono">
          <label class="chk"><input type="checkbox" v-model="upper" /> uppercase</label>
          <span v-if="result.len">{{ result.bits }}-bit · {{ result.len }} bytes</span>
          <button class="mini" v-if="shown" @click="copy">{{ copied ? '✓' : 'copy' }}</button>
        </div>
      </div>
      <p v-if="error" class="err mono">{{ error }}</p>
      <code v-else class="hex public digest">{{ shown || '—' }}</code>
    </div>
  </div>
</template>

<style scoped>
.tool {
  display: flex;
  flex-direction: column;
  gap: 18px;
}
.controls {
  display: flex;
  gap: 14px;
}
.ctl {
  flex: 1;
}
.result {
  background: var(--ink);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
  padding: 15px;
}
.result-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.meta {
  display: flex;
  align-items: center;
  gap: 14px;
  font-size: 0.74rem;
  color: var(--muted);
}
.chk {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin: 0;
  text-transform: none;
  letter-spacing: 0;
  cursor: pointer;
}
.chk input {
  accent-color: var(--violet);
}
.digest {
  font-size: 0.92rem;
  line-height: 1.7;
}
.mini {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  color: var(--dim);
  background: var(--ink-3);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 3px 9px;
  cursor: pointer;
}
.mini:hover {
  color: var(--teal-2);
  border-color: var(--teal);
}
.err {
  color: #ff9c9c;
  font-size: 0.82rem;
  margin: 0;
}
@media (max-width: 520px) {
  .controls {
    flex-direction: column;
  }
}
</style>
