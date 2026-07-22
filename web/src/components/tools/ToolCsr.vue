<script setup>
import { ref, computed, nextTick } from 'vue';
import { state, pc } from '../../store.js';
import OutputBlock from '../ui/OutputBlock.vue';

const source = ref('generate'); // generate | provide
const cn = ref('example.com');
const sansRaw = ref('example.com, www.example.com');

// generate mode
const GEN = [
  { kind: 'ed25519', csr: 'ed25519', name: 'Ed25519', params: null },
  { kind: 'ecdsa', csr: 'ec', name: 'ECDSA', params: [[1, 'P-256'], [2, 'P-384'], [3, 'P-521']] },
  { kind: 'rsa', csr: 'rsa', name: 'RSA', params: [[2048, '2048-bit'], [3072, '3072-bit'], [4096, '4096-bit']], slow: true },
];
const genKind = ref('ed25519');
const genParam = ref(0);
const genCur = computed(() => GEN.find((g) => g.kind === genKind.value));
function pickGen(g) {
  genKind.value = g.kind;
  genParam.value = g.params ? g.params[0][0] : 0;
}

// provide mode
const provType = ref('ec'); // ec | ed25519 | rsa
const provPem = ref('');

const busy = ref(false);
const error = ref('');
const out = ref(null); // { csr, priv? }

const sans = () =>
  sansRaw.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);

async function build() {
  if (state.status !== 'ready') return;
  error.value = '';
  if (!cn.value.trim()) {
    error.value = 'Enter a subject common name (CN).';
    return;
  }
  busy.value = true;
  await nextTick();
  await new Promise((r) => setTimeout(r, 20));
  let key = null;
  try {
    let csrType, handle, priv;
    if (source.value === 'generate') {
      const k = pc.generateKey(genKind.value, genParam.value);
      key = k;
      csrType = genCur.value.csr;
      handle = k.handle;
      priv = k.privatePem();
    } else {
      if (!/-----BEGIN/.test(provPem.value)) {
        error.value = 'Paste a PEM private key (-----BEGIN … PRIVATE KEY-----).';
        busy.value = false;
        return;
      }
      key = pc.loadPrivatePem(provType.value, provPem.value.trim());
      csrType = provType.value;
      handle = key.handle;
    }
    const csr = pc.csrPem(csrType, handle, cn.value.trim(), sans());
    out.value = { csr, priv };
  } catch (e) {
    error.value = String(e.message || e);
    out.value = null;
  } finally {
    if (key) key.free();
    busy.value = false;
  }
}
</script>

<template>
  <div class="tool">
    <div class="grid">
      <div>
        <label>Common name (CN)</label>
        <input type="text" v-model="cn" spellcheck="false" placeholder="example.com" />
      </div>
      <div>
        <label>Subject alternative names (DNS)</label>
        <input type="text" v-model="sansRaw" spellcheck="false" placeholder="example.com, www.example.com" />
      </div>
    </div>

    <div class="seg">
      <button :class="{ on: source === 'generate' }" @click="source = 'generate'">Generate a new key</button>
      <button :class="{ on: source === 'provide' }" @click="source = 'provide'">Use my own key</button>
    </div>

    <div v-if="source === 'generate'" class="keybox">
      <div class="algos">
        <button
          v-for="g in GEN"
          :key="g.kind"
          class="algo"
          :class="{ active: genKind === g.kind }"
          @click="pickGen(g)"
        >
          {{ g.name }}
        </button>
      </div>
      <div v-if="genCur.params" class="ctl">
        <label>Parameters</label>
        <select v-model.number="genParam">
          <option v-for="p in genCur.params" :key="p[0]" :value="p[0]">{{ p[1] }}</option>
        </select>
      </div>
      <p v-if="genCur.slow" class="note mono">RSA keygen runs on the main thread and can take a few seconds.</p>
    </div>

    <div v-else class="keybox">
      <div class="ctl">
        <label>Key type</label>
        <select v-model="provType">
          <option value="ec">ECDSA (SEC1 / PKCS#8)</option>
          <option value="ed25519">Ed25519 (PKCS#8)</option>
          <option value="rsa">RSA (PKCS#8 / PKCS#1)</option>
        </select>
      </div>
      <label>Private key PEM</label>
      <textarea v-model="provPem" rows="5" spellcheck="false" placeholder="-----BEGIN PRIVATE KEY-----&#10;…&#10;-----END PRIVATE KEY-----"></textarea>
    </div>

    <button class="btn btn-primary build" :disabled="busy" @click="build">
      <span v-if="busy" class="spinner"></span>
      {{ busy ? 'Building…' : 'Create CSR' }}
    </button>

    <p v-if="error" class="err mono">{{ error }}</p>

    <div v-if="out" class="results">
      <OutputBlock label="certificate signing request" tone="public" :value="out.csr" filename="request.csr" />
      <div v-if="out.priv">
        <OutputBlock label="private key — save this, it is not recoverable" tone="secret" :value="out.priv" filename="private.pem" />
      </div>
    </div>
  </div>
</template>

<style scoped>
.tool {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.seg {
  display: inline-flex;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  overflow: hidden;
  width: fit-content;
}
.seg button {
  font-family: var(--font-mono);
  font-size: 0.8rem;
  padding: 9px 16px;
  background: var(--ink-2);
  color: var(--dim);
  border: none;
  cursor: pointer;
}
.seg button.on {
  background: var(--violet-glow);
  color: var(--paper);
}
.keybox {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 16px;
  background: var(--ink-2);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
}
.algos {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.algo {
  font-family: var(--font-mono);
  font-size: 0.8rem;
  padding: 8px 14px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--line);
  background: var(--ink-3);
  color: var(--dim);
  cursor: pointer;
}
.algo.active {
  color: var(--paper);
  border-color: var(--violet);
  background: var(--violet-glow);
}
.ctl {
  max-width: 260px;
}
.build {
  align-self: flex-start;
  min-height: 44px;
}
.build:disabled {
  opacity: 0.7;
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
  font-size: 0.74rem;
  color: var(--amber);
  margin: 0;
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
@media (max-width: 560px) {
  .grid {
    grid-template-columns: 1fr;
  }
}
</style>
