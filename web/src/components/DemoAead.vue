<script setup>
import { ref, reactive, computed, watch } from 'vue';
import { state, pc } from '../store.js';
import DemoCard from './ui/DemoCard.vue';

const algos = [
  ['AES256_GCM', 'AES-256-GCM'],
  ['CHACHA20_POLY1305', 'ChaCha20-Poly1305'],
];
const algo = ref('AES256_GCM');
const message = ref('attack at dawn');
const aad = ref('v1');

const key = ref(new Uint8Array(32));
const nonce = ref(new Uint8Array(12));
function reseed() {
  crypto.getRandomValues(key.value);
  crypto.getRandomValues(nonce.value);
  key.value = key.value.slice();
  nonce.value = nonce.value.slice();
}
reseed();

const out = reactive({ ct: '', tag: '', plain: '', ok: false, err: '' });

function run(tamper = false) {
  if (state.status !== 'ready') return;
  out.err = '';
  try {
    const ctTag = pc.aeadEncrypt(
      pc.AEAD[algo.value],
      key.value,
      nonce.value,
      pc.utf8(aad.value),
      pc.utf8(message.value),
    );
    const body = ctTag.slice(0, ctTag.length - 16);
    const tag = ctTag.slice(ctTag.length - 16);
    out.ct = pc.toHex(body);
    out.tag = pc.toHex(tag);

    const probe = ctTag.slice();
    if (tamper) probe[0] ^= 0x01;
    try {
      const back = pc.aeadDecrypt(pc.AEAD[algo.value], key.value, nonce.value, pc.utf8(aad.value), probe);
      out.plain = pc.fromUtf8(back);
      out.ok = true;
    } catch {
      out.plain = '⛔ authentication failed — ciphertext rejected';
      out.ok = false;
    }
  } catch (e) {
    out.err = String(e);
  }
}

watch([algo, message, aad, key, nonce, () => state.status], () => run(false), { immediate: true });
</script>

<template>
  <DemoCard
    index="D.01"
    title="Authenticated encryption"
    subtitle="Encrypt-then-authenticate with AES-GCM or ChaCha20-Poly1305. Change one bit of the ciphertext and the tag check refuses it."
    api="purecrypto::cipher::aead — seal / open"
  >
    <template #badge><span class="tag public">AEAD</span></template>

    <div class="row">
      <div class="col">
        <label>Cipher</label>
        <select v-model="algo">
          <option v-for="[k, l] in algos" :key="k" :value="k">{{ l }}</option>
        </select>
      </div>
      <div class="col grow">
        <label>Associated data (authenticated, not encrypted)</label>
        <input type="text" v-model="aad" spellcheck="false" />
      </div>
    </div>

    <div>
      <label>Plaintext</label>
      <textarea v-model="message" rows="2" spellcheck="false"></textarea>
    </div>

    <div class="keys">
      <div>
        <span class="tag secret">key · 256-bit</span>
        <code class="hex secret">{{ pc.toHex(key) }}</code>
      </div>
      <div>
        <span class="tag">nonce · 96-bit</span>
        <code class="hex">{{ pc.toHex(nonce) }}</code>
      </div>
      <button class="btn small" @click="reseed">↻ new key & nonce</button>
    </div>

    <div class="out">
      <div class="out-line">
        <span class="tag public">ciphertext</span>
        <code class="hex public">{{ out.ct || '—' }}</code>
      </div>
      <div class="out-line">
        <span class="tag public">tag · 128-bit</span>
        <code class="hex public">{{ out.tag || '—' }}</code>
      </div>
    </div>

    <div class="verify">
      <div class="decrypted" :class="{ bad: !out.ok }">
        <span class="mono lbl">decrypt →</span>
        <span class="mono val">{{ out.plain }}</span>
      </div>
      <button class="btn small ghost" @click="run(true)">flip a ciphertext bit ✗</button>
    </div>
    <p v-if="out.err" class="err mono">{{ out.err }}</p>
  </DemoCard>
</template>

<style scoped>
.row {
  display: flex;
  gap: 14px;
}
.col {
  min-width: 0;
}
.col.grow {
  flex: 1;
}
.keys {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 14px;
  background: var(--ink-2);
  border-radius: var(--radius-sm);
  border: 1px solid var(--line-soft);
}
.keys > div {
  display: flex;
  align-items: baseline;
  gap: 10px;
  flex-wrap: wrap;
}
.keys .tag {
  flex-shrink: 0;
}
.out {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.out-line {
  display: flex;
  align-items: baseline;
  gap: 10px;
  flex-wrap: wrap;
}
.out-line .tag {
  flex-shrink: 0;
}
.verify {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  flex-wrap: wrap;
}
.decrypted {
  display: flex;
  align-items: baseline;
  gap: 10px;
  padding: 11px 14px;
  border-radius: var(--radius-sm);
  background: var(--teal-glow);
  border: 1px solid rgba(47, 224, 200, 0.3);
  flex: 1;
  min-width: 220px;
}
.decrypted.bad {
  background: rgba(255, 90, 90, 0.1);
  border-color: rgba(255, 90, 90, 0.4);
}
.decrypted .lbl {
  color: var(--muted);
  font-size: 0.76rem;
}
.decrypted .val {
  font-size: 0.86rem;
  color: var(--teal-2);
}
.decrypted.bad .val {
  color: #ff9c9c;
}
.btn.small {
  padding: 8px 13px;
  font-size: 0.76rem;
}
.btn.ghost {
  background: transparent;
}
.err {
  color: #ff9c9c;
  font-size: 0.78rem;
  margin: 0;
}
@media (max-width: 560px) {
  .row {
    flex-direction: column;
  }
}
</style>
