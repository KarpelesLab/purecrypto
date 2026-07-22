<script setup>
import { ref, computed, watch, onBeforeUnmount } from 'vue';
import { state, pc } from '../store.js';
import DemoCard from './ui/DemoCard.vue';

const message = ref('Signed under a post-quantum key.');
const key = ref(null);
const publicPem = ref('');
const sig = ref(null);

function generate() {
  if (state.status !== 'ready') return;
  if (key.value) key.value.free();
  key.value = pc.mldsa(pc.MLDSA.D65);
  publicPem.value = key.value.publicPem();
  sign();
}
function sign() {
  if (key.value) sig.value = key.value.sign(pc.utf8(message.value));
}
const verified = computed(() => {
  if (!sig.value || !publicPem.value) return null;
  return pc.mldsaVerify(pc.MLDSA.D65, publicPem.value, pc.utf8(message.value), sig.value);
});

watch(() => state.status, (s) => s === 'ready' && generate(), { immediate: true });
onBeforeUnmount(() => key.value && key.value.free());
</script>

<template>
  <DemoCard
    index="D.04"
    title="ML-DSA lattice signatures"
    subtitle="NIST FIPS 204 (ML-DSA-65). A quantum-resistant signature scheme — note the signature is kilobytes, not the 64 bytes of Ed25519, the trade for lattice security."
    api="purecrypto::mldsa — sign / verify"
  >
    <template #badge><span class="tag pq">post-quantum</span></template>

    <div>
      <label>Message</label>
      <textarea v-model="message" rows="2" spellcheck="false"></textarea>
    </div>

    <div class="stat-row">
      <div class="stat">
        <span class="num mono">{{ sig ? sig.length.toLocaleString() : '—' }}</span>
        <span class="lbl mono">signature bytes</span>
      </div>
      <div class="stat">
        <span class="num mono teal">{{ publicPem ? '1,952' : '—' }}</span>
        <span class="lbl mono">public key bytes</span>
      </div>
      <div class="stat">
        <span class="num mono">ML-DSA-65</span>
        <span class="lbl mono">NIST level 3</span>
      </div>
    </div>

    <div class="verify-row">
      <div class="verdict" :class="verified === false ? 'bad' : verified ? 'ok' : ''">
        <span v-if="verified === true">✓ signature valid for this message</span>
        <span v-else-if="verified === false">✗ invalid — message changed since signing</span>
        <span v-else>—</span>
      </div>
      <button class="btn small" @click="sign">re-sign</button>
      <button class="btn small ghost" @click="generate">↻ new keypair</button>
    </div>
  </DemoCard>
</template>

<style scoped>
.stat-row {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
}
.stat {
  background: var(--ink-2);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.stat .num {
  font-size: 1.5rem;
  color: var(--violet-2);
  letter-spacing: -0.01em;
}
.stat .num.teal {
  color: var(--teal-2);
}
.stat .lbl {
  font-size: 0.7rem;
  color: var(--muted);
  letter-spacing: 0.05em;
}
.verify-row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.verdict {
  flex: 1;
  min-width: 240px;
  font-family: var(--font-mono);
  font-size: 0.82rem;
  padding: 11px 14px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--line-soft);
  color: var(--muted);
}
.verdict.ok {
  color: var(--teal-2);
  background: var(--teal-glow);
  border-color: rgba(47, 224, 200, 0.3);
}
.verdict.bad {
  color: #ff9c9c;
  background: rgba(255, 90, 90, 0.1);
  border-color: rgba(255, 90, 90, 0.4);
}
.btn.small {
  padding: 8px 13px;
  font-size: 0.76rem;
}
.btn.ghost {
  background: transparent;
}
@media (max-width: 620px) {
  .stat-row {
    grid-template-columns: 1fr;
  }
}
</style>
