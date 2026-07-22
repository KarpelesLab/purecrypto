<script setup>
import { ref, reactive, watch, onBeforeUnmount } from 'vue';
import { state, pc } from '../store.js';
import DemoCard from './ui/DemoCard.vue';

const recipient = ref(null); // keeps the private (decapsulation) key
const ekDer = ref(null); // public encapsulation key, DER
const r = reactive({ ct: null, ssA: null, ssB: null, agree: false, bytes: 0 });

function newRecipient() {
  if (state.status !== 'ready') return;
  if (recipient.value) recipient.value.free();
  recipient.value = pc.mlkem(pc.MLKEM.K768);
  ekDer.value = recipient.value.publicDer();
  encapsulate();
}
function encapsulate() {
  if (!recipient.value) return;
  const { ct, ss } = pc.mlkemEncaps(pc.MLKEM.K768, ekDer.value); // sender side
  const ssB = recipient.value.decaps(ct); // recipient side
  r.ct = ct;
  r.ssA = ss;
  r.ssB = ssB;
  r.bytes = ct.length;
  r.agree = ss.length === ssB.length && ss.every((x, i) => x === ssB[i]);
}

const short = (bytes, head = 24) =>
  bytes ? pc.toHex(bytes.slice(0, head)) + ` … (${bytes.length} bytes)` : '—';

watch(() => state.status, (s) => s === 'ready' && newRecipient(), { immediate: true });
onBeforeUnmount(() => recipient.value && recipient.value.free());
</script>

<template>
  <DemoCard
    index="D.03"
    title="ML-KEM key encapsulation"
    subtitle="The NIST FIPS 203 post-quantum KEM (ML-KEM-768). A sender encapsulates to the recipient's public key; both sides derive the same 256-bit secret — without it ever crossing the wire."
    api="purecrypto::mlkem — encapsulate / decapsulate"
  >
    <template #badge><span class="tag pq">post-quantum</span></template>

    <div class="flow">
      <div class="party">
        <span class="tag public">recipient public key</span>
        <code class="hex public">{{ short(ekDer, 24) }}</code>
      </div>
      <div class="party">
        <span class="tag public">ciphertext (sender → recipient)</span>
        <code class="hex public">{{ short(r.ct, 24) }}</code>
      </div>
    </div>

    <div class="secrets">
      <div class="secret-box">
        <span class="mono who">sender derives</span>
        <code class="hex secret">{{ r.ssA ? pc.toHex(r.ssA) : '—' }}</code>
      </div>
      <div class="secret-box">
        <span class="mono who">recipient derives</span>
        <code class="hex secret">{{ r.ssB ? pc.toHex(r.ssB) : '—' }}</code>
      </div>
    </div>

    <div class="verdict" :class="{ ok: r.agree }">
      <span v-if="r.agree">✓ shared secrets match — {{ r.ssA.length * 8 }}-bit key agreed</span>
      <span v-else>—</span>
    </div>

    <div class="actions">
      <button class="btn small" @click="encapsulate">↻ encapsulate again</button>
      <button class="btn small ghost" @click="newRecipient">new recipient key</button>
    </div>
  </DemoCard>
</template>

<style scoped>
.flow,
.secrets {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.party,
.secret-box {
  background: var(--ink-2);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
  padding: 13px;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 9px;
}
.who {
  font-size: 0.72rem;
  color: var(--muted);
  letter-spacing: 0.06em;
}
.verdict {
  font-family: var(--font-mono);
  font-size: 0.84rem;
  padding: 12px 14px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--line-soft);
  color: var(--muted);
  text-align: center;
}
.verdict.ok {
  color: var(--teal-2);
  background: var(--teal-glow);
  border-color: rgba(47, 224, 200, 0.3);
}
.actions {
  display: flex;
  gap: 10px;
}
.btn.small {
  padding: 8px 13px;
  font-size: 0.76rem;
}
.btn.ghost {
  background: transparent;
}
@media (max-width: 560px) {
  .flow,
  .secrets {
    grid-template-columns: 1fr;
  }
}
</style>
