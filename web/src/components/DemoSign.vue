<script setup>
import { ref, computed, watch, onBeforeUnmount } from 'vue';
import { state, pc } from '../store.js';
import DemoCard from './ui/DemoCard.vue';

const message = ref('I authorize this transaction.');
const key = ref(null);
const publicPem = ref('');
const privatePem = ref('');
const sig = ref(null);
const showSecret = ref(false);

function generate() {
  if (state.status !== 'ready') return;
  if (key.value) key.value.free();
  key.value = pc.ed25519();
  publicPem.value = key.value.publicPem();
  privatePem.value = key.value.privatePem();
  sign();
}
function sign() {
  if (!key.value) return;
  sig.value = key.value.sign(pc.utf8(message.value));
}

// Verify the CURRENT message against the stored signature — so editing the
// message after signing visibly breaks verification until you re-sign.
const verified = computed(() => {
  if (!sig.value || !publicPem.value) return null;
  return pc.ed25519Verify(publicPem.value, pc.utf8(message.value), sig.value);
});

watch(() => state.status, (s) => s === 'ready' && generate(), { immediate: true });
onBeforeUnmount(() => key.value && key.value.free());
</script>

<template>
  <DemoCard
    index="D.02"
    title="Ed25519 digital signatures"
    subtitle="Generate a keypair, sign a message, and verify it. Edit the message after signing and the signature no longer checks out."
    api="purecrypto::ec::ed25519 — sign / verify"
  >
    <template #badge><span class="tag">EdDSA</span></template>

    <div class="pems">
      <div class="pem">
        <div class="pem-head">
          <span class="tag secret">private key</span>
          <button class="link" @click="showSecret = !showSecret">
            {{ showSecret ? 'hide' : 'reveal' }}
          </button>
        </div>
        <pre v-if="showSecret" class="hex secret">{{ privatePem.trim() }}</pre>
        <pre v-else class="hex secret redacted">{{ '••••• PKCS#8 private key hidden •••••' }}</pre>
      </div>
      <div class="pem">
        <div class="pem-head"><span class="tag public">public key</span></div>
        <pre class="hex public">{{ publicPem.trim() }}</pre>
      </div>
    </div>

    <div>
      <label>Message</label>
      <textarea v-model="message" rows="2" spellcheck="false"></textarea>
    </div>

    <div class="sig-row">
      <span class="tag">signature · 512-bit</span>
      <code class="hex">{{ sig ? pc.toHex(sig) : '—' }}</code>
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
.pems {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.pem {
  background: var(--ink-2);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
  padding: 12px;
  min-width: 0;
}
.pem-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}
pre {
  margin: 0;
  white-space: pre-wrap;
  font-size: 0.68rem;
  line-height: 1.5;
}
.redacted {
  opacity: 0.6;
}
.link {
  background: none;
  border: none;
  color: var(--dim);
  font-family: var(--font-mono);
  font-size: 0.72rem;
  cursor: pointer;
}
.link:hover {
  color: var(--paper);
}
.sig-row {
  display: flex;
  align-items: baseline;
  gap: 10px;
  flex-wrap: wrap;
}
.sig-row .tag {
  flex-shrink: 0;
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
@media (max-width: 560px) {
  .pems {
    grid-template-columns: 1fr;
  }
}
</style>
