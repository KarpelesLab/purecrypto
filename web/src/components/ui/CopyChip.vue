<script setup>
import { ref } from 'vue';
const props = defineProps({ text: String, prefix: { type: String, default: '$' } });
const copied = ref(false);
function copy() {
  navigator.clipboard?.writeText(props.text).then(() => {
    copied.value = true;
    setTimeout(() => (copied.value = false), 1400);
  });
}
</script>

<template>
  <button class="chip" @click="copy" :title="`Copy: ${text}`">
    <span class="pfx" v-if="prefix">{{ prefix }}</span>
    <span class="txt">{{ text }}</span>
    <span class="ind">{{ copied ? '✓ copied' : '⧉' }}</span>
  </button>
</template>

<style scoped>
.chip {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  font-family: var(--font-mono);
  font-size: 0.84rem;
  padding: 11px 15px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--line);
  background: var(--ink-2);
  color: var(--paper);
  cursor: pointer;
  transition:
    border-color 0.16s ease,
    transform 0.16s ease;
}
.chip:hover {
  border-color: var(--teal);
  transform: translateY(-1px);
}
.pfx {
  color: var(--muted);
}
.ind {
  color: var(--teal);
  font-size: 0.76rem;
}
</style>
