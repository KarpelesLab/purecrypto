<script setup>
import { ref } from 'vue';
const props = defineProps({
  label: String,
  value: String,
  tone: { type: String, default: '' }, // '', 'secret', 'public'
  filename: String,
});
const copied = ref(false);
function copy() {
  navigator.clipboard?.writeText(props.value).then(() => {
    copied.value = true;
    setTimeout(() => (copied.value = false), 1400);
  });
}
function download() {
  const blob = new Blob([props.value], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = props.filename || 'output.txt';
  a.click();
  URL.revokeObjectURL(a.href);
}
</script>

<template>
  <div class="out">
    <div class="out-head">
      <span class="tag" :class="tone">{{ label }}</span>
      <div class="acts" v-if="value">
        <button class="mini" @click="copy">{{ copied ? '✓ copied' : 'copy' }}</button>
        <button v-if="filename" class="mini" @click="download">download</button>
      </div>
    </div>
    <pre class="hex" :class="tone">{{ value || '—' }}</pre>
  </div>
</template>

<style scoped>
.out {
  background: var(--ink-2);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
  padding: 12px;
}
.out-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}
.acts {
  display: flex;
  gap: 6px;
}
.mini {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  color: var(--dim);
  background: var(--ink-3);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 4px 9px;
  cursor: pointer;
}
.mini:hover {
  color: var(--paper);
  border-color: var(--teal);
}
pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 0.72rem;
  line-height: 1.55;
  max-height: 320px;
  overflow: auto;
}
</style>
