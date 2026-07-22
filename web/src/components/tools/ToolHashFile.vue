<script setup>
import { ref, computed } from 'vue';
import { state, pc } from '../../store.js';

const dragging = ref(false);
const busy = ref(false);
const file = ref(null); // { name, size }
const progress = ref(0); // 0..1
const results = ref([]); // [{ name, hex, bits }]
const stats = ref(null); // { ms, mbps }
const error = ref('');

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

async function hashFile(f) {
  if (state.status !== 'ready' || !f) return;
  error.value = '';
  results.value = [];
  stats.value = null;
  file.value = { name: f.name, size: f.size };
  busy.value = true;
  progress.value = 0;

  // One pass: stream chunks, update every hasher from each chunk exactly once.
  const algos = pc.supportedHashes();
  const mh = pc.multiHash(algos);
  const t0 = performance.now();
  try {
    const reader = f.stream().getReader();
    let done_ = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      mh.updateChunk(value);
      done_ += value.length;
      progress.value = f.size ? done_ / f.size : 1;
    }
    results.value = mh.finish();
    const ms = performance.now() - t0;
    stats.value = { ms, mbps: ms > 0 ? f.size / 1048576 / (ms / 1000) : 0 };
    progress.value = 1;
  } catch (e) {
    error.value = String(e.message || e);
  } finally {
    busy.value = false;
  }
}

function onDrop(e) {
  dragging.value = false;
  const f = e.dataTransfer?.files?.[0];
  if (f) hashFile(f);
}
function onPick(e) {
  const f = e.target.files?.[0];
  if (f) hashFile(f);
}

const copiedRow = ref(-1);
function copy(row, i) {
  navigator.clipboard?.writeText(row.hex).then(() => {
    copiedRow.value = i;
    setTimeout(() => (copiedRow.value = -1), 1200);
  });
}
const pct = computed(() => Math.round(progress.value * 100));
</script>

<template>
  <div class="tool">
    <label
      class="drop"
      :class="{ over: dragging }"
      @dragover.prevent="dragging = true"
      @dragleave.prevent="dragging = false"
      @drop.prevent="onDrop"
    >
      <input type="file" @change="onPick" hidden />
      <div class="drop-inner">
        <span class="di">⇪</span>
        <span class="dt">Drop a file here, or click to choose</span>
        <span class="ds mono">read once · hashed under all {{ state.status === 'ready' ? pc.supportedHashes().length : 24 }} algorithms · never uploaded</span>
      </div>
    </label>

    <div v-if="file" class="filebar mono">
      <span class="fn">{{ file.name }}</span>
      <span class="fs">{{ fmtSize(file.size) }}</span>
      <span v-if="stats" class="fr">{{ stats.ms.toFixed(0) }} ms · {{ stats.mbps.toFixed(0) }} MB/s</span>
    </div>

    <div v-if="busy" class="bar">
      <div class="bar-fill" :style="{ width: pct + '%' }"></div>
      <span class="bar-lbl mono">{{ pct }}%</span>
    </div>

    <p v-if="error" class="err mono">{{ error }}</p>

    <div v-if="results.length" class="rows">
      <div v-for="(r, i) in results" :key="r.name" class="row">
        <span class="alg mono">{{ r.name }}</span>
        <code class="hex public">{{ r.hex }}</code>
        <button class="mini" @click="copy(r, i)">{{ copiedRow === i ? '✓' : 'copy' }}</button>
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
.drop {
  display: block;
  border: 1.5px dashed var(--line);
  border-radius: var(--radius);
  padding: 34px;
  text-align: center;
  cursor: pointer;
  background: var(--ink-2);
  transition:
    border-color 0.18s ease,
    background 0.18s ease;
  text-transform: none;
  letter-spacing: 0;
}
.drop.over {
  border-color: var(--violet);
  background: var(--violet-glow);
}
.drop-inner {
  display: flex;
  flex-direction: column;
  gap: 8px;
  align-items: center;
}
.di {
  font-size: 1.7rem;
  color: var(--violet-2);
}
.dt {
  font-size: 1rem;
  color: var(--paper);
}
.ds {
  font-size: 0.74rem;
  color: var(--muted);
}
.filebar {
  display: flex;
  align-items: center;
  gap: 14px;
  font-size: 0.8rem;
  padding: 10px 14px;
  background: var(--ink-2);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
}
.fn {
  color: var(--paper);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fs {
  color: var(--muted);
}
.fr {
  margin-left: auto;
  color: var(--teal-2);
}
.bar {
  position: relative;
  height: 26px;
  background: var(--ink-2);
  border: 1px solid var(--line-soft);
  border-radius: 999px;
  overflow: hidden;
}
.bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--violet), var(--teal));
  transition: width 0.1s linear;
}
.bar-lbl {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  font-size: 0.72rem;
  color: var(--paper);
}
.rows {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
  overflow: hidden;
}
.row {
  display: grid;
  grid-template-columns: 128px 1fr auto;
  gap: 12px;
  align-items: center;
  padding: 9px 13px;
  border-bottom: 1px solid var(--line-soft);
  background: var(--ink-1);
}
.row:last-child {
  border-bottom: none;
}
.row:nth-child(even) {
  background: var(--ink-2);
}
.alg {
  font-size: 0.76rem;
  color: var(--violet-2);
}
.row .hex {
  font-size: 0.72rem;
}
.mini {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  color: var(--dim);
  background: var(--ink-3);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 3px 8px;
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
@media (max-width: 620px) {
  .row {
    grid-template-columns: 92px 1fr auto;
  }
}
</style>
