<script setup>
import { state } from '../store.js';
</script>

<template>
  <header class="nav">
    <div class="wrap nav-inner">
      <a href="#top" class="brand">
        <span class="mark" aria-hidden="true"></span>
        <span class="brand-name mono">purecrypto</span>
      </a>
      <nav class="links">
        <a href="#capabilities">Capabilities</a>
        <a href="#demos">Live demos</a>
        <a href="#tools">Tools</a>
        <a href="#principles">Principles</a>
      </nav>
      <div class="nav-right">
        <span class="status" :data-s="state.status">
          <span class="dot"></span>
          {{ state.status === 'ready' ? 'wasm ready' : state.status === 'error' ? 'wasm failed' : 'loading wasm' }}
        </span>
        <a class="gh" href="https://github.com/KarpelesLab/purecrypto" target="_blank" rel="noopener">GitHub ↗</a>
      </div>
    </div>
  </header>
</template>

<style scoped>
.nav {
  position: sticky;
  top: 0;
  z-index: 50;
  backdrop-filter: blur(14px);
  background: rgba(9, 11, 19, 0.72);
  border-bottom: 1px solid var(--line-soft);
}
.nav-inner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 62px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
}
.mark {
  width: 18px;
  height: 18px;
  border-radius: 5px;
  background: linear-gradient(135deg, var(--violet), var(--teal));
  box-shadow: 0 0 18px -4px var(--violet);
}
.brand-name {
  font-weight: 600;
  letter-spacing: -0.01em;
}
.links {
  display: flex;
  gap: 26px;
  font-size: 0.9rem;
  color: var(--dim);
}
.links a:hover {
  color: var(--paper);
}
.nav-right {
  display: flex;
  align-items: center;
  gap: 18px;
}
.status {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--muted);
}
.dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--muted);
  transition: background 0.3s ease;
}
.status[data-s='ready'] .dot {
  background: var(--teal);
  box-shadow: 0 0 10px var(--teal);
}
.status[data-s='loading'] .dot {
  background: var(--amber);
  animation: pulse 1.1s ease-in-out infinite;
}
.status[data-s='error'] .dot {
  background: #ff6b6b;
}
@keyframes pulse {
  50% {
    opacity: 0.25;
  }
}
.gh {
  font-family: var(--font-mono);
  font-size: 0.82rem;
  color: var(--dim);
}
.gh:hover {
  color: var(--paper);
}
@media (max-width: 720px) {
  .links {
    display: none;
  }
  .status {
    display: none;
  }
}
</style>
