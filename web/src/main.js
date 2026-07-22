import { createApp } from 'vue';
import './styles/base.css';
import App from './App.vue';
import { initCrypto } from './store.js';

// Kick off wasm loading immediately; the UI reflects progress.
initCrypto();

createApp(App).mount('#app');
