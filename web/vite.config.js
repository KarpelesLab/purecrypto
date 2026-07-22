import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// GitHub Pages serves a project site under /<repo>/. Override with PAGES_BASE
// (e.g. "/" for a user/org page or custom domain).
const base = process.env.PAGES_BASE || '/purecrypto/';

export default defineConfig({
  base,
  plugins: [vue()],
  build: {
    target: 'es2022',
    // The .wasm lives in public/ and is fetched at runtime, not bundled.
    assetsInlineLimit: 0,
  },
});
