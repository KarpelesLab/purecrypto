# purecrypto demo site

A Vue 3 + Vite single-page site that runs the **real** purecrypto library in the
browser via WebAssembly. Every demo calls the crate's C ABI (the `ffi` feature)
compiled to `wasm32-unknown-unknown`; there are no JavaScript crypto shims.

Deployed to GitHub Pages by [`.github/workflows/pages.yml`](../.github/workflows/pages.yml).

## How it works

- The crate is built as a wasm `cdylib` with the `ffi` feature. It exports the
  `pc_*` C functions plus `pc_malloc` / `pc_free` (so JS can place buffers in
  linear memory), and imports `purecrypto.random_get` for entropy.
- [`src/lib/purecrypto.js`](src/lib/purecrypto.js) is a small, dependency-free
  bridge: it wires `purecrypto.random_get` to `crypto.getRandomValues`, marshals
  bytes through the allocator, and wraps the `pc_*` calls in an ergonomic API.

## Develop locally

```sh
cd web
npm install
npm run wasm     # builds purecrypto.wasm from the crate into public/
npm run smoke    # validates the JS <-> wasm bridge (real crypto, headless)
npm run dev      # http://localhost:5173
```

`npm run build` produces the static site in `dist/`. `npm run dom-smoke` mounts
the built bundle in jsdom and asserts every live demo produces valid output.

The site's base path defaults to `/purecrypto/` (a GitHub project page). Override
with `PAGES_BASE=/ npm run build` for a user page or custom domain.
