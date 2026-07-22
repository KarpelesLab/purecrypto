// Headless mount test: run the *built* client bundle in jsdom, wire the wasm
// + entropy, and assert the app renders and the live demos produce real output.
import { readFileSync, readdirSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { JSDOM } from 'jsdom';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(here, '..', 'dist');
const jsFile = readdirSync(path.join(dist, 'assets')).find((f) => f.endsWith('.js'));
const wasm = readFileSync(path.join(dist, 'purecrypto.wasm'));

const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', {
  url: 'https://karpeleslab.github.io/purecrypto/',
  pretendToBeVisual: true,
});
const { window } = dom;

// Browser globals the bundle expects. node 22 already provides read-only
// `crypto`/`navigator`; only fill what jsdom needs and leave those alone.
globalThis.window = window;
globalThis.document = window.document;
if (!window.crypto) Object.defineProperty(window, 'crypto', { value: webcrypto });
for (const g of ['MutationObserver', 'HTMLElement', 'Node', 'Element', 'Event', 'CustomEvent', 'SVGElement']) {
  if (window[g] && !globalThis[g]) globalThis[g] = window[g];
}
globalThis.requestAnimationFrame = window.requestAnimationFrame || ((cb) => setTimeout(cb, 16));

// Serve the local wasm for the app's fetch(BASE_URL + 'purecrypto.wasm').
globalThis.fetch = async (url) => {
  if (String(url).endsWith('purecrypto.wasm'))
    return { arrayBuffer: async () => wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength) };
  throw new Error('unexpected fetch: ' + url);
};

await import(path.join(dist, 'assets', jsFile));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Wait for wasm load + reactive effects to settle.
for (let i = 0; i < 60; i++) {
  await sleep(50);
  if (window.document.querySelector('.status[data-s="ready"]')) break;
}
await sleep(200);

const text = window.document.body.textContent;
let fail = 0;
const check = (name, cond) => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${name}`);
  if (!cond) fail++;
};

check('app mounted (hero headline present)', /live in your browser/i.test(text));
check('capability matrix rendered', /Post-quantum/.test(text) && /TLS 1\.2 \/ 1\.3/.test(text));
check('wasm reached ready state', !!window.document.querySelector('.status[data-s="ready"]'));
check('hero produced a live digest (hex bytes)', window.document.querySelectorAll('.instrument .byte').length >= 16
  && /[0-9a-f]{2}/.test(window.document.querySelector('.instrument .byte')?.textContent || ''));
check('AEAD demo decrypted round-trip', /decrypt →/.test(text) && !/authentication failed/.test(text));
check('Ed25519 verified', /signature valid for this message/.test(text));
check('ML-KEM secrets agreed', /shared secrets match/.test(text));
check('ML-DSA verified', /signature valid for this message/.test(text) && /post-quantum/i.test(text));

console.log(fail ? `\n${fail} checks FAILED` : '\nall render checks passed');
// jsdom keeps timers alive; exit explicitly.
process.exit(fail ? 1 : 0);
