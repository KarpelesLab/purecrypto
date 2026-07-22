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

const doc = window.document;
const $ = (s) => doc.querySelector(s);
const cardBy = (id) => [...doc.querySelectorAll('.demo')].find((c) => c.textContent.includes(id));

check('app mounted (hero headline present)', /live in your browser/i.test(text));
check('capability matrix rendered', /Post-quantum/.test(text) && /TLS 1\.2 \/ 1\.3/.test(text));
check('wasm reached ready state', !!$('.status[data-s="ready"]'));
check('hero produced a live digest (hex bytes)', doc.querySelectorAll('.instrument .byte').length >= 16
  && /[0-9a-f]{2}/.test($('.instrument .byte')?.textContent || ''));
check('AEAD demo decrypted round-trip', /decrypt →/.test(text) && !/authentication failed/.test(text));
check('Ed25519 verified', !!cardBy('D.02') && /signature valid/.test(cardBy('D.02').textContent));
check('ML-KEM secrets agreed', /shared secrets match/.test(text));

// ML-DSA card: verified + a signature preview that actually changes on re-sign.
const dsa = cardBy('D.04');
check('ML-DSA verified', !!dsa && /signature valid/.test(dsa.textContent));
const sigBefore = dsa?.querySelector('.live-row:nth-child(2) .hex')?.textContent;
check('ML-DSA shows a signature preview', !!sigBefore && /[0-9a-f]{2}/.test(sigBefore));
[...dsa.querySelectorAll('button')].find((b) => /re-sign/i.test(b.textContent))?.click();
await sleep(150);
const sigAfter = dsa?.querySelector('.live-row:nth-child(2) .hex')?.textContent;
check('ML-DSA re-sign changes the signature (hedged)', sigBefore && sigAfter && sigBefore !== sigAfter);

// Tools section.
check('tools section + 4 tabs', !!$('#tools') && doc.querySelectorAll('#tools .tab').length === 4);
check('hash tool shows a digest', /[0-9a-f]{32}/.test($('#tools .digest')?.textContent || ''));

// Switch to the Key generator tab and generate an Ed25519 key.
[...doc.querySelectorAll('#tools .tab')].find((t) => /Key generator/.test(t.textContent))?.click();
await sleep(60);
[...doc.querySelectorAll('#tools button')].find((b) => /Generate keypair/.test(b.textContent))?.click();
await sleep(250);
const toolsText = $('#tools').textContent;
check('keygen tool produced a private key PEM', /BEGIN PRIVATE KEY/.test(toolsText));
check('keygen tool produced a public key PEM', /BEGIN PUBLIC KEY/.test(toolsText));

// Switch to CSR tab and build a CSR (default Ed25519 + example.com).
[...doc.querySelectorAll('#tools .tab')].find((t) => /^CSR|CSR$/.test(t.textContent) || /PKCS#10/.test(t.textContent))?.click();
await sleep(60);
[...doc.querySelectorAll('#tools button')].find((b) => /Create CSR/.test(b.textContent))?.click();
await sleep(250);
check('CSR tool produced a certificate request', /BEGIN CERTIFICATE REQUEST/.test($('#tools').textContent));

console.log(fail ? `\n${fail} checks FAILED` : '\nall render + tool checks passed');
// jsdom keeps timers alive; exit explicitly.
process.exit(fail ? 1 : 0);
