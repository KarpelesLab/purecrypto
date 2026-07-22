import { reactive } from 'vue';
import * as pc from './lib/purecrypto.js';

// Shared load state for the wasm module. Components read `state.status`.
export const state = reactive({
  status: 'idle', // idle | loading | ready | error
  error: null,
});

export function initCrypto() {
  if (state.status === 'ready' || state.status === 'loading') return;
  state.status = 'loading';
  const url = `${import.meta.env.BASE_URL}purecrypto.wasm`;
  pc.load(url)
    .then(() => {
      state.status = 'ready';
    })
    .catch((e) => {
      state.status = 'error';
      state.error = String(e);
    });
}

export { pc };
