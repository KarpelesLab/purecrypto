<script setup>
import { ref, computed } from 'vue';
import { state, pc } from '../../store.js';

const EXAMPLE = `-----BEGIN CERTIFICATE-----
MIICQDCCAeagAwIBAgIUeWHu3wD7eXkYh6SiXBGLXw3L/DkwCgYIKoZIzj0EAwIw
QjEZMBcGA1UEAwwQYW5hbHl6ZXIuZXhhbXBsZTEYMBYGA1UECgwPcHVyZWNyeXB0
byBkZW1vMQswCQYDVQQGEwJVUzAeFw0yNjA3MjIyMTQxMTZaFw0yODEwMjQyMTQx
MTZaMEIxGTAXBgNVBAMMEGFuYWx5emVyLmV4YW1wbGUxGDAWBgNVBAoMD3B1cmVj
cnlwdG8gZGVtbzELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATt774n+5uJCXpoSF6hHVHtEdMn01TE52X6szjOpWyX9dXnWfQ6H3ep45+K3pb1
2JXyUMfxACu0KpA55Qmis5OZo4G5MIG2MB0GA1UdDgQWBBRSLrxAGzAmUkpKBI7U
DJHzzPn5aDAfBgNVHSMEGDAWgBRSLrxAGzAmUkpKBI7UDJHzzPn5aDAPBgNVHRMB
Af8EBTADAQH/MDcGA1UdEQQwMC6CEGFuYWx5emVyLmV4YW1wbGWCFHd3dy5hbmFs
eXplci5leGFtcGxlhwTAAAIKMAsGA1UdDwQEAwIFoDAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIgfKllYmCUmZggQqm66yLk
bC7Z9LUo11DfpxYAQfWyywkCIQDhUwkF9VMVkGtRZgIdrL1RJt7wFk0wBpA/Ve7G
v6fB8w==
-----END CERTIFICATE-----`;

const SIG_ALG = {
  '1.2.840.113549.1.1.5': 'RSA · SHA-1', '1.2.840.113549.1.1.11': 'RSA · SHA-256',
  '1.2.840.113549.1.1.12': 'RSA · SHA-384', '1.2.840.113549.1.1.13': 'RSA · SHA-512',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.3.2': 'ECDSA · SHA-256', '1.2.840.10045.4.3.3': 'ECDSA · SHA-384',
  '1.2.840.10045.4.3.4': 'ECDSA · SHA-512',
  '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
  '2.16.840.1.101.3.4.3.17': 'ML-DSA-44', '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
  '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
};
const EKU = {
  '1.3.6.1.5.5.7.3.1': 'TLS server auth', '1.3.6.1.5.5.7.3.2': 'TLS client auth',
  '1.3.6.1.5.5.7.3.3': 'code signing', '1.3.6.1.5.5.7.3.4': 'email protection',
  '1.3.6.1.5.5.7.3.8': 'timestamping', '1.3.6.1.5.5.7.3.9': 'OCSP signing',
  '2.5.29.37.0': 'any usage',
};
const KU = [
  [0x0080, 'digital signature'], [0x0040, 'non-repudiation'], [0x0020, 'key encipherment'],
  [0x0010, 'data encipherment'], [0x0008, 'key agreement'], [0x0004, 'certificate sign'],
  [0x0002, 'CRL sign'], [0x0001, 'encipher only'], [0x8000, 'decipher only'],
];

const pasted = ref('');
const info = ref(null);
const error = ref('');
const dragging = ref(false);

function analyze(input) {
  if (state.status !== 'ready') return;
  error.value = '';
  try {
    info.value = pc.analyzeCert(input);
  } catch (e) {
    error.value = String(e.message || e);
    info.value = null;
  }
}
function analyzePasted() {
  if (!pasted.value.trim()) {
    error.value = 'Paste a PEM certificate, or drop a file.';
    return;
  }
  analyze(pasted.value.trim());
}
function loadExample() {
  pasted.value = EXAMPLE;
  analyze(EXAMPLE);
}
async function onFile(f) {
  if (!f) return;
  const buf = new Uint8Array(await f.arrayBuffer());
  // Text starting with "-----BEGIN" is PEM; anything else is treated as DER.
  const head = pc.fromUtf8(buf.slice(0, 12));
  if (head.includes('-----BEGIN')) {
    const text = pc.fromUtf8(buf);
    pasted.value = text.trim();
    analyze(text.trim());
  } else {
    pasted.value = '';
    analyze(buf);
  }
}

const dn = (d) =>
  !d ? '—' : [['CN', d.cn], ['O', d.o], ['OU', d.ou], ['C', d.c]]
    .filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(', ') || '—';

const fmtDate = (unix) => new Date(unix * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');

const validity = computed(() => {
  if (!info.value) return null;
  const now = Date.now() / 1000;
  const { not_before: nb, not_after: na } = info.value;
  if (now < nb) return { cls: 'warn', text: 'not yet valid' };
  if (now > na) return { cls: 'bad', text: 'expired' };
  const days = Math.floor((na - now) / 86400);
  return { cls: days < 30 ? 'warn' : 'ok', text: days < 30 ? `expires in ${days} days` : `valid · ${days} days left` };
});
const keyLabel = computed(() => {
  const k = info.value?.key;
  if (!k) return '—';
  if (k.curve) return `${k.algorithm} · ${k.curve}`;
  if (k.bits) return `${k.algorithm} · ${k.bits}-bit`;
  return k.algorithm;
});
const sigLabel = computed(() => {
  const o = info.value?.sig_alg_oid;
  return o ? SIG_ALG[o] || o : '—';
});
const kuFlags = computed(() => {
  const v = info.value?.key_usage;
  return v == null ? [] : KU.filter(([bit]) => v & bit).map(([, n]) => n);
});
const ekuList = computed(() => (info.value?.eku || []).map((o) => EKU[o] || o));
</script>

<template>
  <div class="tool">
    <label
      class="drop"
      :class="{ over: dragging }"
      @dragover.prevent="dragging = true"
      @dragleave.prevent="dragging = false"
      @drop.prevent="dragging = false; onFile($event.dataTransfer?.files?.[0])"
    >
      <input type="file" hidden accept=".pem,.crt,.cer,.der,application/x-x509-ca-cert" @change="onFile($event.target.files?.[0])" />
      <span class="di">⇪</span>
      <span class="dt">Drop a certificate (.pem / .crt / .der), or click to choose</span>
    </label>

    <div>
      <label>…or paste a PEM certificate</label>
      <textarea v-model="pasted" rows="4" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----&#10;…"></textarea>
    </div>
    <div class="actions">
      <button class="btn btn-primary" @click="analyzePasted">Analyze</button>
      <button class="btn" @click="loadExample">Load an example</button>
    </div>

    <p v-if="error" class="err mono">{{ error }}</p>

    <div v-if="info" class="report">
      <div class="report-head">
        <div>
          <span class="lead-cn">{{ info.subject?.cn || '(no common name)' }}</span>
          <div class="badges">
            <span class="tag" :class="validity.cls">{{ validity.text }}</span>
            <span v-if="info.self_signed" class="tag pq">self-signed</span>
            <span v-if="info.is_ca === 'true'" class="tag secret">CA</span>
          </div>
        </div>
      </div>

      <div class="fields">
        <div class="field"><span class="fk">Subject</span><span class="fv">{{ dn(info.subject) }}</span></div>
        <div class="field"><span class="fk">Issuer</span><span class="fv">{{ dn(info.issuer) }}</span></div>
        <div class="field"><span class="fk">Not before</span><span class="fv mono">{{ fmtDate(info.not_before) }}</span></div>
        <div class="field"><span class="fk">Not after</span><span class="fv mono">{{ fmtDate(info.not_after) }}</span></div>
        <div class="field"><span class="fk">Public key</span><span class="fv">{{ keyLabel }}</span></div>
        <div class="field"><span class="fk">Signature</span><span class="fv">{{ sigLabel }}</span></div>
        <div class="field"><span class="fk">Serial</span><span class="fv mono small">{{ info.serial || '—' }}</span></div>
        <div class="field" v-if="info.is_ca === 'true'">
          <span class="fk">Path length</span><span class="fv mono">{{ info.path_len === null ? 'unlimited' : info.path_len }}</span>
        </div>
      </div>

      <div v-if="info.sans_dns.length || info.sans_ip.length" class="chips-row">
        <span class="fk">Subject alt names</span>
        <div class="chips">
          <span v-for="d in info.sans_dns" :key="d" class="chip">DNS: {{ d }}</span>
          <span v-for="ip in info.sans_ip" :key="ip" class="chip">IP: {{ ip }}</span>
        </div>
      </div>
      <div v-if="kuFlags.length" class="chips-row">
        <span class="fk">Key usage</span>
        <div class="chips"><span v-for="u in kuFlags" :key="u" class="chip">{{ u }}</span></div>
      </div>
      <div v-if="ekuList.length" class="chips-row">
        <span class="fk">Extended key usage</span>
        <div class="chips"><span v-for="e in ekuList" :key="e" class="chip">{{ e }}</span></div>
      </div>

      <div class="fp">
        <div class="field"><span class="fk">SHA-256</span><code class="hex public">{{ info.fingerprints.sha256 }}</code></div>
        <div class="field"><span class="fk">SHA-1</span><code class="hex">{{ info.fingerprints.sha1 }}</code></div>
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
  display: flex;
  align-items: center;
  gap: 12px;
  justify-content: center;
  border: 1.5px dashed var(--line);
  border-radius: var(--radius);
  padding: 22px;
  cursor: pointer;
  background: var(--ink-2);
  text-transform: none;
  letter-spacing: 0;
  transition: border-color 0.16s ease, background 0.16s ease;
}
.drop.over {
  border-color: var(--violet);
  background: var(--violet-glow);
}
.di {
  font-size: 1.4rem;
  color: var(--violet-2);
}
.dt {
  font-size: 0.92rem;
  color: var(--dim);
}
.actions {
  display: flex;
  gap: 10px;
}
.report {
  display: flex;
  flex-direction: column;
  gap: 18px;
  padding: 20px;
  background: var(--ink);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius-sm);
}
.report-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--line-soft);
}
.lead-cn {
  font-family: var(--font-display);
  font-weight: 600;
  font-size: 1.3rem;
}
.badges {
  display: flex;
  gap: 8px;
  margin-top: 10px;
  flex-wrap: wrap;
}
.tag.ok {
  color: var(--teal-2);
  border-color: rgba(47, 224, 200, 0.3);
  background: var(--teal-glow);
}
.tag.warn {
  color: var(--amber);
  border-color: rgba(255, 180, 84, 0.3);
  background: rgba(255, 180, 84, 0.09);
}
.tag.bad {
  color: #ff9c9c;
  border-color: rgba(255, 90, 90, 0.4);
  background: rgba(255, 90, 90, 0.1);
}
.fields {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px 24px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}
.fk {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--muted);
}
.fv {
  font-size: 0.92rem;
  color: var(--paper);
  word-break: break-word;
}
.fv.small {
  font-size: 0.76rem;
}
.chips-row {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
}
.chip {
  font-family: var(--font-mono);
  font-size: 0.74rem;
  padding: 4px 10px;
  border-radius: 6px;
  border: 1px solid var(--line-soft);
  background: var(--ink-2);
  color: var(--dim);
}
.fp {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-top: 16px;
  border-top: 1px solid var(--line-soft);
}
.fp .hex {
  font-size: 0.74rem;
}
.err {
  color: #ff9c9c;
  font-size: 0.82rem;
  margin: 0;
}
@media (max-width: 560px) {
  .fields {
    grid-template-columns: 1fr;
  }
}
</style>
