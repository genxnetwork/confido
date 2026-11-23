export {ORIGINS} from './config.js';
import {ORIGINS} from './config.js';
export const DATA_ORIGINS = ['https://kdsintf.amd.com', 'https://api.github.com'];
export const decode = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
export function encode(bytes) {let text = ''; for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192)); return btoa(text);}
export async function fetchBytes(url, {body, limit = 4194304, signal} = {}) {
  if (![...ORIGINS, ...DATA_ORIGINS].includes(new URL(url).origin)) throw Error('Origin is not in the configured allowlist');
  const requestSignal = AbortSignal.any([...(signal ? [signal] : []), AbortSignal.timeout(30000)]);
  const r = await fetch(url, {method: body ? 'POST' : 'GET', body: body && JSON.stringify(body), headers: {'Accept': new URL(url).origin === DATA_ORIGINS[1] ? 'application/vnd.github.raw+json' : 'application/json', ...(body && {'Content-Type': 'application/json'})}, credentials: 'omit', redirect: 'error', cache: 'no-store', signal: requestSignal});
  if (!r.ok) {await r.body?.cancel(); const e = Error(`HTTP ${r.status}`); e.status = r.status; e.retryAfter = r.headers.get('retry-after'); throw e;}
  const reader = r.body.getReader(), chunks = []; let size = 0;
  try {while (true) {const {done, value} = await reader.read(); if (done) break; size += value.length; if (size > limit) throw Error('Response exceeds size limit'); chunks.push(value);}} finally {await reader.cancel();}
  const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) {bytes.set(chunk, offset); offset += chunk.length;} return {bytes, headers: r.headers};
}
async function kds(url, signal) {
  const deadline = performance.now() + 60000;
  signal = AbortSignal.any([signal, AbortSignal.timeout(60000)]);
  for (let attempt = 0; attempt < 3; attempt++) {
    try {return await fetchBytes(url, {limit: 65536, signal});} catch (e) {
      if (![429, 500, 502, 503, 504].includes(e.status) || attempt === 2) throw e;
      const h = e.retryAfter, delay = h === null ? 1000 * 2 ** attempt : /^\d+$/.test(h) ? Number(h) * 1000 : Math.max(0, Date.parse(h) - Date.now());
      if (!Number.isFinite(delay) || delay >= deadline - performance.now()) throw Error('KDS retry deadline exceeded');
      await new Promise(resolve => setTimeout(resolve, delay));
      if (signal.aborted) throw Error('Challenge cancelled');
    }
  }
}
export async function collect(endpoint, policyBytes, rpc) {
  if (!ORIGINS.includes(endpoint)) throw Error('Unconfigured evidence origin');
  const policy = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(policyBytes)), ref = policy.reference;
  if (policy.schema_version !== 2 || policy.profile !== 'azure-snp-vtpm-ima/1' || !/^[\w.-]+\/[\w.-]+$/.test(ref?.repository) || !/^[a-f0-9]{40}$/.test(ref?.commit) || !ref.path.split('/').every(s => /^[\w.-]+$/.test(s) && !['.', '..'].includes(s))) throw Error('Invalid immutable local policy');
  const controller = new AbortController(), signal = controller.signal, timer = setTimeout(() => controller.abort(), 120000);
  try {
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const report = await fetchBytes(endpoint + '/tee-report', {body: {nonce: encode(nonce)}, signal});
    if (!report.headers.get('cache-control')?.split(',').some(s => s.trim().toLowerCase() === 'no-store')) throw Error('Missing no-store');
    const hints = await rpc('inspect', {report: report.bytes});
    const product = hints.product ?? policy.platform?.product;
    if (hints.trusted !== false || !['Milan', 'Genoa'].includes(product) || product !== policy.platform?.product || !/^[a-f0-9]{128}$/.test(hints.chip_id) || hints.tcb.length !== 4 || !hints.tcb.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) throw Error('Invalid KDS selectors');
    const base = DATA_ORIGINS[0] + '/vcek/v1/' + product;
    const chain = await kds(base + '/cert_chain', signal);
    const query = ['blSPL', 'teeSPL', 'snpSPL', 'ucodeSPL'].map((k, i) => `${k}=${String(hints.tcb[i]).padStart(2, '0')}`).join('&');
    const vcek = await kds(`${base}/${hints.chip_id}?${query}`, signal);
    const reference = await fetchBytes(`${DATA_ORIGINS[1]}/repos/${ref.repository}/contents/${ref.path}?ref=${ref.commit}`, {signal});
    if (signal.aborted) throw Error('Challenge expired');
    const input = {report: report.bytes, amd_chain: chain.bytes, vcek: vcek.bytes, reference: reference.bytes, policy: policyBytes, nonce, at: Math.floor(Date.now() / 1000)};
    const result = await rpc('verify', input);
    if (signal.aborted || result.expected_nonce_base64 !== encode(nonce)) throw Error('Challenge expired/mismatched');
    return {schema_version: 2, mode: 'live_collection', origin: endpoint, inputs: Object.fromEntries(['report', 'amd_chain', 'vcek', 'reference'].map(k => [k, encode(input[k])])), context: {expected_nonce_base64: encode(nonce), evaluation_unix_seconds: input.at}, verification: result};
  } finally {clearTimeout(timer); controller.abort();}
}
