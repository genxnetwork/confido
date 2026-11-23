import {collect, decode, ORIGINS, DATA_ORIGINS} from './collection.js';
import {SERVICES} from './config.js';
const $ = id => document.getElementById(id); let busy = false, record;
for (const service of SERVICES) {
  const option = document.createElement('option');
  option.value = service.origin; option.textContent = service.origin;
  $('origin').append(option);
}
function selectService() {
  $('service').value = SERVICES.find(service => service.origin === $('origin').value)?.service_id ?? '';
}
$('origin').addEventListener('change', selectService);
selectService();
$('live').disabled = SERVICES.length === 0;
function workerRpc() {
  const worker = new Worker(new URL('./worker.js', import.meta.url), {type: 'module'}), pending = new Map(); let seq = 0;
  worker.onmessage = ({data}) => {const task = pending.get(data.id); if (!task) return; clearTimeout(task.timer); pending.delete(data.id); data.error ? task.reject(Error(data.error)) : task.resolve(data.result);};
  worker.onerror = e => {for (const t of pending.values()) {clearTimeout(t.timer); t.reject(Error(e.message));} pending.clear(); worker.terminate();};
  return {call(operation, input) {return new Promise((resolve, reject) => {const id = ++seq, timer = setTimeout(() => {pending.delete(id); reject(Error('Verifier timed out')); worker.terminate();}, 30000); pending.set(id, {resolve, reject, timer}); worker.postMessage({id, operation, input});});}, close() {worker.terminate();}};
}
async function file(id, limit) {const f = $(id).files[0]; if (!f || f.size > limit) throw Error('Select a file within the size limit'); return new Uint8Array(await f.arrayBuffer());}
async function run(operation) {
  if (busy) return; busy = true; record = null; $('save').disabled = true; $('result').textContent = ''; $('status').textContent = 'Verifying…'; const rpc = workerRpc();
  try {
    if (operation === 'live') {
      const endpoint = $('origin').value; if (!ORIGINS.includes(endpoint)) throw Error('Unconfigured evidence service');
      if (!await chrome.permissions.request({origins: [endpoint, ...DATA_ORIGINS].map(o => o + '/*')})) throw Error('Retrieval permission was declined');
      await rpc.call('metadata', {});
      record = await collect(endpoint, $('service').value, await file('policy', 65536), rpc.call);
    } else {
      await rpc.call('metadata', {});
      const policy = await file('policy', 65536), archive = JSON.parse(new TextDecoder().decode(await file('archive', 16777216)));
      if (archive.schema_version !== 2) throw Error('Archive schema 2 required; use the CLI to migrate a legacy archive');
      const at = Number($('time').value); if (!$('time').value || !Number.isSafeInteger(at) || at < 0) throw Error('Choose an independent evaluation time');
      const input = Object.fromEntries(['report', 'amd_chain', 'vcek', 'reference'].map(k => [k, decode(archive.inputs[k])]));
      const result = await rpc.call('verify', {...input, policy, nonce: decode(archive.context.expected_nonce_base64), at});
      record = {schema_version: 2, mode: 'historical_replay', inputs: archive.inputs, context: {...archive.context, evaluation_unix_seconds: at}, verification: result};
    }
    $('status').textContent = `${record.mode === 'historical_replay' ? 'Historical evidence' : 'Evidence'}: ${record.verification.status}. Connection authentication and admission are not evaluated.`;
    $('result').textContent = JSON.stringify(record.verification, null, 2); $('save').disabled = false;
  } catch (e) {$('status').textContent = String(e);} finally {rpc.close(); busy = false;}
}
$('live').addEventListener('click', () => run('live')); $('replay').addEventListener('click', () => run('replay'));
$('save').addEventListener('click', () => {if (!record) return; const url = URL.createObjectURL(new Blob([JSON.stringify(record, null, 2)], {type: 'application/json'})), a = document.createElement('a'); a.href = url; a.download = 'confido-verification.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);});
