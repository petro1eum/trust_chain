// Public OSS receipt verification for a recorded synthetic example.
// This module contains no Pro encryption, decryption or formula interpreter.
const PINS = Object.freeze({
  authority: 'xM9W7VFCC7BeRjvbr1L3aDQYNOKJsAbwLbX5RJ01oHs=',
  source: 'UOeCdkJhrJLrB3zdDiS/FxPqY4BfgIo87+NCI4nfx+g=',
  owner: 'xNw/E2YLP/Om1QMwHoaGHaFdmeXNWHRKA/nVX2qSKYo=',
});
const encoder = new TextEncoder();
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonicalize(value[key])).join(',') + '}';
}
function bytes(b64) { return Uint8Array.from(atob(b64), ch => ch.charCodeAt(0)); }
async function digest(value) {
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(canonicalize(value)));
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('');
}
async function verifyReceipt(receipt, pin, tool) {
  if (receipt.format !== 'tcreceipt' || receipt.version !== 1 || receipt.key.algorithm !== 'ed25519' || receipt.key.public_key_b64 !== pin) return false;
  const env = receipt.envelope;
  if (env.tool_id !== tool || env.canon != null) return false;
  const signed = {};
  for (const field of ['tool_id', 'data', 'timestamp', 'nonce', 'parent_signature']) signed[field] = env[field] ?? null;
  // This recording uses modern signatures: signature_id is covered.
  for (const field of ['signature_id', 'metadata', 'certificate', 'tsa_proof']) if (env[field] != null) signed[field] = env[field];
  const key = await crypto.subtle.importKey('raw', bytes(pin), 'Ed25519', false, ['verify']);
  return crypto.subtle.verify('Ed25519', key, bytes(env.signature), encoder.encode(canonicalize(signed).replace(/[\u007f-\uffff]/g, ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'))));
}

export async function verifyRecordedEvidence(bundle) {
  const {source, plan, receipt, encrypted} = bundle;
  const view = source.envelope.data;
  const activation = view.source_activation;
  const evidence = receipt.envelope.data;
  return [
    ['Platform permission signature · recorded authority key', await verifyReceipt(activation, PINS.authority, 'factcrypt.activate-source')],
    ['Source export signature · recorded source key', await verifyReceipt(source, PINS.source, 'factcrypt.seal')],
    ['Owner result signature · recorded owner key', await verifyReceipt(receipt, PINS.owner, 'factcrypt.resolve')],
    ['Source key bound by the signed permission', activation.envelope.data.source_public_key === PINS.source],
    ['Export digest bound by plan and result', plan.export_digest === await digest(view) && evidence.export_digest === plan.export_digest],
    ['Formula plan digest bound by signed result', evidence.plan_digest === await digest(plan)],
    ['Encrypted result digest bound by signed result', evidence.encrypted_result_digest === await digest(encrypted)],
    ['Export identity and parent signature linkage', plan.export_id === view.export_id && evidence.export_id === view.export_id && receipt.envelope.parent_signature === source.envelope.signature],
  ];
}

for (const button of document.querySelectorAll('[data-step]')) {
  button.addEventListener('click', () => {
    for (const other of document.querySelectorAll('[data-step]')) other.setAttribute('aria-pressed', String(other === button));
    for (const panel of document.querySelectorAll('[data-panel]')) panel.hidden = panel.dataset.panel !== button.dataset.step;
  });
}
const byId = id => document.getElementById(id);
const path = 'assets/factcrypt-demo/';
async function readFile(name, json = true) {
  const response = await fetch(path + name);
  if (!response.ok) throw new Error('Unable to load ' + name);
  return json ? response.json() : response.text();
}
function showBundle(bundle) {
  const view = bundle.source.envelope.data;
  byId('public-markdown').textContent = view.markdown;
  byId('plan-json').textContent = JSON.stringify(bundle.plan, null, 2);
  byId('result-markdown').textContent = bundle.result;
  const rows = byId('public-rows');
  for (let i = 0; i < view.facts.length; i += 3) {
    const tr = document.createElement('tr');
    for (const fact of view.facts.slice(i, i + 3)) {
      const td = document.createElement('td');
      const reference = document.createElement('code'); reference.className = 'fact-reference'; reference.textContent = '{{fact:' + fact.id + '}}';
      const unit = document.createElement('span'); unit.className = 'unit'; unit.textContent = fact.type + (fact.unit ? ' · ' + fact.unit : '');
      td.append(reference, unit); tr.append(td);
    }
    rows.append(tr);
  }
  byId('formulas').replaceChildren();
  for (const calculation of bundle.plan.calculations) {
    const div = document.createElement('div'); div.className = 'formula';
    const label = document.createElement('strong'); label.textContent = calculation.id;
    const pre = document.createElement('pre'); pre.textContent = calculation.expression;
    div.append(label, pre); byId('formulas').append(div);
  }
}
async function verify(bundle, changeFormula) {
  byId('verify').disabled = byId('tamper').disabled = true;
  byId('checks').replaceChildren();
  byId('verification-status').className = '';
  byId('verification-status').textContent = 'Checking signatures and artifact hashes…';
  try {
    if (!crypto.subtle) throw new Error('WebCrypto is unavailable');
    const candidate = structuredClone(bundle);
    if (changeFormula) candidate.plan.calculations[0].expression += ' + 1';
    const checks = await verifyRecordedEvidence(candidate);
    for (const [label, passed] of checks) {
      const item = document.createElement('li');
      item.className = passed ? 'check-pass' : 'check-fail';
      item.textContent = (passed ? 'PASS · ' : 'FAIL · ') + label;
      byId('checks').append(item);
    }
    const valid = checks.every(([, passed]) => passed);
    byId('verification-status').textContent = valid
      ? 'Recorded signatures and artifact links verified · 8/8 checks passed.'
      : changeFormula ? 'Changed formula rejected · the plan no longer matches the signed result.' : 'Verification failed · these files do not match the recorded evidence.';
    byId('verification-status').className = valid ? 'check-pass' : 'check-fail';
  } catch (error) {
    byId('verification-status').textContent = 'Verification unavailable or invalid evidence. Use a current browser with Ed25519 WebCrypto support, or inspect the downloaded files.';
    byId('verification-status').className = 'check-fail';
  } finally { byId('verify').disabled = byId('tamper').disabled = false; }
}
try {
  const [source, plan, receipt, encrypted, result] = await Promise.all([
    readFile('public.tcreceipt'), readFile('plan.json'), readFile('replay-result.tcreceipt'), readFile('replay-result.encrypted.json'), readFile('result.md', false),
  ]);
  const bundle = {source, plan, receipt, encrypted, result};
  showBundle(bundle);
  byId('load-status').textContent = 'Recorded files loaded. Select a step above or verify the evidence below.';
  byId('verify').disabled = byId('tamper').disabled = false;
  byId('verify').addEventListener('click', () => verify(bundle, false));
  byId('tamper').addEventListener('click', () => verify(bundle, true));
} catch (error) {
  byId('load-status').textContent = 'Could not load the recorded files. Reload this page or use the direct file links below.';
}
