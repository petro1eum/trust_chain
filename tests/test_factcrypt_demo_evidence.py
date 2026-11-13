"""Run the published FactCrypt example's WebCrypto checks against real receipts."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

NODE = shutil.which("node")
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(NODE is None, reason="node binary not on PATH")
def test_public_demo_rejects_changed_evidence(tmp_path):
    script = tmp_path / "verify-demo.mjs"
    script.write_text(r'''
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
const root = process.argv[2];
const source = readFileSync(root + '/docs/factcrypt-demo.js', 'utf8')
  .split('for (const button of document.querySelectorAll')[0]
  .replace('export async function', 'async function');
const verify = new Function('crypto', source + '\nreturn verifyRecordedEvidence;')(webcrypto);
const read = name => JSON.parse(readFileSync(root + '/docs/assets/factcrypt-demo/' + name, 'utf8'));
const bundle = {source: read('public.tcreceipt'), plan: read('plan.json'),
  receipt: read('replay-result.tcreceipt'), encrypted: read('replay-result.encrypted.json')};
const original = await verify(bundle);
const edits = {
  source: b => b.source.envelope.data.facts[0].type = 'decimal',
  signature: b => b.receipt.envelope.signature = 'A'.repeat(86) + '==',
  key: b => b.source.key.public_key_b64 = b.receipt.key.public_key_b64,
  plan: b => b.plan.calculations[0].expression += ' + 1',
  ciphertext: b => b.encrypted.tampered = true,
  parent: b => b.receipt.envelope.parent_signature = 'wrong',
  authority: b => b.source.envelope.data.source_activation.envelope.data.source_public_key = 'wrong',
};
const rejected = {};
for (const [name, edit] of Object.entries(edits)) {
  const candidate = structuredClone(bundle); edit(candidate);
  rejected[name] = (await verify(candidate)).some(([, passed]) => !passed);
}
console.log(JSON.stringify({original, rejected}));
''')
    result = subprocess.run([NODE, str(script), str(ROOT)], capture_output=True,
                            text=True, check=True, timeout=20)
    evidence = json.loads(result.stdout)
    assert len(evidence["original"]) == 8
    assert all(passed for _, passed in evidence["original"])
    assert len(evidence["rejected"]) == 7
    assert all(evidence["rejected"].values())
