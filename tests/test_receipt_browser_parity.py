"""Interop: Node WebCrypto ≡ Python signer.

Пропускаем квитанцию, собранную Python-ом, через тот же канонический
сериализатор и Ed25519-верификатор, что используется в
``examples/verify.html``.  Если этот тест упадёт — значит drag-and-drop
verifier в браузере начнёт врать.

Тест скипается автоматически, если в PATH нет ``node`` — это не регрессия,
а отсутствие runtime-а.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from trustchain.receipt import _canonical_envelope_bytes, build_receipt
from trustchain.v2.signer import Signer

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node binary not on PATH")


# Execute the actual shipped page logic, not a copied verifier that can drift.
_NODE_SCRIPT = r"""
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
const html = readFileSync(process.argv[3], 'utf8');
const code = html.split('<script>')[1].split('// ------------------------------------------------------------------ UI')[0];
const api = new Function('crypto', code + '\nreturn {buildCanonicalEnvelope, verifyReceipt};')(webcrypto);
const r = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const result = await api.verifyReceipt(r);
const tampered = structuredClone(r);
tampered.envelope.data = { ...(tampered.envelope.data || {}), __tamper__: 1 };
const bad = await api.verifyReceipt(tampered);
console.log(JSON.stringify({
  canonical: new TextDecoder().decode(api.buildCanonicalEnvelope(r.envelope)),
  verify_ok: result.signature_ok,
  tamper_rejected: bad.signature_ok === false,
}));
"""


def _run_node_verify(receipt_path: Path, page="docs/verify.html") -> dict:
    script = Path(receipt_path.parent) / "_verify.mjs"
    script.write_text(textwrap.dedent(_NODE_SCRIPT))
    proc = subprocess.run(
        [NODE, str(script), str(receipt_path), str(Path(__file__).resolve().parents[1] / page)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if proc.returncode != 0:
        raise AssertionError(f"node exited {proc.returncode}: {proc.stderr}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_node_webcrypto_matches_python_signer(tmp_path: Path):
    signer = Signer()
    resp = signer.sign(
        tool_id="calc",
        data={"x": 1, "y": [1, 2, 3], "z": {"b": 2, "a": 1}},
    )
    receipt = build_receipt(resp, signer.get_public_key(), key_id=signer.get_key_id())
    path = receipt.save(tmp_path / "sample.tcreceipt")

    py_canonical = _canonical_envelope_bytes(receipt.envelope).decode()
    js = _run_node_verify(path)
    assert js["canonical"] == py_canonical, "JS/PY canonicalization diverged"
    assert js["verify_ok"] is True
    assert js["tamper_rejected"] is True


def test_node_parity_with_metadata_and_certificate(tmp_path: Path):
    signer = Signer()
    resp = signer.sign(
        tool_id="weather",
        data={"loc": "London"},
        metadata={"model": "gpt-4o", "run_id": "abc123"},
        certificate={"subject_cn": "agent-x", "issuer_cn": "TrustChain CA"},
    )
    receipt = build_receipt(resp, signer.get_public_key(), key_id=signer.get_key_id())
    path = receipt.save(tmp_path / "sample.tcreceipt")

    py_canonical = _canonical_envelope_bytes(receipt.envelope).decode()
    js = _run_node_verify(path)
    assert js["canonical"] == py_canonical
    assert js["verify_ok"] is True
    assert js["tamper_rejected"] is True


@pytest.mark.parametrize("page", ["docs/verify.html", "examples/verify.html"])
def test_shipped_page_handles_unicode_and_attribution(tmp_path, page):
    signer = Signer()
    response = signer.sign("source", {"client": "Учебный клиент А 🔐", "value": 12},
                           signer_role="tool", input_hash="sha256:example",
                           metadata={"label": "Цена"})
    receipt = build_receipt(response, signer.get_public_key())
    result = _run_node_verify(receipt.save(tmp_path / "unicode.tcreceipt"), page)
    assert result["canonical"] == _canonical_envelope_bytes(receipt.envelope).decode()
    assert result["verify_ok"] and result["tamper_rejected"]


def test_shipped_page_keeps_legacy_signature_support(tmp_path):
    import base64
    signer = Signer()
    receipt = build_receipt(signer.sign("legacy", {"message": "Пример"}), signer.get_public_key())
    receipt.envelope["signature"] = base64.b64encode(signer._raw_sign(
        _canonical_envelope_bytes(receipt.envelope, include_signature_id=False)
    )).decode()
    result = _run_node_verify(receipt.save(tmp_path / "legacy.tcreceipt"))
    assert result["verify_ok"] and result["tamper_rejected"]


def test_factcrypt_recording_verifies_in_shipped_page(tmp_path):
    root = Path(__file__).resolve().parents[1] / "docs/assets/factcrypt-demo"
    source = json.loads((root / "public.tcreceipt").read_text())
    result_receipt = json.loads((root / "replay-result.tcreceipt").read_text())
    for index, receipt in enumerate([source, source["envelope"]["data"]["source_activation"], result_receipt]):
        path = tmp_path / f"recording-{index}.tcreceipt"
        path.write_text(json.dumps(receipt))
        result = _run_node_verify(path)
        assert result["verify_ok"] and result["tamper_rejected"]
