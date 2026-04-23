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


# Same canonicalization/verification logic that ships inside verify.html.
# Keeping it in the test repo as a string means we don't silently drift.
_NODE_SCRIPT = r"""
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
const crypto = webcrypto;

const b64 = s => new Uint8Array(Buffer.from(s, 'base64'));

function canonicalize(x) {
  if (x === null || typeof x !== 'object') return JSON.stringify(x);
  if (Array.isArray(x)) return '[' + x.map(canonicalize).join(',') + ']';
  const keys = Object.keys(x).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(x[k])).join(',') + '}';
}

function buildCanonicalEnvelope(env) {
  const obj = {
    tool_id: env.tool_id ?? null,
    data: env.data ?? null,
    timestamp: env.timestamp ?? null,
    nonce: env.nonce ?? null,
    parent_signature: env.parent_signature ?? null,
  };
  if (env.metadata    !== undefined && env.metadata    !== null) obj.metadata    = env.metadata;
  if (env.certificate !== undefined && env.certificate !== null) obj.certificate = env.certificate;
  if (env.tsa_proof   !== undefined && env.tsa_proof   !== null) obj.tsa_proof   = env.tsa_proof;
  return new TextEncoder().encode(canonicalize(obj));
}

const r = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const pk = await crypto.subtle.importKey(
  'raw', b64(r.key.public_key_b64), { name: 'Ed25519' }, true, ['verify']
);
const msg = buildCanonicalEnvelope(r.envelope);
const ok = await crypto.subtle.verify('Ed25519', pk, b64(r.envelope.signature), msg);

// Tamper leg: flip a byte in data, expect false.
const tampered = structuredClone(r);
tampered.envelope.data = { ...(tampered.envelope.data || {}), __tamper__: 1 };
const tamperedOk = await crypto.subtle.verify(
  'Ed25519', pk, b64(r.envelope.signature), buildCanonicalEnvelope(tampered.envelope)
);

console.log(JSON.stringify({
  canonical: new TextDecoder().decode(msg),
  verify_ok: ok,
  tamper_rejected: tamperedOk === false,
}));
"""


def _run_node_verify(receipt_path: Path) -> dict:
    script = Path(receipt_path.parent) / "_verify.mjs"
    script.write_text(textwrap.dedent(_NODE_SCRIPT))
    proc = subprocess.run(
        [NODE, str(script), str(receipt_path)],
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
