"""Canonicalization conformance vectors + Python<->JS parity (RFC-003 follow-up).

Pins the TrustChain canonicalization contract (json.dumps sort_keys=True,
separators=(",",":"), ensure_ascii=True) with explicit expected strings so any
accidental scheme drift is caught, and — when node is available — asserts the JS
SDK's _canonicalStringify() produces byte-identical output. The JS canonicalizer
previously sorted only top-level keys AND dropped nested keys entirely; these
vectors (nested objects, arrays, non-ASCII) would have exposed that.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_SDK = Path(__file__).resolve().parents[1] / "trustchain" / "js_sdk" / "trustchain.js"

# (payload, expected canonical string) — expected pins the exact contract.
VECTORS = [
    ({"b": 2, "a": 1}, '{"a":1,"b":2}'),
    (
        {"b": {"y": 1, "x": 2}, "a": [3, {"n": 2, "m": 1}]},
        '{"a":[3,{"m":1,"n":2}],"b":{"x":2,"y":1}}',
    ),
    (
        {"city": "Берлин", "note": "café"},
        '{"city":"\\u0411\\u0435\\u0440\\u043b\\u0438\\u043d","note":"caf\\u00e9"}',
    ),
    (
        {"n": None, "t": True, "f": False, "i": 42, "s": "x"},
        '{"f":false,"i":42,"n":null,"s":"x","t":true}',
    ),
]


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@pytest.mark.parametrize("payload,expected", VECTORS)
def test_python_canonicalization_matches_contract(payload, expected):
    assert _canonical(payload) == expected


@pytest.mark.skipif(shutil.which("node") is None, reason="node binary not on PATH")
def test_js_sdk_canonicalization_matches_python():
    harness = (
        # node -e shifts argv: argv[1]=SDK path, argv[2]=payloads JSON
        "const {TrustChainVerifier} = require(process.argv[1]);"
        "const v = new TrustChainVerifier();"
        "const vs = JSON.parse(process.argv[2]);"
        "console.log(JSON.stringify(vs.map((o) => v._canonicalStringify(o))));"
    )
    payloads = [p for p, _ in VECTORS]
    out = subprocess.run(
        ["node", "-e", harness, str(_SDK), json.dumps(payloads)],
        capture_output=True,
        text=True,
        check=True,
    )
    js_results = json.loads(out.stdout)
    for (payload, expected), js in zip(VECTORS, js_results):
        assert js == expected, f"JS != contract for {payload!r}: {js!r} != {expected!r}"
        assert js == _canonical(payload)  # JS == Python
