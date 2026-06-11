"""signature_id is bound into Ed25519 payload (with legacy verify fallback)."""

import json

from trustchain.v2.signer import Signer, _build_canonical_data


def test_sign_includes_signature_id_in_canonical():
    signer = Signer()
    resp = signer.sign("tool-a", {"x": 1})
    canonical = _build_canonical_data(
        tool_id=resp.tool_id,
        data=resp.data,
        timestamp=resp.timestamp,
        nonce=resp.nonce,
        parent_signature=resp.parent_signature,
        signature_id=resp.signature_id,
    )
    assert canonical["signature_id"] == resp.signature_id
    assert signer.verify(resp) is True


def test_tampered_signature_id_fails_verify():
    signer = Signer()
    resp = signer.sign("tool-a", {"x": 1})
    object.__setattr__(resp, "signature_id", "00000000-0000-0000-0000-000000000099")
    assert signer.verify(resp) is False
