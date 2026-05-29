"""chain.verify() cryptographic re-verification (file backend).

These tests pin the contract that `tc chain-verify --pubkey` re-verifies every
operation's Ed25519 signature (not just link/structure), and that tampering
with a stored payload is detected.
"""

import glob
import json
import os

from trustchain import TrustChain, TrustChainConfig


def _file_tc(tmp_path):
    return TrustChain(
        TrustChainConfig(
            enable_chain=True,
            chain_storage="file",
            chain_dir=str(tmp_path),
            enable_nonce=False,
        )
    )


def test_chain_verify_structure_only_without_pubkey(tmp_path):
    tc = _file_tc(tmp_path)
    tc.sign("tool_a", {"x": 1})
    tc.sign("tool_b", {"y": 2})

    result = tc.chain.verify()
    assert result["valid"] is True
    # Honest reporting: without a key, signatures are NOT re-verified.
    assert result["signatures_checked"] is False
    assert result["signatures_verified"] == 0


def test_chain_verify_reverifies_signatures_with_pubkey(tmp_path):
    tc = _file_tc(tmp_path)
    tc.sign("tool_a", {"x": 1})
    tc.sign("tool_b", {"y": 2})
    pk = tc.export_public_key()

    result = tc.chain.verify(public_key=pk)
    assert result["valid"] is True
    assert result["signatures_checked"] is True
    assert result["signatures_verified"] == 2
    assert result.get("signatures_unverifiable", 0) == 0


def test_chain_verify_detects_payload_tampering(tmp_path):
    tc = _file_tc(tmp_path)
    tc.sign("tool_a", {"x": 1})
    tc.sign("tool_b", {"y": 2})
    pk = tc.export_public_key()

    # Tamper the persisted payload of the first operation.
    objs = sorted(glob.glob(os.path.join(str(tmp_path), "objects", "*.json")))
    envelope = json.loads(open(objs[0]).read())
    envelope["value"]["data"] = {"x": 999}
    with open(objs[0], "w") as f:
        json.dump(envelope, f)

    tc2 = _file_tc(tmp_path)

    # Structure-only verification cannot detect a payload swap.
    assert tc2.chain.verify()["valid"] is True

    # Cryptographic re-verification with the signer key catches it.
    result = tc2.chain.verify(public_key=pk)
    assert result["valid"] is False
    assert any(b.get("error") == "invalid_signature" for b in result["broken_links"])
