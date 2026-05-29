import dataclasses

import pytest

from trustchain import TrustChain, TrustChainConfig


def test_dag_merge(tmp_path):
    """Test merging multiple parents into a single DAG commit."""
    tc = TrustChain(
        config=TrustChainConfig(
            enable_chain=True, chain_storage="file", chain_dir=str(tmp_path)
        )
    )

    # Branch 1
    sig1 = tc.sign("tool_a", {"result": "A"}, parent_signature=None)
    # Branch 2
    sig2 = tc.sign("tool_b", {"result": "B"}, parent_signature=None)

    # Orchestrator merges them
    merge = tc.sign(
        "orchestrator",
        {"action": "merge"},
        parent_signatures=[sig1.signature, sig2.signature],
    )

    # parent_signatures must be carried on the response itself
    assert merge.parent_signatures == [sig1.signature, sig2.signature]

    # ...and must be cryptographically covered by the signature, not just
    # recorded. Use the pure signer verify path (no nonce side-effects).
    assert tc._signer.verify(merge) is True

    # Tampering with the declared parents breaks verification — proof that the
    # DAG merge links are inside the signed payload.
    tampered = dataclasses.replace(
        merge, parent_signatures=[sig1.signature, "forged-parent"]
    )
    assert tc._signer.verify(tampered) is False

    # Verify the chain integrity (DAG check)
    result = tc.chain.verify()
    assert result["valid"] is True, f"Chain should be valid: {result}"

    # Log should contain 3 operations
    ops = tc.chain.log(limit=10)
    assert len(ops) == 3

    # The merge op must persist its multiple parents in the chain log.
    merge_op = ops[-1]
    assert merge_op["tool"] == "orchestrator"
    assert merge_op.get("parent_signatures") == [sig1.signature, sig2.signature]


def test_revert_operation(tmp_path):
    """Test creating a compensatory transaction."""
    tc = TrustChain(
        config=TrustChainConfig(
            enable_chain=True, chain_storage="file", chain_dir=str(tmp_path)
        )
    )

    tc.sign("bash_tool", {"cmd": "rm -rf /"}, parent_signature=None)
    op_id = tc.chain.log()[0]["id"]

    # Execute revert
    tc.revert(op_id=op_id, reason="Malicious command detected")

    # Verify chain
    result = tc.chain.verify()
    assert result["valid"] is True

    # Verify revert structure
    ops = tc.chain.log(limit=10)
    assert len(ops) == 2

    revert_op = ops[-1]
    assert revert_op["tool"] == "tc_revert"
    assert revert_op["data"]["action"] == "revert"
    assert revert_op["data"]["target_op"] == op_id
    assert revert_op["data"]["reason"] == "Malicious command detected"
