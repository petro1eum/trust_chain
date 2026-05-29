import pytest

from trustchain import TrustChain, TrustChainConfig


def test_checkpoint_tag_branch(tmp_path):
    tc = TrustChain(
        config=TrustChainConfig(chain_storage="file", chain_dir=str(tmp_path))
    )

    # Must sign something first
    with pytest.raises(ValueError, match="HEAD is empty"):
        tc.chain.checkpoint("my_checkpoint")

    tc.sign("test_tool", {"action": "first"})
    h1 = tc.chain.head()

    # Create refs
    tc.chain.checkpoint("v1-checkpoint")
    tc.chain.tag("v1-tag")
    tc.chain.branch("feature-branch")

    refs = tc.chain.list_refs()

    assert len(refs["checkpoint"]) == 1
    assert refs["checkpoint"][0]["name"] == "v1-checkpoint"
    assert refs["checkpoint"][0]["head"] == h1

    assert len(refs["tag"]) == 1
    assert refs["tag"][0]["name"] == "v1-tag"
    assert refs["tag"][0]["head"] == h1

    assert len(refs["head"]) == 1
    assert refs["head"][0]["name"] == "feature-branch"
    assert refs["head"][0]["head"] == h1


def test_checkout_and_reset(tmp_path):
    tc = TrustChain(
        config=TrustChainConfig(chain_storage="file", chain_dir=str(tmp_path))
    )

    tc.sign("test", {"step": 1})
    h1 = tc.chain.head()

    tc.sign("test", {"step": 2})
    h2 = tc.chain.head()

    # Create branch at h2
    tc.chain.branch("latest")

    # Reset soft back to op1
    op1_id = tc.chain.log()[0]["id"]
    res = tc.chain.reset(op1_id, soft=True)
    assert res["changed"] is True
    assert res["new_head"] == h1
    assert res["detached_count"] == 1
    assert tc.chain.head() == h1

    # Checkout latest
    cout = tc.chain.checkout("latest")
    assert cout["head"] == h2
    assert tc.chain.head() == h2


def test_generate_anchor(tmp_path):
    tc = TrustChain(
        config=TrustChainConfig(chain_storage="file", chain_dir=str(tmp_path))
    )

    tc.sign("test", {"step": 1})
    anchor = tc.chain.generate_anchor()

    assert anchor["format"] == "tc-anchor"
    assert anchor["chain_valid"] is True
    assert "chain_sha256" in anchor
    assert anchor["length"] == 1
