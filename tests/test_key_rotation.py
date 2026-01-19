"""Tests for key rotation functionality."""

import json
import os
import tempfile

import pytest

from trustchain import TrustChain, TrustChainConfig


class TestKeyRotation:
    """Test key rotation functionality."""

    def test_rotate_keys_generates_new_key(self):
        """Verify rotate_keys() generates a new key pair."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))
        old_key = tc.get_key_id()
        new_key = tc.rotate_keys(save=False)

        assert old_key != new_key
        assert tc.get_key_id() == new_key

    def test_rotate_keys_saves_to_file(self):
        """Verify rotate_keys() saves to file when configured."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, "keys.json")

            tc = TrustChain(TrustChainConfig(key_file=key_file, enable_nonce=False))
            tc.save_keys()

            # Read initial key
            with open(key_file) as f:
                initial_data = json.load(f)

            # Rotate
            new_key = tc.rotate_keys(save=True)

            # Read new key
            with open(key_file) as f:
                new_data = json.load(f)

            assert initial_data["key_id"] != new_data["key_id"]
            assert new_data["key_id"] == new_key

    def test_rotate_keys_invalidates_old_signatures(self):
        """Verify old signatures cannot be verified after rotation."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        @tc.tool("test")
        def test_tool(x: int):
            return {"value": x}

        # Sign before rotation
        signed = test_tool(42)
        assert tc.verify(signed)

        # Rotate keys
        tc.rotate_keys(save=False)

        # Old signature should fail
        assert not tc.verify(signed)

    def test_export_public_key(self):
        """Verify export_public_key() returns valid Base64."""
        tc = TrustChain()
        pub_key = tc.export_public_key()

        assert isinstance(pub_key, str)
        assert len(pub_key) > 0

    def test_save_and_load_keys(self):
        """Verify keys can be saved and loaded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, "keys.json")

            # Create and save
            tc1 = TrustChain(TrustChainConfig(key_file=key_file, enable_nonce=False))
            tc1.save_keys()
            key_id = tc1.get_key_id()

            @tc1.tool("test")
            def test_tool(x: int):
                return {"value": x}

            signed = test_tool(42)

            # Load in new instance
            tc2 = TrustChain(TrustChainConfig(key_file=key_file, enable_nonce=False))

            assert tc2.get_key_id() == key_id
            assert tc2.verify(signed)
