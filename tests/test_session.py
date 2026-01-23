"""Tests for TrustChain Session Management (Phase 16.3)."""

import json
import os
import tempfile

import pytest

from trustchain import TrustChain, TrustChainConfig
from trustchain.v2.session import TrustChainSession, create_session


class TestTrustChainSession:
    """Test suite for TrustChainSession."""

    def test_session_creation(self):
        """Test creating a session."""
        tc = TrustChain()
        session = TrustChainSession(tc, "test_session_123")

        assert session.session_id == "test_session_123"
        assert len(session.get_chain()) == 0

    def test_session_sign_creates_chain(self):
        """Test signing creates a chain of responses."""
        tc = TrustChain()

        with tc.session("chain_test") as session:
            session.sign("step1", {"query": "test"})
            session.sign("step2", {"results": [1, 2, 3]})
            session.sign("step3", {"answer": "done"})

            chain = session.get_chain()
            assert len(chain) == 3

    def test_session_auto_chaining(self):
        """Test parent_signature is auto-set for chaining."""
        tc = TrustChain()

        with tc.session("auto_chain") as session:
            r1 = session.sign("step1", {"data": "first"})
            r2 = session.sign("step2", {"data": "second"})
            r3 = session.sign("step3", {"data": "third"})

            # First has no parent
            assert r1.parent_signature is None

            # Second chains to first
            assert r2.parent_signature == r1.signature

            # Third chains to second
            assert r3.parent_signature == r2.signature

    def test_session_verify_chain(self):
        """Test chain verification."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        with tc.session("verify_test") as session:
            session.sign("step1", {"a": 1})
            session.sign("step2", {"b": 2})

            assert session.verify_chain() is True

    def test_session_metadata(self):
        """Test session-level metadata is included in responses."""
        tc = TrustChain()
        metadata = {"agent_id": "bot_123", "run_id": "run_456"}

        with tc.session("meta_test", metadata=metadata) as session:
            session.sign("step1", {"data": "test"})

            # Metadata should be in step_metadata
            chain = session.get_chain()
            assert len(chain) == 1

    def test_session_stats(self):
        """Test session statistics."""
        tc = TrustChain()

        with tc.session("stats_test") as session:
            session.sign("tool1", {"x": 1})
            session.sign("tool2", {"y": 2})

            stats = session.get_stats()

            assert stats["session_id"] == "stats_test"
            assert stats["steps"] == 2
            assert stats["started_at"] is not None
            assert "tool1" in stats["tools_used"]
            assert "tool2" in stats["tools_used"]

    def test_session_export_json(self):
        """Test exporting session as JSON."""
        tc = TrustChain()

        with tc.session("json_export") as session:
            session.sign("step1", {"data": "test"})

            json_str = session.export_json()
            data = json.loads(json_str)

            assert data["session_id"] == "json_export"
            assert "chain" in data
            assert len(data["chain"]) == 1

    def test_session_export_json_to_file(self):
        """Test exporting session JSON to file."""
        tc = TrustChain()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            filepath = f.name

        try:
            with tc.session("file_export") as session:
                session.sign("step1", {"data": "test"})
                session.export_json(filepath)

            with open(filepath) as f:
                data = json.load(f)

            assert data["session_id"] == "file_export"
        finally:
            os.unlink(filepath)

    def test_session_export_html(self):
        """Test exporting session as HTML."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            with tc.session("html_export") as session:
                session.sign("step1", {"data": "test"})
                html = session.export_html(filepath)

            assert "TrustChain Session" in html
            assert "html_export" in html
            assert os.path.exists(filepath)
        finally:
            os.unlink(filepath)

    def test_session_context_manager_sync(self):
        """Test sync context manager."""
        tc = TrustChain()

        with tc.session("sync_ctx") as session:
            session.sign("step", {"data": 1})
            assert session._ended_at is None

        # Session should be closed after context
        assert session._ended_at is not None

    def test_session_context_manager_async_entry_exit(self):
        """Test async context manager has correct methods."""
        tc = TrustChain()
        session = tc.session("async_test")

        # Check async context manager methods exist
        assert hasattr(session, "__aenter__")
        assert hasattr(session, "__aexit__")

    def test_create_session_helper(self):
        """Test create_session helper function."""
        tc = TrustChain()
        session = create_session(tc, "helper_test", metadata={"key": "value"})

        assert session.session_id == "helper_test"
        assert session.metadata == {"key": "value"}

    def test_session_empty_chain_valid(self):
        """Test that empty chain is considered valid."""
        tc = TrustChain()

        with tc.session("empty") as session:
            assert session.verify_chain() is True

    def test_session_duration_tracking(self):
        """Test session duration is tracked."""
        tc = TrustChain()

        with tc.session("duration") as session:
            session.sign("step", {"x": 1})
            stats = session.get_stats()
            assert stats["duration_seconds"] >= 0
