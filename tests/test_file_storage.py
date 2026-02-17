"""Tests for FileStorage + ChainStore (Git-like .trustchain/ persistence)."""

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from trustchain import TrustChain, TrustChainConfig
from trustchain.v2.chain_store import ChainStore
from trustchain.v2.storage import FileStorage, MemoryStorage


@pytest.fixture
def tmp_dir():
    """Create a temp directory for testing and clean up after."""
    d = tempfile.mkdtemp(prefix="tc_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


class TestFileStorage:
    """Tests for FileStorage (Git-like objects/ directory)."""

    def test_store_and_get(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        fs.store("key1", {"tool": "bash", "data": "hello"})
        result = fs.get("key1")
        assert result == {"tool": "bash", "data": "hello"}

    def test_get_missing_key(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        assert fs.get("nonexistent") is None

    def test_delete(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        fs.store("x", {"v": 1})
        assert fs.get("x") is not None
        fs.delete("x")
        assert fs.get("x") is None

    def test_clear(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        fs.store("a", 1)
        fs.store("b", 2)
        assert fs.size() == 2
        fs.clear()
        assert fs.size() == 0

    def test_list_all(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        fs.store("op_0001", {"tool": "bash"})
        fs.store("op_0002", {"tool": "view"})
        all_items = fs.list_all()
        assert len(all_items) == 2

    def test_ttl_expiration(self, tmp_dir):
        import time

        fs = FileStorage(tmp_dir)
        fs.store("ephemeral", "temp", ttl=0)  # expires immediately
        time.sleep(0.01)
        assert fs.get("ephemeral") is None

    def test_persistence_across_instances(self, tmp_dir):
        """Key test: data survives closing and reopening storage."""
        fs1 = FileStorage(tmp_dir)
        fs1.store("op_0001", {"tool": "bash", "data": "ls -la"})
        fs1.store("op_0002", {"tool": "view", "data": "file.txt"})

        # Create a new instance — should see existing data
        fs2 = FileStorage(tmp_dir)
        assert fs2.size() == 2
        assert fs2.get("op_0001") == {"tool": "bash", "data": "ls -la"}
        assert fs2.get("op_0002") == {"tool": "view", "data": "file.txt"}

    def test_directory_creation(self, tmp_dir):
        nested = f"{tmp_dir}/deep/nested/dir"
        fs = FileStorage(nested)
        fs.store("test", "value")
        assert Path(nested).exists()
        assert (Path(nested) / "objects").exists()

    def test_safe_key(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        fs.store("path/with/slashes", "data")
        assert fs.get("path/with/slashes") == "data"


class TestChainStore:
    """Tests for ChainStore (Git-like chain API)."""

    def test_commit_and_log(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        cs = ChainStore(fs, root_dir=tmp_dir)

        cs.commit(
            tool="bash_tool",
            data={"command": "ls -la"},
            signature="sig_001",
            signature_id="sid_001",
        )
        cs.commit(
            tool="view_file",
            data={"path": "/etc/hosts"},
            signature="sig_002",
            signature_id="sid_002",
            parent_signature="sig_001",
        )

        log = cs.log()
        assert len(log) == 2
        assert log[0]["tool"] == "bash_tool"
        assert log[1]["tool"] == "view_file"

    def test_head_tracking(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        cs = ChainStore(fs, root_dir=tmp_dir)

        assert cs.head() is None
        cs.commit(tool="t1", data={}, signature="AAA", signature_id="s1")
        assert cs.head() == "AAA"
        cs.commit(
            tool="t2",
            data={},
            signature="BBB",
            signature_id="s2",
            parent_signature="AAA",
        )
        assert cs.head() == "BBB"

    def test_head_persists_to_file(self, tmp_dir):
        """HEAD file persists across instances."""
        fs = FileStorage(tmp_dir)
        cs1 = ChainStore(fs, root_dir=tmp_dir)
        cs1.commit(tool="t1", data={}, signature="HEAD_SIG", signature_id="s1")

        # New instance should read HEAD from file
        fs2 = FileStorage(tmp_dir)
        cs2 = ChainStore(fs2, root_dir=tmp_dir)
        assert cs2.head() == "HEAD_SIG"
        assert cs2.length == 1

    def test_verify_valid_chain(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        cs = ChainStore(fs, root_dir=tmp_dir)

        cs.commit(tool="t1", data={}, signature="A", signature_id="s1")
        cs.commit(
            tool="t2", data={}, signature="B", signature_id="s2", parent_signature="A"
        )
        cs.commit(
            tool="t3", data={}, signature="C", signature_id="s3", parent_signature="B"
        )

        result = cs.verify()
        assert result["valid"] is True
        assert result["length"] == 3
        assert result["broken_links"] == []

    def test_verify_broken_chain(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        cs = ChainStore(fs, root_dir=tmp_dir)

        cs.commit(tool="t1", data={}, signature="A", signature_id="s1")
        cs.commit(
            tool="t2",
            data={},
            signature="B",
            signature_id="s2",
            parent_signature="WRONG",
        )

        result = cs.verify()
        assert result["valid"] is False
        assert len(result["broken_links"]) == 1

    def test_blame(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        cs = ChainStore(fs, root_dir=tmp_dir)

        cs.commit(
            tool="bash_tool", data={"cmd": "ls"}, signature="A", signature_id="s1"
        )
        cs.commit(
            tool="view_file",
            data={"path": "x"},
            signature="B",
            signature_id="s2",
            parent_signature="A",
        )
        cs.commit(
            tool="bash_tool",
            data={"cmd": "cat"},
            signature="C",
            signature_id="s3",
            parent_signature="B",
        )

        blame = cs.blame("bash_tool")
        assert len(blame) == 2
        assert all(op["tool"] == "bash_tool" for op in blame)

    def test_status(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        cs = ChainStore(fs, root_dir=tmp_dir)

        cs.commit(tool="t1", data={}, signature="A", signature_id="s1", latency_ms=100)
        cs.commit(
            tool="t2",
            data={},
            signature="B",
            signature_id="s2",
            latency_ms=200,
            parent_signature="A",
        )

        status = cs.status()
        assert status["length"] == 2
        assert "t1" in status["tools"]
        assert status["avg_latency_ms"] == 150.0

    def test_diff(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        cs = ChainStore(fs, root_dir=tmp_dir)

        cs.commit(tool="bash", data={"cmd": "ls"}, signature="A", signature_id="s1")
        cs.commit(
            tool="bash",
            data={"cmd": "cat"},
            signature="B",
            signature_id="s2",
            parent_signature="A",
        )

        d = cs.diff("op_0001", "op_0002")
        assert d["same_tool"] is True
        assert d["a"]["data"]["cmd"] == "ls"
        assert d["b"]["data"]["cmd"] == "cat"

    def test_session_refs(self, tmp_dir):
        fs = FileStorage(tmp_dir)
        cs = ChainStore(fs, root_dir=tmp_dir)

        cs.commit(
            tool="t1", data={}, signature="A", signature_id="s1", session_id="task_123"
        )
        cs.commit(
            tool="t2",
            data={},
            signature="B",
            signature_id="s2",
            session_id="task_456",
            parent_signature="A",
        )

        sessions = cs.sessions()
        assert "task_123" in sessions
        assert "task_456" in sessions

        assert cs.session_head("task_123") == "A"
        assert cs.session_head("task_456") == "B"


class TestTrustChainWithFileStorage:
    """Integration tests: TrustChain + FileStorage chain persistence."""

    def test_sign_auto_commits_to_chain(self, tmp_dir):
        tc = TrustChain(
            TrustChainConfig(
                chain_storage="file",
                chain_dir=tmp_dir,
            )
        )

        tc.sign("bash_tool", {"command": "echo hello"})
        tc.sign("view_file", {"path": "/tmp/test.txt"})

        log = tc.chain.log()
        assert len(log) == 2
        assert log[0]["tool"] == "bash_tool"
        assert log[1]["tool"] == "view_file"

    def test_auto_chaining_parent_signatures(self, tmp_dir):
        tc = TrustChain(
            TrustChainConfig(
                chain_storage="file",
                chain_dir=tmp_dir,
            )
        )

        tc.sign("step1", {"data": "first"})
        tc.sign("step2", {"data": "second"})
        tc.sign("step3", {"data": "third"})

        log = tc.chain.log()
        # First has no parent
        assert log[0]["parent_signature"] is None
        # Second links to first
        assert log[1]["parent_signature"] == log[0]["signature"]
        # Third links to second
        assert log[2]["parent_signature"] == log[1]["signature"]

    def test_chain_survives_restart(self, tmp_dir):
        """Critical test: operations persist across TrustChain instances."""
        # Instance 1: create operations
        tc1 = TrustChain(
            TrustChainConfig(
                chain_storage="file",
                chain_dir=tmp_dir,
                enable_nonce=False,
            )
        )
        tc1.sign("bash_tool", {"command": "ls"})
        tc1.sign("view_file", {"path": "README.md"})
        assert tc1.chain.length == 2

        # Instance 2: should see operations from instance 1
        tc2 = TrustChain(
            TrustChainConfig(
                chain_storage="file",
                chain_dir=tmp_dir,
                enable_nonce=False,
            )
        )
        assert tc2.chain.length == 2
        log = tc2.chain.log()
        assert log[0]["tool"] == "bash_tool"
        assert log[1]["tool"] == "view_file"

        # Verify chain integrity across restart
        result = tc2.chain.verify()
        assert result["valid"] is True

    def test_verify_produces_valid_chain(self, tmp_dir):
        tc = TrustChain(
            TrustChainConfig(
                chain_storage="file",
                chain_dir=tmp_dir,
            )
        )
        tc.sign("t1", {"a": 1})
        tc.sign("t2", {"b": 2})
        tc.sign("t3", {"c": 3})

        result = tc.chain.verify()
        assert result["valid"] is True
        assert result["length"] == 3

    def test_blame_works_with_real_signing(self, tmp_dir):
        tc = TrustChain(
            TrustChainConfig(
                chain_storage="file",
                chain_dir=tmp_dir,
            )
        )
        tc.sign("bash_tool", {"cmd": "ls"})
        tc.sign("view_file", {"path": "x"})
        tc.sign("bash_tool", {"cmd": "cat"})

        blame = tc.chain.blame("bash_tool")
        assert len(blame) == 2

    def test_memory_chain_no_persistence(self, tmp_dir):
        """Memory chain should work but not persist."""
        tc = TrustChain(
            TrustChainConfig(
                chain_storage="memory",
            )
        )
        tc.sign("t1", {"a": 1})
        assert tc.chain.length == 1

    def test_disable_chain(self, tmp_dir):
        """enable_chain=False should not record anything."""
        tc = TrustChain(
            TrustChainConfig(
                enable_chain=False,
            )
        )
        tc.sign("t1", {"a": 1})
        assert tc.chain.length == 0
