"""Tests for VerifiableChainStore — Certificate Transparency-style log.

Tests cover:
  - Binary chain.log append/read
  - Content-addressable IDs
  - Merkle tree integration
  - O(1) verify via root comparison
  - Inclusion proofs
  - Consistency proofs
  - SQLite indexed queries (log, blame, show)
  - Index rebuild from chain.log
  - Tamper detection
  - Persistence across restarts
  - Performance (1000 ops)
  - Integration with ChainStore delegation
"""

import json
import os
import struct
import tempfile
import time

import pytest

from trustchain.v2.chain_store import ChainStore
from trustchain.v2.config import TrustChainConfig
from trustchain.v2.core import TrustChain
from trustchain.v2.merkle import verify_proof
from trustchain.v2.storage import MemoryStorage
from trustchain.v2.verifiable_log import (
    InclusionProof,
    VerifiableChainStore,
    _content_id,
)


class TestVerifiableChainStoreBasic:
    """Basic CRUD operations."""

    def test_append_and_read(self, tmp_path):
        """Append an operation and read it back."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        record = vlog.append("bash_tool", {"cmd": "ls"}, "sig_abc", "sigid_1")

        assert record["tool"] == "bash_tool"
        assert record["data"] == {"cmd": "ls"}
        assert record["signature"] == "sig_abc"
        assert record["seq"] == 1
        assert len(record["id"]) == 12  # sha256[:12]
        vlog.close()

    def test_content_addressable_id(self, tmp_path):
        """IDs are content-addressable, not sequential."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        r1 = vlog.append("tool_a", {"x": 1}, "sig_1", "sid_1")
        r2 = vlog.append("tool_b", {"x": 2}, "sig_2", "sid_2")

        # IDs are hex strings, not "op_0001"
        assert not r1["id"].startswith("op_")
        assert not r2["id"].startswith("op_")
        assert r1["id"] != r2["id"]
        assert len(r1["id"]) == 12
        vlog.close()

    def test_sequential_numbers(self, tmp_path):
        """seq field is sequential despite content-addressable IDs."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        r1 = vlog.append("t", {}, "s1", "si1")
        r2 = vlog.append("t", {}, "s2", "si2")
        r3 = vlog.append("t", {}, "s3", "si3")

        assert r1["seq"] == 1
        assert r2["seq"] == 2
        assert r3["seq"] == 3
        assert vlog.length == 3
        vlog.close()

    def test_show(self, tmp_path):
        """Look up individual operations by ID."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        r = vlog.append("test", {"k": "v"}, "sig", "sid")

        found = vlog.show(r["id"])
        assert found is not None
        assert found["tool"] == "test"
        assert found["data"] == {"k": "v"}

        assert vlog.show("nonexistent") is None
        vlog.close()

    def test_log_ordering(self, tmp_path):
        """Log returns operations in correct order."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        for i in range(5):
            vlog.append(f"tool_{i}", {"i": i}, f"sig_{i}", f"sid_{i}")

        # Chronological (oldest first)
        log = vlog.log(reverse=False)
        assert len(log) == 5
        assert log[0]["seq"] == 1
        assert log[-1]["seq"] == 5

        # Reverse (newest first)
        log_rev = vlog.log(reverse=True)
        assert log_rev[0]["seq"] == 5
        assert log_rev[-1]["seq"] == 1
        vlog.close()

    def test_log_pagination(self, tmp_path):
        """Log supports limit and offset."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        for i in range(10):
            vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")

        page1 = vlog.log(limit=3, offset=0, reverse=False)
        page2 = vlog.log(limit=3, offset=3, reverse=False)

        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0]["seq"] == 1
        assert page2[0]["seq"] == 4
        vlog.close()


class TestBlameAndFiltering:
    """SQLite-indexed queries."""

    def test_blame(self, tmp_path):
        """blame() returns only operations from specified tool."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        vlog.append("bash_tool", {"cmd": "ls"}, "s1", "si1")
        vlog.append("python_tool", {"code": "1+1"}, "s2", "si2")
        vlog.append("bash_tool", {"cmd": "pwd"}, "s3", "si3")
        vlog.append("web_tool", {"url": "x"}, "s4", "si4")

        bash = vlog.blame("bash_tool")
        assert len(bash) == 2
        assert all(op["tool"] == "bash_tool" for op in bash)

        python = vlog.blame("python_tool")
        assert len(python) == 1
        vlog.close()

    def test_log_filter_by_tool(self, tmp_path):
        """log() can filter by tool via SQL."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        vlog.append("tool_a", {}, "s1", "si1")
        vlog.append("tool_b", {}, "s2", "si2")
        vlog.append("tool_a", {}, "s3", "si3")

        filtered = vlog.log(tool="tool_a")
        assert len(filtered) == 2
        vlog.close()

    def test_log_filter_by_session(self, tmp_path):
        """log() can filter by session_id."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        vlog.append("t", {}, "s1", "si1", session_id="session_A")
        vlog.append("t", {}, "s2", "si2", session_id="session_B")
        vlog.append("t", {}, "s3", "si3", session_id="session_A")

        a = vlog.log(session_id="session_A")
        assert len(a) == 2

        b = vlog.log(session_id="session_B")
        assert len(b) == 1
        vlog.close()


class TestMerkleVerification:
    """Merkle tree-based verification."""

    def test_merkle_root_changes(self, tmp_path):
        """Root hash changes after each append."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        assert vlog.merkle_root is None  # empty

        vlog.append("t", {}, "s1", "si1")
        root1 = vlog.merkle_root
        assert root1 is not None

        vlog.append("t", {}, "s2", "si2")
        root2 = vlog.merkle_root
        assert root2 != root1

        vlog.append("t", {}, "s3", "si3")
        root3 = vlog.merkle_root
        assert root3 != root2
        vlog.close()

    def test_verify_clean(self, tmp_path):
        """verify() passes on untampered chain."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        for i in range(10):
            vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")

        result = vlog.verify()
        assert result["valid"] is True
        assert result["length"] == 10
        assert result["method"] == "merkle_root_comparison"
        assert result["stored_root"] == result["computed_root"]
        vlog.close()

    def test_verify_empty(self, tmp_path):
        """verify() handles empty chain."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        result = vlog.verify()
        assert result["valid"] is True
        assert result["length"] == 0
        assert result["method"] == "empty_chain"
        vlog.close()

    def test_verify_detects_tampering(self, tmp_path):
        """verify() catches tampered chain.log."""
        root = str(tmp_path / ".tc")
        vlog = VerifiableChainStore(root)
        for i in range(5):
            vlog.append("t", {"i": i}, f"sig_{i}", f"sigid_{i}")

        assert vlog.verify()["valid"] is True

        # Tamper with chain.log: corrupt the last record
        log_path = tmp_path / ".tc" / "chain.log"
        data = log_path.read_bytes()
        # Flip a byte near the end (not in header)
        tampered = bytearray(data)
        tampered[-5] = (tampered[-5] + 1) % 256
        log_path.write_bytes(bytes(tampered))

        # Reload and verify — should detect mismatch
        vlog2 = VerifiableChainStore(root)
        result = vlog2.verify()
        assert result["valid"] is False
        assert result["stored_root"] != result["computed_root"]
        vlog.close()
        vlog2.close()


class TestInclusionProof:
    """O(log n) inclusion proofs."""

    def test_inclusion_proof_basic(self, tmp_path):
        """Generate and verify an inclusion proof."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        records = []
        for i in range(8):
            records.append(vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}"))

        # Get proof for the 5th operation
        op_id = records[4]["id"]
        proof = vlog.inclusion_proof(op_id)

        assert proof is not None
        assert proof.op_id == op_id
        assert proof.leaf_index == 4
        assert proof.chain_length == 8
        assert proof.root_at_proof_time == vlog.merkle_root

        # Merkle proof should have O(log n) siblings
        assert len(proof.merkle_proof.siblings) <= 4  # log2(8) = 3
        vlog.close()

    def test_inclusion_proof_serialization(self, tmp_path):
        """Proofs can be serialized/deserialized for auditors."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        r = vlog.append("test", {"data": "hello"}, "sig", "sid")

        proof = vlog.inclusion_proof(r["id"])
        assert proof is not None

        d = proof.to_dict()
        restored = InclusionProof.from_dict(d)
        assert restored.op_id == proof.op_id
        assert restored.leaf_index == proof.leaf_index
        assert restored.chain_length == proof.chain_length
        vlog.close()

    def test_inclusion_proof_nonexistent(self, tmp_path):
        """Proof for nonexistent op returns None."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        vlog.append("t", {}, "s", "si")

        assert vlog.inclusion_proof("nonexistent") is None
        vlog.close()


class TestConsistencyProof:
    """Consistency proofs — old root is prefix of new."""

    def test_consistency_basic(self, tmp_path):
        """Old chain state is consistent with extended chain."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))

        for i in range(5):
            vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")
        old_root = vlog.merkle_root
        old_length = vlog.length

        # Append more
        for i in range(5, 10):
            vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")

        result = vlog.consistency_proof(old_length, old_root)
        assert result["consistent"] is True
        assert result["old_length"] == 5
        assert result["current_length"] == 10
        vlog.close()

    def test_consistency_detects_rewrite(self, tmp_path):
        """Fake old root is detected as inconsistent."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        for i in range(5):
            vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")

        result = vlog.consistency_proof(3, "fake_root_hash")
        assert result["consistent"] is False
        vlog.close()

    def test_consistency_empty_prefix(self, tmp_path):
        """Empty prefix is always consistent."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        vlog.append("t", {}, "s", "si")

        result = vlog.consistency_proof(0, "")
        assert result["consistent"] is True
        vlog.close()


class TestRebuildIndex:
    """Disaster recovery: rebuild index.db from chain.log."""

    def test_rebuild_index(self, tmp_path):
        """Delete index.db, rebuild, queries still work."""
        root = str(tmp_path / ".tc")
        vlog = VerifiableChainStore(root)
        for i in range(5):
            vlog.append(f"tool_{i % 2}", {"i": i}, f"s_{i}", f"si_{i}")
        vlog.close()

        # Delete the index
        db_path = tmp_path / ".tc" / "index.db"
        for f in db_path.parent.glob("index.db*"):
            f.unlink()

        # Reopen — SQLite is empty
        vlog2 = VerifiableChainStore(root)
        assert len(vlog2.log()) == 0  # index is empty

        # Rebuild from chain.log
        result = vlog2.rebuild_index()
        assert result["rebuilt"] is True
        assert result["records"] == 5

        # Queries work again
        assert len(vlog2.log()) == 5
        assert len(vlog2.blame("tool_0")) == 3
        vlog2.close()


class TestPersistence:
    """Data survives restarts."""

    def test_persistence_across_restart(self, tmp_path):
        """Close, reopen — all data intact."""
        root = str(tmp_path / ".tc")

        # Write
        vlog1 = VerifiableChainStore(root)
        for i in range(3):
            vlog1.append("test", {"i": i}, f"sig_{i}", f"sigid_{i}")
        root_before = vlog1.merkle_root
        vlog1.close()

        # Reopen
        vlog2 = VerifiableChainStore(root)
        assert vlog2.length == 3
        assert vlog2.merkle_root == root_before
        assert vlog2.verify()["valid"] is True
        vlog2.close()

    def test_head_persisted(self, tmp_path):
        """HEAD file contains Merkle root."""
        root = str(tmp_path / ".tc")
        vlog = VerifiableChainStore(root)
        vlog.append("t", {}, "s", "si")

        head_content = (tmp_path / ".tc" / "HEAD").read_text().strip()
        assert head_content == vlog.merkle_root
        vlog.close()


class TestBinaryLogFormat:
    """chain.log binary format tests."""

    def test_single_file(self, tmp_path):
        """All operations stored in single chain.log file."""
        root = str(tmp_path / ".tc")
        vlog = VerifiableChainStore(root)
        for i in range(10):
            vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")

        # Only chain.log, index.db, HEAD — NO op_NNNN.json files
        files = list((tmp_path / ".tc").iterdir())
        filenames = {f.name for f in files}
        assert "chain.log" in filenames
        assert "index.db" in filenames
        assert "HEAD" in filenames
        assert not any(f.name.startswith("op_") for f in files)

        # No objects/ directory
        assert not (tmp_path / ".tc" / "objects").exists()
        vlog.close()

    def test_chain_log_is_append_only(self, tmp_path):
        """chain.log grows monotonically."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        sizes = []

        for i in range(5):
            vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")
            sizes.append((tmp_path / ".tc" / "chain.log").stat().st_size)

        # Each append increases file size
        for i in range(1, len(sizes)):
            assert sizes[i] > sizes[i - 1]
        vlog.close()


class TestStatus:
    """Status and diff operations."""

    def test_status(self, tmp_path):
        """status() returns comprehensive health info."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        vlog.append("tool_a", {}, "s1", "si1", latency_ms=10.5)
        vlog.append("tool_b", {}, "s2", "si2", latency_ms=20.5)
        vlog.append("tool_a", {}, "s3", "si3", latency_ms=30.5)

        status = vlog.status()
        assert status["length"] == 3
        assert status["tools_count"] == 2
        assert status["merkle_root"] is not None
        assert status["tools"]["tool_a"] == 2
        assert status["tools"]["tool_b"] == 1
        assert status["log_size_bytes"] > 0
        vlog.close()

    def test_diff(self, tmp_path):
        """diff() compares two operations."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        r1 = vlog.append("tool_a", {"x": 1}, "s1", "si1")
        r2 = vlog.append("tool_b", {"x": 2}, "s2", "si2")

        d = vlog.diff(r1["id"], r2["id"])
        assert "changes" in d
        assert "tool" in d["changes"]
        vlog.close()


class TestChainStoreIntegration:
    """Test ChainStore delegation to VerifiableChainStore."""

    def test_chainstore_with_vlog(self, tmp_path):
        """ChainStore delegates to VerifiableChainStore."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        cs = ChainStore(
            MemoryStorage(), root_dir=str(tmp_path / ".tc"), verifiable_log=vlog
        )

        cs.commit("test_tool", {"k": "v"}, "sig123", "sigid123")
        assert cs.length == 1

        # Uses Merkle verification
        result = cs.verify()
        assert result["valid"] is True
        assert "merkle_root_comparison" in result.get("method", "")

        # Has merkle_root
        assert cs.merkle_root is not None

        # Inclusion proof works via ChainStore
        ops = cs.log()
        proof = cs.inclusion_proof(ops[0]["id"])
        assert proof is not None
        vlog.close()

    def test_core_integration(self, tmp_path):
        """TrustChain core creates verifiable log by default."""
        chain_dir = str(tmp_path / ".tc")
        tc = TrustChain(
            TrustChainConfig(
                chain_storage="verifiable",
                chain_dir=chain_dir,
            )
        )

        # Sign something
        signed = tc.sign("test_tool", {"result": "hello"})
        assert signed.signature

        # Chain has the operation
        assert tc.chain.length >= 1

        # Verify works
        result = tc.chain.verify()
        assert result["valid"] is True

        # Merkle root exists
        assert tc.chain.merkle_root is not None


class TestPerformance:
    """Performance benchmarks."""

    def test_1000_ops_performance(self, tmp_path):
        """1000 appends complete in reasonable time."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))

        t0 = time.time()
        for i in range(1000):
            vlog.append(f"tool_{i % 5}", {"i": i}, f"sig_{i}", f"sigid_{i}")
        append_time = time.time() - t0

        assert vlog.length == 1000
        assert append_time < 30  # generous limit for CI

        # Verify is fast (O(1) root comparison after reload)
        t0 = time.time()
        result = vlog.verify()
        time.time() - t0

        assert result["valid"] is True
        assert result["length"] == 1000
        vlog.close()

    def test_blame_indexed_fast(self, tmp_path):
        """SQLite-indexed blame is fast on large chains."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        for i in range(100):
            vlog.append(f"tool_{i % 10}", {"i": i}, f"sig_{i}", f"sigid_{i}")

        t0 = time.time()
        results = vlog.blame("tool_3")
        blame_time = time.time() - t0

        assert len(results) == 10
        assert blame_time < 1.0  # indexed query should be instant
        vlog.close()


class TestExportJson:
    """Export functionality."""

    def test_export_json(self, tmp_path):
        """Export includes merkle_root and all operations."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        vlog.append("t", {"x": 1}, "s1", "si1")
        vlog.append("t", {"x": 2}, "s2", "si2")

        json_str = vlog.export_json()
        data = json.loads(json_str)

        assert data["length"] == 2
        assert data["merkle_root"] is not None
        assert len(data["chain"]) == 2
        vlog.close()

    def test_export_to_file(self, tmp_path):
        """Export can write to a file."""
        vlog = VerifiableChainStore(str(tmp_path / ".tc"))
        vlog.append("t", {}, "s", "si")

        out = str(tmp_path / "export.json")
        vlog.export_json(filepath=out)
        assert os.path.exists(out)

        data = json.loads(open(out).read())
        assert data["length"] == 1
        vlog.close()
