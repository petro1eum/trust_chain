"""Tests for Execution Graph (Phase 14)."""

import pytest

from trustchain import TrustChain, TrustChainConfig
from trustchain.v2.graph import ExecutionGraph, Fork, Orphan, Replay


class TestExecutionGraph:
    """Test execution graph functionality."""

    def test_from_chain(self):
        """Test building graph from chain."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        step1 = tc._signer.sign("search", {"query": "test"})
        step2 = tc._signer.sign(
            "analyze", {"count": 10}, parent_signature=step1.signature
        )
        step3 = tc._signer.sign(
            "report", {"summary": "done"}, parent_signature=step2.signature
        )

        graph = ExecutionGraph.from_chain([step1, step2, step3])

        assert len(graph.nodes) == 3
        assert len(graph.roots) == 1
        assert graph.roots[0].response.tool_id == "search"

    def test_detect_forks(self):
        """Test fork detection."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        root = tc._signer.sign("start", {"init": True})
        branch_a = tc._signer.sign(
            "path_a", {"choice": "A"}, parent_signature=root.signature
        )
        branch_b = tc._signer.sign(
            "path_b", {"choice": "B"}, parent_signature=root.signature
        )

        graph = ExecutionGraph.from_chain([root, branch_a, branch_b])
        forks = graph.detect_forks()

        assert len(forks) == 1
        assert forks[0].parent_tool == "start"
        assert len(forks[0].branches) == 2

    def test_detect_replays(self):
        """Test replay detection."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        # Same tool with same data multiple times
        resp1 = tc._signer.sign("payment", {"amount": 100})
        resp2 = tc._signer.sign("payment", {"amount": 100})
        resp3 = tc._signer.sign("payment", {"amount": 100})

        graph = ExecutionGraph.from_chain([resp1, resp2, resp3])
        replays = graph.detect_replays()

        assert len(replays) == 1
        assert replays[0].tool_id == "payment"
        assert len(replays[0].occurrences) == 3

    def test_detect_orphans(self):
        """Test orphan detection."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        # Response with non-existent parent
        orphan_resp = tc._signer.sign(
            "orphan", {"data": "lost"}, parent_signature="nonexistent_signature"
        )

        graph = ExecutionGraph.from_chain([orphan_resp])
        orphans = graph.detect_orphans()

        assert len(orphans) == 1
        assert orphans[0].missing_parent == "nonexistent_signature"

    def test_get_path(self):
        """Test path retrieval."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        step1 = tc._signer.sign("a", {})
        step2 = tc._signer.sign("b", {}, parent_signature=step1.signature)
        step3 = tc._signer.sign("c", {}, parent_signature=step2.signature)

        graph = ExecutionGraph.from_chain([step1, step2, step3])
        path = graph.get_path(step3.signature)

        assert len(path) == 3
        assert path[0].tool_id == "a"
        assert path[1].tool_id == "b"
        assert path[2].tool_id == "c"

    def test_get_stats(self):
        """Test statistics."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        step1 = tc._signer.sign("search", {})
        step2 = tc._signer.sign("analyze", {}, parent_signature=step1.signature)

        graph = ExecutionGraph.from_chain([step1, step2])
        stats = graph.get_stats()

        assert stats["total_nodes"] == 2
        assert stats["total_roots"] == 1
        assert stats["max_depth"] == 1
        assert stats["unique_tools"] == 2

    def test_export_mermaid(self):
        """Test Mermaid export."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        step1 = tc._signer.sign("start", {})
        step2 = tc._signer.sign("end", {}, parent_signature=step1.signature)

        graph = ExecutionGraph.from_chain([step1, step2])
        mermaid = graph.export_mermaid()

        assert "graph TD" in mermaid
        assert "start" in mermaid
        assert "end" in mermaid
        assert "-->" in mermaid

    def test_export_graphviz(self):
        """Test Graphviz export."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        step1 = tc._signer.sign("start", {})
        step2 = tc._signer.sign("end", {}, parent_signature=step1.signature)

        graph = ExecutionGraph.from_chain([step1, step2])
        dot = graph.export_graphviz()

        assert "digraph" in dot
        assert "->" in dot

    def test_to_dict(self):
        """Test dict export."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        step1 = tc._signer.sign("tool", {})
        graph = ExecutionGraph.from_chain([step1])
        d = graph.to_dict()

        assert "nodes" in d
        assert "roots" in d
        assert "stats" in d
        assert len(d["nodes"]) == 1
