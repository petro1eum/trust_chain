"""Tests for trustchain/ui/explorer.py - Audit Trail UI."""

import os
import pytest
import json
from pathlib import Path

from trustchain import TrustChain
from trustchain.ui.explorer import ChainExplorer, export_chain_graph


class TestChainExplorer:
    """Test ChainExplorer class."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    @pytest.fixture
    def chain(self, tc):
        """Create a sample chain of operations."""
        chain = []
        parent_sig = None

        operations = [
            ("login", {"user": "alice"}),
            ("query", {"table": "users"}),
            ("update", {"id": 1, "name": "Alice"}),
        ]

        for tool_id, data in operations:
            resp = tc._signer.sign(tool_id, data, parent_signature=parent_sig)
            chain.append(resp)
            parent_sig = resp.signature

        return chain

    def test_create_explorer(self, chain, tc):
        explorer = ChainExplorer(chain, tc)

        assert explorer.responses == chain
        assert explorer.tc == tc

    def test_create_empty_explorer(self, tc):
        explorer = ChainExplorer(tc=tc)

        assert explorer.responses == []

    def test_add_response(self, tc):
        explorer = ChainExplorer(tc=tc)

        resp = tc._signer.sign("test", {"value": 1})
        explorer.add_response(resp)

        assert len(explorer.responses) == 1


class TestHTMLExport:
    """Test HTML export functionality."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    @pytest.fixture
    def chain(self, tc):
        chain = []
        for i in range(3):
            resp = tc._signer.sign(f"tool_{i}", {"step": i})
            chain.append(resp)
        return chain

    @pytest.fixture
    def temp_html(self, tmp_path):
        return tmp_path / "test_report.html"

    def test_export_creates_file(self, chain, tc, temp_html):
        explorer = ChainExplorer(chain, tc)
        path = explorer.export_html(str(temp_html))

        assert os.path.exists(path)
        assert temp_html.exists()

    def test_export_returns_path(self, chain, tc, temp_html):
        explorer = ChainExplorer(chain, tc)
        path = explorer.export_html(str(temp_html))

        assert path == str(temp_html)

    def test_html_contains_title(self, chain, tc, temp_html):
        explorer = ChainExplorer(chain, tc)
        explorer.export_html(str(temp_html))

        content = temp_html.read_text()
        assert "TrustChain" in content
        assert "Audit Report" in content

    def test_html_contains_operations(self, chain, tc, temp_html):
        explorer = ChainExplorer(chain, tc)
        explorer.export_html(str(temp_html))

        content = temp_html.read_text()
        assert "tool_0" in content
        assert "tool_1" in content
        assert "tool_2" in content

    def test_html_contains_signatures(self, chain, tc, temp_html):
        explorer = ChainExplorer(chain, tc)
        explorer.export_html(str(temp_html))

        content = temp_html.read_text()
        assert "Signature" in content

    def test_html_contains_stats(self, chain, tc, temp_html):
        explorer = ChainExplorer(chain, tc)
        explorer.export_html(str(temp_html))

        content = temp_html.read_text()
        assert "Operations" in content
        assert "Verified" in content

    def test_html_no_emojis(self, chain, tc, temp_html):
        explorer = ChainExplorer(chain, tc)
        explorer.export_html(str(temp_html))

        content = temp_html.read_text()
        # No common emojis
        assert "\U0001f512" not in content  # lock emoji
        assert "\U0001f511" not in content  # key emoji
        assert "\U0001f517" not in content  # link emoji


class TestJSONExport:
    """Test JSON export functionality."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    @pytest.fixture
    def chain(self, tc):
        chain = []
        parent_sig = None

        for i in range(3):
            resp = tc._signer.sign(f"op_{i}", {"value": i}, parent_signature=parent_sig)
            chain.append(resp)
            parent_sig = resp.signature

        return chain

    def test_to_json(self, chain, tc):
        explorer = ChainExplorer(chain, tc)
        json_str = explorer.to_json()

        assert isinstance(json_str, str)

    def test_json_parseable(self, chain, tc):
        explorer = ChainExplorer(chain, tc)
        json_str = explorer.to_json()

        data = json.loads(json_str)
        assert isinstance(data, list)
        assert len(data) == 3

    def test_json_contains_fields(self, chain, tc):
        explorer = ChainExplorer(chain, tc)
        json_str = explorer.to_json()
        data = json.loads(json_str)

        item = data[0]
        assert "tool_id" in item
        assert "signature" in item
        assert "timestamp" in item
        assert "data" in item

    def test_json_contains_parent_signature(self, chain, tc):
        explorer = ChainExplorer(chain, tc)
        json_str = explorer.to_json()
        data = json.loads(json_str)

        # First item has no parent
        assert data[0]["parent_signature"] is None

        # Second item has parent
        assert data[1]["parent_signature"] is not None
        assert data[1]["parent_signature"] == data[0]["signature"]


class TestExportChainGraphFunction:
    """Test convenience function."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    @pytest.fixture
    def chain(self, tc):
        return [tc._signer.sign("test", {"x": 1})]

    @pytest.fixture
    def temp_html(self, tmp_path):
        return tmp_path / "graph.html"

    def test_export_chain_graph(self, tc, chain, temp_html):
        path = export_chain_graph(tc, chain, str(temp_html))

        assert os.path.exists(path)
        assert temp_html.exists()


class TestVerificationDisplay:
    """Test verification status in reports."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_verified_operations_shown(self, tc, tmp_path):
        chain = [tc._signer.sign("test", {"value": 1})]
        explorer = ChainExplorer(chain, tc)

        path = tmp_path / "report.html"
        explorer.export_html(str(path))

        content = path.read_text()
        assert "VERIFIED" in content

    def test_multiple_operations_verified(self, tc, tmp_path):
        chain = []
        for i in range(5):
            resp = tc._signer.sign(f"op_{i}", {"i": i})
            chain.append(resp)

        explorer = ChainExplorer(chain, tc)
        path = tmp_path / "report.html"
        explorer.export_html(str(path))

        content = path.read_text()
        # All 5 should be verified
        assert content.count("VERIFIED") >= 5


class TestChainLinkDisplay:
    """Test chain link display in reports."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_chain_links_shown(self, tc, tmp_path):
        chain = []
        parent_sig = None

        for i in range(3):
            resp = tc._signer.sign("op", {"i": i}, parent_signature=parent_sig)
            chain.append(resp)
            parent_sig = resp.signature

        explorer = ChainExplorer(chain, tc)
        path = tmp_path / "report.html"
        explorer.export_html(str(path))

        content = path.read_text()
        assert "Parent" in content or "Chain Links" in content
