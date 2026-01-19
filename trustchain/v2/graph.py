"""Execution Graph for TrustChain (Phase 14).

Note: Uses `from __future__ import annotations` for Python 3.8 compatibility.

DAG representation of agent execution for forensic analysis.
Supports fork detection, replay detection, and visualization.

Usage:
    from trustchain.v2.graph import ExecutionGraph

    graph = ExecutionGraph.from_chain(responses)
    forks = graph.detect_forks()
    graph.export_mermaid("execution.md")
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from .signer import SignedResponse


@dataclass
class GraphNode:
    """A node in the execution graph."""

    response: SignedResponse
    children: list[GraphNode] = field(default_factory=list)
    depth: int = 0

    @property
    def id(self) -> str:
        """Short ID for display."""
        return self.response.signature[:8]

    @property
    def tool_id(self) -> str:
        return self.response.tool_id

    @property
    def timestamp(self) -> float:
        return self.response.timestamp


@dataclass
class Fork:
    """A fork in the execution graph (multiple children from one parent)."""

    parent_signature: str
    parent_tool: str
    branches: list[SignedResponse]
    timestamp: float


@dataclass
class Replay:
    """A potential replay attack (same tool+args executed multiple times)."""

    tool_id: str
    data_hash: str
    occurrences: list[SignedResponse]


@dataclass
class Orphan:
    """An orphan response (references non-existent parent)."""

    response: SignedResponse
    missing_parent: str


class ExecutionGraph:
    """DAG representation of signed responses."""

    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.roots: list[GraphNode] = []
        self._signature_to_node: dict[str, GraphNode] = {}

    @classmethod
    def from_chain(cls, responses: list[SignedResponse]) -> ExecutionGraph:
        """Build graph from list of responses."""
        graph = cls()

        # Create nodes
        for resp in responses:
            node = GraphNode(response=resp)
            graph.nodes[resp.signature] = node
            graph._signature_to_node[resp.signature] = node

        # Link nodes
        for resp in responses:
            node = graph.nodes[resp.signature]

            if resp.parent_signature:
                parent_node = graph._signature_to_node.get(resp.parent_signature)
                if parent_node:
                    parent_node.children.append(node)
                    node.depth = parent_node.depth + 1
            else:
                graph.roots.append(node)

        return graph

    def detect_forks(self) -> list[Fork]:
        """Detect points where execution branched into multiple paths."""
        forks = []

        for sig, node in self.nodes.items():
            if len(node.children) > 1:
                forks.append(
                    Fork(
                        parent_signature=sig,
                        parent_tool=node.tool_id,
                        branches=[child.response for child in node.children],
                        timestamp=node.timestamp,
                    )
                )

        return forks

    def detect_replays(self) -> list[Replay]:
        """Detect potential replay attacks (same tool+data multiple times)."""
        # Group by tool_id + data hash
        groups: dict[str, list[SignedResponse]] = defaultdict(list)

        for node in self.nodes.values():
            data_str = str(node.response.data)
            key = f"{node.tool_id}:{hash(data_str)}"
            groups[key].append(node.response)

        replays = []
        for key, responses in groups.items():
            if len(responses) > 1:
                tool_id, data_hash = key.split(":", 1)
                replays.append(
                    Replay(tool_id=tool_id, data_hash=data_hash, occurrences=responses)
                )

        return replays

    def detect_orphans(self) -> list[Orphan]:
        """Detect responses that reference non-existent parents."""
        orphans = []

        for node in self.nodes.values():
            parent_sig = node.response.parent_signature
            if parent_sig and parent_sig not in self._signature_to_node:
                orphans.append(
                    Orphan(response=node.response, missing_parent=parent_sig)
                )

        return orphans

    def get_path(self, signature: str) -> list[SignedResponse]:
        """Get the path from root to a specific node."""
        path = []
        current = self._signature_to_node.get(signature)

        while current:
            path.insert(0, current.response)
            parent_sig = current.response.parent_signature
            current = self._signature_to_node.get(parent_sig) if parent_sig else None

        return path

    def get_stats(self) -> dict:
        """Get graph statistics."""
        depths = [node.depth for node in self.nodes.values()]
        tools = [node.tool_id for node in self.nodes.values()]

        return {
            "total_nodes": len(self.nodes),
            "total_roots": len(self.roots),
            "max_depth": max(depths) if depths else 0,
            "unique_tools": len(set(tools)),
            "forks": len(self.detect_forks()),
            "replays": len(self.detect_replays()),
            "orphans": len(self.detect_orphans()),
        }

    def export_mermaid(self, filepath: str | None = None) -> str:
        """Export graph as Mermaid diagram."""
        lines = ["graph TD"]

        # Add nodes
        for sig, node in self.nodes.items():
            short_id = sig[:8]
            tool = node.tool_id
            lines.append(f'    {short_id}["{tool}"]')

        # Add edges
        for sig, node in self.nodes.items():
            for child in node.children:
                parent_id = sig[:8]
                child_id = child.response.signature[:8]
                lines.append(f"    {parent_id} --> {child_id}")

        # Mark roots
        for root in self.roots:
            root_id = root.response.signature[:8]
            lines.append(f"    style {root_id} fill:#90EE90")

        # Mark forks
        for fork in self.detect_forks():
            fork_id = fork.parent_signature[:8]
            lines.append(f"    style {fork_id} fill:#FFD700")

        content = "\n".join(lines)

        if filepath:
            with open(filepath, "w") as f:
                f.write(f"```mermaid\n{content}\n```\n")

        return content

    def export_graphviz(self, filepath: str | None = None) -> str:
        """Export graph as Graphviz DOT format."""
        lines = ["digraph ExecutionGraph {", "    rankdir=TB;"]

        # Add nodes
        for sig, node in self.nodes.items():
            short_id = sig[:8]
            tool = node.tool_id
            ts = datetime.fromtimestamp(node.timestamp).strftime("%H:%M:%S")
            lines.append(f'    "{short_id}" [label="{tool}\\n{ts}"];')

        # Add edges
        for sig, node in self.nodes.items():
            for child in node.children:
                parent_id = sig[:8]
                child_id = child.response.signature[:8]
                lines.append(f'    "{parent_id}" -> "{child_id}";')

        lines.append("}")
        content = "\n".join(lines)

        if filepath:
            with open(filepath, "w") as f:
                f.write(content)

        return content

    def to_dict(self) -> dict:
        """Export graph as dictionary."""
        return {
            "nodes": [
                {
                    "signature": sig,
                    "tool_id": node.tool_id,
                    "timestamp": node.timestamp,
                    "depth": node.depth,
                    "parent": node.response.parent_signature,
                    "children": [c.response.signature for c in node.children],
                }
                for sig, node in self.nodes.items()
            ],
            "roots": [r.response.signature for r in self.roots],
            "stats": self.get_stats(),
        }
