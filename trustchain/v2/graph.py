"""Execution Graph - TrustChain Pro Feature.

This module provides DAG representation of agent execution
for forensic analysis, fork detection, and replay detection.

NOTE: This feature requires TrustChain Pro license.
Get a license at https://trustchain.dev/pro
"""


class _ProFeatureStub:
    """Stub class that raises import error on instantiation."""

    def __init__(self, *args, **kwargs):
        raise ImportError(
            "Execution Graph requires TrustChain Pro. "
            "Upgrade at https://trustchain.dev/pro\n\n"
            "Usage:\n"
            "  pip install trustchain-pro\n"
            "  from trustchain_pro import ExecutionGraph"
        )

    @classmethod
    def from_chain(cls, *args, **kwargs):
        raise ImportError(
            "Execution Graph requires TrustChain Pro. "
            "Upgrade at https://trustchain.dev/pro"
        )


# Stub exports that raise ImportError
ExecutionGraph = _ProFeatureStub
GraphNode = _ProFeatureStub
Fork = _ProFeatureStub
Replay = _ProFeatureStub
Orphan = _ProFeatureStub

__all__ = [
    "ExecutionGraph",
    "GraphNode",
    "Fork",
    "Replay",
    "Orphan",
]
