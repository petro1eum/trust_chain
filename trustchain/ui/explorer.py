"""Audit Trail UI - TrustChain Pro Feature.

This module provides HTML/PDF export for audit trail visualization.

NOTE: This feature requires TrustChain Pro license.
Get a license at https://trustchain.dev/pro
"""

from typing import Any


class _ProFeatureStub:
    """Stub class that raises import error on instantiation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise ImportError(
            "Audit Trail Export requires TrustChain Pro. "
            "Upgrade at https://trustchain.dev/pro\n\n"
            "Usage:\n"
            "  pip install trustchain-pro\n"
            "  from trustchain_pro import ChainExplorer"
        )


# Stub exports that raise ImportError
ChainExplorer = _ProFeatureStub


def export_chain_graph(*args: Any, **kwargs: Any) -> Any:
    """Export chain as HTML - requires TrustChain Pro."""
    raise ImportError(
        "Audit Trail Export requires TrustChain Pro. "
        "Upgrade at https://trustchain.dev/pro"
    )


__all__ = [
    "ChainExplorer",
    "export_chain_graph",
]
