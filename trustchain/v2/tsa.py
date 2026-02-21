"""Timestamp Authority (TSA) - TrustChain Pro Feature.

This module provides RFC 3161 timestamp integration for independent,
verifiable timestamps from external trusted authorities.

NOTE: This feature requires TrustChain Pro license.
Get a license at https://trustchain.dev/pro
"""

from typing import Any


class _ProFeatureStub:
    """Stub class that raises import error on instantiation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise ImportError(
            "TSA Integration requires TrustChain Pro. "
            "Upgrade at https://trustchain.dev/pro\n\n"
            "Usage:\n"
            "  pip install trustchain-pro\n"
            "  from trustchain_pro import TSAClient"
        )


# Stub exports that raise ImportError
TSAClient = _ProFeatureStub
TSAResponse = _ProFeatureStub
TSAVerifyResult = _ProFeatureStub
TSAError = ImportError


def get_tsa_client(*args: Any, **kwargs: Any) -> Any:
    """Get a TSA client - requires TrustChain Pro."""
    raise ImportError(
        "TSA Integration requires TrustChain Pro. "
        "Upgrade at https://trustchain.dev/pro"
    )


# Keep provider list for documentation
TSA_PROVIDERS = {
    "freetsa": "https://freetsa.org/tsr",
    "digicert": "http://timestamp.digicert.com",
    "sectigo": "http://timestamp.sectigo.com",
    "comodo": "http://timestamp.comodoca.com",
    "globalsign": "http://timestamp.globalsign.com/tsa/r6advanced1",
}

__all__ = [
    "TSAClient",
    "TSAResponse",
    "TSAVerifyResult",
    "TSAError",
    "get_tsa_client",
    "TSA_PROVIDERS",
]
