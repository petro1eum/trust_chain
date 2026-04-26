"""Standards adapters for TrustChain evidence.

These adapters keep the native ``.tcreceipt`` and ``SignedResponse`` formats as
the source of truth while exporting deterministic JSON shapes for ecosystems
that use SCITT, W3C Verifiable Credentials, or in-toto/Sigstore.
"""

from trustchain.standards.intoto import (
    INTOTO_STATEMENT_TYPE,
    TRUSTCHAIN_PREDICATE_TYPE,
    to_intoto_statement,
    verify_intoto_statement_shape,
)
from trustchain.standards.scitt import (
    SCITT_AIR_JSON_PROFILE,
    SCITT_AIR_PAYLOAD_TYPE,
    to_scitt_air_json,
    verify_scitt_air_json,
)
from trustchain.standards.w3c_vc import (
    VC_CONTEXT,
    VC_PROOF_TYPE,
    VC_TYPE,
    receipt_from_w3c_vc,
    to_w3c_vc,
    verify_w3c_vc_shape,
)

__all__ = [
    "INTOTO_STATEMENT_TYPE",
    "SCITT_AIR_JSON_PROFILE",
    "SCITT_AIR_PAYLOAD_TYPE",
    "TRUSTCHAIN_PREDICATE_TYPE",
    "VC_CONTEXT",
    "VC_PROOF_TYPE",
    "VC_TYPE",
    "receipt_from_w3c_vc",
    "to_intoto_statement",
    "to_scitt_air_json",
    "to_w3c_vc",
    "verify_intoto_statement_shape",
    "verify_scitt_air_json",
    "verify_w3c_vc_shape",
]
