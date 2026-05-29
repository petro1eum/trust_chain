"""Tests for org Intermediate CA with external public key."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trustchain.v2.x509_pki import TrustChainCA


def test_issue_intermediate_ca_external_key():
    root = TrustChainCA.create_root_ca(path_length=2)
    platform = root.issue_intermediate_ca(path_length=1)

    org_sk = Ed25519PrivateKey.generate()
    pk_b64 = base64.b64encode(
        org_sk.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    ).decode("ascii")

    org_ca = platform.issue_intermediate_ca(
        name="Acme Org CA",
        organization="Acme",
        path_length=0,
        public_key_b64=pk_b64,
        org_id="acme",
    )
    assert org_ca._private_key is None
    assert org_ca.certificate is not None
    from trustchain.v2.x509_pki import OID_ORG_ID

    ext = org_ca.certificate.extensions.get_extension_for_oid(OID_ORG_ID)
    assert ext.value.value == b"acme"

    # Platform-held org CA with generated key can issue leaf
    org_ca_with_key = platform.issue_intermediate_ca(
        name="Dev Org CA",
        organization="Dev",
        path_length=0,
        org_id="dev",
    )
    leaf = org_ca_with_key.issue_agent_cert(agent_id="dev-agent")
    assert leaf.agent_id == "dev-agent"
