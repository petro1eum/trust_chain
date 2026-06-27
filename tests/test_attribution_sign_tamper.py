"""E2E: attribution in signed metadata is tamper-evident."""

from __future__ import annotations

import dataclasses
import tempfile

from trustchain import TrustChain, TrustChainConfig
from trustchain.attribution import ATTRIBUTION_METADATA_KEY, build_attribution_metadata


def test_tampered_attribution_metadata_fails_verify():
    with tempfile.TemporaryDirectory() as td:
        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=td,
                enable_nonce=False,
            )
        )
        meta = {
            ATTRIBUTION_METADATA_KEY: build_attribution_metadata(
                [
                    {"category": "human", "weight": 0.7},
                    {"category": "company_ai", "weight": 0.3},
                ],
                consumption={"tokens_cost": 12.0},
            )
        }
        signed = tc.sign(
            tool_id="attribution-demo", data={"result": "ok"}, metadata=meta
        )
        assert tc.verify(signed) is True

        tampered_meta = dict(signed.metadata or {})
        tampered_meta[ATTRIBUTION_METADATA_KEY] = build_attribution_metadata(
            [{"category": "human", "weight": 1.0}]
        )
        tampered = dataclasses.replace(signed, metadata=tampered_meta)
        assert tc.verify(tampered) is False
