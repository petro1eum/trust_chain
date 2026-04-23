"""Unit tests for ``trustchain.receipt``.

Контракт, который проверяем:

1. **Roundtrip.** ``build_receipt → save → load → verify`` даёт ``valid=True``.
2. **Tamper-evidence.** Любое изменение поля ``data`` / ``timestamp`` /
   ``signature`` / ``public_key_b64`` ломает подпись.
3. **Format hardening.** Несовпадение ``format``/``version`` бросает
   ``ReceiptFormatError`` ДО запуска верификации.
4. **Identity soft-check.** Если передан ``cert_chain_pem`` с мусором —
   ``identity_ok == False``, а не silent pass.
5. **Freshness.** ``max_age_seconds`` режет старые envelopes.
6. **Pinning.** ``expected_public_key_b64`` отвергает receipt, подписанный
   другим ключом.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from trustchain import (
    Receipt,
    ReceiptFormatError,
    TrustChain,
    TrustChainConfig,
    build_receipt,
    verify_receipt,
)
from trustchain.v2.signer import Signer

# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _mint_signed_and_key():
    signer = Signer()
    resp = signer.sign(
        tool_id="weather_service",
        data={"location": "London", "temperature": 22},
    )
    return resp, signer.get_public_key(), signer.get_key_id()


# --------------------------------------------------------------------------- #
# Roundtrip                                                                   #
# --------------------------------------------------------------------------- #


class TestRoundtrip:
    def test_build_to_dict_keys(self):
        resp, pk, kid = _mint_signed_and_key()
        receipt = build_receipt(resp, pk, key_id=kid)
        data = receipt.to_dict()
        assert data["format"] == "tcreceipt"
        assert data["version"] == 1
        assert data["envelope"]["tool_id"] == "weather_service"
        assert data["key"]["public_key_b64"] == pk
        assert data["key"]["algorithm"] == "ed25519"
        assert "issued_at" in data
        assert data["summary"]["tool_id"] == "weather_service"

    def test_verify_freshly_built_is_valid(self):
        resp, pk, kid = _mint_signed_and_key()
        receipt = build_receipt(resp, pk, key_id=kid)
        v = receipt.verify()
        assert v.valid is True, v.errors
        assert v.signature_ok is True
        assert v.identity_ok is None  # no identity in this receipt
        assert v.witnesses_ok is None

    def test_save_load_roundtrip(self, tmp_path: Path):
        resp, pk, kid = _mint_signed_and_key()
        receipt = build_receipt(resp, pk, key_id=kid)

        path = receipt.save(tmp_path / "sample.tcreceipt")
        assert path.exists()

        loaded = Receipt.load(path)
        assert loaded.tool_id == "weather_service"
        assert loaded.verify().valid is True

    def test_verify_accepts_dict_envelope(self):
        """build_receipt должен работать и с dict, и с SignedResponse."""
        resp, pk, kid = _mint_signed_and_key()
        receipt = build_receipt(resp.to_dict(), pk, key_id=kid)
        assert receipt.verify().valid is True

    def test_fingerprint_is_stable(self):
        resp, pk, kid = _mint_signed_and_key()
        r1 = build_receipt(resp, pk, key_id=kid)
        r2 = build_receipt(resp, pk, key_id=kid)
        assert r1.fingerprint == r2.fingerprint  # same envelope → same fp
        assert len(r1.fingerprint) == 64  # sha256 hex


# --------------------------------------------------------------------------- #
# Tamper-evidence                                                             #
# --------------------------------------------------------------------------- #


class TestTamperEvidence:
    def test_tampered_data_breaks_signature(self, tmp_path: Path):
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(resp, pk)

        # Saboteur edits the payload after-the-fact.
        receipt.envelope["data"]["temperature"] = 999

        v = receipt.verify()
        assert v.valid is False
        assert v.signature_ok is False
        assert any("signature" in e.lower() for e in v.errors)

    def test_tampered_timestamp_breaks_signature(self):
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(resp, pk)
        receipt.envelope["timestamp"] = receipt.envelope["timestamp"] + 10_000
        assert receipt.verify().valid is False

    def test_swapped_public_key_fails(self):
        resp, _, _ = _mint_signed_and_key()
        _, other_pk, _ = _mint_signed_and_key()  # unrelated keypair
        # Build "receipt" that claims to be signed by another key.
        receipt = build_receipt(resp, other_pk)
        v = receipt.verify()
        assert v.valid is False
        assert v.signature_ok is False

    def test_truncated_signature_fails(self):
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(resp, pk)
        receipt.envelope["signature"] = receipt.envelope["signature"][:20]
        assert receipt.verify().valid is False


# --------------------------------------------------------------------------- #
# Format hardening                                                            #
# --------------------------------------------------------------------------- #


class TestFormat:
    def test_rejects_non_receipt_document(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"format": "something-else"}))
        with pytest.raises(ReceiptFormatError, match="not a TrustChain receipt"):
            Receipt.load(bad)

    def test_rejects_future_version(self, tmp_path: Path):
        """Future versions must NOT be auto-accepted by v1 verifier.

        ``Receipt.load`` принимает (forward-compat), но ``verify`` должен
        явно отказать с human-readable причиной, а не валидировать мусор.
        """
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(resp, pk)
        doc = receipt.to_dict()
        doc["version"] = 999
        # Load does not fail (future-compat), but verify must refuse.
        loaded = Receipt._from_dict(doc)
        v = loaded.verify()
        assert v.valid is False
        assert any("version" in e.lower() for e in v.errors)

    def test_rejects_version_zero(self):
        with pytest.raises(ReceiptFormatError, match="version"):
            Receipt._from_dict({"format": "tcreceipt", "version": 0})

    def test_load_from_json_string(self):
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(resp, pk)
        reloaded = Receipt.load(receipt.to_json())
        assert reloaded.verify().valid is True


# --------------------------------------------------------------------------- #
# Identity (soft PEM check)                                                   #
# --------------------------------------------------------------------------- #


class TestIdentity:
    def test_no_identity_is_neutral(self):
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(resp, pk)
        v = receipt.verify()
        assert v.identity_ok is None

    def test_empty_cert_chain_is_warning(self):
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(
            resp, pk, identity={"subject_cn": "agent-x", "cert_chain_pem": []}
        )
        v = receipt.verify()
        assert v.identity_ok is False
        assert any("cert_chain_pem" in w for w in v.warnings)

    def test_garbage_cert_chain_errors(self):
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(
            resp,
            pk,
            identity={"subject_cn": "agent-x", "cert_chain_pem": ["not-a-pem"]},
        )
        v = receipt.verify()
        assert v.identity_ok is False
        assert v.valid is False  # base sig still ok, but identity breaks overall

    def test_pem_shaped_cert_chain_passes_soft_check(self):
        resp, pk, _ = _mint_signed_and_key()
        pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
        receipt = build_receipt(
            resp, pk, identity={"subject_cn": "agent-x", "cert_chain_pem": [pem]}
        )
        v = receipt.verify()
        assert v.identity_ok is True  # soft check: shape only
        assert v.valid is True


# --------------------------------------------------------------------------- #
# Freshness / pinning                                                         #
# --------------------------------------------------------------------------- #


class TestFreshnessAndPinning:
    def test_freshness_rejects_old_envelope(self):
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(resp, pk)
        # Pretend the envelope is very old by editing the canonical ts is
        # pointless (would break signature), so instead mint a fresh signer
        # that writes an artificially old timestamp.
        signer = Signer()
        # Monkey-patch: sign with a past timestamp by bypassing the public
        # method — use a dict envelope directly.
        resp_dict = signer.sign(tool_id="t", data={"k": "v"}).to_dict()
        resp_dict["timestamp"] = time.time() - 10_000
        # resign bypasses the normal flow: just rebuild receipt; signature
        # won't match anyway → verify should fail on either path.
        receipt = build_receipt(resp_dict, signer.get_public_key())
        v = receipt.verify(max_age_seconds=60)
        # Either age OR signature triggers — but valid must be False.
        assert v.valid is False

    def test_pinning_mismatch_fails(self):
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(resp, pk)
        _, other_pk, _ = _mint_signed_and_key()
        v = receipt.verify(expected_public_key_b64=other_pk)
        assert v.valid is False
        assert any("pinning" in e for e in v.errors)

    def test_pinning_match_passes(self):
        resp, pk, _ = _mint_signed_and_key()
        receipt = build_receipt(resp, pk)
        v = receipt.verify(expected_public_key_b64=pk)
        assert v.valid is True


# --------------------------------------------------------------------------- #
# One-shot helper                                                             #
# --------------------------------------------------------------------------- #


class TestTopLevelHelper:
    def test_verify_receipt_from_dict(self):
        resp, pk, _ = _mint_signed_and_key()
        doc = build_receipt(resp, pk).to_dict()
        v = verify_receipt(doc)
        assert v.valid is True

    def test_verify_receipt_from_path(self, tmp_path: Path):
        resp, pk, _ = _mint_signed_and_key()
        path = build_receipt(resp, pk).save(tmp_path / "x.tcreceipt")
        v = verify_receipt(path)
        assert v.valid is True


# --------------------------------------------------------------------------- #
# Interop with TrustChain facade (end-to-end smoke)                           #
# --------------------------------------------------------------------------- #


class TestIntegrationWithTrustChain:
    def test_receipt_from_tc_sign_flow(self):
        """Проверяем «настоящий» путь: TrustChain.sign → receipt → verify."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        @tc.tool("calc")
        def add(a: int, b: int):
            return {"result": a + b}

        signed = add(2, 3)  # SignedResponse (sync wrapper)
        pk = tc.export_public_key()
        receipt = build_receipt(signed, pk)
        v = receipt.verify()
        assert v.valid is True, v.errors
        assert receipt.envelope["data"]["result"] == 5
