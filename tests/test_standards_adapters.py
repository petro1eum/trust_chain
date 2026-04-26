"""Standards adapter smoke tests."""

from trustchain import build_receipt
from trustchain.standards import (
    receipt_from_w3c_vc,
    to_intoto_statement,
    to_scitt_air_json,
    to_w3c_vc,
    verify_intoto_statement_shape,
    verify_scitt_air_json,
    verify_w3c_vc_shape,
)
from trustchain.v2.signer import Signer


def _signed_receipt():
    signer = Signer()
    response = signer.sign("sec_filing_lookup", {"company": "Acme", "revenue": 42})
    receipt = build_receipt(
        response,
        signer.get_public_key(),
        key_id=signer.get_key_id(),
    )
    return response, receipt


def test_scitt_air_json_profile_is_deterministic_and_verifiable() -> None:
    response, _receipt = _signed_receipt()

    record = to_scitt_air_json(
        response,
        agent_id="agent:researcher",
        sequence_number=7,
        previous_chain_hash="abc123",
    )

    assert record["profile"] == "trustchain.scitt.air-json.v1"
    assert record["protected_headers"]["sequence_number"] == 7
    assert record["payload"]["tool_id"] == "sec_filing_lookup"
    assert verify_scitt_air_json(record)

    record["payload"]["signed_response"]["tool_id"] = "tampered"
    assert not verify_scitt_air_json(record)


def test_w3c_vc_envelope_keeps_native_receipt_as_source_of_truth() -> None:
    _response, receipt = _signed_receipt()

    vc = to_w3c_vc(
        receipt,
        issuer="did:web:trust-chain.ai",
        subject_id="did:example:agent:researcher",
    )

    assert "TrustChainReceiptCredential" in vc["type"]
    assert vc["credentialSubject"]["toolId"] == "sec_filing_lookup"
    assert verify_w3c_vc_shape(vc)
    assert receipt_from_w3c_vc(vc)["format"] == "tcreceipt"

    vc["credentialSubject"]["receiptHash"] = "sha256:bad"
    assert not verify_w3c_vc_shape(vc)


def test_intoto_statement_binds_subject_digest_to_trustchain_envelope() -> None:
    response, _receipt = _signed_receipt()

    statement = to_intoto_statement(response)

    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == "https://trust-chain.ai/predicate/tcreceipt/v1"
    assert statement["predicate"]["tool_id"] == "sec_filing_lookup"
    assert verify_intoto_statement_shape(statement)

    statement["subject"][0]["digest"]["sha256"] = "bad"
    assert not verify_intoto_statement_shape(statement)
