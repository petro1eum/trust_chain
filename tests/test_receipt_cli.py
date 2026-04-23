"""End-to-end tests for ``tc receipt`` CLI subcommands.

Контракт exit-codes (стабильный, на него опираются автоматизация и CI):

* ``0`` — ok (signature + optional extras all pass)
* ``1`` — usage error / missing file
* ``2`` — tampered (signature_ok=False)
* ``3`` — degraded (signature ok, identity/witness extras failed)
* ``4`` — format error (not a valid .tcreceipt)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trustchain.cli import app
from trustchain.receipt import build_receipt
from trustchain.v2.signer import Signer

runner = CliRunner()


@pytest.fixture
def signed_and_pk():
    signer = Signer()
    resp = signer.sign(
        tool_id="calc",
        data={"expression": "2+2", "result": 4},
    )
    return resp, signer.get_public_key(), signer.get_key_id()


@pytest.fixture
def receipt_path(tmp_path: Path, signed_and_pk):
    resp, pk, kid = signed_and_pk
    receipt = build_receipt(resp, pk, key_id=kid)
    path = tmp_path / "sample.tcreceipt"
    receipt.save(path)
    return path


class TestShow:
    def test_show_pretty_output(self, receipt_path: Path):
        result = runner.invoke(app, ["receipt", "show", str(receipt_path)])
        assert result.exit_code == 0
        assert "calc" in result.stdout
        assert "fingerprint" in result.stdout.lower()

    def test_show_json_output(self, receipt_path: Path):
        result = runner.invoke(app, ["receipt", "show", "--json", str(receipt_path)])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["format"] == "tcreceipt"
        assert payload["version"] == 1
        assert payload["envelope"]["tool_id"] == "calc"

    def test_show_missing_file_exit1(self, tmp_path: Path):
        result = runner.invoke(
            app, ["receipt", "show", str(tmp_path / "nope.tcreceipt")]
        )
        assert result.exit_code == 1

    def test_show_garbage_file_exit4(self, tmp_path: Path):
        bad = tmp_path / "bad.tcreceipt"
        bad.write_text("not json at all")
        result = runner.invoke(app, ["receipt", "show", str(bad)])
        assert result.exit_code == 4


class TestVerify:
    def test_verify_good_exit0(self, receipt_path: Path):
        result = runner.invoke(app, ["receipt", "verify", str(receipt_path)])
        assert result.exit_code == 0
        assert "VALID" in result.stdout

    def test_verify_tampered_exit2(self, tmp_path: Path, receipt_path: Path):
        doc = json.loads(receipt_path.read_text())
        doc["envelope"]["data"]["result"] = 999
        bad = tmp_path / "tampered.tcreceipt"
        bad.write_text(json.dumps(doc))
        result = runner.invoke(app, ["receipt", "verify", str(bad)])
        assert result.exit_code == 2
        assert "INVALID" in result.stdout

    def test_verify_degraded_exit3(self, tmp_path: Path, receipt_path: Path):
        """Подпись ок, но cert_chain мусорный → degraded (exit 3)."""
        doc = json.loads(receipt_path.read_text())
        doc["identity"] = {"subject_cn": "x", "cert_chain_pem": ["not-pem"]}
        bad = tmp_path / "degraded.tcreceipt"
        bad.write_text(json.dumps(doc))
        result = runner.invoke(app, ["receipt", "verify", str(bad)])
        assert result.exit_code == 3
        assert "DEGRADED" in result.stdout

    def test_verify_json_output_shape(self, receipt_path: Path):
        result = runner.invoke(app, ["receipt", "verify", "--json", str(receipt_path)])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["valid"] is True
        assert payload["signature_ok"] is True
        assert "errors" in payload

    def test_verify_pin_mismatch_exit2(self, receipt_path: Path):
        # Any well-formed but different b64 key will do.
        other_key = "A" * 43 + "="
        result = runner.invoke(
            app, ["receipt", "verify", "--pin", other_key, str(receipt_path)]
        )
        assert result.exit_code == 2

    def test_verify_format_error_exit4(self, tmp_path: Path):
        bad = tmp_path / "not_a_receipt.json"
        bad.write_text(json.dumps({"format": "other", "version": 1}))
        result = runner.invoke(app, ["receipt", "verify", str(bad)])
        assert result.exit_code == 4


class TestBuild:
    def test_build_from_signed_json_and_inline_key(self, tmp_path: Path, signed_and_pk):
        resp, pk, _ = signed_and_pk
        signed_file = tmp_path / "signed.json"
        signed_file.write_text(json.dumps(resp.to_dict()))
        out = tmp_path / "built.tcreceipt"
        result = runner.invoke(
            app,
            [
                "receipt",
                "build",
                "--key",
                pk,
                "--output",
                str(out),
                str(signed_file),
            ],
        )
        assert result.exit_code == 0, result.stdout
        assert out.exists()
        # Roundtrip check — built receipt must verify cleanly.
        result = runner.invoke(app, ["receipt", "verify", str(out)])
        assert result.exit_code == 0

    def test_build_from_exported_key_file(self, tmp_path: Path, signed_and_pk):
        resp, pk, kid = signed_and_pk
        signed_file = tmp_path / "signed.json"
        signed_file.write_text(json.dumps(resp.to_dict()))
        key_file = tmp_path / "agent.key.json"
        key_file.write_text(json.dumps({"public_key": pk, "key_id": kid}))

        result = runner.invoke(
            app,
            ["receipt", "build", "--key", str(key_file), str(signed_file)],
        )
        assert result.exit_code == 0, result.stdout
        payload = json.loads(result.stdout)
        assert payload["key"]["key_id"] == kid
