"""tc-verify --full-chain PKIX helpers (local PEMs, no network)."""

import base64
import gzip
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from trustchain.v2.x509_pki import TrustChainCA


def test_tc_verify_full_chain_local_pems(tmp_path: Path) -> None:
    root = TrustChainCA.create_root_ca()
    intermediate = root.issue_intermediate_ca()
    agent = intermediate.issue_agent_cert("tc-verify-test-agent")

    pk = agent.certificate.public_key()
    raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pk_b64 = base64.b64encode(raw).decode("ascii")

    (tmp_path / "root.pem").write_text(root.certificate_pem, encoding="utf-8")
    (tmp_path / "int.pem").write_text(intermediate.certificate_pem, encoding="utf-8")
    agent_pem = agent.certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode("utf-8")
    (tmp_path / "agent.pem").write_text(agent_pem, encoding="utf-8")

    gz_path = tmp_path / "chain.jsonl.gz"
    meta = {"type": "meta", "key_id": "test", "operations_count": 0}
    gz_path.write_bytes(gzip.compress((json.dumps(meta) + "\n").encode("utf-8")))

    cmd = [
        sys.executable,
        "-m",
        "trustchain.tc_verify_main",
        str(gz_path),
        "--pubkey",
        pk_b64,
        "--full-chain",
        "--root-ca-pem",
        str(tmp_path / "root.pem"),
        "--intermediate-pem",
        str(tmp_path / "int.pem"),
        "--agent-cert-pem",
        str(tmp_path / "agent.pem"),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "verified_signatures=0" in proc.stdout
    assert "full_chain=OK" in proc.stderr or "full_chain=checked" in proc.stdout
