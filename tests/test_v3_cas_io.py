"""v3 CAS read helpers."""

import json
from pathlib import Path

from trustchain.v3.cas_io import is_cas_sha256_hex, read_cas_json
from trustchain.v3.objects import Blob


def test_is_cas_sha256_hex() -> None:
    assert is_cas_sha256_hex("a" * 64)
    assert not is_cas_sha256_hex("g" * 64)
    assert not is_cas_sha256_hex("ab")


def test_read_cas_json_roundtrip(tmp_path: Path) -> None:
    body = {"type": "tree", "entries": {"k": "v"}}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    b = Blob(raw)
    b.write(tmp_path)
    got = read_cas_json(tmp_path, b.digest)
    assert got == body
