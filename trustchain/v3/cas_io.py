"""Read JSON blobs from v3 content-addressed layout under ``.trustchain/objects/``."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_CAS_HEX = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def is_cas_sha256_hex(s: str) -> bool:
    return bool(s and _CAS_HEX.match(s.strip()))


def read_cas_json(trustchain_root: Path, digest: str) -> dict[str, Any] | None:
    """Load canonical JSON object stored at ``objects/{aa}/{bb…}``."""
    from trustchain.v3.objects import cas_path

    d = digest.strip().lower()
    if not _CAS_HEX.match(d):
        return None
    path = cas_path(trustchain_root, d)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
