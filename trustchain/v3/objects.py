"""Content-addressed objects for the v3 context layer (git-like rollback)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence


def _sha256_hex(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _canon_json(obj: Any) -> str:
    """Deterministic JSON for digests and CAS blobs."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def cas_path(root: Path, digest: str) -> Path:
    """``objects/ab/cdef...`` layout (2 + 62 hex)."""
    if len(digest) < 3:
        raise ValueError("digest too short")
    return root / "objects" / digest[:2] / digest[2:]


@dataclass(frozen=True)
class Blob:
    """Immutable byte payload addressed by SHA-256."""

    content: bytes

    @property
    def digest(self) -> str:
        return _sha256_hex(self.content)

    def write(self, trustchain_root: Path) -> Path:
        p = cas_path(trustchain_root, self.digest)
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_bytes(self.content)
        return p


@dataclass(frozen=True)
class Tree:
    """Directory-like snapshot (JSON canonical)."""

    entries: dict[str, str]  # name -> child digest (blob or tree)

    @property
    def digest(self) -> str:
        body = {"type": "tree", "entries": self.entries}
        return _sha256_hex(_canon_json(body).encode("utf-8"))

    def write(self, trustchain_root: Path) -> Path:
        body = {"type": "tree", "entries": self.entries}
        blob = Blob(_canon_json(body).encode("utf-8"))
        return blob.write(trustchain_root)


@dataclass(frozen=True)
class Commit:
    """Commit object: tree + parents + message + optional tool custody metadata."""

    tree_digest: str
    parents: Sequence[str]
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        body = {
            "type": "commit",
            "tree": self.tree_digest,
            "parents": list(self.parents),
            "message": self.message,
            "metadata": self.metadata,
        }
        return _sha256_hex(_canon_json(body).encode("utf-8"))

    def write(self, trustchain_root: Path) -> Path:
        body = {
            "type": "commit",
            "tree": self.tree_digest,
            "parents": list(self.parents),
            "message": self.message,
            "metadata": self.metadata,
        }
        blob = Blob(_canon_json(body).encode("utf-8"))
        return blob.write(trustchain_root)


@dataclass(frozen=True)
class Ref:
    """Named pointer to a commit digest (e.g. ``refs/heads/main``)."""

    name: str
    commit_digest: str

    def write(self, trustchain_root: Path) -> Path:
        path = trustchain_root / "refs" / self.name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.commit_digest + "\n", encoding="utf-8")
        return path
