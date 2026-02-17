"""Storage backends for TrustChain v2.

Provides pluggable storage with Git-like .trustchain/ directory structure.

Directory layout:
    .trustchain/
    ├── HEAD                  # latest signature hash
    ├── config.json           # key_id, algorithm, created_at
    ├── objects/              # one JSON file per signed operation
    │   ├── op_0001.json
    │   └── ...
    └── refs/
        └── sessions/         # per-session HEAD pointers
"""

import json
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional


class Storage(ABC):
    """Abstract storage interface."""

    @abstractmethod
    def store(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store a value with optional TTL."""
        pass

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Retrieve a value by key."""
        pass

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete a value by key."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all stored values."""
        pass

    def list_all(self) -> List[Dict[str, Any]]:
        """List all stored values. Override for efficient implementations."""
        return []

    def size(self) -> int:
        """Get current number of stored items."""
        return 0


class MemoryStorage(Storage):
    """In-memory storage with LRU eviction and TTL support."""

    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self._data: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    def store(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store a value with optional TTL."""
        # Clean expired entries first
        self._clean_expired()

        # LRU eviction if at capacity
        if len(self._data) >= self.max_size and key not in self._data:
            self._data.popitem(last=False)  # Remove oldest

        # Store with expiration time
        expires_at = None
        if ttl is not None:
            expires_at = time.time() + ttl

        self._data[key] = {
            "value": value,
            "expires_at": expires_at,
            "created_at": time.time(),
        }

        # Move to end (most recently used)
        self._data.move_to_end(key)

    def get(self, key: str) -> Optional[Any]:
        """Retrieve a value by key."""
        if key not in self._data:
            return None

        entry = self._data[key]

        # Check expiration
        if entry["expires_at"] is not None and time.time() > entry["expires_at"]:
            del self._data[key]
            return None

        # Move to end (most recently used)
        self._data.move_to_end(key)
        return entry["value"]

    def delete(self, key: str) -> None:
        """Delete a value by key."""
        self._data.pop(key, None)

    def clear(self) -> None:
        """Clear all stored values."""
        self._data.clear()

    def list_all(self) -> List[Dict[str, Any]]:
        """List all stored values."""
        self._clean_expired()
        return [entry["value"] for entry in self._data.values()]

    def _clean_expired(self) -> None:
        """Remove expired entries."""
        current_time = time.time()
        expired_keys = [
            key
            for key, entry in self._data.items()
            if entry["expires_at"] is not None and current_time > entry["expires_at"]
        ]
        for key in expired_keys:
            del self._data[key]

    def size(self) -> int:
        """Get current number of stored items."""
        self._clean_expired()
        return len(self._data)

    def stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        self._clean_expired()
        return {
            "size": len(self._data),
            "max_size": self.max_size,
            "oldest_key": next(iter(self._data)) if self._data else None,
            "newest_key": next(reversed(self._data)) if self._data else None,
        }


class FileStorage(Storage):
    """Git-like persistent file storage.

    Each value is stored as a separate JSON file inside .trustchain/objects/.
    Provides content-addressable storage where the key maps to a filename.

    Structure:
        {root_dir}/
        ├── objects/
        │   ├── {key}.json    # one file per stored record
        │   └── ...
        └── metadata.json     # storage metadata (count, created_at)
    """

    def __init__(self, root_dir: str = "~/.trustchain"):
        self._root = Path(root_dir).expanduser().resolve()
        self._objects_dir = self._root / "objects"
        self._objects_dir.mkdir(parents=True, exist_ok=True)
        self._metadata_path = self._root / "metadata.json"

        # Ensure metadata exists
        if not self._metadata_path.exists():
            self._write_metadata({"created_at": time.time(), "version": "2.0"})

    def store(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store a value as a JSON file in objects/."""
        safe_key = self._safe_key(key)
        obj_path = self._objects_dir / f"{safe_key}.json"

        record = {
            "key": key,
            "value": value,
            "created_at": time.time(),
        }
        if ttl is not None:
            record["expires_at"] = time.time() + ttl

        obj_path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")

    def get(self, key: str) -> Optional[Any]:
        """Retrieve a value from objects/."""
        safe_key = self._safe_key(key)
        obj_path = self._objects_dir / f"{safe_key}.json"

        if not obj_path.exists():
            return None

        try:
            record = json.loads(obj_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        # Check TTL
        if "expires_at" in record and time.time() > record["expires_at"]:
            obj_path.unlink(missing_ok=True)
            return None

        return record.get("value")

    def delete(self, key: str) -> None:
        """Delete a stored value."""
        safe_key = self._safe_key(key)
        obj_path = self._objects_dir / f"{safe_key}.json"
        obj_path.unlink(missing_ok=True)

    def clear(self) -> None:
        """Remove all stored objects."""
        for f in self._objects_dir.glob("*.json"):
            f.unlink(missing_ok=True)

    def list_all(self) -> List[Dict[str, Any]]:
        """List all stored values, sorted by creation time."""
        results = []
        for f in sorted(self._objects_dir.glob("*.json")):
            try:
                record = json.loads(f.read_text(encoding="utf-8"))
                # Skip expired
                if "expires_at" in record and time.time() > record["expires_at"]:
                    continue
                results.append(record["value"])
            except (json.JSONDecodeError, OSError, KeyError):
                continue
        return results

    def size(self) -> int:
        """Count stored objects."""
        return len(list(self._objects_dir.glob("*.json")))

    def stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        files = sorted(self._objects_dir.glob("*.json"))
        return {
            "backend": "file",
            "root_dir": str(self._root),
            "size": len(files),
            "oldest_key": files[0].stem if files else None,
            "newest_key": files[-1].stem if files else None,
        }

    # ── Internal helpers ──

    @staticmethod
    def _safe_key(key: str) -> str:
        """Sanitize key for use as filename."""
        # Replace unsafe chars but keep readability
        return key.replace("/", "_").replace("\\", "_").replace("..", "_")

    def _write_metadata(self, data: dict) -> None:
        """Write storage metadata."""
        self._metadata_path.write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8"
        )
