"""ChainStore — Git-like persistent chain-of-trust ledger.

Provides a high-level API for managing a cryptographic chain of signed
operations, using Git-like semantics: commits, HEAD, refs, log, blame.

The chain is stored in a .trustchain/ directory structure:

    .trustchain/
    ├── HEAD                  # latest commit signature
    ├── config.json           # chain metadata
    ├── objects/              # one JSON file per signed operation
    │   ├── op_0001.json
    │   └── ...
    └── refs/
        └── sessions/         # per-session HEAD pointers
            ├── task_abc123
            └── task_def456

Usage:
    from trustchain import TrustChain
    tc = TrustChain(config=TrustChainConfig(chain_storage="file"))

    # Signing automatically appends to chain
    signed = tc.sign("bash_tool", {"command": "ls -la"})

    # Query the chain
    tc.chain.log(limit=10)           # like `git log`
    tc.chain.verify()                # like `git verify-commit`
    tc.chain.head()                  # current HEAD
    tc.chain.blame("bash_tool")      # find operations by tool
    tc.chain.status()                # chain health summary
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .storage import Storage


def _safe_ref_segment(name: str) -> str:
    s = name.strip().replace("..", "_")
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "_", s)
    if not s or s in (".", "_"):
        raise ValueError("invalid name: use letters, digits, ._-")
    return s[:120]


def reconstruct_signed_response(record: Dict[str, Any]):
    """Rebuild a :class:`SignedResponse` from a persisted chain record.

    The signed Ed25519 payload covers the *float* ``response_timestamp`` (not
    the rounded ISO ``timestamp``), so that field is required to reconstruct
    the canonical bytes byte-for-byte. Returns ``None`` if the record lacks the
    data needed to re-verify the signature.
    """
    from .signer import SignedResponse

    if "response_timestamp" not in record:
        # Pre-3.x records did not persist the exact signed timestamp, so the
        # signature cannot be cryptographically re-derived from storage.
        return None

    return SignedResponse(
        tool_id=record.get("tool", ""),
        data=record.get("data"),
        signature=record.get("signature", ""),
        signature_id=record.get("signature_id", ""),
        timestamp=float(record["response_timestamp"]),
        nonce=record.get("nonce"),
        parent_signature=record.get("parent_signature"),
        parent_signatures=record.get("parent_signatures"),
        metadata=record.get("metadata"),
        certificate=record.get("certificate"),
        tsa_proof=record.get("tsa_proof"),
    )


def verify_record_signature(record: Dict[str, Any], verifier) -> Optional[bool]:
    """Re-verify a single chain record's Ed25519 signature.

    Returns ``True``/``False`` for a verifiable record, or ``None`` when the
    record cannot be reconstructed (and therefore cannot be re-verified).
    """
    signed = reconstruct_signed_response(record)
    if signed is None:
        return None
    return bool(verifier.verify(signed).valid)


def _signature_to_op_map(ops: List[dict]) -> dict[str, dict]:
    m: dict[str, dict] = {}
    for o in ops:
        if isinstance(o, dict):
            sig = o.get("signature")
            if isinstance(sig, str) and sig:
                m[sig] = o
    return m


def _detach_ids_tip_down_to_target(
    sig_to_op: dict[str, dict], tip_sig: str, target_id: str
) -> Tuple[List[str], Optional[dict]]:
    detach: List[str] = []
    cur: Optional[dict] = sig_to_op.get(tip_sig)
    if not cur:
        return detach, None
    while cur:
        oid = cur.get("id")
        if oid == target_id:
            return detach, cur
        detach.append(str(oid))
        parent = cur.get("parent_signature")
        if not isinstance(parent, str) or not parent:
            break
        cur = sig_to_op.get(parent)
    return detach, None


class ChainStore:
    """Git-like persistent chain-of-trust ledger.

    Wraps a Storage backend with chain-specific semantics:
    - Ordered append-only ledger (each commit links to parent)
    - HEAD tracking (latest commit signature)
    - Session refs (per-session HEAD pointers)
    - Log, blame, verify operations

    When backed by a VerifiableChainStore (default since v3.0),
    all operations use Certificate Transparency-style Merkle proofs
    for O(1) verification and O(log n) inclusion proofs.
    """

    def __init__(
        self,
        storage: Storage,
        root_dir: Optional[str] = None,
        verifiable_log: Any = None,
    ) -> None:
        self._storage = storage
        self._root = Path(root_dir).expanduser().resolve() if root_dir else None
        self._length = 0
        self._head: Optional[str] = None  # latest signature
        self._last_parent_sig: Optional[str] = None
        self._vlog = verifiable_log  # VerifiableChainStore (optional)

        # Initialize from persisted state
        self._load_state()

    # ── Git-like public API ──

    def commit(
        self,
        tool: str,
        data: Dict[str, Any],
        signature: str,
        signature_id: str,
        nonce: Optional[str] = None,
        parent_signature: Optional[str] = None,
        parent_signatures: Optional[list[str]] = None,
        key_id: str = "",
        algorithm: str = "Ed25519",
        latency_ms: float = 0,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        response_timestamp: Optional[float] = None,
        certificate: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a signed operation to the chain (like `git commit`).

        ``response_timestamp`` — *exact* float timestamp covered by the
        Ed25519 signature (see ``SignedResponse.timestamp``). We persist it
        separately from the store-level ISO ``timestamp`` so downstream
        consumers (``.tcreceipt`` builders, chain re-verification tools) can
        reconstruct the canonical envelope byte-for-byte. Without this, the
        store would only know the ISO string it wrote, which is rounded and
        truncated versus the float the signer actually signed.

        ``certificate`` — identity material that was covered by the
        signature (``_signer.sign(certificate=…)``). Kept here so receipts
        can recreate the canonical payload without re-contacting the signer.

        Both fields are optional and absent by default — the format stays
        backward-compatible with existing records, and old consumers that
        don't read them are unaffected.

        Returns the full commit record.
        """
        if self._vlog:
            # Delegate to VerifiableChainStore (Certificate Transparency)
            record = self._vlog.append(
                tool=tool,
                data=data,
                signature=signature,
                signature_id=signature_id,
                parent_hash=parent_signature,
                parent_signatures=parent_signatures,
                key_id=key_id,
                algorithm=algorithm,
                latency_ms=latency_ms,
                session_id=session_id,
                nonce=nonce,
                metadata=metadata,
                response_timestamp=response_timestamp,
                certificate=certificate,
            )
            self._length = self._vlog.length
            self._head = signature
            self._last_parent_sig = signature
            if session_id:
                self._save_ref(session_id, signature)
            return record  # type: ignore[no-any-return]

        # Legacy path: Storage backend
        self._length += 1
        op_id = f"op_{self._length:04d}"

        record = {
            "id": op_id,
            "tool": tool,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
            "latency_ms": latency_ms,
            "signature": signature,
            "signature_id": signature_id,
            "nonce": nonce,
            "parent_signature": parent_signature,
            "key_id": key_id,
            "algorithm": algorithm,
        }
        if parent_signatures is not None:
            record["parent_signatures"] = parent_signatures
        if metadata:
            record["metadata"] = metadata
        if response_timestamp is not None:
            record["response_timestamp"] = float(response_timestamp)
        if certificate is not None:
            record["certificate"] = certificate

        self._storage.store(op_id, record)
        self._head = signature
        self._last_parent_sig = signature
        self._save_head()

        if session_id:
            self._save_ref(session_id, signature)

        return record

    def head(self) -> Optional[str]:
        """Get current HEAD signature (like `git rev-parse HEAD`)."""
        return self._head

    def parent_signature(self) -> Optional[str]:
        """Get the parent signature for the next commit."""
        return self._last_parent_sig

    def log(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Return chain history (like `git log`).

        Returns operations in chronological order (oldest first).
        """
        if self._vlog:
            return self._vlog.log(limit=limit, offset=offset, reverse=False)  # type: ignore[no-any-return]

        all_ops = self._storage.list_all()
        all_ops.sort(key=lambda x: x.get("id", "") if isinstance(x, dict) else "")
        return all_ops[offset : offset + limit]

    def log_reverse(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return chain history newest-first (like `git log` default)."""
        if self._vlog:
            return self._vlog.log(limit=limit, reverse=True)  # type: ignore[no-any-return]

        all_ops = self._storage.list_all()
        all_ops.sort(
            key=lambda x: x.get("id", "") if isinstance(x, dict) else "", reverse=True
        )
        return all_ops[:limit]

    def show(self, op_id: str) -> Optional[Dict[str, Any]]:
        """Show a single commit (like `git show <hash>`)."""
        if self._vlog:
            return self._vlog.show(op_id)  # type: ignore[no-any-return]
        return self._storage.get(op_id)

    def blame(self, tool: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Find all operations by a specific tool (like `git blame`).

        Useful for forensic investigation: "show me every time
        the agent ran bash_tool".
        """
        if self._vlog:
            return self._vlog.blame(tool, limit=limit)  # type: ignore[no-any-return]

        all_ops = self._storage.list_all()
        results = [
            op for op in all_ops if isinstance(op, dict) and op.get("tool") == tool
        ]
        return results[:limit]

    def verify(self, public_key: Optional[str] = None) -> Dict[str, Any]:
        """Verify the integrity of the entire chain (like `git fsck`).

        Structural checks (always run):
          * each ``parent_signature`` / ``parent_signatures`` link references
            an earlier operation in the chain/DAG.

        Cryptographic checks (only when ``public_key`` is provided):
          * each operation's Ed25519 signature is re-verified against the
            base64 signer ``public_key`` by reconstructing the canonical
            payload from the stored record. Without a public key the chain
            store has no key material, so signatures are NOT re-verified —
            the result then reflects link/structure integrity only.

        With VerifiableChainStore/Postgres: O(1) Merkle root comparison plus
        optional per-record signature re-verification.
        """
        if self._vlog:
            try:
                return self._vlog.verify(public_key=public_key)  # type: ignore[call-arg,no-any-return]
            except TypeError:
                # Backend without signature re-verification support.
                return self._vlog.verify()  # type: ignore[no-any-return]

        all_ops = self.log(limit=999999)
        broken = []

        if not all_ops:
            return {
                "valid": True,
                "length": 0,
                "head": None,
                "broken_links": [],
                "signatures_verified": 0,
                "signatures_checked": bool(public_key),
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }

        # Optional cryptographic re-verification of every record's signature.
        verifier = None
        sigs_verified = 0
        sigs_unverifiable = 0
        if public_key:
            from .verifier import TrustChainVerifier

            # Chain records are persistent and may be arbitrarily old; disable
            # the freshness/age window for re-verification.
            verifier = TrustChainVerifier(public_key, max_age_seconds=None)
            for op in all_ops:
                res = verify_record_signature(op, verifier)
                if res is True:
                    sigs_verified += 1
                elif res is None:
                    sigs_unverifiable += 1
                else:
                    broken.append(
                        {
                            "index": all_ops.index(op),
                            "id": op.get("id"),
                            "error": "invalid_signature",
                            "signature": op.get("signature"),
                        }
                    )

        for i in range(1, len(all_ops)):
            this_parent = all_ops[i].get("parent_signature")
            this_parents = all_ops[i].get("parent_signatures")

            if this_parents is not None:
                # DAG Verification: ensure all declared parent signatures exist in the chain
                for p in this_parents:
                    found = False
                    for j in range(0, i):
                        if all_ops[j].get("signature") == p:
                            found = True
                            break
                    if not found:
                        broken.append(
                            {
                                "index": i,
                                "id": all_ops[i].get("id"),
                                "expected_parent": p,
                                "actual_parent": "Missing in DAG",
                            }
                        )
            else:
                # Tree/Branch Verification
                if this_parent is not None:
                    found = False
                    for j in range(0, i):
                        if all_ops[j].get("signature") == this_parent:
                            found = True
                            break
                    if not found:
                        broken.append(
                            {
                                "index": i,
                                "id": all_ops[i].get("id"),
                                "expected_parent": "Existing signature in DAG",
                                "actual_parent": this_parent,
                            }
                        )
                # If this_parent is None, it is a new root (orphan branch), which is allowed in DAGs.

        return {
            "valid": len(broken) == 0,
            "length": len(all_ops),
            "head": all_ops[-1].get("signature") if all_ops else None,
            "broken_links": broken,
            "signatures_checked": bool(public_key),
            "signatures_verified": sigs_verified,
            "signatures_unverifiable": sigs_unverifiable,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def status(self) -> Dict[str, Any]:
        """Chain health summary (like `git status`)."""
        if self._vlog:
            return self._vlog.status()  # type: ignore[no-any-return]

        all_ops = self._storage.list_all()
        tools_count: Dict[str, int] = {}
        total_latency = 0.0

        for op in all_ops:
            if isinstance(op, dict):
                tool = op.get("tool", "unknown")
                tools_count[tool] = tools_count.get(tool, 0) + 1
                total_latency += op.get("latency_ms", 0)

        total = len(all_ops)
        return {
            "length": total,
            "head": self._head,
            "tools": tools_count,
            "avg_latency_ms": round(total_latency / total, 2) if total > 0 else 0,
            "storage_backend": type(self._storage).__name__,
            "root_dir": str(self._root) if self._root else None,
        }

    def diff(self, op_id_a: str, op_id_b: str) -> Dict[str, Any]:
        """Compare two operations (like `git diff`)."""
        if self._vlog:
            return self._vlog.diff(op_id_a, op_id_b)  # type: ignore[no-any-return]

        a = self.show(op_id_a)
        b = self.show(op_id_b)
        if not a or not b:
            return {"error": "One or both operations not found"}

        return {
            "a": {"id": op_id_a, "tool": a.get("tool"), "data": a.get("data")},
            "b": {"id": op_id_b, "tool": b.get("tool"), "data": b.get("data")},
            "same_tool": a.get("tool") == b.get("tool"),
            "time_delta_seconds": self._time_delta(a, b),
        }

    def export_json(self, filepath: Optional[str] = None) -> str:
        """Export entire chain as JSON."""
        if self._vlog:
            return self._vlog.export_json(filepath)  # type: ignore[no-any-return]

        data = {
            "head": self._head,
            "status": self.status(),
            "chain": self.log(limit=999999),
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }
        json_str = json.dumps(data, indent=2, default=str)
        if filepath:
            Path(filepath).write_text(json_str, encoding="utf-8")
        return json_str

    # ── Verifiable Log-specific API ──

    def inclusion_proof(self, op_id: str) -> Any:
        """Get O(log n) Merkle inclusion proof for an operation."""
        if self._vlog:
            return self._vlog.inclusion_proof(op_id)
        return None

    def consistency_proof(self, old_length: int, old_root: str) -> dict[str, Any]:
        """Prove old chain state is a prefix of current (no rewrites)."""
        if self._vlog:
            return self._vlog.consistency_proof(old_length, old_root)  # type: ignore[no-any-return]
        return {"consistent": False, "reason": "verifiable_log_not_enabled"}

    @property
    def merkle_root(self) -> Optional[str]:
        """Current Merkle root hash (None if verifiable log not enabled)."""
        if self._vlog:
            return self._vlog.merkle_root  # type: ignore[no-any-return]
        return None

    def rebuild_index(self) -> dict[str, Any]:
        """Rebuild SQLite index from chain.log source of truth."""
        if self._vlog:
            return self._vlog.rebuild_index()  # type: ignore[no-any-return]
        return {"rebuilt": False, "reason": "verifiable_log_not_enabled"}

    # ── Session refs ──

    def sessions(self) -> List[str]:
        """List all session refs (like `git branch -a`)."""
        if not self._root:
            return []
        refs_dir = self._root / "refs" / "sessions"
        if not refs_dir.exists():
            return []
        return sorted(f.stem for f in refs_dir.glob("*.ref"))

    def session_head(self, session_id: str) -> Optional[str]:
        """Get HEAD for a specific session (like `git rev-parse <branch>`)."""
        if not self._root:
            return None
        ref_path = self._root / "refs" / "sessions" / f"{session_id}.ref"
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8").strip()
        return None

    # ── Properties ──

    @property
    def length(self) -> int:
        """Number of operations in the chain."""
        return self._length

    # ── Git-like Refs API ──

    def checkpoint(self, name: str) -> str:
        """Save current HEAD to refs/checkpoints/<name>.ref (git-like tag)."""
        if self._vlog:
            raise NotImplementedError(
                "checkpoint is not supported for verifiable/PG backend."
            )
        h = self.head()
        if not h:
            raise ValueError("HEAD is empty — nothing to checkpoint.")
        if not self._root:
            raise ValueError("Chain root directory is required.")

        seg = _safe_ref_segment(name)
        path = self._root / "refs" / "checkpoints" / f"{seg}.ref"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(h.strip() + "\n", encoding="utf-8")
        return h

    def tag(self, name: str) -> str:
        """Save current HEAD to refs/tags/<name>.ref."""
        if self._vlog:
            raise NotImplementedError("tag is not supported for verifiable/PG backend.")
        h = self.head()
        if not h:
            raise ValueError("HEAD is empty — nothing to tag.")
        if not self._root:
            raise ValueError("Chain root directory is required.")

        seg = _safe_ref_segment(name)
        path = self._root / "refs" / "tags" / f"{seg}.ref"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(h.strip() + "\n", encoding="utf-8")
        return h

    def branch(self, name: str) -> str:
        """Create refs/heads/<name>.ref pointing at the current HEAD."""
        if self._vlog:
            raise NotImplementedError(
                "branch is not supported for verifiable/PG backend."
            )
        h = self.head()
        if not h:
            raise ValueError("HEAD is empty — create commits before branching.")
        if not self._root:
            raise ValueError("Chain root directory is required.")

        seg = _safe_ref_segment(name)
        path = self._root / "refs" / "heads" / f"{seg}.ref"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(h.strip() + "\n", encoding="utf-8")
        return h

    def list_refs(self) -> Dict[str, List[Dict[str, str]]]:
        """List checkpoint, tags, and heads ref files."""
        if not self._root or not self._root.exists():
            raise ValueError(f"No chain at {self._root}")

        result = {"checkpoint": [], "tag": [], "head": [], "v3": []}

        for kind, sub in (
            ("checkpoint", "refs/checkpoints"),
            ("tag", "refs/tags"),
            ("head", "refs/heads"),
        ):
            d = self._root / sub
            if not d.is_dir():
                continue
            for f in sorted(d.glob("*.ref")):
                try:
                    txt = f.read_text(encoding="utf-8").strip().splitlines()
                    tip = txt[0] if txt else ""
                except OSError:
                    tip = ""
                result[kind].append({"name": f.stem, "head": tip})

        v3d = self._root / "refs" / "v3"
        if v3d.is_dir():
            for f in sorted(v3d.iterdir()):
                if not f.is_file():
                    continue
                try:
                    txt = f.read_text(encoding="utf-8").strip().splitlines()
                    tip = txt[0] if txt else ""
                except OSError:
                    tip = ""
                result["v3"].append({"name": f.name, "head": tip})

        return result

    def checkout(
        self, name: str, dry_run: bool = False, max_scan: int = 50000
    ) -> Dict[str, Any]:
        """Switch HEAD to signature from refs/heads/<name>.ref."""
        if self._vlog:
            raise NotImplementedError(
                "checkout is not supported for verifiable/PG chain."
            )
        if not self._root:
            raise ValueError("Chain root directory is required.")

        seg = _safe_ref_segment(name)
        ref_path = self._root / "refs" / "heads" / f"{seg}.ref"
        if not ref_path.is_file():
            raise ValueError(f"Branch not found: {seg}")

        lines = ref_path.read_text(encoding="utf-8").strip().splitlines()
        tip_sig = (lines[0] if lines else "").strip()
        if not tip_sig:
            raise ValueError(f"Empty ref {ref_path.name}")

        chrono = self.log(limit=max_scan, offset=0)
        sig_map = _signature_to_op_map([o for o in chrono if isinstance(o, dict)])
        if tip_sig not in sig_map:
            raise ValueError(
                "Signature from ref not found among operations. Try increasing max_scan."
            )

        op = sig_map[tip_sig]
        op_id = str(op.get("id", "?"))

        if dry_run:
            return {"branch": seg, "op_id": op_id, "head": tip_sig, "dry_run": True}

        old = self.head() or ""
        self._head = tip_sig
        self._last_parent_sig = tip_sig
        self._save_head()

        reflog = self._root / "reflog.txt"
        line = (
            f"{datetime.now(timezone.utc).isoformat()}\tcheckout\t{seg}\t"
            f"{old[:64]}\t{tip_sig[:64]}\t{op_id}\n"
        )
        with reflog.open("a", encoding="utf-8") as rf:
            rf.write(line)

        return {"branch": seg, "op_id": op_id, "head": tip_sig, "dry_run": False}

    def reset(
        self,
        target_id: str,
        soft: bool = True,
        dry_run: bool = False,
        max_scan: int = 50000,
    ) -> Dict[str, Any]:
        """Move HEAD backwards to a specific target_id (must be ancestor)."""
        if not soft and not dry_run:
            raise NotImplementedError("Only --soft reset is currently supported.")
        if self._vlog:
            raise NotImplementedError(
                "reset is not supported for verifiable/PG backend."
            )
        if not self._root:
            raise ValueError("Chain root directory is required.")

        target_id = target_id.strip()
        if not target_id or target_id.upper() == "HEAD":
            raise ValueError("Pass a concrete op id (e.g. op_0002), not HEAD.")

        shown = self.show(target_id)
        if not isinstance(shown, dict):
            raise ValueError(f"Operation not found: {target_id!r}")

        chrono = self.log(limit=max_scan, offset=0)
        tip_sig = self.head()
        if not tip_sig:
            raise ValueError("HEAD is empty — nothing to reset.")

        sig_map = _signature_to_op_map([o for o in chrono if isinstance(o, dict)])
        if tip_sig not in sig_map:
            raise ValueError("HEAD signature not found among scanned operations.")

        detach_ids, target_op = _detach_ids_tip_down_to_target(
            sig_map, tip_sig, target_id
        )
        if target_op is None:
            raise ValueError(
                f"{target_id!r} is not on the ancestry path from current HEAD"
            )

        new_head = target_op.get("signature")
        if not isinstance(new_head, str) or not new_head:
            raise ValueError("Target op has no signature")

        if not detach_ids:
            return {
                "target_id": target_id,
                "new_head": new_head,
                "detached_count": 0,
                "detached_ids": [],
                "dry_run": dry_run,
                "changed": False,
            }

        if dry_run:
            return {
                "target_id": target_id,
                "new_head": new_head,
                "detached_count": len(detach_ids),
                "detached_ids": detach_ids,
                "dry_run": True,
                "changed": True,
            }

        old_tip = tip_sig
        self._head = new_head
        self._last_parent_sig = new_head
        self._save_head()

        reflog = self._root / "reflog.txt"
        line = (
            f"{datetime.now(timezone.utc).isoformat()}\treset-soft\t"
            f"{old_tip[:64]}\t{new_head[:64]}\t{target_id}\tafter={len(detach_ids)}\n"
        )
        with reflog.open("a", encoding="utf-8") as rf:
            rf.write(line)

        return {
            "target_id": target_id,
            "new_head": new_head,
            "detached_count": len(detach_ids),
            "detached_ids": detach_ids,
            "dry_run": False,
            "changed": True,
        }

    def generate_anchor(self) -> Dict[str, Any]:
        """Export the current chain HEAD and canonical chain digest for anchoring."""
        verify_result = self.verify()
        ops = self.log(limit=999999)
        canonical = json.dumps(
            ops,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")

        return {
            "format": "tc-anchor",
            "version": 1,
            "profile": "trustchain.anchor.chain-head.v1",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "chain_dir": str(self._root) if self._root else None,
            "length": len(ops),
            "head": verify_result.get("head"),
            "chain_valid": bool(verify_result.get("valid")),
            "chain_sha256": hashlib.sha256(canonical).hexdigest(),
            "merkle_root": self.merkle_root,
        }

    # ── Internal ──

    def _load_state(self) -> None:
        """Load HEAD and chain length from persisted state."""
        if self._vlog:
            self._length = self._vlog.length
            self._head = self._vlog.merkle_root
            self._last_parent_sig = None
            if self._length > 0:
                tail = self._vlog.log(limit=1, offset=0, reverse=True)
                if tail and isinstance(tail[0], dict):
                    sig = tail[0].get("signature")
                    if isinstance(sig, str) and sig:
                        self._last_parent_sig = sig
                        self._head = sig
            return

        if self._root:
            head_path = self._root / "HEAD"
            if head_path.exists():
                self._head = head_path.read_text(encoding="utf-8").strip()
                self._last_parent_sig = self._head

        # Count existing objects (lazy — не читаем содержимое всех файлов).
        # list_all() на большом сторадже (prod: 2.9GB / 740k JSON-файлов)
        # занимает минуты и блокирует импорт backend.routers.trustchain_api
        # (там `TrustChain()` создаётся на module-level) → cold-start >3 мин
        # → uvicorn не принимает TCP → nginx upstream timeout (504) → user
        # видит «минуты жду ответ». size() — просто
        # `len(list(objects_dir.glob("*.json")))` без read_text/json.loads,
        # и выполняется за миллисекунды даже на сотнях тысяч файлов.
        try:
            self._length = self._storage.size()
        except Exception:
            self._length = 0
        # «derive HEAD from last op» убран намеренно: он требовал list_all
        # (не-ленивый скан всего стоража), а на проде HEAD всегда пишется
        # через _save_head после каждой операции (см. chain_store.append).
        # Если HEAD-файла нет — цепь либо пуста, либо сломана, и full-scan
        # её не восстановит; правильный путь — explicit recovery-инструмент.

    def _save_head(self) -> None:
        """Persist HEAD to file."""
        if self._root and self._head:
            head_path = self._root / "HEAD"
            head_path.write_text(self._head, encoding="utf-8")

    def _save_ref(self, session_id: str, signature: str) -> None:
        """Persist a session ref."""
        if self._root:
            refs_dir = self._root / "refs" / "sessions"
            refs_dir.mkdir(parents=True, exist_ok=True)
            safe_id = session_id.replace("/", "_").replace("\\", "_")
            ref_path = refs_dir / f"{safe_id}.ref"
            ref_path.write_text(signature, encoding="utf-8")

    @staticmethod
    def _time_delta(a: dict, b: dict) -> Optional[float]:
        """Calculate time delta between two operations."""
        try:
            t_a = datetime.fromisoformat(a["timestamp"])
            t_b = datetime.fromisoformat(b["timestamp"])
            return abs((t_b - t_a).total_seconds())
        except (KeyError, ValueError):
            return None
