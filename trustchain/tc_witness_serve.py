"""HTTP witness node — ``tc-witness serve`` (SPEC-WITNESS-NODE-1 R1/R2).

Runs a long-lived, independently-keyed witness over stdlib HTTP. The node
co-signs a log's ``SignedTreeHead`` only when the head is consistent with the
witness's OWN persisted memory of that log: anti-rollback, anti-fork, log-key
pinning, and — when the client supplies a consistency proof — independent
RFC 6962 verification (the SPEC-CHAIN-INTEGRITY-1 R4 property over the wire).

Design constraints (SPEC-WITNESS-NODE-1 R1):

* stdlib only — ``http.server.ThreadingHTTPServer``, no new runtime deps;
* refusals never mutate state; state writes are atomic (tmp + rename);
* wire compat: accepts both the bare-STH POST existing clients send and the
  ``{"sth": ..., "consistency": ...}`` envelope for proof-carrying clients.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from trustchain.v2 import rfc6962
from trustchain.v2.witness import CoSignedTreeHead, SignedTreeHead, verify_tree_head


class WitnessStateStore:
    """Per-log observation memory with atomic persistence.

    The state file is the witness's anchor of the no-rewrite guarantee: it is
    only ever advanced after a successful co-sign, and it is written via
    tmp + ``os.replace`` so a crash cannot leave a torn file behind.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._state: dict[str, Any] = {}
        if self._path.exists():
            try:
                self._state = json.loads(self._path.read_text("utf-8"))
            except (OSError, ValueError):
                self._state = {}

    def get(self, log_id: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._state.get(log_id)
            return dict(entry) if entry else None

    def put(self, log_id: str, entry: dict[str, Any]) -> None:
        with self._lock:
            self._state[log_id] = entry
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                dir=str(self._path.parent), prefix=self._path.name, suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self._state, fh, indent=2)
                os.replace(tmp, self._path)
            finally:
                if os.path.exists(tmp):
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass


@dataclass
class WitnessNode:
    """Protocol logic for the serve node — HTTP-free, unit-testable.

    Refusal rules are SPEC-WITNESS-NODE-1 R2; the HTTP layer only translates
    ``observe()`` results into status codes.
    """

    witness_id: str
    public_key: bytes
    sign_fn: Any
    state: WitnessStateStore
    pinned_log_keys: frozenset[str] = field(default_factory=frozenset)
    require_consistency: bool = False

    def observed(self, log_id: str) -> dict[str, Any] | None:
        return self.state.get(log_id)

    def observe(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Apply the R2 refusal rules; co-sign and persist on success."""
        if isinstance(body.get("sth"), dict):
            sth_dict: Any = body["sth"]
            consistency = body.get("consistency")
        else:
            sth_dict = body
            consistency = None
        try:
            sth = SignedTreeHead.from_dict(dict(sth_dict))
        except (TypeError, KeyError, ValueError):
            return 400, {"error": "malformed STH"}
        if not verify_tree_head(sth):
            return 400, {"error": "invalid log signature on STH"}

        if self.pinned_log_keys and sth.public_key not in self.pinned_log_keys:
            return 403, {"error": "log public key not in pinned set"}

        last = self.state.get(sth.log_id)
        if last is not None:
            pinned_first = last.get("log_public_key")
            if (
                not self.pinned_log_keys
                and pinned_first
                and sth.public_key != pinned_first
            ):
                return 409, {"error": "log key changed since first observation"}
            if sth.tree_size < int(last["tree_size"]):
                return 409, {
                    "error": (
                        f"log shrank: {last['tree_size']} -> {sth.tree_size} — "
                        "possible revert/rewrite"
                    )
                }
            if (
                sth.tree_size == int(last["tree_size"])
                and sth.root_hash != last["root_hash"]
            ):
                return 409, {"error": f"forked history at tree_size {sth.tree_size}"}
            if sth.tree_size > int(last["tree_size"]):
                status, err = self._check_growth(sth, last, consistency)
                if status != 200:
                    return status, err

        cosig = self._cosign(sth)
        self.state.put(
            sth.log_id,
            {
                "log_id": sth.log_id,
                "tree_size": sth.tree_size,
                "root_hash": sth.root_hash,
                "observed_at": cosig.observed_at,
                "log_public_key": sth.public_key,
            },
        )
        return 200, cosig.to_dict()

    def _check_growth(
        self,
        sth: SignedTreeHead,
        last: dict[str, Any],
        consistency: dict[str, Any] | None,
    ) -> tuple[int, dict[str, Any]]:
        old_size = int(last["tree_size"])
        if old_size == 0:
            # Nothing to be consistent with (RFC 6962 proofs need m > 0);
            # anti-rollback/fork checks above still applied.
            return 200, {}
        if isinstance(consistency, dict) and "proof" in consistency:
            try:
                claimed_old_size = int(consistency.get("old_tree_size", -1))
            except (TypeError, ValueError):
                claimed_old_size = -1
            if (
                claimed_old_size != old_size
                or consistency.get("old_root_hash") != last["root_hash"]
            ):
                return 409, {
                    "error": (
                        "consistency proof is not anchored at this witness's "
                        "last observation"
                    )
                }
            proof = consistency.get("proof") or []
            if not isinstance(proof, list) or not rfc6962.store_verify_consistency(
                old_size,
                sth.tree_size,
                str(last["root_hash"]),
                sth.root_hash,
                [str(p) for p in proof],
            ):
                return 409, {
                    "error": "independent RFC 6962 consistency verification failed"
                }
            return 200, {}
        if self.require_consistency:
            return 409, {"error": "consistency proof required (--require-consistency)"}
        return 200, {}

    def _cosign(self, sth: SignedTreeHead) -> CoSignedTreeHead:
        digest = hashlib.sha256(sth.digest() + self.witness_id.encode("utf-8")).digest()
        sig = self.sign_fn(digest)
        return CoSignedTreeHead(
            sth=sth,
            witness_id=self.witness_id,
            witness_public_key=base64.b64encode(self.public_key).decode("ascii"),
            witness_signature=base64.b64encode(sig).decode("ascii"),
            observed_at=time.time(),
        )


class _WitnessHTTPHandler(BaseHTTPRequestHandler):
    """Thin HTTP translation over a bound ``WitnessNode`` (see make_server)."""

    node: WitnessNode

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._send(
                200,
                {
                    "ok": True,
                    "witness_id": self.node.witness_id,
                    "public_key": base64.b64encode(self.node.public_key).decode(
                        "ascii"
                    ),
                },
            )
            return
        if parsed.path == "/observed":
            log_id = (parse_qs(parsed.query).get("log_id") or [""])[0]
            entry = self.node.observed(log_id) if log_id else None
            if entry is None:
                self._send(404, {"error": "no observation for log_id"})
            else:
                self._send(200, entry)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        if parsed.path not in ("/observe", "/"):
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "invalid JSON body"})
            return
        status, payload = self.node.observe(body)
        self._send(status, payload)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # quiet by default; ops logging belongs to the unit/journal


def make_server(node: WitnessNode, host: str, port: int) -> ThreadingHTTPServer:
    """Bind ``node`` into a handler class and return a ready HTTP server."""
    handler = type("BoundWitnessHandler", (_WitnessHTTPHandler,), {"node": node})
    return ThreadingHTTPServer((host, port), handler)


def load_node(
    key_path: str,
    state_path: str | None = None,
    *,
    pinned_log_keys: Sequence[str] = (),
    require_consistency: bool = False,
) -> WitnessNode:
    """Build a WitnessNode from a ``tc-witness init`` key file."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key_p = Path(key_path).expanduser()
    data = json.loads(key_p.read_text("utf-8"))
    if data.get("type") != "ed25519":
        raise ValueError(f"{key_path}: expected type=ed25519, got {data.get('type')}")
    seed = base64.b64decode(data["private_key"])
    pub = base64.b64decode(data["public_key"])
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    state_p = (
        Path(state_path).expanduser()
        if state_path
        else key_p.with_name(key_p.name + ".observed.json")
    )
    return WitnessNode(
        witness_id=data["witness_id"],
        public_key=pub,
        sign_fn=priv.sign,
        state=WitnessStateStore(state_p),
        pinned_log_keys=frozenset(pinned_log_keys),
        require_consistency=require_consistency,
    )


def run_server(args: Any) -> int:
    """Entry point for the ``tc-witness serve`` subcommand."""
    node = load_node(
        args.key,
        getattr(args, "state", None),
        pinned_log_keys=tuple(args.log_pubkey or ()),
        require_consistency=bool(args.require_consistency),
    )
    httpd = make_server(node, args.host, args.port)
    host, port = httpd.server_address[0], httpd.server_address[1]
    print(f"tc-witness serve: id={node.witness_id} listening on {host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
