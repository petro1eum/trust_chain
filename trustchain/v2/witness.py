"""Cross-log public witness / co-signer protocol (ADR-SEC-006).

Назначение
----------
Даже если оператор TrustChain log-а скомпрометирован, независимые witness-узлы
дают **публичную непротиворечивость** (append-only) и защиту от «тихого
rewrite history».

Модель (вдохновлена RFC 9162 §8 Certificate Transparency):

1. **Log** — наш ``PostgresVerifiableChainStore``. Публикует свой HEAD как
   ``SignedTreeHead{log_id, tree_size, root_hash, timestamp}``, подписанный
   собственным Ed25519 ключом.
2. **Witness** — независимый процесс с собственным Ed25519 ключом. Периодически:

   * ``observe(log)`` — тянет текущий STH, проверяет consistency-proof против
     предыдущего наблюдения (``old_length → current_length``), подписывает
     свой ``CoSignedTreeHead`` и публикует.
   * При первом наблюдении consistency-check пропускается (``old_length=0``).
   * Если log ревертнул историю (``current < observed`` или
     ``old_root != recomputed``), witness **отказывается** подписать и
     возвращает ``WitnessError``.

3. **Auditor / клиент** — собирает STH от log-а и co-signed STH от N witnesses,
   сверяет ``root_hash`` совпадает. Требование «k of N witnesses подписали
   тот же root» равносильно public timestamping: без сговора k witnesses
   log не может переписать историю постфактум.

Зачем это критично
------------------

Приватный lg ``.export_public_key()`` + собственный чейн подписей даёт
**целостность** (tamper-evidence), но не **недепонируемость во времени**:
оператор log-а мог бы пересобрать цепочку задним числом, пока никто не
видел старый HEAD. Witness-сеть делает такую атаку **невозможной**, потому
что witnesses уже подписали старые HEAD-ы своими независимыми ключами и
опубликовали их наружу.

Scope OSS модуля
----------------

* Все структуры (``SignedTreeHead``, ``CoSignedTreeHead``) — канонический
  JSON, детерминированный хэш.
* Подписи: Ed25519 (re-used ``trustchain.kms.KeyProvider`` абстракция).
* ``InMemoryWitnessStore`` — минимальный append-only stream witnessed STHs,
  достаточно для CI и small-scale деплоя. Prod использует
  ``PostgresWitnessStore`` (trustchain_pro) или S3/GCS object-lock bucket.
* CLI: ``tc-witness observe <log-dsn>`` / ``tc-witness verify <sth-file>``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

# ── Canonical JSON helpers ────────────────────────────────────────────────────


def _canonical_json(obj: Any) -> bytes:
    """Deterministic JSON (sorted keys, no whitespace) — для подписей."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sth_digest(log_id: str, tree_size: int, root_hash: str, timestamp: float) -> bytes:
    return hashlib.sha256(
        _canonical_json(
            {
                "log_id": log_id,
                "tree_size": tree_size,
                "root_hash": root_hash,
                "timestamp": timestamp,
            }
        )
    ).digest()


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SignedTreeHead:
    """Snapshot of a log's head, signed by the log operator.

    ``timestamp`` — Unix epoch seconds с миллисекундной точностью.
    ``signature`` — base64-encoded Ed25519 signature over canonical JSON of
    ``{log_id, tree_size, root_hash, timestamp}``.
    """

    log_id: str
    tree_size: int
    root_hash: str
    timestamp: float
    signature: str  # base64
    public_key: str  # base64 raw Ed25519 public key (32 bytes)
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SignedTreeHead:
        return cls(**d)

    def digest(self) -> bytes:
        return _sth_digest(self.log_id, self.tree_size, self.root_hash, self.timestamp)


@dataclass(frozen=True)
class CoSignedTreeHead:
    """Witness counter-signature on an STH.

    Подписывается ``CoSignedTreeHead`` → ``sth.digest() || witness_id``.
    Это связывает co-sig с *конкретным* witness-ом и с конкретным STH.
    """

    sth: SignedTreeHead
    witness_id: str
    witness_public_key: str  # base64
    witness_signature: str  # base64
    observed_at: float
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "sth": self.sth.to_dict(),
            "witness_id": self.witness_id,
            "witness_public_key": self.witness_public_key,
            "witness_signature": self.witness_signature,
            "observed_at": self.observed_at,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CoSignedTreeHead:
        return cls(
            sth=SignedTreeHead.from_dict(d["sth"]),
            witness_id=d["witness_id"],
            witness_public_key=d["witness_public_key"],
            witness_signature=d["witness_signature"],
            observed_at=d["observed_at"],
            version=d.get("version", 1),
        )

    def digest(self) -> bytes:
        return hashlib.sha256(
            self.sth.digest() + self.witness_id.encode("utf-8")
        ).digest()


# ── Errors ────────────────────────────────────────────────────────────────────


class WitnessError(Exception):
    """Raised when an STH fails verification or a log reverted history."""


# ── Log protocol (only what witness needs) ────────────────────────────────────


class WitnessableLog(Protocol):
    """Minimal protocol a log must expose so a witness can observe it."""

    @property
    def length(self) -> int: ...

    @property
    def merkle_root(self) -> str | None: ...

    def consistency_proof(self, old_length: int, old_root: str) -> dict: ...


# ── Log-side: sign an STH ─────────────────────────────────────────────────────


def sign_tree_head(
    *,
    log_id: str,
    tree_size: int,
    root_hash: str,
    sign_fn,
    public_key: bytes,
    timestamp: float | None = None,
) -> SignedTreeHead:
    """Produce a log-signed STH.

    ``sign_fn`` — callable (bytes → bytes). Typically
    ``KeyProvider.sign`` или ``trustchain.signer.Signer.sign``.
    """
    ts = timestamp if timestamp is not None else time.time()
    digest = _sth_digest(log_id, tree_size, root_hash, ts)
    sig = sign_fn(digest)
    return SignedTreeHead(
        log_id=log_id,
        tree_size=int(tree_size),
        root_hash=root_hash,
        timestamp=ts,
        signature=base64.b64encode(sig).decode("ascii"),
        public_key=base64.b64encode(public_key).decode("ascii"),
    )


def verify_tree_head(sth: SignedTreeHead) -> bool:
    """Verify the log operator's signature on ``sth``."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as e:  # pragma: no cover
        raise WitnessError("cryptography package required") from e
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(
            base64.b64decode(sth.public_key)
        )
        pub.verify(base64.b64decode(sth.signature), sth.digest())
        return True
    except Exception:
        return False


# ── Witness ───────────────────────────────────────────────────────────────────


@dataclass
class Witness:
    """A single witness node with its own Ed25519 identity.

    ``sign_fn(data) -> bytes`` — can be a local ``Signer.sign`` or a
    ``KeyProvider.sign`` (for Vault/HSM-backed witnesses). This matters for
    enterprise: witnesses run on hardware-backed keys distinct from log keys,
    so a log compromise cannot forge witness signatures.

    ``verify_fn`` — optional; defaults to ed25519 verify against
    ``public_key``.
    """

    witness_id: str
    public_key: bytes  # raw 32 bytes
    sign_fn: Any  # Callable[[bytes], bytes]
    _last_observation: dict[str, Any] = field(default_factory=dict)

    def observe(self, log: WitnessableLog, sth: SignedTreeHead) -> CoSignedTreeHead:
        """Verify append-only invariant и co-sign an STH.

        Алгоритм:

        1. Проверить подпись log-оператора на ``sth``.
        2. Если witness уже наблюдал данный ``log_id`` раньше, запросить
           ``log.consistency_proof(old_length, old_root)``. Любой отрицательный
           ответ → ``WitnessError``.
        3. Проверить, что ``sth.tree_size == log.length`` и
           ``sth.root_hash == log.merkle_root`` (клиент подаёт STH,
           сгенерированный прямо перед вызовом).
        4. Подписать digest(sth) своим ключом, вернуть ``CoSignedTreeHead``.
        """
        if not verify_tree_head(sth):
            raise WitnessError("invalid log signature on STH")

        if sth.log_id != (self._last_observation.get("log_id") or sth.log_id):
            # This witness has only ever observed this log; id must be stable.
            raise WitnessError(
                f"log_id changed: was {self._last_observation['log_id']!r}, "
                f"got {sth.log_id!r}"
            )

        if sth.tree_size != log.length:
            raise WitnessError(
                f"STH tree_size {sth.tree_size} != log.length {log.length}"
            )
        if sth.root_hash != (log.merkle_root or ""):
            raise WitnessError("STH root_hash does not match log's current root")

        last = self._last_observation.get(sth.log_id)
        if last is not None:
            proof = log.consistency_proof(last["tree_size"], last["root_hash"])
            if not proof.get("consistent"):
                raise WitnessError(
                    f"consistency proof failed: {proof.get('reason') or proof}"
                )
            if sth.tree_size < last["tree_size"]:
                raise WitnessError(
                    f"tree shrunk: {last['tree_size']} → {sth.tree_size}"
                )

        # Co-sign.
        digest = hashlib.sha256(sth.digest() + self.witness_id.encode("utf-8")).digest()
        sig = self.sign_fn(digest)

        cosig = CoSignedTreeHead(
            sth=sth,
            witness_id=self.witness_id,
            witness_public_key=base64.b64encode(self.public_key).decode("ascii"),
            witness_signature=base64.b64encode(sig).decode("ascii"),
            observed_at=time.time(),
        )
        self._last_observation = {
            "log_id": sth.log_id,
            "tree_size": sth.tree_size,
            "root_hash": sth.root_hash,
        }
        self._last_observation[sth.log_id] = {
            "tree_size": sth.tree_size,
            "root_hash": sth.root_hash,
        }
        return cosig


def verify_cosigned(cosig: CoSignedTreeHead) -> bool:
    """Verify the witness signature on a co-signed STH.

    Подпись log-оператора проверяется отдельно через ``verify_tree_head``.
    Клиенту обычно нужны оба — поэтому CLI ``tc-witness verify`` делает это
    последовательно и печатает по компоненту.
    """
    if not verify_tree_head(cosig.sth):
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        pub = ed25519.Ed25519PublicKey.from_public_bytes(
            base64.b64decode(cosig.witness_public_key)
        )
        pub.verify(base64.b64decode(cosig.witness_signature), cosig.digest())
        return True
    except Exception:
        return False


# ── Quorum verification ──────────────────────────────────────────────────────


def verify_quorum(
    cosigs: list[CoSignedTreeHead],
    *,
    min_witnesses: int,
    trusted_witness_keys: dict[str, bytes],
) -> dict[str, Any]:
    """Check that at least ``min_witnesses`` из ``trusted_witness_keys`` co-signed
    **the same root_hash** for the same ``log_id`` / ``tree_size``.

    Возвращает ``{"ok": bool, "agreed_root": str | None, "signers": [...]}``.
    """
    if not cosigs:
        return {"ok": False, "reason": "no co-signatures provided"}

    # Все co-sig должны быть валидны и относиться к одному log_id / tree_size.
    log_ids = {c.sth.log_id for c in cosigs}
    if len(log_ids) != 1:
        return {"ok": False, "reason": f"mixed log_ids: {log_ids}"}
    tree_sizes = {c.sth.tree_size for c in cosigs}
    if len(tree_sizes) != 1:
        return {"ok": False, "reason": f"mixed tree_sizes: {tree_sizes}"}

    # Группируем по root_hash; считаем уникальных доверенных свидетелей.
    buckets: dict[str, set[str]] = {}
    for c in cosigs:
        if c.witness_id not in trusted_witness_keys:
            continue
        expected_pub = trusted_witness_keys[c.witness_id]
        if base64.b64decode(c.witness_public_key) != expected_pub:
            continue
        if not verify_cosigned(c):
            continue
        buckets.setdefault(c.sth.root_hash, set()).add(c.witness_id)

    for root, signers in buckets.items():
        if len(signers) >= min_witnesses:
            return {
                "ok": True,
                "agreed_root": root,
                "signers": sorted(signers),
                "min_required": min_witnesses,
            }
    return {
        "ok": False,
        "reason": f"quorum not reached (need {min_witnesses})",
        "buckets": {r: sorted(s) for r, s in buckets.items()},
    }


__all__ = [
    "CoSignedTreeHead",
    "SignedTreeHead",
    "Witness",
    "WitnessError",
    "WitnessableLog",
    "sign_tree_head",
    "verify_cosigned",
    "verify_quorum",
    "verify_tree_head",
]
