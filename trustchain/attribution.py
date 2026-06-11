"""Weighted dependency attribution for signed chain records (provenance layer).

Generic primitives for recording *what a result depended on* alongside a
signed chain operation, and for projecting those dependencies into scalar
metrics. The library stays semantically neutral: it does not know what
"portable", "human" or "company_ai" mean — consumers (e.g. the Human Capital
platform's Avatar Economics, ADR-002) define their own category taxonomy and
classification sets. TrustChain provides:

    1. A canonical, deterministic attribution block that fits into the signed
       ``metadata`` of a chain record (v2 ``SignedResponse.metadata`` /
       ``chain_store`` record) or a v3 ``Commit.metadata`` — both are covered
       by the Ed25519 canonical payload, so attribution is tamper-evident.
    2. Aggregation of per-record dependency vectors into a single normalized
       vector (record-weighted, verbose-record safe).
    3. Share projection: the fraction of total attributed weight that falls
       into a caller-supplied category set, with an explicit ``critical``
       override (a single critical dependency outside the set collapses the
       share to 0 — threshold effects are not linear).

Design rules:
    - Pure functions, no I/O: anyone can re-run the math over a chain log and
      reproduce the result (optimistic-oracle friendly).
    - Negative weights are clamped to 0; empty input maps to ``empty_default``
      so absence of evidence has an explicit, documented meaning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

ATTRIBUTION_METADATA_KEY = "attribution"
ATTRIBUTION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Dependency:
    """One edge of a record's dependency graph.

    ``critical=True`` marks a dependency without which the result is not
    reproducible (threshold semantics — see :func:`project_share`).
    """

    category: str
    weight: float
    critical: bool = False
    resource: str = ""

    def clamped_weight(self) -> float:
        return max(0.0, float(self.weight))


@dataclass(frozen=True)
class AttributionBlock:
    """Attribution payload of a single signed record."""

    dependencies: tuple[Dependency, ...]
    record_weight: float = 1.0
    evidence: Mapping[str, Any] = field(default_factory=dict)
    consumption: Mapping[str, float] = field(default_factory=dict)

    def normalized_vector(self) -> dict[str, float]:
        """Per-record category weights normalized to sum 1 (zero-safe)."""
        total = sum(d.clamped_weight() for d in self.dependencies)
        if total <= 0.0:
            return {}
        vector: dict[str, float] = {}
        for dep in self.dependencies:
            w = dep.clamped_weight()
            if w > 0.0:
                vector[dep.category] = vector.get(dep.category, 0.0) + w / total
        return vector

    def has_critical_outside(self, category_set: frozenset[str]) -> bool:
        """True if any critical dependency falls OUTSIDE ``category_set``."""
        return any(
            d.critical and d.category not in category_set for d in self.dependencies
        )


def aggregate_vectors(blocks: Iterable[AttributionBlock]) -> dict[str, float]:
    """Record-weighted average of normalized per-record vectors.

    Each record is normalized internally first so that a verbose record
    (many logged dependencies, large raw weights) cannot dominate the
    aggregate beyond its ``record_weight``. Result sums to 1; empty
    input → empty dict.
    """
    accum: dict[str, float] = {}
    total_weight = 0.0
    for block in blocks:
        vector = block.normalized_vector()
        if not vector:
            continue
        w = max(0.0, float(block.record_weight))
        if w == 0.0:
            continue
        for category, share in vector.items():
            accum[category] = accum.get(category, 0.0) + w * share
        total_weight += w
    if total_weight <= 0.0:
        return {}
    return {k: v / total_weight for k, v in accum.items()}


def project_share(
    vector: Mapping[str, float],
    category_set: frozenset[str],
    *,
    empty_default: float = 1.0,
    critical_outside: bool = False,
) -> float:
    """Fraction of total attributed weight that falls into ``category_set``.

    ``critical_outside=True`` (a critical dependency outside the set exists)
    forces the share to 0.0 regardless of weights — linear weights cannot
    express "nothing works without X".

    Empty/zero vector returns ``empty_default`` (consumers decide whether
    absence of attribution means "fully inside" — e.g. fully portable — or 0).
    Result is clamped to [0, 1].
    """
    if critical_outside:
        return 0.0
    total = sum(max(0.0, float(v)) for v in vector.values())
    if total <= 0.0:
        return max(0.0, min(1.0, float(empty_default)))
    inside = sum(max(0.0, float(vector.get(k, 0.0))) for k in category_set)
    return max(0.0, min(1.0, inside / total))


def aggregate_consumption(blocks: Iterable[AttributionBlock]) -> dict[str, float]:
    """Sum money-denominated consumption across records (cost plane).

    Kept separate from the dependency vector by design: cost measures who
    PAID for a result, not who CREATED it, and must never silently feed a
    distribution-share projection.
    """
    totals: dict[str, float] = {}
    for block in blocks:
        for key, cost in block.consumption.items():
            totals[key] = totals.get(key, 0.0) + max(0.0, float(cost))
    return totals


# ---------------------------------------------------------------------------
# Metadata (de)serialization — fits v2 SignedResponse.metadata / v3 Commit.metadata
# ---------------------------------------------------------------------------


def build_attribution_metadata(
    dependencies: Sequence[Mapping[str, Any]],
    *,
    record_weight: float = 1.0,
    evidence: Mapping[str, Any] | None = None,
    consumption: Mapping[str, float] | None = None,
) -> dict:
    """Canonical attribution block to embed under
    ``metadata[ATTRIBUTION_METADATA_KEY]`` before signing.

    Deterministic shape (stable keys, clamped weights) so that two parties
    serializing the same logical attribution produce identical canonical
    JSON — and therefore identical signatures and hashes.
    """
    deps = []
    for dep in dependencies:
        deps.append(
            {
                "category": str(dep["category"]),
                "weight": max(0.0, float(dep.get("weight", 0.0))),
                "critical": bool(dep.get("critical", False)),
                "resource": str(dep.get("resource", "")),
            }
        )
    return {
        "schema": ATTRIBUTION_SCHEMA_VERSION,
        "record_weight": max(0.0, float(record_weight)),
        "dependencies": deps,
        "evidence": dict(evidence or {}),
        "consumption": {k: float(v) for k, v in (consumption or {}).items()},
    }


def parse_attribution_metadata(metadata: Mapping[str, Any]) -> AttributionBlock | None:
    """Extract an :class:`AttributionBlock` from record metadata.

    Returns None when the record carries no attribution block. Raises
    ``ValueError`` for an unsupported schema version (fail loud rather than
    silently misinterpreting economic evidence).
    """
    block = metadata.get(ATTRIBUTION_METADATA_KEY)
    if block is None:
        return None
    schema = int(block.get("schema", ATTRIBUTION_SCHEMA_VERSION))
    if schema != ATTRIBUTION_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported attribution schema {schema} "
            f"(supported: {ATTRIBUTION_SCHEMA_VERSION})"
        )
    deps = tuple(
        Dependency(
            category=str(d["category"]),
            weight=max(0.0, float(d.get("weight", 0.0))),
            critical=bool(d.get("critical", False)),
            resource=str(d.get("resource", "")),
        )
        for d in block.get("dependencies", ())
    )
    return AttributionBlock(
        dependencies=deps,
        record_weight=max(0.0, float(block.get("record_weight", 1.0))),
        evidence=dict(block.get("evidence", {})),
        consumption={k: float(v) for k, v in block.get("consumption", {}).items()},
    )
