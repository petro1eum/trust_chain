"""Tests for real three-way tree synthesis in v3 merge commits (POST_MVP)."""

from __future__ import annotations

from pathlib import Path

import pytest

from trustchain.v3.cas_io import read_cas_json
from trustchain.v3.merge_commit import write_v3_merge_commit
from trustchain.v3.objects import Blob, Commit, Tree


def _mk_blob(root: Path, payload: bytes) -> str:
    b = Blob(payload)
    b.write(root)
    return b.digest


def _mk_tree(root: Path, entries: dict[str, str]) -> str:
    t = Tree(entries=entries)
    t.write(root)
    return t.digest


def _mk_commit(root: Path, tree_digest: str, parents: list[str], message: str) -> str:
    c = Commit(tree_digest=tree_digest, parents=parents, message=message, metadata={})
    c.write(root)
    return c.digest


def _tree_from_commit(root: Path, commit_digest: str) -> dict[str, str]:
    obj = read_cas_json(root, commit_digest)
    assert isinstance(obj, dict)
    t = read_cas_json(root, obj["tree"])
    assert isinstance(t, dict)
    return dict(t.get("entries") or {})


# ── fast-forward: one parent is ancestor of the other ────────────────────────


def test_merge_ff_tree_uses_descendant(tmp_path: Path) -> None:
    root = tmp_path / ".trustchain"
    root.mkdir(parents=True)

    blob_a = _mk_blob(root, b"A")
    blob_b = _mk_blob(root, b"B")

    t0 = _mk_tree(root, {"x": blob_a})
    c0 = _mk_commit(root, t0, parents=[], message="c0")

    t1 = _mk_tree(root, {"x": blob_a, "y": blob_b})
    c1 = _mk_commit(root, t1, parents=[c0], message="c1")

    tip = write_v3_merge_commit(root, c0, c1, "ff merge")
    merged = _tree_from_commit(root, tip)
    assert merged == {"x": blob_a, "y": blob_b}

    meta = read_cas_json(root, tip)["metadata"]
    assert meta["merge_info"]["strategy"] in ("ff-from-b", "ff-from-a")
    assert meta["merge_info"]["conflicts"] == []


# ── three-way with LCA, no conflicts (add on each side) ───────────────────────


def test_merge_three_way_no_conflict(tmp_path: Path) -> None:
    root = tmp_path / ".trustchain"
    root.mkdir(parents=True)

    blob_base = _mk_blob(root, b"base")
    blob_a = _mk_blob(root, b"A")
    blob_b = _mk_blob(root, b"B")

    t_base = _mk_tree(root, {"common": blob_base})
    c_base = _mk_commit(root, t_base, parents=[], message="base")

    t_a = _mk_tree(root, {"common": blob_base, "only_a": blob_a})
    c_a = _mk_commit(root, t_a, parents=[c_base], message="a-branch")

    t_b = _mk_tree(root, {"common": blob_base, "only_b": blob_b})
    c_b = _mk_commit(root, t_b, parents=[c_base], message="b-branch")

    tip = write_v3_merge_commit(root, c_a, c_b, "merge")
    merged = _tree_from_commit(root, tip)
    assert merged == {"common": blob_base, "only_a": blob_a, "only_b": blob_b}

    meta = read_cas_json(root, tip)["metadata"]
    assert meta["merge_info"]["strategy"] == "three-way"
    assert meta["merge_info"]["lca"] == c_base
    assert meta["merge_info"]["conflicts"] == []


# ── three-way with true conflict: both sides change same key ─────────────────


def test_merge_records_conflict_and_takes_b(tmp_path: Path) -> None:
    root = tmp_path / ".trustchain"
    root.mkdir(parents=True)

    blob_base = _mk_blob(root, b"v0")
    blob_a = _mk_blob(root, b"vA")
    blob_b = _mk_blob(root, b"vB")

    t_base = _mk_tree(root, {"x": blob_base})
    c_base = _mk_commit(root, t_base, parents=[], message="base")

    t_a = _mk_tree(root, {"x": blob_a})
    c_a = _mk_commit(root, t_a, parents=[c_base], message="a")

    t_b = _mk_tree(root, {"x": blob_b})
    c_b = _mk_commit(root, t_b, parents=[c_base], message="b")

    tip = write_v3_merge_commit(root, c_a, c_b, "merge-conflict")
    merged = _tree_from_commit(root, tip)
    assert merged == {"x": blob_b}, "B wins in deterministic conflict rule"

    meta = read_cas_json(root, tip)["metadata"]
    conflicts = meta["merge_info"]["conflicts"]
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c["key"] == "x"
    assert c["winner"] == "b"
    assert c["a"] == blob_a
    assert c["b"] == blob_b
    assert c["base"] == blob_base


# ── union (no common ancestor) ───────────────────────────────────────────────


def test_merge_union_no_lca(tmp_path: Path) -> None:
    root = tmp_path / ".trustchain"
    root.mkdir(parents=True)

    ba = _mk_blob(root, b"a-only")
    bb = _mk_blob(root, b"b-only")

    t_a = _mk_tree(root, {"left": ba})
    c_a = _mk_commit(root, t_a, parents=[], message="root-a")

    t_b = _mk_tree(root, {"right": bb})
    c_b = _mk_commit(root, t_b, parents=[], message="root-b")

    tip = write_v3_merge_commit(root, c_a, c_b, "two roots")
    merged = _tree_from_commit(root, tip)
    assert merged == {"left": ba, "right": bb}

    meta = read_cas_json(root, tip)["metadata"]
    assert meta["merge_info"]["strategy"] == "union-no-lca"
    assert meta["merge_info"]["lca"] is None
    assert meta["merge_info"]["conflicts"] == []
