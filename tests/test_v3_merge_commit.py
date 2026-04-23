"""Тесты v3 merge-коммита."""

from pathlib import Path

import pytest

from trustchain.v3.cas_io import read_cas_json
from trustchain.v3.merge_commit import write_v3_merge_commit
from trustchain.v3.objects import Commit, Tree


def test_write_v3_merge_commit_two_roots(tmp_path: Path) -> None:
    root = tmp_path / ".trustchain"
    root.mkdir(parents=True)
    tree = Tree(entries={})
    tree.write(root)
    td = tree.digest

    c0 = Commit(tree_digest=td, parents=[], message="root-a", metadata={})
    c0.write(root)
    c1 = Commit(tree_digest=td, parents=[], message="root-b", metadata={})
    c1.write(root)

    tip = write_v3_merge_commit(root, c0.digest, c1.digest, "merge two roots")

    obj = read_cas_json(root, tip)
    assert isinstance(obj, dict)
    assert obj.get("type") == "commit"
    assert obj.get("parents") == [c0.digest, c1.digest]
    assert obj.get("message") == "merge two roots"
    assert obj.get("metadata", {}).get("kind") == "merge"

    ref = (
        (root / "refs" / "v3" / "main")
        .read_text(encoding="utf-8")
        .strip()
        .splitlines()[0]
    )
    assert ref == tip


def test_write_v3_merge_commit_rejects_same_parent(tmp_path: Path) -> None:
    root = tmp_path / ".trustchain"
    root.mkdir(parents=True)
    tree = Tree(entries={})
    tree.write(root)
    c0 = Commit(tree_digest=tree.digest, parents=[], message="x", metadata={})
    c0.write(root)
    with pytest.raises(ValueError, match="два разных"):
        write_v3_merge_commit(root, c0.digest, c0.digest, "bad")
