"""v3 merge-commit with real tree synthesis (three-way merge on CAS).

Старая реализация всегда писала ``Tree(entries={})`` — что соответствует
«drop all state» и не позволяет инструментам (``tc checkout``, replay-UI)
корректно восстановить состояние в merge-point.  Enterprise-контракт
(POST_MVP §merge):

1. *Fast-forward* по tree: если один родитель — предок другого, tree
   merge-коммита равно tree потомка.  Merge всё ещё записывается как
   явный двухпарентный commit, чтобы сохранить «историю слияния».
2. *Ancestor-aware three-way*: если есть общий предок (LCA), берём его
   tree как base; для каждого ключа применяем правило::

        base   A       B      → выбор
        x      x       x       x       (no change)
        x      A'      x       A'      (только A изменил)
        x      x       B'      B'      (только B изменил)
        x      A'      B'      A'=B'?  — иначе ``conflict`` (B wins + metadata)
        -      A'      -       A'      (добавлен в A)
        -      -       B'      B'      (добавлен в B)

   Конфликты не роняют merge (enterprise-пайплайн не может остановиться),
   но фиксируются в ``metadata.conflicts`` — список ключей + выбранная
   сторона, чтобы аудитор мог их проверить.
3. *No common ancestor*: union по ключам; пересечения → same-value
   keep, mismatch → conflict (B wins, записать в metadata).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trustchain.v3.cas_io import is_cas_sha256_hex, read_cas_json
from trustchain.v3.objects import Commit, Ref, Tree


def _parents_of(root: Path, digest: str) -> list[str]:
    obj = read_cas_json(root, digest)
    if not isinstance(obj, dict) or obj.get("type") != "commit":
        return []
    parents = obj.get("parents")
    return [str(p) for p in parents] if isinstance(parents, list) else []


def _tree_entries_of(root: Path, commit_digest: str) -> dict[str, str]:
    obj = read_cas_json(root, commit_digest)
    if not isinstance(obj, dict) or obj.get("type") != "commit":
        return {}
    tree_digest = str(obj.get("tree") or "")
    if not tree_digest:
        return {}
    tobj = read_cas_json(root, tree_digest)
    if not isinstance(tobj, dict) or tobj.get("type") != "tree":
        return {}
    entries = tobj.get("entries")
    if not isinstance(entries, dict):
        return {}
    return {str(k): str(v) for k, v in entries.items()}


def _ancestors(root: Path, tip: str, *, limit: int = 4096) -> set[str]:
    """BFS over commit DAG from ``tip`` inclusive; caps out at ``limit``."""
    seen: set[str] = set()
    q: list[str] = [tip]
    while q and len(seen) < limit:
        cur = q.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for p in _parents_of(root, cur):
            if p not in seen:
                q.append(p)
    return seen


def _find_lca(root: Path, a: str, b: str) -> str | None:
    """Nearest common ancestor via BFS intersection; deterministic picks the
    first encountered from the A-side walk (which is BFS-ordered)."""
    b_ancestors = _ancestors(root, b)
    if not b_ancestors:
        return None
    seen_a: set[str] = set()
    q: list[str] = [a]
    while q:
        cur = q.pop(0)
        if cur in seen_a:
            continue
        seen_a.add(cur)
        if cur in b_ancestors:
            return cur
        for p in _parents_of(root, cur):
            if p not in seen_a:
                q.append(p)
    return None


def _three_way_merge(
    base: dict[str, str], a: dict[str, str], b: dict[str, str]
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Return (merged, conflicts). ``conflicts`` is a list of {key, winner, base, a, b}."""
    conflicts: list[dict[str, Any]] = []
    out: dict[str, str] = {}
    keys: set[str] = set(base) | set(a) | set(b)
    for k in sorted(keys):
        bv = base.get(k)
        av = a.get(k)
        bv_b = b.get(k)
        if av == bv_b:
            # Identical on both sides (or both absent): trivial.
            if av is not None:
                out[k] = av
            continue
        if av == bv:
            # A didn't touch, B changed (or added).
            if bv_b is not None:
                out[k] = bv_b
            continue
        if bv_b == bv:
            # B didn't touch, A changed (or added).
            if av is not None:
                out[k] = av
            continue
        # Both changed differently relative to base → conflict.  B wins (stable
        # tiebreak), but record for audit.
        winner = bv_b if bv_b is not None else av
        if winner is not None:
            out[k] = winner
        conflicts.append(
            {
                "key": k,
                "winner": "b" if bv_b is not None and winner == bv_b else "a",
                "base": bv,
                "a": av,
                "b": bv_b,
            }
        )
    return out, conflicts


def _is_ancestor(root: Path, maybe_ancestor: str, of_: str) -> bool:
    return maybe_ancestor in _ancestors(root, of_)


def _merged_tree_for(
    root: Path, parent_a: str, parent_b: str
) -> tuple[str, dict[str, Any]]:
    """Synthesize merge tree digest; return (tree_digest, strategy_info)."""
    entries_a = _tree_entries_of(root, parent_a)
    entries_b = _tree_entries_of(root, parent_b)

    # Fast-forward by tree content.
    if _is_ancestor(root, parent_a, parent_b):
        t = Tree(entries=entries_b)
        t.write(root)
        return t.digest, {"strategy": "ff-from-b", "conflicts": []}
    if _is_ancestor(root, parent_b, parent_a):
        t = Tree(entries=entries_a)
        t.write(root)
        return t.digest, {"strategy": "ff-from-a", "conflicts": []}

    lca = _find_lca(root, parent_a, parent_b)
    base = _tree_entries_of(root, lca) if lca else {}
    merged, conflicts = _three_way_merge(base, entries_a, entries_b)
    t = Tree(entries=merged)
    t.write(root)
    return (
        t.digest,
        {
            "strategy": "three-way" if lca else "union-no-lca",
            "lca": lca,
            "conflicts": conflicts,
        },
    )


def write_v3_merge_commit(
    chain_root: Path,
    parent_a: str,
    parent_b: str,
    message: str,
    *,
    update_v3_main: bool = True,
    append_reflog: bool = True,
) -> str:
    """Write a merge commit with ``parents=[A,B]`` and a **real** tree.

    Tree synthesis:

    * ``parent_a`` is ancestor of ``parent_b`` → tree of ``parent_b``.
    * ``parent_b`` is ancestor of ``parent_a`` → tree of ``parent_a``.
    * otherwise → three-way merge against LCA (fall-back to union if no LCA).

    Conflict resolution is deterministic (B wins on true divergence) and
    recorded under ``metadata.merge_info.conflicts`` for downstream audit.
    """
    root = chain_root.expanduser().resolve()
    pa = parent_a.strip().lower()
    pb = parent_b.strip().lower()
    if not is_cas_sha256_hex(pa) or not is_cas_sha256_hex(pb):
        raise ValueError("родители должны быть 64-символьными hex SHA-256")
    if pa == pb:
        raise ValueError("merge: нужны два разных родителя")

    ja = read_cas_json(root, pa)
    jb = read_cas_json(root, pb)
    if not isinstance(ja, dict) or ja.get("type") != "commit":
        raise ValueError(f"объект не commit: {pa[:16]}…")
    if not isinstance(jb, dict) or jb.get("type") != "commit":
        raise ValueError(f"объект не commit: {pb[:16]}…")

    tree_digest, strategy = _merged_tree_for(root, pa, pb)

    meta: dict[str, Any] = {
        "kind": "merge",
        "parent_a": pa,
        "parent_b": pb,
        "merge_info": strategy,
    }
    commit = Commit(
        tree_digest=tree_digest,
        parents=[pa, pb],
        message=message.strip() or "merge",
        metadata=meta,
    )
    commit.write(root)
    tip = commit.digest

    if update_v3_main:
        old_ref = ""
        ref_path = root / "refs" / "v3" / "main"
        if ref_path.is_file():
            try:
                old_ref = ref_path.read_text(encoding="utf-8").strip().splitlines()[0]
            except OSError:
                old_ref = ""
        Ref(name="v3/main", commit_digest=tip).write(root)
        if append_reflog:
            line = (
                f"{datetime.now(timezone.utc).isoformat()}\tv3-merge\t"
                f"{old_ref[:64]}\t{tip[:64]}\t{pa[:12]}+{pb[:12]}\n"
            )
            rfl = root / "reflog.txt"
            with rfl.open("a", encoding="utf-8") as rf:
                rf.write(line)

    return tip
