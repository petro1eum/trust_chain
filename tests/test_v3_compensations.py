"""v3 compensations registry."""

import json
from pathlib import Path

from trustchain.v3.compensations import (
    clear_registry,
    register_reversible,
    reverse_tool_for,
    reverse_tool_for_chain,
)


def test_register_and_lookup() -> None:
    clear_registry()
    register_reversible("file_write", "file_restore_from_snapshot")
    assert reverse_tool_for("file_write") == "file_restore_from_snapshot"
    assert reverse_tool_for("unknown") is None


def test_clear_registry() -> None:
    clear_registry()
    register_reversible("a", "b")
    clear_registry()
    assert reverse_tool_for("a") is None


def test_reverse_tool_for_chain_json(tmp_path: Path) -> None:
    clear_registry()
    root = tmp_path / ".trustchain"
    root.mkdir()
    (root / "reversibles.json").write_text(
        json.dumps({"forward_x": "reverse_y"}), encoding="utf-8"
    )
    assert reverse_tool_for_chain(root, "forward_x") == "reverse_y"
    assert reverse_tool_for_chain(root, "missing") is None


def test_process_registry_wins_over_file(tmp_path: Path) -> None:
    clear_registry()
    root = tmp_path / ".trustchain"
    root.mkdir()
    (root / "reversibles.json").write_text(
        json.dumps({"t": "from_file"}), encoding="utf-8"
    )
    register_reversible("t", "from_proc")
    assert reverse_tool_for_chain(root, "t") == "from_proc"
    clear_registry()
