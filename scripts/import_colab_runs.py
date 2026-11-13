"""Validate saved Colab runs and publish only canonical OSS code and outputs.

These checks establish consistency with browser-observed execution, not a
cryptographic attestation of Google execution. No notebook code is run here.
Drive user metadata and diagnostic cells are excluded from the public previews.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

import nbformat

from notebook_preview import PUBLIC_NOTEBOOKS, save_preview

ROOT = Path(__file__).resolve().parents[1]


def output_record(cell, prefix):
    records = []
    for output in cell.get("outputs", []):
        if output.get("output_type") == "stream" and output.get("name") == "stdout":
            for line in output.text.splitlines():
                if line.startswith(prefix + " "):
                    records.append(json.loads(line[len(prefix) + 1:]))
    if len(records) != 1:
        raise ValueError(f"Expected exactly one {prefix} output")
    return records[0]


def validate_run(name: str, executed: Path):
    if name not in PUBLIC_NOTEBOOKS:
        raise ValueError("Only canonical OSS notebook names are accepted")
    source = ROOT / "examples" / f"trustchain_{name}.ipynb"
    original = nbformat.read(source, as_version=4)
    run = nbformat.read(executed, as_version=4)
    nbformat.validate(run)
    cells = [c for c in run.cells if c.cell_type == "code"]
    originals = [c for c in original.cells if c.cell_type == "code"]
    if len(cells) != len(originals) + 2:
        raise ValueError("Expected every original cell plus preflight and postflight")
    if [c.source.strip() for c in cells[1:-1]] != [c.source.strip() for c in originals]:
        raise ValueError("Executed code differs from the current canonical source")
    counts = [c.execution_count for c in cells]
    if any(type(n) is not int or n < 1 for n in counts):
        raise ValueError("An execution count is missing")
    if counts != list(range(counts[0], counts[0] + len(counts))):
        raise ValueError("Cells were not executed in sequence")
    for cell in cells:
        if any(o.output_type == "error" for o in cell.outputs):
            raise ValueError("A cell has an execution error")
        if cell.metadata.get("executionInfo", {}).get("status") != "ok":
            raise ValueError("A cell lacks successful Colab execution metadata")
    before = output_record(cells[0], "COLAB_PREFLIGHT")
    after = output_record(cells[-1], "COLAB_ACCEPTANCE_PASS")
    if before.get("core_before_install") is not False:
        raise ValueError("Core must be absent before installation")
    for record in (before, after):
        if record.get("pro_installed") is not False or record.get("pro_license_present") is not False:
            raise ValueError("Pro must be absent throughout the run")
    conflicts = set(after["pip_check_after"]) - set(before["baseline_pip_check"])
    conflicts.discard("No broken requirements found.")
    if conflicts or after.get("new_dependency_conflicts") != []:
        raise ValueError("The installation introduced dependency conflicts")
    if before["python"] != after["python"] or not after.get("runtime_host"):
        raise ValueError("Inconsistent runtime evidence")
    # Copy only outputs/counts into the reviewed source: no Drive identity metadata.
    for target, actual in zip(originals, cells[1:-1]):
        target.outputs = deepcopy(actual.outputs)
        target.execution_count = actual.execution_count
    timestamp = cells[-1].metadata.executionInfo.timestamp / 1000
    metadata = {
        "executed_at": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "python": after["python"], "trustchain": after["trustchain"],
        "execution_environment": "Google Colab; fresh hosted CPU runtime",
        "installation_cells_skipped": False,
        "provider_credentials_removed": False,
        "live_model_called": False,
        "pro_installed": False, "pro_license_present": False,
        "core_present_before_install": False,
        "baseline_pip_check": before["baseline_pip_check"],
        "pip_check_after": after["pip_check_after"],
        "new_dependency_conflicts": [],
        "acceptance_check_cells": 2,
        "all_original_code_cells_match": True,
        "evidence_kind": "browser-observed run; saved ipynb consistency checks",
    }
    return source, original, metadata, after["runtime_host"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="append", required=True, metavar="NAME=EXECUTED_IPYNB")
    parser.add_argument("--preview-dir", type=Path, default=ROOT / "docs/notebooks")
    args = parser.parse_args()
    pairs = [item.split("=", 1) for item in args.run]
    if len(pairs) != 5 or any(len(p) != 2 for p in pairs) or {p[0] for p in pairs} != PUBLIC_NOTEBOOKS:
        parser.error("Supply each of tutorial, advanced, llm, full_demo, receipts exactly once")
    # Validate the entire set before writing any public output.
    runs = [validate_run(name, Path(path)) for name, path in pairs]
    if len({r[3] for r in runs}) != 5:
        raise ValueError("Expected five independent runtime hosts")
    for source, notebook, metadata, _ in runs:
        result = save_preview(source, notebook, args.preview_dir, colab_run=metadata)
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
