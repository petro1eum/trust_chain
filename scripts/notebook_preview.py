"""Render reviewed OSS notebooks with their actual outputs for GitHub Pages.

Only the five canonical public notebooks are accepted. Pro notebooks/test licenses
must never be exported into this public repository.
"""
from __future__ import annotations
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from importlib.metadata import version
import json
from pathlib import Path
import platform
import sys
from urllib.parse import unquote, urljoin, urlsplit

PUBLIC_NOTEBOOKS = {"tutorial", "advanced", "llm", "full_demo", "receipts"}


def validate_preview_source(path: Path, test_license: bool):
    from nbconvert import HTMLExporter  # optional dependency, checked before execution
    root = Path(__file__).resolve().parents[1]
    allowed = {root / "examples" / f"trustchain_{name}.ipynb" for name in PUBLIC_NOTEBOOKS}
    if test_license or path.resolve() not in allowed:
        raise ValueError("Public previews are restricted to canonical OSS notebooks without a Pro test license")


def save_preview(path: Path, notebook, directory: Path, *, colab_run: dict | None = None):
    from nbconvert import HTMLExporter
    validate_preview_source(path, False)
    body, _ = HTMLExporter(template_name="basic", exclude_input_prompt=True,
                           exclude_output_prompt=True).from_notebook_node(notebook)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(body, "html.parser")
    for node in soup.find_all(id=True):
        node["id"] = unquote(node["id"])
    for node in soup.find_all("a", href=True):
        href = node["href"]
        if href and not href.startswith("#") and not urlsplit(href).scheme:
            node["href"] = urljoin("https://github.com/petro1eum/trust_chain/blob/main/examples/", href)
    body = str(soup).replace(escape(sys.prefix), "&lt;python-environment&gt;")
    title = {"trustchain_llm": "The LLM tool boundary", "trustchain_receipts": "Portable receipts", "trustchain_advanced": "Keys, batches & tenants", "trustchain_tutorial": "Getting started", "trustchain_full_demo": "A complete agent workflow"}[path.stem]
    source = f"https://github.com/petro1eum/trust_chain/blob/main/examples/{path.name}"
    colab = f"https://colab.research.google.com/github/petro1eum/trust_chain/blob/main/examples/{path.name}"
    metadata = {"notebook": path.name, "source_sha256": sha256(path.read_bytes()).hexdigest(),
                "executed_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
                "trustchain": version("trustchain"), "code_cells": sum(c.cell_type == "code" for c in notebook.cells),
                "outputs": sum(len(c.get("outputs", [])) for c in notebook.cells),
                "execution_errors": 0, "environment_paths_redacted": True, "installation_cells_skipped": True,
                "provider_credentials_removed": True, "live_model_called": False,
                "execution_environment": "fresh local kernel; preinstalled dependencies",
                "html": path.stem + ".html"}
    if colab_run is not None:
        metadata.update(colab_run)
        baseline = "; ".join(metadata["baseline_pip_check"]) or "no issues"
        run_note = (f"Executed {metadata['executed_at'][:10]} in a fresh Google Colab Python "
                    f"{metadata['python']} runtime with Core {metadata['trustchain']}. "
                    "Every original code cell ran, including dependency installation. "
                    "TrustChain Pro and its license were absent before and after execution. "
                    f"No new dependency conflicts were introduced. Baseline pip check: {baseline} "
                    "No live model was called. Optional external services may show an unavailable result. "
                    "This page is a saved preview, not a live Python session.")
    else:
        run_note = (f"Executed {metadata['executed_at'][:10]} in a fresh local Python {metadata['python']} "
                    f"kernel with Core {metadata['trustchain']}. Dependencies were installed before the run, "
                    "so installation cells are omitted here. Provider credentials were removed; "
                    "no live model was called. Local environment paths are redacted. Optional external "
                    "services may show a skipped or unavailable result. This page is a saved preview, "
                    "not a live Python session.")
    html = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)} · Executed TrustChain notebook</title><link rel="stylesheet" href="../docs.css"><link rel="stylesheet" href="../notebook.css"></head>
<body><a class="skip" href="#content">Skip to notebook</a><header><a href="../index.html">TrustChain</a><nav aria-label="Notebook"><a href="../notebooks.html">Notebook catalog</a><a href="{source}">Source on GitHub</a><a href="{colab}">Run in Colab</a></nav></header>
<main id="content"><p class="eyebrow">OSS · saved execution</p><h1>{escape(title)}</h1><p class="lead">Read the code alongside its actual synthetic outputs.</p><div class="note">{escape(run_note)}</div><p class="small">{metadata['code_cells']} code cells completed without execution errors. <a href="manifest.json">Source hash and run metadata</a>.</p><article class="notebook-output">{body}</article></main><footer><a href="../notebooks.html">All public notebooks</a> · <a href="../factcrypt-demo.html">FactCrypt example · paid Pro</a></footer></body></html>'''
    directory.mkdir(parents=True, exist_ok=True)
    (directory / metadata['html']).write_text(html)
    manifest = directory / "manifest.json"
    records = json.loads(manifest.read_text()) if manifest.exists() else {}
    records[path.name] = metadata
    manifest.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    return metadata
