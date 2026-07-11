"""Regression contract for the source-built witness container."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_witness_image_installs_the_merged_source() -> None:
    dockerfile = (ROOT / "deploy/witness/Dockerfile").read_text(encoding="utf-8")

    assert "COPY trustchain ./trustchain" in dockerfile
    assert "pip install --no-cache-dir ." in dockerfile
    assert 'pip install --no-cache-dir "trustchain>=3.2.0"' not in dockerfile


def test_witness_compose_uses_repository_root_context() -> None:
    compose = yaml.safe_load(
        (ROOT / "deploy/witness/docker-compose.yml").read_text(encoding="utf-8")
    )
    build = compose["services"]["tc-witness"]["build"]

    assert build["context"] == "../.."
    assert build["dockerfile"] == "deploy/witness/Dockerfile"
