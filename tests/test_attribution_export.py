"""Attribution helpers are exported from the top-level trustchain package."""

import trustchain


def test_attribution_public_exports():
    for name in (
        "AttributionBlock",
        "Dependency",
        "build_attribution_metadata",
        "parse_attribution_metadata",
        "project_share",
        "aggregate_vectors",
        "ATTRIBUTION_METADATA_KEY",
    ):
        assert hasattr(trustchain, name), f"missing export: {name}"
