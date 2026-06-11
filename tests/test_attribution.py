"""Tests for the generic dependency-attribution layer (trustchain.attribution)."""

import pytest

from trustchain.attribution import (
    ATTRIBUTION_METADATA_KEY,
    ATTRIBUTION_SCHEMA_VERSION,
    AttributionBlock,
    Dependency,
    aggregate_consumption,
    aggregate_vectors,
    build_attribution_metadata,
    parse_attribution_metadata,
    project_share,
)

PORTABLE = frozenset({"human", "personal_ai", "third_party"})


def _block(deps, weight=1.0, **kw):
    return AttributionBlock(
        dependencies=tuple(Dependency(**d) for d in deps),
        record_weight=weight,
        **kw,
    )


class TestNormalization:
    def test_vector_normalizes_to_one(self):
        block = _block(
            [
                {"category": "human", "weight": 2.0},
                {"category": "company_ai", "weight": 2.0},
            ]
        )
        vector = block.normalized_vector()
        assert abs(sum(vector.values()) - 1.0) < 1e-12
        assert abs(vector["human"] - 0.5) < 1e-12

    def test_negative_weights_clamped(self):
        block = _block(
            [
                {"category": "human", "weight": 1.0},
                {"category": "company_ai", "weight": -3.0},
            ]
        )
        assert block.normalized_vector() == {"human": 1.0}

    def test_duplicate_categories_summed(self):
        block = _block(
            [
                {"category": "human", "weight": 1.0, "resource": "design"},
                {"category": "human", "weight": 1.0, "resource": "review"},
                {"category": "company_ai", "weight": 2.0},
            ]
        )
        vector = block.normalized_vector()
        assert abs(vector["human"] - 0.5) < 1e-12


class TestAggregation:
    def test_record_weighted_average(self):
        blocks = [
            _block([{"category": "human", "weight": 1.0}], weight=1.0),
            _block([{"category": "company_ai", "weight": 1.0}], weight=3.0),
        ]
        vector = aggregate_vectors(blocks)
        assert abs(vector["human"] - 0.25) < 1e-12
        assert abs(vector["company_ai"] - 0.75) < 1e-12

    def test_verbose_record_does_not_dominate(self):
        blocks = [
            _block(
                [
                    {"category": "company_ai", "weight": 100.0},
                    {"category": "company_data", "weight": 100.0},
                ]
            ),
            _block([{"category": "human", "weight": 0.01}]),
        ]
        vector = aggregate_vectors(blocks)
        assert abs(vector["human"] - 0.5) < 1e-12

    def test_empty_blocks_skipped(self):
        blocks = [
            _block([]),
            _block([{"category": "human", "weight": 1.0}], weight=0.0),
        ]
        assert aggregate_vectors(blocks) == {}


class TestProjection:
    def test_share_inside_set(self):
        vector = {"human": 0.55, "personal_ai": 0.15, "company_ai": 0.30}
        assert abs(project_share(vector, PORTABLE) - 0.70) < 1e-12

    def test_unknown_category_outside_set(self):
        vector = {"human": 0.5, "mystery_ai": 0.5}
        assert abs(project_share(vector, PORTABLE) - 0.5) < 1e-12

    def test_critical_outside_collapses(self):
        vector = {"human": 0.9, "company_data": 0.1}
        assert project_share(vector, PORTABLE, critical_outside=True) == 0.0

    def test_empty_vector_default(self):
        assert project_share({}, PORTABLE) == 1.0
        assert project_share({}, PORTABLE, empty_default=0.0) == 0.0

    def test_critical_detection_via_block(self):
        block = _block(
            [
                {"category": "human", "weight": 0.9, "critical": True},
                {"category": "company_data", "weight": 0.1, "critical": True},
            ]
        )
        assert block.has_critical_outside(PORTABLE)  # company_data is critical+outside
        inside_only = _block([{"category": "human", "weight": 1.0, "critical": True}])
        assert not inside_only.has_critical_outside(PORTABLE)


class TestConsumption:
    def test_costs_summed_separately_from_vector(self):
        blocks = [
            _block(
                [{"category": "human", "weight": 1.0}],
                consumption={"tokens_cost": 100.0},
            ),
            _block(
                [{"category": "company_ai", "weight": 1.0}],
                consumption={"tokens_cost": 50.0, "gpu_hours_cost": 10.0},
            ),
        ]
        assert aggregate_consumption(blocks) == {
            "tokens_cost": 150.0,
            "gpu_hours_cost": 10.0,
        }


class TestMetadataRoundtrip:
    def test_build_and_parse(self):
        meta = {
            ATTRIBUTION_METADATA_KEY: build_attribution_metadata(
                [
                    {"category": "human", "weight": 0.55},
                    {"category": "personal_ai", "weight": 0.15},
                    {
                        "category": "company_ai",
                        "weight": 0.20,
                        "resource": "internal-llm-v3",
                    },
                    {"category": "company_data", "weight": 0.10},
                ],
                evidence={"output_accepted": True},
                consumption={"tokens_cost": 42.0},
            )
        }
        block = parse_attribution_metadata(meta)
        assert block is not None
        assert block.evidence["output_accepted"] is True
        vector = aggregate_vectors([block])
        assert abs(project_share(vector, PORTABLE) - 0.70) < 1e-12

    def test_absent_block_returns_none(self):
        assert parse_attribution_metadata({"other": 1}) is None

    def test_unsupported_schema_raises(self):
        meta = {ATTRIBUTION_METADATA_KEY: {"schema": ATTRIBUTION_SCHEMA_VERSION + 1}}
        with pytest.raises(ValueError):
            parse_attribution_metadata(meta)

    def test_deterministic_payload(self):
        a = build_attribution_metadata([{"category": "human", "weight": 1.0}])
        b = build_attribution_metadata([{"category": "human", "weight": 1.0}])
        assert a == b
