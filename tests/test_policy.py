"""Tests for Policy Layer (Phase 13)."""

import pytest

from trustchain import TrustChain, TrustChainConfig
from trustchain.v2.policy import (
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyEngine,
    PolicyRequirement,
    PolicyViolationError,
)


class TestPolicyCondition:
    """Test policy condition matching."""

    def test_tool_match(self):
        """Test tool name matching."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))
        response = tc._signer.sign("database_query", {"sql": "SELECT *"})

        cond = PolicyCondition(tool="database_query")
        assert cond.matches(response)

        cond2 = PolicyCondition(tool="other_tool")
        assert not cond2.matches(response)

    def test_output_contains(self):
        """Test output contains matching."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))
        response = tc._signer.sign("query", {"data": "SSN: 123-45-6789"})

        cond = PolicyCondition(output_contains=["ssn", "passport"])
        assert cond.matches(response)

        cond2 = PolicyCondition(output_contains=["credit_card"])
        assert not cond2.matches(response)


class TestPolicy:
    """Test policy evaluation."""

    def test_deny_policy(self):
        """Test deny action."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))
        response = tc._signer.sign("dangerous_tool", {"action": "delete"})

        policy = Policy(
            name="no_dangerous_tools",
            condition=PolicyCondition(tool="dangerous_tool"),
            action=PolicyAction.DENY,
            message="Dangerous tools are not allowed",
        )

        passed, msg = policy.evaluate(response)
        assert not passed
        assert "Dangerous tools are not allowed" in msg

    def test_allow_policy(self):
        """Test allow action."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))
        response = tc._signer.sign("safe_tool", {"data": "hello"})

        policy = Policy(
            name="allow_safe",
            condition=PolicyCondition(tool="safe_tool"),
            action=PolicyAction.ALLOW,
        )

        passed, msg = policy.evaluate(response)
        assert passed

    def test_require_parent_policy(self):
        """Test require parent tool policy."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        # Create chain
        consent = tc._signer.sign("user_consent", {"granted": True})
        query = tc._signer.sign(
            "database_query", {"sql": "SELECT ssn"}, parent_signature=consent.signature
        )

        policy = Policy(
            name="require_consent_for_pii",
            condition=PolicyCondition(tool="database_query"),
            action=PolicyAction.REQUIRE,
            requirements=[PolicyRequirement(parent_tool="user_consent")],
        )

        # With proper chain - should pass
        passed, msg = policy.evaluate(query, chain=[consent, query])
        assert passed

        # Without chain - should fail
        passed2, msg2 = policy.evaluate(query, chain=None)
        assert not passed2


class TestPolicyEngine:
    """Test policy engine."""

    def test_load_yaml(self):
        """Test YAML loading."""
        yaml_content = """
policies:
  - name: no_pii
    if:
      tool: database_query
      output.contains: ["ssn", "passport"]
    then:
      deny:
        message: PII access denied
"""
        engine = PolicyEngine()
        engine.load_yaml(yaml_content)

        assert len(engine.policies) == 1
        assert engine.policies[0].name == "no_pii"
        assert engine.policies[0].action == PolicyAction.DENY

    def test_evaluate_multiple_policies(self):
        """Test evaluation of multiple policies."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        engine = PolicyEngine()
        engine.add_policy(
            Policy(
                name="allow_search",
                condition=PolicyCondition(tool="search"),
                action=PolicyAction.ALLOW,
            )
        )
        engine.add_policy(
            Policy(
                name="deny_delete",
                condition=PolicyCondition(tool="delete"),
                action=PolicyAction.DENY,
                message="Delete not allowed",
            )
        )

        search_resp = tc._signer.sign("search", {"query": "test"})
        delete_resp = tc._signer.sign("delete", {"id": 1})

        passed1, violations1 = engine.evaluate(search_resp)
        assert passed1
        assert len(violations1) == 0

        passed2, violations2 = engine.evaluate(delete_resp)
        assert not passed2
        assert len(violations2) == 1
