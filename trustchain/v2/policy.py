"""Policy Layer for TrustChain (Phase 13).

Note: Uses `from __future__ import annotations` for Python 3.8 compatibility.

Runtime policy enforcement for signed tool calls.
Supports YAML-based policy definitions with deny/allow/require rules.

Example policy:
    policies:
      - name: no_pii_without_consent
        if:
          tool: database_query
          output.contains: ["ssn", "passport"]
        then:
          require:
            - parent_tool: user_consent
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import yaml

from .signer import SignedResponse


class PolicyAction(Enum):
    """Policy enforcement action."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE = "require"


@dataclass
class PolicyCondition:
    """Condition for policy matching."""

    tool: str | None = None
    output_contains: list[str] | None = None
    args_match: dict | None = None
    amount_gt: float | None = None
    amount_lt: float | None = None

    def matches(self, response: SignedResponse, args: dict | None = None) -> bool:
        """Check if condition matches the response."""
        # Tool name match
        if self.tool and response.tool_id != self.tool:
            return False

        # Output contains check
        if self.output_contains:
            data_str = str(response.data).lower()
            if not any(term.lower() in data_str for term in self.output_contains):
                return False

        # Args match
        if self.args_match and args:
            for key, value in self.args_match.items():
                if args.get(key) != value:
                    return False

        # Amount checks
        if self.amount_gt is not None:
            amount = self._extract_amount(response.data, args)
            if amount is None or amount <= self.amount_gt:
                return False

        if self.amount_lt is not None:
            amount = self._extract_amount(response.data, args)
            if amount is None or amount >= self.amount_lt:
                return False

        return True

    def _extract_amount(self, data: Any, args: dict | None = None) -> float | None:
        """Extract numeric amount from data or args."""
        # Try args first
        if args:
            for key in ["amount", "value", "sum", "total"]:
                if key in args:
                    try:
                        return float(args[key])
                    except (ValueError, TypeError):
                        pass

        # Try data
        if isinstance(data, dict):
            for key in ["amount", "value", "sum", "total"]:
                if key in data:
                    try:
                        return float(data[key])
                    except (ValueError, TypeError):
                        pass

        return None


@dataclass
class PolicyRequirement:
    """Requirement for policy enforcement."""

    parent_tool: str | None = None
    signature_valid: bool = True
    within_seconds: int | None = None


@dataclass
class Policy:
    """A single policy rule."""

    name: str
    condition: PolicyCondition
    action: PolicyAction = PolicyAction.ALLOW
    requirements: list[PolicyRequirement] = field(default_factory=list)
    message: str = ""

    def evaluate(
        self,
        response: SignedResponse,
        chain: list[SignedResponse] | None = None,
        args: dict | None = None,
    ) -> tuple[bool, str]:
        """Evaluate policy against response.

        Returns:
            (passed, message) tuple
        """
        # Check if condition matches
        if not self.condition.matches(response, args):
            return True, ""  # Policy doesn't apply

        # Action: DENY
        if self.action == PolicyAction.DENY:
            return False, self.message or f"Policy '{self.name}' denied this action"

        # Action: ALLOW
        if self.action == PolicyAction.ALLOW:
            return True, ""

        # Action: REQUIRE
        if self.action == PolicyAction.REQUIRE:
            for req in self.requirements:
                passed, msg = self._check_requirement(req, response, chain)
                if not passed:
                    return False, msg

        return True, ""

    def _check_requirement(
        self,
        req: PolicyRequirement,
        response: SignedResponse,
        chain: list[SignedResponse] | None,
    ) -> tuple[bool, str]:
        """Check a single requirement."""
        # Parent tool requirement
        if req.parent_tool:
            if not chain:
                return (
                    False,
                    f"Policy '{self.name}': requires parent tool '{req.parent_tool}' but no chain provided",
                )

            # Find parent in chain
            parent_found = False
            for resp in chain:
                if resp.signature == response.parent_signature:
                    if resp.tool_id == req.parent_tool:
                        parent_found = True
                        break

            if not parent_found:
                return (
                    False,
                    f"Policy '{self.name}': requires parent tool '{req.parent_tool}'",
                )

        return True, ""


@dataclass
class PolicyEngine:
    """Engine for evaluating policies against signed responses."""

    policies: list[Policy] = field(default_factory=list)

    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the engine."""
        self.policies.append(policy)

    def load_yaml(self, yaml_content: str) -> None:
        """Load policies from YAML string."""
        data = yaml.safe_load(yaml_content)
        if not data or "policies" not in data:
            return

        for policy_data in data["policies"]:
            policy = self._parse_policy(policy_data)
            self.add_policy(policy)

    def load_file(self, filepath: str) -> None:
        """Load policies from YAML file."""
        with open(filepath) as f:
            self.load_yaml(f.read())

    def _parse_policy(self, data: dict) -> Policy:
        """Parse policy from dict."""
        name = data.get("name", "unnamed")

        # Parse condition
        if_data = data.get("if", {})
        condition = PolicyCondition(
            tool=if_data.get("tool"),
            output_contains=if_data.get("output.contains"),
            args_match=if_data.get("args"),
        )

        # Parse amount conditions
        for key, value in if_data.items():
            if key.startswith("args.") and isinstance(value, dict):
                if ">" in value:
                    condition.amount_gt = float(value[">"])
                if "<" in value:
                    condition.amount_lt = float(value["<"])

        # Parse action and requirements
        then_data = data.get("then", {})

        if "deny" in then_data:
            action = PolicyAction.DENY
            message = then_data.get("deny", {}).get("message", "")
        elif "require" in then_data:
            action = PolicyAction.REQUIRE
            requirements = []
            for req_data in then_data.get("require", []):
                requirements.append(
                    PolicyRequirement(
                        parent_tool=req_data.get("parent_tool"),
                        signature_valid=req_data.get("signature_valid", True),
                    )
                )
            message = ""
        else:
            action = PolicyAction.ALLOW
            requirements = []
            message = ""

        return Policy(
            name=name,
            condition=condition,
            action=action,
            requirements=requirements if action == PolicyAction.REQUIRE else [],
            message=message,
        )

    def evaluate(
        self,
        response: SignedResponse,
        chain: list[SignedResponse] | None = None,
        args: dict | None = None,
    ) -> tuple[bool, list[str]]:
        """Evaluate all policies against a response.

        Returns:
            (all_passed, list of violation messages)
        """
        violations = []

        for policy in self.policies:
            passed, message = policy.evaluate(response, chain, args)
            if not passed:
                violations.append(message)

        return len(violations) == 0, violations


class PolicyViolationError(Exception):
    """Raised when a policy is violated."""

    def __init__(self, violations: list[str]):
        self.violations = violations
        super().__init__(f"Policy violations: {', '.join(violations)}")
