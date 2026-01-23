"""Policy Hooks for TrustChain (OSS).

Provides extension points for policy enforcement without the full engine.
Use TrustChain Pro for complete PolicyEngine with YAML rules.

Usage:
    def my_validator(response: SignedResponse, context: dict) -> bool:
        if response.tool_id == "payment" and context.get("amount", 0) > 10000:
            return False  # Block
        return True

    tc.register_policy_hook(my_validator)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .signer import SignedResponse


# Type alias for policy hook functions
PolicyHook = Callable[["SignedResponse", dict], bool]


class PolicyHookRegistry:
    """Registry for policy hooks (OSS version).

    Allows registering custom validation functions that run
    after tool execution but before returning the response.

    For advanced governance with YAML rules, see TrustChain Pro.
    """

    def __init__(self):
        self._hooks: list[PolicyHook] = []

    def register(self, hook: PolicyHook) -> None:
        """Register a policy hook.

        Args:
            hook: Function(response, context) -> bool
                  Returns True to allow, False to block
        """
        self._hooks.append(hook)

    def unregister(self, hook: PolicyHook) -> None:
        """Remove a policy hook."""
        if hook in self._hooks:
            self._hooks.remove(hook)

    def evaluate(
        self,
        response: SignedResponse,
        context: dict | None = None,
    ) -> tuple[bool, str | None]:
        """Run all hooks against a response.

        Args:
            response: The signed response to validate
            context: Additional context (args, metadata, etc.)

        Returns:
            (passed, error_message) - True if all hooks pass
        """
        context = context or {}

        for hook in self._hooks:
            try:
                if not hook(response, context):
                    hook_name = getattr(hook, "__name__", "anonymous")
                    return False, f"Policy hook '{hook_name}' blocked request"
            except Exception as e:
                hook_name = getattr(hook, "__name__", "anonymous")
                return False, f"Policy hook '{hook_name}' error: {e}"

        return True, None

    def clear(self) -> None:
        """Remove all hooks."""
        self._hooks.clear()

    @property
    def count(self) -> int:
        """Number of registered hooks."""
        return len(self._hooks)


# Global registry instance
_global_registry = PolicyHookRegistry()


def register_policy_hook(hook: PolicyHook) -> None:
    """Register a global policy hook.

    Example:
        def block_large_payments(response, context):
            if context.get("amount", 0) > 10000:
                return False
            return True

        register_policy_hook(block_large_payments)
    """
    _global_registry.register(hook)


def get_policy_registry() -> PolicyHookRegistry:
    """Get the global policy hook registry."""
    return _global_registry
