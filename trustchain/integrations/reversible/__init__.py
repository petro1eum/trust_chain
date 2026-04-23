"""Built-in forward → reverse tool id hints (OSS presets).

Runtime agents map these to real tool implementations; the chain stores intent only.
"""

from trustchain.integrations.reversible.presets import BUILTIN_REVERSIBLE_MAP

__all__ = ["BUILTIN_REVERSIBLE_MAP"]
