"""LangChain must not load on ``import trustchain`` (Python 3.14+ pydantic v1 warning)."""

from __future__ import annotations

import sys
import warnings


def test_import_trustchain_does_not_load_langchain_core():
    for key in list(sys.modules):
        if key == "langchain_core" or key.startswith("langchain_core."):
            del sys.modules[key]
    if "trustchain" in sys.modules:
        del sys.modules["trustchain"]

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        import trustchain  # noqa: F401

    pydantic_v1 = [
        w
        for w in caught
        if issubclass(w.category, UserWarning) and "Pydantic V1" in str(w.message)
    ]
    assert (
        not pydantic_v1
    ), f"unexpected warnings: {[str(w.message) for w in pydantic_v1]}"
    assert "langchain_core" not in sys.modules


def test_lazy_langchain_export_still_works():
    from trustchain.integrations import to_langchain_tool

    try:
        from langchain_core.tools import BaseTool  # noqa: F401
    except ImportError:
        assert to_langchain_tool is None
    else:
        assert to_langchain_tool is not None
        assert "langchain_core" in sys.modules
