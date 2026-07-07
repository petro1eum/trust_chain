"""Per-tool signing keys — key-backed tool attribution (RFC-003 follow-up).

A tool that signs its results with its OWN key, bound in the registry, turns
``signer_role="tool"`` from a self-asserted label into a proof: the result must
carry a signature by that exact key.
"""

from __future__ import annotations

import pytest

from trustchain.v2.certificate import ToolRegistry
from trustchain.v2.signer import Signer, verify_with_public_key


def test_verify_with_public_key_roundtrip():
    s = Signer()
    resp = s.sign("t", {"x": 1}, signer_role="tool", bind_custody=True)
    assert verify_with_public_key(resp, s.get_public_key()) is True
    assert verify_with_public_key(resp, Signer().get_public_key()) is False


def test_tool_signature_proven_by_registered_key(tmp_path):
    reg = ToolRegistry(registry_dir=str(tmp_path), strict=False)
    tool = Signer()
    reg.bind_tool_key("weather_api", tool.get_public_key())
    resp = tool.sign("weather_api", {"temp": 21}, signer_role="tool", bind_custody=True)
    assert reg.verify_tool_signature(resp) is True
    assert reg.get_tool_key("weather_api") == tool.get_public_key()


def test_unregistered_tool_id_fails(tmp_path):
    reg = ToolRegistry(registry_dir=str(tmp_path), strict=False)
    resp = Signer().sign("unknown", {"x": 1}, signer_role="tool")
    assert reg.verify_tool_signature(resp) is False


def test_agent_selfattestation_is_not_a_tool_signature(tmp_path):
    reg = ToolRegistry(registry_dir=str(tmp_path), strict=False)
    tool = Signer()
    reg.bind_tool_key("t", tool.get_public_key())
    resp = tool.sign("t", {"x": 1})  # no signer_role="tool" => agent self-assertion
    assert reg.verify_tool_signature(resp) is False


def test_impostor_key_for_tool_fails(tmp_path):
    reg = ToolRegistry(registry_dir=str(tmp_path), strict=False)
    reg.bind_tool_key("t", Signer().get_public_key())  # the real tool key
    impostor = Signer()
    resp = impostor.sign("t", {"x": 1}, signer_role="tool")  # signed by a different key
    assert reg.verify_tool_signature(resp) is False


def test_jcs_tool_signature_also_verifies(tmp_path):
    pytest.importorskip("rfc8785")  # canon="jcs" needs trustchain[jcs]
    # cross-key verify is canon-aware
    reg = ToolRegistry(registry_dir=str(tmp_path), strict=False)
    tool = Signer()
    reg.bind_tool_key("t", tool.get_public_key())
    resp = tool.sign("t", {"x": "café"}, signer_role="tool", canon="jcs")
    assert reg.verify_tool_signature(resp) is True
