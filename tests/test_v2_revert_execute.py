"""revert(execute=True) actually invokes the registered reverse tool.

DB-free / no network: file-backed chain in a tmp_path .trustchain dir and the
in-process compensation registry (register_reversible). Asserts:
  * execute=True invokes the registered reverse tool (it appends to a list /
    sets a flag) and the signed marker records executed=True + reverse_tool;
  * default execute=False is marker-only (back-compat): the reverse tool is
    NOT invoked and the signed data carries exactly the original 3 keys.

This test FAILS on the old code (revert ignores reversibles and never calls the
reverse tool) and PASSES on the opt-in execute=True fix.
"""

import pytest

from trustchain import TrustChain, TrustChainConfig
from trustchain.v3.compensations import clear_registry, register_reversible


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_registry()
    yield
    clear_registry()


def _make_tc(tmp_path):
    return TrustChain(
        config=TrustChainConfig(
            enable_chain=True, chain_storage="file", chain_dir=str(tmp_path)
        )
    )


def test_revert_execute_invokes_registered_reverse_tool(tmp_path):
    tc = _make_tc(tmp_path)

    # Record forward op.
    tc.sign("bash_tool", {"cmd": "rm -rf /"}, parent_signature=None)
    op_id = tc.chain.log()[0]["id"]

    # Register a reverse tool whose handler records that it actually ran.
    invoked = []

    def undo_bash(**kwargs):
        invoked.append(kwargs)
        return {"restored": True}

    register_reversible("bash_tool", "undo_bash")
    # Bind a callable for the reverse tool id the way production resolves it
    # (self._tools[reverse_tool]["func"]).
    tc._tools["undo_bash"] = {"func": undo_bash}

    revert = tc.revert(op_id=op_id, reason="Malicious command detected", execute=True)

    # The reverse tool was ACTUALLY invoked exactly once.
    assert len(invoked) == 1
    assert invoked[0]["target_op"] == op_id

    # The signed compensatory marker records the execution outcome.
    assert revert.data["action"] == "revert"
    assert revert.data["target_op"] == op_id
    assert revert.data["executed"] is True
    assert revert.data["reverse_tool"] == "undo_bash"
    assert revert.data["reverse_result"] == {"restored": True}

    # Audit trail is intact: forward + revert marker both committed.
    ops = tc.chain.log(limit=10)
    assert len(ops) == 2
    assert ops[-1]["tool"] == "tc_revert"
    assert tc.chain.verify()["valid"] is True


def test_revert_default_is_marker_only_back_compat(tmp_path):
    tc = _make_tc(tmp_path)

    tc.sign("bash_tool", {"cmd": "rm -rf /"}, parent_signature=None)
    op_id = tc.chain.log()[0]["id"]

    invoked = []

    def undo_bash(**kwargs):
        invoked.append(kwargs)
        return {"restored": True}

    register_reversible("bash_tool", "undo_bash")
    tc._tools["undo_bash"] = {"func": undo_bash}

    # Default execute=False: marker-only. The reverse tool must NOT run, and the
    # signed data must carry exactly the original 3 keys (byte-identical path).
    revert = tc.revert(op_id=op_id, reason="Malicious command detected")

    assert invoked == []
    assert revert.data == {
        "action": "revert",
        "target_op": op_id,
        "reason": "Malicious command detected",
    }


def test_revert_execute_marker_only_when_no_reverse_tool(tmp_path):
    tc = _make_tc(tmp_path)

    tc.sign("bash_tool", {"cmd": "rm -rf /"}, parent_signature=None)
    op_id = tc.chain.log()[0]["id"]

    # No reverse tool registered: execute=True falls back to marker-only and
    # records that nothing was executed.
    revert = tc.revert(op_id=op_id, reason="no reverse registered", execute=True)

    assert revert.data["executed"] is False
    assert revert.data["reverse_tool"] is None
    assert tc.chain.verify()["valid"] is True
