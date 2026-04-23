"""TrustChain v3 — git-like context layer (CAS, DAG commits, refs).

Implementation is staged; see docs/ADR-016_Context_Layer.md.
"""

from trustchain.v3.cas_io import is_cas_sha256_hex, read_cas_json
from trustchain.v3.compensations import (
    register_reversible,
    reverse_tool_for,
    reverse_tool_for_chain,
)
from trustchain.v3.log_walk import v3_commits_newest_first
from trustchain.v3.manifest_hash import (
    canonical_manifest_json,
    tool_manifest_sha256_hex,
)
from trustchain.v3.merge_commit import write_v3_merge_commit
from trustchain.v3.migrate_v2 import migrate_v2_linear_to_v3, migration_state_path
from trustchain.v3.objects import Blob, Commit, Ref, Tree

__all__ = [
    "Blob",
    "Tree",
    "Commit",
    "Ref",
    "canonical_manifest_json",
    "tool_manifest_sha256_hex",
    "is_cas_sha256_hex",
    "read_cas_json",
    "v3_commits_newest_first",
    "migrate_v2_linear_to_v3",
    "migration_state_path",
    "write_v3_merge_commit",
    "register_reversible",
    "reverse_tool_for",
    "reverse_tool_for_chain",
]
