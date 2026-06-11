# TrustChain enforcement

`.apatch/enforcement.json` is active. All code changes must go through `apatch_apply_session` (MCP) so TrustChain records Ed25519 proofs.

Install git hook:

```bash
git config core.hooksPath scripts/hooks
# or: ln -sf ../../scripts/hooks/pre-commit-trustchain.sh .git/hooks/pre-commit
```

Verify before commit: `apatch verify notarization --staged`

Check mode: `apatch doctor --json` → `trustchain.mode` should be `enforce`.
