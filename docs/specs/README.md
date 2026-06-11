# Executable specifications (RFP-007)

Specs live here as `SPEC-<ID>.md`. **Fresh agent:** run `apatch_doctor` and read
`spec_authoring`, `spec_execution`, `spec_run` in the JSON response — format rules are
embedded there; do not guess.

1. Copy `SPEC-TEMPLATE.md` → `SPEC-<YOUR-ID>.md`
2. `apatch_spec_lint(spec='SPEC-<YOUR-ID>')` — fix until `passed: true`
3. Track: `apatch_spec_next` / `apatch_execute_next` / `apatch_spec_run`

Authoring standard: apatch `docs/spec-authoring.md` (apatch repo). Consumer playbook: `AGENTS.md` §3I–§3K.
