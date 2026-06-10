# ИИ-агенты и apatch MCP

Этот проект использует [apatch](https://github.com/petro1eum/apatch) для управляемых мутаций кода.

> **Ты в consumer-репозитории.** Этот файл (`AGENTS.md`) — **единственный** операционный контракт. Пути `docs/…` репозитория apatch **недоступны**. Всё нужное — здесь, в `manifests/PROFILE.*.md`, `manifests/*.json`.  
> **Только MCP tools** (`apatch_*`). Не `search_replace`, не `sed`, не терминал `apatch` при доступном MCP. Каждый вызов: `target_dir="."`.

---

## 0. Политика (не обсуждается)

Любое изменение исходного кода в protected-зонах обязано пройти **governed lifecycle** и иметь **Ed25519-подпись** в `.trustchain/` (при `enforce`). Правка в обход → `DIRECT_WRITE_BLOCKED`, `TRUSTCHAIN_REJECTED`, `NOTARIZATION_FAILED`; git hook отклонит commit.

**Core invariant:** `Intent → Session → Mutation → Verification → Attestation | Rollback`

Читай в **каждом** MCP-ответе: `state_update.next_action`, `invariant.satisfied`, `error_type`, `recommended_action`.

---

## 1. Каждая сессия начинается здесь

```text
apatch_doctor(target_dir=".")
```

**Протокол (не обсуждается):** `apatch_doctor` → **`protocol_contract`** — там же, почему
нельзя ручной staging `patches.jsonl` и N× `spec_next`. **Вся спека за один проход:**
**`spec_run`** (RFP-009) → `apatch_spec_run(spec, requirements={Rk: {needles}})` — consumer
**не** читает `docs/RFP-009-spec-run.md` в репо apatch; capability в поле MCP.

**Executable specs:** также читай **`spec_authoring`**, **`spec_execution`** (§3I),
**`spec_run`** (§3K). Спеки: `docs/specs/SPEC-*.md`. Cursor rule `apatch-protocol.mdc`
(`alwaysApply`) после `init-consumer --with-mcp`.

| Поле doctor | Что делать |
|-------------|------------|
| `recommended_workflow` | Канонический порядок шагов (ниже) |
| `recommended_verify` | Человекочитаемая verify-цепочка |
| `recommended_verify_resolved` | Shell verify с абсолютными путями — передавай в `verify=` и default `apatch_verify_run` |
| `agent_protocol` | `mass_refactor`, `preflight_tool`, `checkpoint_after_every_chunk`, sandbox |
| `trustchain.mode` | `audit_pending` → `audit` → **`enforce`** (цель consumer) |
| `trustchain.behaviors` | `no_trustchain_allowed`, `incremental_notarization`, … |
| `sandbox` | Если `enabled` — protected зоны только через lease |
| `enforcement.active` | Если true — `no_trustchain` на apply **запрещён** |
| `warnings` | Устрани до массового рефакторинга |
| `mcp_health.tool_count` | Актуальное число MCP tools (справочник §8 синхронизирован) |
| `spec_authoring` | **Формат SPEC.md** — rules, lint_tool, template_minimal |
| `spec_execution` | §3I loop, workflow_choice (3I/3J/3K) |
| `spec_run` | §3K batch, needles, verify_deferred, lessons |
| `agent_protocol.executable_specs_entrypoint` | Краткая отсылка: doctor → spec_* playbooks |
| **`protocol_contract`** | **Антипаттерны** (ручной jsonl, обход session) + task_routing + RFP-009 summary |

**Жёсткий протокол (spec):**

0. **Вся спека** → `apatch_spec_run` (RFP-009), не N× §3I и не hand-staged jsonl.
1. **Одно Rk** → `apatch_execute_next(needles=[…])` или §3I вручную.
2. Цикл §3I на Rk: `spec_next` → `session_start(requirement)` → **`apatch_generate_batch`** → `simulate` → `apply_session` → **`verify_run` (из спеки)** → `attest` → `session_end`.

**Жёсткий протокол (общий):**

1. Массовые правки (>15 кандидатов) — только **`apatch_apply_session`**, не `apatch_apply`.
2. После **каждого** chunk сохраняй `checkpoint`; при сбое — `apatch_rollback(session_id=checkpoint)`.
3. Повторяй apply_session пока `continue=true` (`agent_next` / `state_update.next_action`).
4. Перед массовым apply: **`apatch_simulate`** → оцени `risk_level`, `rollback_probability`.
5. При ошибке apatch — чини apatch, не обходи regex/sed.

---

## 2. Что делаешь? (decision tree)

```text
Задача?
├─ Strip / декомпозиция монолита     → §3A  (session → dry-run → strip/phase → verify → attest)
├─ Мутации (replace / create / …)   → §3B  (session → generate_batch → simulate → apply_session)
├─ Replay транскрипта IDE             → §3C  (scan → plan_batch → apply, only_drifted)
├─ Pipeline / orchestrate манифест  → §3D  (orchestrate или plan_graph → execute_graph)
├─ Рефакторинг с БД                 → §3E  (generate → apply_session → db_check → db_revision)
├─ Один–несколько точечных патчей   → §3F  (≤15 канд.: plan → apply)
├─ Spec-driven: вся спека (≥2 Rk)   → §3K  (spec_run + inline requirements)
├─ Spec-driven: одно Rk / debug     → §3J  (execute_next)
├─ Spec-driven: inspection / dogfood → §3I  (spec_next → session per Rk)
└─ Post-mortem / откат              → §3G  (replay, rollback, sandbox_audit)
```

**Всегда:** `apatch_session_start` перед мутацией, `apatch_session_end` после успешной verify+attest (или `rollback` при провале).  
При `governed_mode=auto_session` (дефолт `--with-enforcement`) сессия создаётся автоматически; при `strict` — явный `session_start` обязателен.

**Artifact-anchored intent (RFP-006):** при работе по спеке/ADR/тикету передай `artifacts` в `apatch_session_start` — тогда TrustChain доказуемо связывает решение с мутациями и attestation. После `apatch_attest` проверь `apatch_trustchain_coverage(artifact="spec:SPEC-42")` (`coverage.complete`).

**Executable specifications (RFP-007):** спеки живут в `docs/specs/SPEC-<ID>.md`. Формат: `# SPEC-<ID>` + `## R1 …` + `(verify: pytest …)` на каждое требование. Цикл — §3I; `apatch_doctor` → `spec_execution`.

---

## 3. Workflows (MCP)

Подставь `verify` из `doctor.recommended_verify_resolved`, если не указано иное.

### 3A. Strip / phase (React, C++, multi-file)

```text
apatch_session_start(target_dir=".", intent="strip <Component> → hook|native")
apatch_suggest_until(file_path="src/pages/Page.tsx",
  start_marker="  const dispatch: AppDispatch = useDispatch();", target_dir=".")
# Ожидай: kind=root_return, confidence≥0.9, source=ast (.tsx → grammar tsx)
# Манифест: end_before "  return (" (отступ важен; не `};`) — strip_guide § AST-first
apatch_strip_dry_run(file_path="src/pages/Page.tsx", manifest_path="manifests/<phase>.json",
  strict_overlap=true, out_dir="src/pages/hooks", target_dir=".")
# dry-run: boundary_assessment (boundary_source, unstable), dangling_references

apatch_strip(file_path="src/pages/Page.tsx", manifest_path="manifests/<phase>.json",
  to_module="hook", module_out_dir="src/hooks", auto_wire=true, target_dir=".")
# или bundle + verify на фазу:
apatch_phase_run(manifest_path="manifests/<phase>.json", profile="frontend", to_module="hook",
  module_out_dir="src/hooks", verify=<resolved>, auto_wire=true, target_dir=".")
# governed (enforce consumer, governed_mode=strict): сначала session_start, затем:
apatch_governed_phase_run(manifest_path="manifests/<phase>.json", profile="frontend", to_module="hook",
  module_out_dir="src/hooks", verify=<resolved>, auto_wire=true, target_dir=".")

apatch_verify_run(target_dir=".")
apatch_attest(target_dir=".")
apatch_attestation_export(target_dir=".", out_path=".apatch/audit_bundle.json")
apatch_session_end(target_dir=".")
```

C++: `profile="cpp"`, `native_out_dir=…`, затем `apatch_natives_check(directory=…)`.  
Multi-file: манифест с `files[]` → `apatch_phase_run` без `file_path`.

### 3B. Мутации (replace / create / delete / rename)

**Единый цикл** — `apatch_generate_batch` (mutation generator), не ручной JSONL с `Add File`.

```text
apatch_session_start(target_dir=".", intent="implement <feature>")
apatch_generate_batch(
  needles=[
    {action: "create", target_file: "src/domain/foo.ts", content: "…"},
    {action: "create", target_file: "src/domain/foo.test.ts", content: "…"},
    {action: "replace", find_text: "…", replace_text: "…", target_file: "src/index.ts"},
    # {action: "delete", target_file: "src/legacy.ts"},
    # {action: "rename", source_file: "src/old.ts", target_file: "src/new.ts"},
  ],
  out_path="patches.jsonl",
  target_dir=".",
)
apatch_simulate(logs_path="patches.jsonl", target_dir=".")
apatch_apply_session(logs_path="patches.jsonl", target_dir=".", verify=<resolved>)
# ПОВТОРЯЙ apply_session пока continue=true

apatch_verify_run(target_dir=".")
apatch_verify_notarization(target_dir=".", staged=true)
apatch_attest(target_dir=".")
apatch_session_end(target_dir=".")
```

| `action` | Поля | Примечание |
|----------|------|------------|
| `replace` (default) | `find_text`, `replace_text`, `target_file?` | файл должен существовать |
| `create` | `target_file`, `content` | файл **не** должен существовать |
| `delete` | `target_file` | |
| `rename` | `source_file`, `target_file` | create + delete в JSONL |

Legacy: needle без `action` = replace. `apatch_plan(old_content="")` — dry-run CREATE.

**Только массовый replace одним паттерном:** `apatch_generate` + тот же цикл simulate → apply_session.  
`match_mode` (replace): `literal` | `whitespace` | `regex` | `json` | `yaml`.

### 3C. Replay транскрипта IDE

```text
apatch_session_start(target_dir=".", intent="replay transcript")
apatch_scan(limit=5, target_dir=".")
apatch_plan_batch(logs_path="<from scan>", target_dir=".")
apatch_apply(logs_path="...", target_dir=".", only_drifted=true, verify=<resolved>, dry_run_first=true)
apatch_verify_run(target_dir=".")
apatch_session_end(target_dir=".")
```

### 3D. Orchestrate / pipeline

```text
apatch_session_start(target_dir=".", intent="orchestrate <manifest>",
  artifacts=["adr:ADR-000", "spec:SPEC-user-model"])
apatch_trustchain_history(target_dir=".", artifact="adr:ADR-000")
apatch_orchestrate(manifest_path="manifests/engineering-pipeline.example.json", target_dir=".", dry_run=true)
apatch_orchestrate(manifest_path="manifests/engineering-pipeline.example.json", target_dir=".")
# альтернатива: apatch_pipeline_run(manifest_path=..., dry_run=true) → без graph

apatch_verify_run(target_dir=".")
apatch_attest(target_dir=".")
apatch_trustchain_coverage(target_dir=".", artifact="adr:ADR-000")
apatch_session_end(target_dir=".")
```

По шагам: `apatch_plan_graph` → `apatch_execute_graph`.

### 3H. Artifact traceability (post-mortem / compliance)

```text
apatch_trustchain_history(target_dir=".", artifact="spec:SPEC-42")
apatch_trustchain_coverage(target_dir=".", artifact="spec:SPEC-42")
# coverage.complete → есть и mutation, и attestation

apatch_trustchain_coverage(target_dir=".", op_id="<op_id from ledger or inclusion>")
# обратный маппинг: op_id → artifacts[], role (mutation|attestation|intent)
```

### 3I. Spec-driven (RFP-007, `docs/specs/SPEC-*.md`)

**Формат (lint проверяет):** H1 `# SPEC-<ID>`; в блоке `> **apatch artifact:** \`spec:SPEC-<ID>\`` (тот же id); каждое требование `## R1 <title>` с уникальным `(verify: <cmd>)`.

```text
apatch_spec_lint(target_dir=".", spec_path="docs/specs/SPEC-<ID>.md")
apatch_spec_next(target_dir=".", spec="SPEC-<ID>")
apatch_session_start(target_dir=".", requirement="SPEC-<ID>#R1")
apatch_generate_batch(needles=[…]) → apatch_simulate → apatch_apply_session(...)
apatch_verify_run(target_dir=".", verify="<verify из spec_next>")
apatch_attest(target_dir=".")
apatch_spec_status(target_dir=".", spec="SPEC-<ID>")
apatch_session_end(target_dir=".")
```

Повторяй `spec_next` → session(requirement) → mutate → verify → attest, пока все `Rk` = `attested`.  
Не делай второй `apply_session` в lifecycle `verifying` — сначала `verify_run`, потом следующий чанк или новая session.

### 3J. Spec executor (RFP-008) — requirement execution

**Единица работы — требование `Rk`, не JSONL.** Не пиши `scripts/build_*_patches.py` — мутации через `apatch_generate_batch` (`action`: replace | create | delete | rename) или inline в `execute_next`.

```text
apatch_execute_next(target_dir=".", spec="SPEC-<ID>", dry_run=true)   # план + next Rk
apatch_execute_next(target_dir=".", spec="SPEC-<ID>")                  # session_start(Rk)
# gap analysis → needles
apatch_execute_next(target_dir=".", spec="SPEC-<ID>", needles=[
  {action: "create", target_file: "…", content: "…"},
  {action: "replace", find_text: "…", replace_text: "…", target_file: "…"},
])
apatch_execute_next(target_dir=".", spec="SPEC-<ID>", finalize=true)  # verify → attest → session_end
apatch_execute_next(target_dir=".", spec="SPEC-<ID>")                  # следующий Rk
```

Человек говорит «продолжай SPEC-ONPREM-2» — агент вызывает `apatch_execute_next`, не «выполни R3».
Зависимости между спеками (`**Зависимость:** [SPEC-PARENT]`) блокируют старт при `SPEC_DEPENDENCY_UNMET`.

§3I (ручной цикл `spec_next` + …) — dogfood / inspection. **Одно Rk** — §3J. **Вся спека** — §3K.

### 3K. Spec run (RFP-009) — вся спека одним workflow

**Когда:** спека из нескольких `Rk`, needles на все pending требования уже известны (или после dry-run).
**Единица вызова:** вся спека (chunked), не одно `Rk` как в §3J.

**Primary path — inline `requirements`, без staging JSON на диск.** `manifest_path` — только CI/review.

```text
apatch_doctor(target_dir=".")
apatch_spec_lint(target_dir=".", spec="SPEC-<ID>")

# 1) План и gaps (без мутаций)
apatch_spec_run(target_dir=".", spec="SPEC-<ID>", dry_run=true)
# → pending[], gaps[], manifest_template (в ответе — не пиши файл)

# 2) Batch run (один или несколько тиков)
apatch_spec_run(target_dir=".", spec="SPEC-<ID>", requirements={
  "R1": {"needles": [{action: "create", target_file: "…", content: "…"}]},
  "R2": {"needles": [{action: "replace", find_text: "…", replace_text: "…", target_file: "…"}]},
})
# chunk_rk_per_call=0 (default) — все pending Rk за один тик
# пока continue=true: apatch_spec_run(target_dir=".", spec="SPEC-<ID>")  # resume

apatch_spec_status(target_dir=".", spec="SPEC-<ID>")   # done: true
```

**Внутри каждого Rk** (автоматически): `session_start` → `generate_batch` → `simulate` →
`apply_session` → `verify_run` (из `(verify: …)` в SPEC.md) → `attest` → `session_end`.
Если verify уже проходит **и needles пуст** — мутации пропускаются (`verify_precheck_passed`).
Если needles заданы — **всегда** `generate_batch` → `apply_session`, даже когда verify зелёный.

**State:** `.apatch/spec_run.json` — `rk_index`, `manifest_sha256`, `per_rk`, `last_checkpoint`.
`reset=true` — сброс; `abort=true` — rollback + clear; смена manifest без reset → `MANIFEST_DRIFT`.

**Ответ:** `continue`, `done`, `progress{rk_done,rk_total}`, `current_requirement`, `agent_next`.
При `blocked`: `error_type` (`SPEC_RUN_BLOCKED`, `MANIFEST_GAP`, …), `requirement_token`, `resume_hint`.

| Выбор | §3K spec_run | §3J execute_next | §3I manual |
|-------|--------------|------------------|------------|
| Много Rk, needles известны | ✅ | ❌ N× round-trips | ❌ |
| Одно Rk / hotfix | overkill | ✅ | ✅ |
| Dogfood apatch/SPEC-*.md | ✅ если batch | ✅ | ✅ эталон attest |

**Антипаттерн:** писать `manifests/SPEC-X.run.json` перед каждым прогоном; N× `execute_next`
когда `requirements` уже собран; ручной `session_start` на каждом Rk при известном manifest.

**Уроки dogfood (не повторять):**

| Ошибка | Как надо |
|--------|----------|
| Needles как текстовые подсказки | Только mutation dicts: `{action, target_file, find_text/replace_text}` или `{action, target_file, content}` |
| **Doc-only Rk: needle только в `attestation.md`** | Needle в **целевом артефакте**, который проверяет `(verify:)` — playbook, manifest `_readme`, тестовый файл. `attestation.md` — зеркало, не единственная мутация. Иначе `verify_precheck` зелёный → `skipped_mutations` → attest не биндится |
| `attest` без мутаций в той же session | `spec_run` держит invariant: mutate + verify + attest + `session_end` per Rk; не вызывай `finalize` отдельно |
| Chunk verify откатывает патч | `verify_deferred=true` на mutate (default в `spec_run` / `execute_next`); verify — после всех chunk'ов `apply_session` |
| Неверные literal в `find_text` | Бери строки из реального кода (пример: API **`/api/v1/work-items/`**, не `/items/`) |

### 3E. Рефакторинг с БД

```text
apatch_session_start(target_dir=".", intent="db refactor <models>")
apatch_generate(...) → patches.jsonl
apatch_apply_session(logs_path="patches.jsonl", verify_deferred=true, verify=<resolved>, target_dir=".")
apatch_impact(target="ModelName", target_dir=".")
apatch_db_check(profile="sqlalchemy", target_dir=".")
apatch_db_revision(profile="sqlalchemy", message="...", dry_run=true, target_dir=".")
apatch_db_safety(profile="sqlalchemy", target_dir=".")
apatch_arch_check(rules_path="manifests/arch-rules.yaml", target_dir=".")
apatch_db_check(profile="sqlalchemy", target_dir=".")   # ok: true
apatch_verify_run(target_dir=".")
apatch_session_end(target_dir=".")
```

Или: `apatch_db_run(manifest_path="manifests/db-refactor.example.json")`.  
Миграции Alembic/Prisma/Django — **отдельно** после apply. Профиль: `manifests/PROFILE.<stack>.md`.

### 3F. Точечные патчи (≤15 кандидатов)

```text
apatch_plan(target_file="...", old_content="...", new_content="...", target_dir=".")
apatch_apply(logs_path="...", steps="5,10", budget="medium", min_confidence=0.85, verify=<resolved>, target_dir=".")
```

При >15 кандидатах ответ укажет `use_tool: apatch_apply_session`.

### 3G. Post-mortem / откат

```text
apatch_replay(target_dir=".", session_id="<checkpoint>")   # → .apatch/replay_log.json
apatch_rollback(session_id="<checkpoint>", target_dir=".")
apatch_sandbox_audit(target_dir=".", auto_revert=true)
apatch_verify_notarization(target_dir=".", staged=true)
```

При `ok: false` + `VERIFY_FAILED` / `NOTARIZATION_FAILED`: **`apatch_rollback`**, не чини файлы вручную.

---

## 4. Failure taxonomy

| `error_type` | `recommended_action` | Когда |
|--------------|----------------------|-------|
| `TRUSTCHAIN_REJECTED` | `retry_chunk` | нет подписи / policy hook |
| `VERIFY_FAILED` | `rollback` | verify упал, файлы откатились |
| `NOTARIZATION_FAILED` | `rollback` | файлы записаны, block не создан |
| `ARCH_VIOLATION` | `reduce_scope` | arch-rules |
| `DB_RISK` | `reduce_scope` | опасные миграции |
| `BUDGET_EXCEEDED` | `reduce_scope` | change budget |
| `APPLY_FAILED` | `rollback` | chunk apply failed |
| `MASS_APPLY_BLOCKED` | `reduce_scope` | >15 канд. без session |
| `DIRECT_WRITE_BLOCKED` | `retry_chunk` | sandbox: Write без lease |
| `LEASE_EXPIRED` | `retry_chunk` | lease истёк |
| `LEASE_CONFLICT` | `retry_chunk` | другой pid держит lease |
| `SESSION_ABORTED` | `retry_chunk` | `abort=true` |
| `RUNTIME_TRANSITION` | см. `hint` / `agent_next` | неверная фаза lifecycle |
| `MANIFEST_GAP` | `reduce_scope` | pending Rk без `needles` в requirements/manifest |
| `MANIFEST_DRIFT` | `retry_chunk` | manifest hash ≠ active `.apatch/spec_run.json`; `reset=true` |
| `SPEC_RUN_BLOCKED` | `rollback` / resume | verify/apply failed на Rk в spec_run |
| `SPEC_DEPENDENCY_UNMET` | `reduce_scope` | upstream SPEC не `done` |

Поля: `error_type`, `recoverable`, `recommended_action`, `failure`, `rejection_prompt`.

Явная проверка фазы: `apatch_session_state(target_dir=".")`.

---

## 5. State machine

Каждый MCP tool пишет **`state_update`** в `.apatch/session_state.json`:

```json
{
  "phase": "idle | plan | apply | verify | arch | db | rollback | complete | blocked",
  "checkpoint": "apatch_sess_…",
  "last_tool": "apatch_apply_session",
  "budget_remaining": 3,
  "trustchain": true,
  "risk_level": "low | medium | high",
  "next_action": "…"
}
```

---

## 6. Локальные файлы

| Путь | Назначение |
|------|------------|
| `manifests/*.json` | strip / phase / pipeline манифесты |
| `manifests/arch-rules.yaml` | `apatch_arch_check` |
| `manifests/semantic-verify.yaml` | `apatch_verify_semantic` |
| `manifests/PROFILE.*.md` | verify и цепочки стека |
| `patches.jsonl` | сгенерированные / replay патчи |
| `.trustchain/` | Ed25519 ledger |
| `.apatch/enforcement.json` | notarization enforcement |
| `.apatch/notarized_index.json` | sha256 нотаризованных файлов |
| `.apatch/sandbox.json` | write sandbox |
| `.apatch/write_lease.json` | capability lease (во время apply) |
| `.apatch/session_state.json` | фаза lifecycle |
| `.apatch/spec_run.json` | spec_run checkpoint (RFP-009): rk_index, manifest hash |
| `.apatch/events.jsonl` | domain events (`apatch_events_tail`) |
| `.apatch/backups/` | бэкапы для rollback |
| `.cursor/hooks.json` | Cursor sandbox hooks |

**Не коммитить:** `extracted/`, `**/extraction_report.json`, `.apatch/*` (кроме `sandbox.json`, `enforcement.json`).

---

## 7. Sandbox и TrustChain

**Sandbox** (`apatch_init_consumer(with_sandbox=true)`):

| Зона | Правило |
|------|---------|
| Protected | `src/**`, `app/**`, `services/**`, `packages/**` — только через `apatch_apply_session` / strip lease |
| Allow | `docs/**`, `manifests/**`, `tests/**`, `scripts/**`, `**/*.md` |
| MCP mutations | Только `apatch_*` tools |
| MCP inspection | `cursor-ide-browser` (default) — navigate/snapshot, read-only |

```text
apatch_sandbox_status(target_dir=".")
apatch_sandbox_audit(target_dir=".", auto_revert=true)
apatch_sandbox_ci_gate(target_dir=".")   # PR gate
```

**TrustChain** (`with_enforcement=true`): `no_trustchain` запрещён; после step — нотаризация; провал → rollback. Перед commit: `apatch_verify_notarization(staged=true)`.

---

## 8. MCP tools — полный справочник (60)

CLI = то же имя без префикса `apatch_` / `apatch ` (`apatch --help`).  
**Только MCP:** `apatch_plan`. **Только CLI (TUI):** интерактивный `apatch apply` без `-y`.

### Session и lifecycle

| MCP | Назначение |
|-----|------------|
| `apatch_doctor` | Окружение, verify, trustchain, sandbox, `recommended_workflow` |
| `apatch_session_start` | Intent + governed session; `artifacts` — `kind:id@hash` или dict (RFP-006); `requirement='SPEC-42#R3'` (RFP-007) |
| `apatch_session_end` | Закрыть session |
| `apatch_session_state` | lifecycle, intent, `artifacts[]`, invariant (read) |
| `apatch_spec_lint` | RFP-007: стандарт авторинга `docs/specs/SPEC-*.md` |
| `apatch_spec_status` | RFP-007: статус каждого `Rk` из ledger |
| `apatch_spec_next` | RFP-007: следующее открытое требование + `verify` |

### Патчи и apply

| MCP | Назначение |
|-----|------------|
| `apatch_scan` | JSONL транскрипты IDE |
| `apatch_view` | Кандидаты в логе |
| `apatch_plan` | Dry-run одного патча |
| `apatch_plan_batch` | Dry-run JSONL |
| `apatch_generate` | JSONL find/replace (`match_mode`, `glob_pattern`, `append`) |
| `apatch_generate_batch` | **Mutation generator:** `action` replace\|create\|delete\|rename → JSONL; `append` |
| `apatch_execute_next` | RFP-008: governed cycle на одно `Rk` (needles → batch внутри) |
| `apatch_spec_run` | RFP-009: вся спека — inline `requirements` (default chunk=all) |
| `apatch_spec_run_manifest_lint` | Валидация run manifest vs SPEC.md |
| `apatch_apply` | ≤15 кандидатов (`budget`, `steps`, `range_str`) |
| `apatch_apply_session` | **Массовый apply чанками** (`chunk_max_files`, `verify_deferred`, `checkpoint`) |
| `apatch_simulate` | Preflight: `risk_map`, `rollback_probability` |
| `apatch_rollback` | Откат по `session_id` (= checkpoint) |
| `apatch_replay` | Timeline chunk'ов |

**apply_session:** `logs_path`, `verify`, `chunk_max_files` (5), `replace_all`, `only_drifted`, `min_confidence`, `verify_deferred`, `reset`, `abort`, `tool`, `keyword`.  
**Ответ:** `ok`, `continue`, `checkpoint`, `chunk_result`, `agent_next`, `verify_rollback`, `state_update`.

### Strip и декомпозиция

| MCP | Назначение |
|-----|------------|
| `apatch_strip_dry_run` | Preview (`strict_overlap`) |
| `apatch_suggest_until` | Границы `until` → `score`, `confidence` |
| `apatch_strip` | Вырезать блоки через `MutationRuntime`; session gate по `governed_mode` |
| `apatch_phase_run` | Strip + module/native + verify через `MutationRuntime`; `files[]` в манифесте |
| `apatch_governed_phase_run` | Alias `phase_run` (тот же runtime-path; отличается `finish_tool` в ответе) |
| `apatch_natives_check` | Дубликаты `register_native()` (C++) |

### Verify и attestation

| MCP | Назначение |
|-----|------------|
| `apatch_verify_run` | Default: shell `recommended_verify_resolved`; или `verify=`, `semantic`, `notarization`, `pipeline_manifest` |
| `apatch_verify_status` | Unified verification status |
| `apatch_verify_semantic` | Маршруты/экспорты (`manifests/semantic-verify.yaml`) |
| `apatch_verify_notarization` | staged/working tree vs notarized index |
| `apatch_attest` | TrustChain commit; подписанные `intent` + `artifacts[]` сессии |
| `apatch_attestation_show` | mode, HEAD, recent events |
| `apatch_attestation_export` | audit bundle JSON |
| `apatch_events_tail` | tail `.apatch/events.jsonl` |
| `apatch_trust_enroll` | Enroll агента (мост к `tc cert request`) → корневой якорь |
| `apatch_verify_anchor` | CI-гейт: подпись apatch → leaf → root CA (PKIX + key-binding) |
| `apatch_verify_inclusion` | CI-гейт: записанные op_id включены во внешний append-only лог (Merkle proof) |

### Orchestration, DB, index

| MCP | Назначение |
|-----|------------|
| `apatch_orchestrate` | simulate → plan_graph → execute_graph |
| `apatch_plan_graph` | Dependency graph |
| `apatch_execute_graph` | Topo execute |
| `apatch_pipeline_run` | Линейный engineering-pipeline |
| `apatch_impact` | Затронутые файлы/тесты |
| `apatch_arch_check` | `manifests/arch-rules.yaml` |
| `apatch_db_check` | Модели без миграции |
| `apatch_db_revision` | Черновик миграции |
| `apatch_db_safety` | DROP/ALTER риски |
| `apatch_db_run` | Манифест db-refactor |
| `apatch_refactor_run` | Bundle `rename_symbol` |
| `apatch_index_build` | `.apatch/project_index.json` |
| `apatch_index_query` | Символы, миграции, ADR |
| `apatch_trustchain_history` | Прошлые intent/artifact; `query` (substring) или `artifact` (`kind:id`) |
| `apatch_trustchain_coverage` | Traceability matrix; `artifact` или `op_id` (reverse lookup) |
| `apatch_compile` | Semantic ID в Markdown |

### Sandbox и consumer

| MCP | Назначение |
|-----|------------|
| `apatch_sandbox_status` | mode, lease, hooks, violations |
| `apatch_sandbox_audit` | audit; `auto_revert=true` |
| `apatch_sandbox_ci_gate` | PR gate (`base` для diff PR; + policy drift) |
| `apatch_policy_sign` | Подписать конфиг монитора → `.apatch/policy.lock.json` (tamper-evident) |
| `apatch_policy_verify` | Проверить подпись политики + дрейф конфига |
| `apatch_init_consumer` | Скаффолд (`profile`, `with_sandbox`, `with_enforcement`, `with_ci`, `refresh_agents`) |

---

## 9. Антипаттерны

| Нельзя | Вместо этого |
|--------|----------------|
| sed / awk / массовый `search_replace` | `apatch_generate_batch` + `apatch_apply_session` |
| `scripts/build_*_patches.py` (кастомный JSONL) | `apatch_generate_batch(needles=[{action:…}, …])` |
| Ручной JSONL с `*** Add File:` для новых файлов | `{action: "create", target_file, content}` в `generate_batch` |
| `apatch_apply` на весь репо | `apatch_apply_session` |
| Терминал `apatch` при MCP | MCP tools |
| Чинить полусломанное дерево руками | `apatch_rollback` |
| Игнорировать `state_update.next_action` | Следовать lifecycle |
| Commit без notarization verify | `apatch_verify_notarization(staged=true)` |
| Inline Python в `verify=` с кавычками | Простая команда: `"pytest"`, `"npm run build"` |
| Читать `docs/` apatch по URL | Этот файл + `manifests/` |

---

<!-- apatch:stack:start -->
<!-- apatch:stack:end -->

---

## 10. Проектный backlog (опционально)

Свои фазы, монолиты, манифесты — **между маркерами** (сохраняются при `apatch init-consumer --refresh-agents`):

<!-- apatch:project:start -->
(пусто — заполни: следующие strip-фазы, verify для этого репо, `manifests/REFACTOR_PLAN.md`)
<!-- apatch:project:end -->

---

## 11. Настройка MCP (для человека, не для агента)

Агент **не поднимает** MCP-сервер. Человек:

1. `pip install -e "/path/to/apatch[mcp]"`
2. `.cursor/mcp.json` в корне проекта — `apatch init-consumer` создаёт шаблон
3. Refresh MCP Servers в IDE
4. `apatch_doctor(target_dir=".")` → `mcp_health.ok: true`

Stderr → `.apatch/mcp_stderr.log`. Env: `PYTHONIOENCODING=utf-8`, `PYTHONUTF8=1`.

Обновить этот playbook из apatch: `apatch init-consumer --refresh-agents` (сохранит §10 project-блок).
