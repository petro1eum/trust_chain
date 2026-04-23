# TrustChain — быстрый старт (один экран)

> **TrustChain** is **SSL for AI**: every agent, subagent, tool, skill and data artifact carries a verifiable X.509 certificate chain anchored in a public CA. Combined with a **git-like context layer**, it lets you checkpoint, branch, and roll back agent actions — so AI mistakes become undoable, and trust becomes provable offline.

Полная модель контекста и откатов: [docs/TRUSTCHAIN_CONTEXT_LAYER.md](docs/TRUSTCHAIN_CONTEXT_LAYER.md). Сравнение с Git: [docs/TRUSTCHAIN_VS_GIT.md](docs/TRUSTCHAIN_VS_GIT.md).

## 1. Установка

```bash
pip install trustchain
```

## 2. Минимальный код

```python
from trustchain import TrustChain, TrustChainConfig

tc = TrustChain(TrustChainConfig(enable_chain=True, chain_dir=".trustchain"))
out = tc.sign(tool_id="demo_tool", data={"answer": 42})
assert tc.verify(out)
print(out.signature[:32], "...")
```

## 3. CLI

```bash
tc init
tc log --limit 5
tc log --graph                   # визуальная линия parent_signature
tc log --v3                      # коммиты v3 CAS после migrate-v3 --apply
tc manifest hash tool.json       # SHA-256 канонического manifest (как tc.manifestHash)
tc chain-verify
tc migrate-v3                    # отчёт: сколько v2-ops → v3 commits (без записи)
# tc migrate-v3 --apply        # CAS + refs/v3/main + v3/migration_state.json
tc checkpoint before-risk        # снимок текущего HEAD в refs/checkpoints/
tc tag release-2026-04           # refs/tags/ (immutable pointer)
tc branch experiment             # указатель ветки в refs/heads/
tc checkout experiment           # HEAD из refs/heads/experiment.ref
tc refs                          # список checkpoint / heads
tc reset --dry-run --soft op_0002  # куда сдвинется HEAD (без записи)
# файл .trustchain/reversibles.json: {"demo_tool":"demo_undo"}
tc revert HEAD                   # подписать revert_intent (не вызывает undo в процессе)
tc cert request --platform https://keys.trust-chain.ai   # шаги выпуска agent leaf cert (Platform CA)
```

Переменная **`TRUSTCHAIN_DIR`** задаёт каталог цепи. Команда **`tc config`** показывает, какой каталог реально использует CLI.

## 4. Офлайн-проверка экспорта

После экспорта `jsonl.gz` (например из TrustChain Agent):

```bash
tc-verify ./trustchain_chain.jsonl.gz --pubkey "BASE64_PUBLIC_KEY"
```

С проверкой PKIX-цепочки и CRL с публичного реестра (лист Ed25519 должен совпасть с `--pubkey`):

```bash
tc-verify ./trustchain_chain.jsonl.gz --pubkey "BASE64_PUBLIC_KEY" --full-chain \
  --registry-base "https://keys.trust-chain.ai" --agent-id "YOUR_AGENT_ID"
```

## 5. Дальше

- [README.md](README.md) — обзор и интеграции  
- [docs/PRODUCT_MATRIX.md](docs/PRODUCT_MATRIX.md) — OSS / Pro / SaaS  
- [docs/TRUSTCHAIN_VS_GIT.md](docs/TRUSTCHAIN_VS_GIT.md) — метафора «git для AI» и реальность  

**Идея в одной строке:** подпись доказывает, что данные пришли из реального вызова тула, а не из галлюцинации модели.
