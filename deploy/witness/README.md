# TrustChain witness node — deploy unit (SPEC-WITNESS-NODE-1 R3)

A witness makes retroactive rewrite of a TrustChain verifiable log impossible
without collusion: it remembers every tree head it co-signed and refuses to
sign a log that shrank, forked, or cannot prove RFC 6962 consistency with its
own memory. That guarantee only means something when the witness runs in a
**second trust domain** — another team, another datacenter, another
organization than the log operator. This directory is that unit.

## Key ceremony (on the witness host — the key never leaves it)

```bash
tc-witness init --id bank-witness-1 --key /var/lib/tc-witness/witness.key.json
```

Hand the log operator two strings only: the witness **id** and the **public
key** printed by `init` (they go into the Platform's
`TC_AUDIT_WITNESS_PUBKEYS=bank-witness-1:<b64>`). The private key and the
observation state stay on the witness host.

## Run — docker compose

```bash
docker compose up -d                    # serves on :8747
docker compose run --rm tc-witness init --id bank-witness-1 \
  --key /var/lib/tc-witness/witness.key.json   # first time only
```

## Run — systemd

```bash
pip install trustchain
sudo useradd --system --home /var/lib/tc-witness tc-witness
sudo install -o tc-witness -d /var/lib/tc-witness
sudo -u tc-witness tc-witness init --id bank-witness-1 \
  --key /var/lib/tc-witness/witness.key.json
sudo cp trustchain-witness.service /etc/systemd/system/
sudo systemctl enable --now trustchain-witness
```

Put TLS in front (nginx/caddy) if the log operator reaches the witness over
untrusted networks; the node itself is plain HTTP on localhost by default.

## Log-operator (Platform) wiring

```bash
TC_LOG_STH_KEY=<b64 Ed25519 seed>            # log's STH signing key
TC_AUDIT_WITNESS_URL=https://witness.example/observe
TC_AUDIT_WITNESS_PUBKEYS=bank-witness-1:<b64>
TC_AUDIT_WITNESS_QUORUM=1                    # k of N witnesses
```

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | liveness + witness identity (id, public key) |
| `GET /observed?log_id=` | witness's last co-signed head — the anchor a log uses to build its consistency proof |
| `POST /observe` | bare STH **or** `{"sth": ..., "consistency": {"old_tree_size", "old_root_hash", "proof"}}` → co-signed STH or a 4xx refusal |

## Operational rules

- **`observed.json` is the anchor of the no-rewrite guarantee.** Back it up
  independently of the log operator; restoring an older state weakens (never
  breaks) the fork check for the gap.
- The shipped units run with `--require-consistency`: growth without a
  verifiable RFC 6962 proof is refused. Drop the flag only for legacy log
  clients that cannot ship proofs yet (the node then still enforces
  anti-rollback and anti-fork).
- Pin log keys explicitly with `--log-pubkey <b64>` when known in advance;
  otherwise the key seen at first observation is pinned (TOFU) and a changed
  key is refused.
- Run witnesses at N≥2 independent sites and set the log's quorum accordingly
  — one witness is tamper-evidence, a quorum is tamper-proofing.
