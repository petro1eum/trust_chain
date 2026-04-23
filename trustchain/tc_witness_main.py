"""CLI: ``tc-witness`` — run a public witness node over a TrustChain log.

Usage
-----

Инициализация witness-ключа (Ed25519)::

    tc-witness init --id mystaff --key /etc/trustchain/witness.json

Подписать наблюдение (snapshot HEAD-а log-а в STH-файл)::

    tc-witness observe --key /etc/trustchain/witness.json \\
        --sth-input sth.json --out cosigned.json

Проверить co-signed STH (offline)::

    tc-witness verify cosigned.json

Квоpум (k-of-N)::

    tc-witness quorum --trusted trusted_witnesses.json --min 2 cosig_*.json
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path
from typing import Any


def _die(msg: str, code: int = 2) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def _cmd_init(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    out_path = Path(args.key).expanduser()
    if out_path.exists() and not args.force:
        _die(f"key file {out_path} already exists (use --force to overwrite)")
    priv = ed25519.Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(
            {
                "type": "ed25519",
                "witness_id": args.id,
                "private_key": base64.b64encode(seed).decode("ascii"),
                "public_key": base64.b64encode(pub).decode("ascii"),
                "created_at": time.time(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    try:
        out_path.chmod(0o600)
    except OSError:
        pass
    print(f"witness id={args.id} pub={base64.b64encode(pub).decode()} → {out_path}")
    return 0


def _load_witness_key(path: str) -> tuple[str, bytes, Any]:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    data = json.loads(Path(path).expanduser().read_text("utf-8"))
    if data.get("type") != "ed25519":
        _die(f"{path}: expected type=ed25519, got {data.get('type')}")
    seed = base64.b64decode(data["private_key"])
    pub = base64.b64decode(data["public_key"])
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    return data["witness_id"], pub, priv


def _cmd_observe(args: argparse.Namespace) -> int:
    import hashlib

    from trustchain.v2.witness import CoSignedTreeHead, SignedTreeHead, verify_tree_head

    sth_data = json.loads(Path(args.sth_input).expanduser().read_text("utf-8"))
    sth = SignedTreeHead.from_dict(sth_data)
    if not verify_tree_head(sth):
        _die("STH signature from log operator is INVALID", code=3)

    witness_id, pub, priv = _load_witness_key(args.key)
    digest = hashlib.sha256(sth.digest() + witness_id.encode("utf-8")).digest()
    sig = priv.sign(digest)
    cos = CoSignedTreeHead(
        sth=sth,
        witness_id=witness_id,
        witness_public_key=base64.b64encode(pub).decode("ascii"),
        witness_signature=base64.b64encode(sig).decode("ascii"),
        observed_at=time.time(),
    )
    out = json.dumps(cos.to_dict(), indent=2)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"co-signed STH written to {args.out}")
    else:
        print(out)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from trustchain.v2.witness import CoSignedTreeHead, verify_cosigned

    data = json.loads(Path(args.file).expanduser().read_text("utf-8"))
    cos = CoSignedTreeHead.from_dict(data)
    ok = verify_cosigned(cos)
    print(
        json.dumps(
            {
                "valid": ok,
                "log_id": cos.sth.log_id,
                "tree_size": cos.sth.tree_size,
                "root_hash": cos.sth.root_hash,
                "witness_id": cos.witness_id,
            },
            indent=2,
        )
    )
    return 0 if ok else 1


def _cmd_quorum(args: argparse.Namespace) -> int:
    from trustchain.v2.witness import CoSignedTreeHead, verify_quorum

    trusted_raw = json.loads(Path(args.trusted).expanduser().read_text("utf-8"))
    trusted = {wid: base64.b64decode(pub_b64) for wid, pub_b64 in trusted_raw.items()}
    cosigs = []
    for path in args.files:
        data = json.loads(Path(path).expanduser().read_text("utf-8"))
        cosigs.append(CoSignedTreeHead.from_dict(data))
    out = verify_quorum(cosigs, min_witnesses=args.min, trusted_witness_keys=trusted)
    print(json.dumps(out, indent=2, default=str))
    return 0 if out.get("ok") else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tc-witness",
        description="TrustChain public witness / co-signer CLI",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="generate a new witness Ed25519 identity")
    p_init.add_argument("--id", required=True, help="witness identifier")
    p_init.add_argument("--key", required=True, help="output key file path")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=_cmd_init)

    p_obs = sub.add_parser("observe", help="co-sign a log-published STH")
    p_obs.add_argument("--key", required=True)
    p_obs.add_argument("--sth-input", required=True, help="path to log-signed STH JSON")
    p_obs.add_argument("--out", help="where to write co-signed STH (else stdout)")
    p_obs.set_defaults(func=_cmd_observe)

    p_ver = sub.add_parser("verify", help="verify a co-signed STH")
    p_ver.add_argument("file")
    p_ver.set_defaults(func=_cmd_verify)

    p_quo = sub.add_parser("quorum", help="check k-of-N quorum over co-signed STHs")
    p_quo.add_argument(
        "--trusted",
        required=True,
        help="JSON file mapping witness_id → base64 public_key",
    )
    p_quo.add_argument("--min", type=int, required=True)
    p_quo.add_argument("files", nargs="+")
    p_quo.set_defaults(func=_cmd_quorum)

    ns = parser.parse_args(argv)
    return int(ns.func(ns))


if __name__ == "__main__":
    raise SystemExit(main())
