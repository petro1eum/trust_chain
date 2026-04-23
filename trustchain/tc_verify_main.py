"""Offline verifier CLI — ``tc-verify``.

Verifies gzip JSONL exports from TrustChain Agent (meta line + operation lines)
using a base64 Ed25519 public key (same format as ``trustchain_keys.json`` export).

Usage:
    tc-verify chain.jsonl.gz --pubkey "$(cat pubkey.b64)"
    tc-verify chain.jsonl.gz --pubkey BASE64 --show-meta

With PKIX (Root → Intermediate → Agent) and CRL (optional)::

    tc-verify export.jsonl.gz --pubkey BASE64 --full-chain \\
        --registry-base https://keys.trust-chain.ai --agent-id my-agent

Or with local PEM files::

    tc-verify export.jsonl.gz --pubkey BASE64 --full-chain \\
        --root-ca-pem root.pem --intermediate-pem ca.pem --agent-cert-pem agent.pem \\
        --crl-pem crl.pem
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_crl

from trustchain import TrustChainVerifier
from trustchain.v2.signer import SignedResponse


def _http_get(url: str, timeout_s: float = 20.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "trustchain-tc-verify/3"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return resp.read().decode("utf-8")


def _fetch_registry_bundle(
    registry_base: str, agent_id: str
) -> tuple[str, str, str, str]:
    base = registry_base.rstrip("/")
    root_pem = _http_get(f"{base}/api/pub/root-ca")
    int_pem = _http_get(f"{base}/api/pub/ca")
    crl_pem = _http_get(f"{base}/api/pub/crl")
    agent_pem = _http_get(
        f"{base}/api/pub/agents/{urllib.parse.quote(agent_id, safe='')}/cert"
    )
    return root_pem, int_pem, agent_pem, crl_pem


def _verify_pkix_chain(
    root_pem: str, intermediate_pem: str, agent_pem: str
) -> x509.Certificate:
    root = load_pem_x509_certificate(root_pem.encode("utf-8"))
    inter = load_pem_x509_certificate(intermediate_pem.encode("utf-8"))
    agent = load_pem_x509_certificate(agent_pem.encode("utf-8"))
    rp = root.public_key()
    rp.verify(inter.signature, inter.tbs_certificate_bytes)
    ip = inter.public_key()
    ip.verify(agent.signature, agent.tbs_certificate_bytes)
    return agent


def _assert_not_revoked(agent: x509.Certificate, crl_pem: str) -> None:
    crl = load_pem_x509_crl(crl_pem.encode("utf-8"))
    rev = crl.get_revoked_certificate_by_serial_number(agent.serial_number)
    if rev is not None:
        raise ValueError(f"agent leaf serial {agent.serial_number} is on CRL")


def _leaf_ed25519_raw(agent: x509.Certificate) -> bytes:
    pk = agent.public_key()
    if not isinstance(pk, Ed25519PublicKey):
        raise TypeError(
            f"Leaf SPKI must be Ed25519 for comparison with --pubkey (got {type(pk).__name__})"
        )
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _pubkey_arg_bytes(pubkey_b64: str) -> bytes:
    return base64.b64decode(pubkey_b64.strip())


def _run_full_chain(
    pubkey_b64: str,
    registry_base: str | None,
    agent_id: str | None,
    root_path: Path | None,
    int_path: Path | None,
    agent_path: Path | None,
    crl_path: Path | None,
) -> None:
    crl_pem: str | None = None
    if registry_base and agent_id:
        try:
            root_pem, int_pem, agent_pem, crl_pem = _fetch_registry_bundle(
                registry_base, agent_id
            )
        except urllib.error.HTTPError as e:
            print(f"tc-verify: registry HTTP {e.code} for {e.url}", file=sys.stderr)
            sys.exit(1)
        except urllib.error.URLError as e:
            print(f"tc-verify: registry fetch failed: {e}", file=sys.stderr)
            sys.exit(1)
    elif root_path and int_path and agent_path:
        root_pem = root_path.read_text(encoding="utf-8")
        int_pem = int_path.read_text(encoding="utf-8")
        agent_pem = agent_path.read_text(encoding="utf-8")
        if crl_path:
            crl_pem = crl_path.read_text(encoding="utf-8")
    else:
        print(
            "tc-verify: --full-chain requires either\n"
            "  (--registry-base URL and --agent-id ID), or\n"
            "  (--root-ca-pem, --intermediate-pem, --agent-cert-pem paths).\n"
            "Optional: --crl-pem when using PEM files (registry fetch includes CRL).",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        agent_cert = _verify_pkix_chain(root_pem, int_pem, agent_pem)
    except Exception as e:
        print(f"tc-verify: PKIX chain verification failed: {e}", file=sys.stderr)
        sys.exit(1)

    if crl_pem:
        try:
            _assert_not_revoked(agent_cert, crl_pem)
        except Exception as e:
            print(f"tc-verify: CRL check failed: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        raw_leaf = _leaf_ed25519_raw(agent_cert)
        raw_arg = _pubkey_arg_bytes(pubkey_b64)
    except Exception as e:
        print(f"tc-verify: public key handling failed: {e}", file=sys.stderr)
        sys.exit(1)

    if raw_leaf != raw_arg:
        print(
            "tc-verify: leaf certificate Ed25519 public key does not match --pubkey "
            f"(leaf {base64.b64encode(raw_leaf).decode()[:24]}… vs arg {pubkey_b64[:24]}…)",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        "tc-verify: full_chain=OK (Root→Intermediate→Agent, leaf matches --pubkey)",
        file=sys.stderr,
    )


def _iter_jsonl_gz(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _parse_meta(rows) -> dict[str, Any] | None:
    for row in rows:
        if isinstance(row, dict) and row.get("type") == "meta":
            return row
    return None


# ── strict error matrix (POST_MVP §tc-verify.strict) ─────────────────────────
# Exit-code contract used both by `--strict` CLI and the `verify_report()` helper.
EXIT_OK = 0
EXIT_SIG_FAIL = 1  # at least one signature did not verify
EXIT_CHAIN_BROKEN = 2  # op.parent_signature missing / mismatched / fork
EXIT_CRL_REVOKED = 3  # leaf cert is on CRL (or CRL missing under --strict)
EXIT_PKIX_FAIL = 4  # PKIX chain validation failed
EXIT_TIME_NONMONOTONIC = 5  # timestamps go backwards
EXIT_META_MISSING = 6  # no meta line / corrupt meta / no operations
EXIT_INPUT_ERROR = 7  # IO / parse errors (replaces old exit=2)


def _check_chain_continuity(op_rows: list[dict]) -> tuple[list[str], bool]:
    """Return (errors, ok).  Enforces:
    • op[0].parent_signature is None or empty (genesis), and
    • op[i].parent_signature == op[i-1].signature for i>=1.
    """
    errors: list[str] = []
    prev_sig: str | None = None
    for i, op in enumerate(op_rows):
        parent = op.get("parent_signature") or None
        sig = op.get("signature") or None
        if i == 0:
            if parent not in (None, "", "null"):
                errors.append(
                    f"line {i + 1}: first op has parent_signature={parent!r}, expected empty"
                )
        else:
            if parent != prev_sig:
                errors.append(
                    f"line {i + 1}: parent_signature {str(parent)[:16]}… != prev.signature "
                    f"{str(prev_sig)[:16]}…"
                )
        prev_sig = sig
    return errors, (not errors)


def _check_time_monotonic(op_rows: list[dict]) -> list[str]:
    errors: list[str] = []
    prev_ts = 0.0
    for i, op in enumerate(op_rows):
        try:
            ts = float(op.get("timestamp") or 0)
        except (TypeError, ValueError):
            errors.append(f"line {i + 1}: invalid timestamp {op.get('timestamp')!r}")
            continue
        if ts < prev_ts:
            errors.append(
                f"line {i + 1}: timestamp {ts} < previous {prev_ts} (non-monotonic)"
            )
        prev_ts = ts
    return errors


def main() -> None:
    p = argparse.ArgumentParser(description="Verify TrustChain chain export (jsonl.gz)")
    p.add_argument("export_file", type=Path, help="Path to trustchain_chain.jsonl.gz")
    p.add_argument(
        "--pubkey", required=True, help="Base64 Ed25519 public key (32 raw bytes, b64)"
    )
    p.add_argument(
        "--show-meta",
        action="store_true",
        help="Print export meta (key_id, counts, include_subagents) and exit 0 without verifying ops",
    )
    p.add_argument(
        "--full-chain",
        action="store_true",
        help="Verify X.509 chain Root→Intermediate→Agent (+ CRL) and match leaf Ed25519 to --pubkey",
    )
    p.add_argument(
        "--registry-base",
        default=None,
        help="Public registry origin, e.g. https://keys.trust-chain.ai (with /api/pub/* paths)",
    )
    p.add_argument(
        "--agent-id", default=None, help="Agent id for --registry-base fetch"
    )
    p.add_argument("--root-ca-pem", type=Path, default=None, help="Root CA PEM file")
    p.add_argument(
        "--intermediate-pem", type=Path, default=None, help="Intermediate CA PEM file"
    )
    p.add_argument(
        "--agent-cert-pem", type=Path, default=None, help="Agent leaf PEM file"
    )
    p.add_argument(
        "--crl-pem",
        type=Path,
        default=None,
        help="CRL PEM file (optional with local PEMs)",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Enterprise strict mode: enforce chain continuity, timestamp "
            "monotonicity, mandatory meta; require --full-chain + CRL when "
            "PKIX artefacts are available.  Returns the unified error matrix "
            "exit code (see docs/POST_MVP.md §tc-verify)."
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit a structured JSON report to stdout instead of human text.",
    )
    args = p.parse_args()

    path: Path = args.export_file
    if not path.is_file():
        print(f"Not a file: {path}", file=sys.stderr)
        sys.exit(EXIT_INPUT_ERROR)

    try:
        rows = list(_iter_jsonl_gz(path))
    except (OSError, json.JSONDecodeError) as e:
        print(f"tc-verify: failed to read {path}: {e}", file=sys.stderr)
        sys.exit(EXIT_INPUT_ERROR)

    meta = _parse_meta(rows)
    if args.show_meta:
        if meta:
            print(json.dumps(meta, indent=2, default=str))
        else:
            print("{}", file=sys.stderr)
        sys.exit(EXIT_OK)

    if args.full_chain:
        _run_full_chain(
            args.pubkey,
            args.registry_base,
            args.agent_id,
            args.root_ca_pem,
            args.intermediate_pem,
            args.agent_cert_pem,
            args.crl_pem,
        )
    elif args.strict:
        # In strict mode PKIX is mandatory.  We don't force registry vs PEM —
        # whichever the operator passes — but at least one must be present.
        if not any(
            [
                args.registry_base,
                args.root_ca_pem,
                args.intermediate_pem,
                args.agent_cert_pem,
            ]
        ):
            msg = "tc-verify: --strict requires PKIX (add --full-chain + --registry-base or PEMs)"
            if args.json:
                print(
                    json.dumps(
                        {
                            "status": "fail",
                            "exit_code": EXIT_PKIX_FAIL,
                            "errors": [msg],
                        }
                    )
                )
            else:
                print(msg, file=sys.stderr)
            sys.exit(EXIT_PKIX_FAIL)
        _run_full_chain(
            args.pubkey,
            args.registry_base,
            args.agent_id,
            args.root_ca_pem,
            args.intermediate_pem,
            args.agent_cert_pem,
            args.crl_pem,
        )

    op_rows = [r for r in rows if isinstance(r, dict) and r.get("type") != "meta"]

    if args.strict and not meta:
        msg = "tc-verify: meta line missing/corrupt"
        if args.json:
            print(
                json.dumps(
                    {"status": "fail", "exit_code": EXIT_META_MISSING, "errors": [msg]}
                )
            )
        else:
            print(msg, file=sys.stderr)
        sys.exit(EXIT_META_MISSING)

    verifier = TrustChainVerifier(args.pubkey, max_age_seconds=None)
    sig_errors: list[str] = []
    n_ok = 0
    n_fail = 0
    n_skip = sum(1 for r in rows if isinstance(r, dict) and r.get("type") == "meta")
    for i, row in enumerate(op_rows):
        try:
            sr = SignedResponse(
                tool_id=str(row.get("tool") or row.get("tool_id") or ""),
                data=row.get("data") if row.get("data") is not None else {},
                signature=str(row.get("signature") or ""),
                timestamp=float(row.get("timestamp") or 0),
                nonce=row.get("nonce"),
                parent_signature=row.get("parent_signature"),
            )
        except Exception as e:
            sig_errors.append(f"line {i + 1}: parse: {e}")
            n_fail += 1
            continue
        if verifier.verify(sr).valid:
            n_ok += 1
        else:
            sig_errors.append(f"line {i + 1}: VERIFY FAIL tool={sr.tool_id}")
            n_fail += 1

    chain_errors: list[str] = []
    time_errors: list[str] = []
    if args.strict:
        chain_errors, _ = _check_chain_continuity(op_rows)
        time_errors = _check_time_monotonic(op_rows)

    extra = ""
    kid = ""
    if meta:
        kid = meta.get("key_id", "")
        oc = meta.get("operations_count")
        sub = meta.get("include_subagents")
        extra = f" key_id={kid!s}" if kid else ""
        if oc is not None:
            extra += f" meta_ops={oc!s}"
        if sub is not None:
            extra += f" include_subagents={sub!s}"
    if args.full_chain or args.strict:
        extra += " full_chain=checked"

    # Error precedence (enterprise matrix, most-critical first):
    #   chain > signature > time > (pkix/crl handled above by _run_full_chain)
    exit_code = EXIT_OK
    category = "ok"
    if n_fail:
        exit_code = EXIT_SIG_FAIL
        category = "signature"
    if args.strict and chain_errors:
        exit_code = EXIT_CHAIN_BROKEN
        category = "chain"
    if args.strict and time_errors and exit_code == EXIT_OK:
        exit_code = EXIT_TIME_NONMONOTONIC
        category = "time"

    if args.json:
        print(
            json.dumps(
                {
                    "status": "ok" if exit_code == EXIT_OK else "fail",
                    "category": category,
                    "exit_code": exit_code,
                    "strict": args.strict,
                    "counts": {
                        "ok": n_ok,
                        "fail": n_fail,
                        "meta_lines": n_skip,
                        "operations": len(op_rows),
                    },
                    "meta": {
                        "key_id": kid,
                        "operations_count": (
                            meta.get("operations_count") if meta else None
                        ),
                        "include_subagents": (
                            meta.get("include_subagents") if meta else None
                        ),
                    },
                    "errors": {
                        "signatures": sig_errors,
                        "chain": chain_errors,
                        "time": time_errors,
                    },
                },
                indent=2,
            )
        )
    else:
        for e in sig_errors:
            print(e, file=sys.stderr)
        for e in chain_errors:
            print(f"chain: {e}", file=sys.stderr)
        for e in time_errors:
            print(f"time: {e}", file=sys.stderr)
        if exit_code == EXIT_OK:
            print(f"OK: verified_signatures={n_ok} meta_lines={n_skip}{extra}")
        else:
            print(
                f"FAIL[{category},exit={exit_code}]: ok={n_ok} fail={n_fail} "
                f"meta_lines={n_skip}{extra}",
                file=sys.stderr,
            )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
