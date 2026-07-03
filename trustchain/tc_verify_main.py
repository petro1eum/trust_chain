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
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise ValueError(
            f"Unsupported URL scheme: {parsed.scheme!r} (only https/http allowed)"
        )
    req = urllib.request.Request(url, headers={"User-Agent": "trustchain-tc-verify/3"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
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
    root_pem: str,
    intermediate_pem: str,
    agent_pem: str,
    *,
    strict: bool = False,
    as_of=None,
) -> x509.Certificate:
    root = load_pem_x509_certificate(root_pem.encode("utf-8"))
    inter = load_pem_x509_certificate(intermediate_pem.encode("utf-8"))
    agent = load_pem_x509_certificate(agent_pem.encode("utf-8"))
    rp = root.public_key()
    rp.verify(inter.signature, inter.tbs_certificate_bytes)
    ip = inter.public_key()
    ip.verify(agent.signature, agent.tbs_certificate_bytes)
    if strict:
        for cert, label in ((root, "root"), (inter, "intermediate"), (agent, "agent")):
            _assert_cert_valid_now(cert, label, at=as_of)
        _assert_is_ca(root, "root")
        _assert_is_ca(inter, "intermediate")
        _assert_issuer_matches(inter, root)
        _assert_issuer_matches(agent, inter)
    return agent


_COMPROMISE_REASONS = {"key_compromise", "ca_compromise", "aa_compromise"}


def _crl_reason(rev) -> str | None:
    """Revocation reason name (e.g. 'key_compromise'), or None if unspecified."""
    try:
        return rev.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
    except x509.ExtensionNotFound:
        return None


def _crl_revocation_date(rev):
    from datetime import timezone

    try:
        return rev.revocation_date_utc
    except AttributeError:
        d = rev.revocation_date
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d


def _assert_not_revoked(agent: x509.Certificate, crl_pem: str, *, as_of=None) -> None:
    crl = load_pem_x509_crl(crl_pem.encode("utf-8"))
    rev = crl.get_revoked_certificate_by_serial_number(agent.serial_number)
    if rev is None:
        return
    if as_of is None:
        # Default (strict-now): any revocation invalidates. Unchanged behavior.
        raise ValueError(f"agent leaf serial {agent.serial_number} is on CRL")
    # Historical validity: a signature made BEFORE the revocation stays valid,
    # UNLESS the reason is key/CA compromise (retroactive — the key may have
    # leaked before the recorded date).
    reason = _crl_reason(rev)
    rev_date = _crl_revocation_date(rev)
    if reason in _COMPROMISE_REASONS or (rev_date is not None and rev_date <= as_of):
        raise ValueError(
            f"agent leaf serial {agent.serial_number} revoked "
            f"(reason={reason}, date={rev_date}) — invalid as-of {as_of}"
        )


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


def _coerce_timestamp(row: dict) -> float:
    """Reconstruct the signed timestamp. Runtime exports carry the signed float in
    ``response_timestamp`` and an ISO-8601 string in ``timestamp``; float()-ing the
    ISO string used to raise and fail every record (RFC-003 BF-04)."""
    for key in ("response_timestamp", "timestamp"):
        val = row.get(key)
        if val is None:
            continue
        if isinstance(val, (int, float)):
            return float(val)
        s = str(val).strip()
        if not s:
            continue
        try:
            return float(s)
        except ValueError:
            pass
        try:
            from datetime import datetime

            return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
    return 0.0


def _cert_validity_bounds(cert: x509.Certificate):
    from datetime import timezone

    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
        return nb, na


def _assert_cert_valid_now(cert: x509.Certificate, label: str, *, at=None) -> None:
    from datetime import datetime, timezone

    nb, na = _cert_validity_bounds(cert)
    when = at or datetime.now(timezone.utc)
    if when < nb or when > na:
        raise ValueError(
            f"{label} cert not temporally valid at {when} (window {nb}..{na})"
        )


def _assert_is_ca(cert: x509.Certificate, label: str) -> None:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ValueError(f"{label} cert missing BasicConstraints (not a CA)") from exc
    if not bc.ca:
        raise ValueError(f"{label} cert is not a CA (BasicConstraints CA:FALSE)")


def _assert_issuer_matches(child: x509.Certificate, issuer: x509.Certificate) -> None:
    if child.issuer != issuer.subject:
        raise ValueError(
            f"issuer/subject name mismatch: {child.issuer.rfc4514_string()} "
            f"!= {issuer.subject.rfc4514_string()}"
        )


def _check_completeness(meta: dict | None, op_rows: list) -> list[str]:
    """Detect naive tail truncation/padding: meta.operations_count must equal the
    number of operation rows actually present (RFC-003 BF-03)."""
    errors: list[str] = []
    if meta is None:
        return errors
    declared = meta.get("operations_count")
    if declared is not None:
        try:
            declared_int = int(declared)
        except (TypeError, ValueError):
            errors.append(f"meta.operations_count is not an integer: {declared!r}")
            return errors
        if declared_int != len(op_rows):
            errors.append(
                f"operations_count mismatch: meta declares {declared_int}, "
                f"found {len(op_rows)} operations (chain truncated or padded)"
            )
    return errors


def _resolve_as_of(args, rows):
    """Resolve the historical-validity instant from --as-of / --as-of-signing.

    Returns an aware datetime, or None (default: validity checked at 'now').
    """
    from datetime import datetime, timezone

    if getattr(args, "as_of", None):
        s = str(args.as_of).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    if getattr(args, "as_of_signing", False):
        times = [
            _coerce_timestamp(r)
            for r in rows
            if isinstance(r, dict) and r.get("type") != "meta"
        ]
        times = [t for t in times if t > 0]
        if times:
            return datetime.fromtimestamp(max(times), tz=timezone.utc)
    return None


def _run_full_chain(
    pubkey_b64: str,
    registry_base: str | None,
    agent_id: str | None,
    root_path: Path | None,
    int_path: Path | None,
    agent_path: Path | None,
    crl_path: Path | None,
    *,
    strict: bool = False,
    as_of=None,
) -> None:
    # R4: under --strict the Root CA must be pinned out-of-band; fetching it from
    # the registry being audited is circular trust (RFC-003 offline-verify).
    if strict and registry_base and not root_path:
        print(
            "tc-verify: --strict must pin the Root CA out-of-band via --root-ca-pem "
            "(fetching the root from --registry-base trusts the audited server)",
            file=sys.stderr,
        )
        sys.exit(EXIT_PKIX_FAIL)
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
        agent_cert = _verify_pkix_chain(
            root_pem, int_pem, agent_pem, strict=strict, as_of=as_of
        )
    except Exception as e:
        print(f"tc-verify: PKIX chain verification failed: {e}", file=sys.stderr)
        sys.exit(EXIT_PKIX_FAIL)

    if crl_pem:
        try:
            _assert_not_revoked(agent_cert, crl_pem, as_of=as_of)
        except Exception as e:
            print(f"tc-verify: CRL check failed: {e}", file=sys.stderr)
            sys.exit(EXIT_CRL_REVOKED)
    elif strict:
        print(
            "tc-verify: --strict requires a CRL (none provided via --crl-pem or registry)",
            file=sys.stderr,
        )
        sys.exit(EXIT_CRL_REVOKED)

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
        ts = _coerce_timestamp(op)
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
        "--as-of",
        default=None,
        help=(
            "Verify cert validity + CRL revocation AS OF this ISO-8601 time "
            "(historical validity) instead of 'now': a signature made while the "
            "cert was valid stays valid after expiry, and revocation invalidates "
            "it only if dated at/before this time or the reason is key/CA compromise."
        ),
    )
    p.add_argument(
        "--as-of-signing",
        action="store_true",
        help=(
            "Like --as-of but derive the time from the log's own latest signed "
            "timestamp (self-asserted; anchor with a trusted timestamp/witness for "
            "strong assurance)."
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

    as_of = _resolve_as_of(args, rows)

    if args.full_chain:
        _run_full_chain(
            args.pubkey,
            args.registry_base,
            args.agent_id,
            args.root_ca_pem,
            args.intermediate_pem,
            args.agent_cert_pem,
            args.crl_pem,
            strict=args.strict,
            as_of=as_of,
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
            strict=True,
            as_of=as_of,
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
                timestamp=_coerce_timestamp(row),
                nonce=row.get("nonce"),
                parent_signature=row.get("parent_signature"),
                signature_id=str(row.get("signature_id") or ""),
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
        chain_errors = _check_completeness(meta, op_rows) + chain_errors
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
