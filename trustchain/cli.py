"""TrustChain CLI — Git-like interface for AI agent audit trails.

Usage:
    tc log                          # chain history (newest first)
    tc log --graph                  # ASCII graph (линейная цепь + подсказки разрыва)
    tc log --v3                     # лог v3 CAS-коммитов (refs/v3/main)
    tc manifest hash tool.json      # SHA-256 канонического manifest (tc.manifestHash)
    tc standards export receipt.tcreceipt --format=scitt
    tc anchor export -o chain.anchor.json
    tc log --limit 5                # last 5 operations
    tc log --tool bash_tool         # filter by tool
    tc status                       # chain health summary
    tc chain-verify                 # verify chain integrity (fsck)
    tc checkpoint NAME             # refs/checkpoints/NAME.ref → current HEAD
    tc tag NAME                    # refs/tags/NAME.ref → current HEAD (immutable marker)
    tc branch NAME                  # refs/heads/NAME.ref → current HEAD
    tc checkout NAME                # HEAD из refs/heads/NAME.ref
    tc refs                         # list checkpoints + heads
    tc revert [HEAD|op_id]          # signed revert_intent (see reversibles.json)
    tc reset --soft op_0002         # HEAD → подпись op; objects/ не чистим
    tc blame bash_tool              # forensics: all ops by tool
    tc show op_0003                 # v2 operation
    tc show <64-hex>               # v3 CAS object (after migrate-v3 --apply)
    tc diff op_0001 op_0005         # compare two operations
    tc export chain.json            # export full chain as JSON
    tc cert request --platform https://keys.trust-chain.ai   # X.509 enrollment steps (human path)
    tc migrate-v3 --apply          # v2 op_*.json → v3 CAS commits + v3/migration_state.json
    tc v3-merge A B "сообщение"    # merge-коммит с двумя родителями (CAS) + refs/v3/main
    tc init                         # initialize .trustchain/ directory
    tc info                         # key + version info
    tc export-key --format=json     # export public key
    tc verify response.json         # verify a signed JSON file
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Tuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from trustchain import TrustChain, TrustChainConfig, __version__
from trustchain.v2.chain_store import ChainStore
from trustchain.v2.storage import FileStorage
from trustchain.v3.compensations import reverse_tool_for_chain

app = typer.Typer(
    name="tc",
    help="TrustChain CLI — Git for AI Agents. Cryptographic audit trail for every tool call.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

cert_app = typer.Typer(
    name="cert",
    help="X.509 identity bound to TrustChain Platform (public CA) — incremental rollout.",
    add_completion=False,
    no_args_is_help=True,
)


def _effective_chain_dir(chain_dir: str) -> Path:
    """Resolve chain root: CLI `--dir` wins, else ``TRUSTCHAIN_DIR``, else default."""
    env_dir = os.environ.get("TRUSTCHAIN_DIR", "").strip()
    base = chain_dir if chain_dir != ".trustchain" or not env_dir else env_dir
    return Path(base).expanduser().resolve()


def _warn_cli_storage_mismatch() -> None:
    """``tc`` always reads the **file** ChainStore under ``TRUSTCHAIN_DIR``."""
    lib_mode = (os.environ.get("TRUSTCHAIN_CHAIN_STORAGE") or "").strip().lower()
    if lib_mode == "postgres":
        console.print(
            "[yellow]Note:[/yellow] TRUSTCHAIN_CHAIN_STORAGE=postgres — this CLI still "
            "reads the [bold]file[/bold] chain under TRUSTCHAIN_DIR. "
            "PostgreSQL-backed ops are not listed here."
        )
    elif lib_mode == "memory":
        console.print(
            "[yellow]Note:[/yellow] TRUSTCHAIN_CHAIN_STORAGE=memory — file chain under "
            "TRUSTCHAIN_DIR may be empty while the library uses RAM."
        )


def _get_chain(chain_dir: str = ".trustchain") -> ChainStore:
    """Load chain from the current directory's .trustchain/ folder."""
    _warn_cli_storage_mismatch()
    root = _effective_chain_dir(chain_dir)
    if not root.exists():
        console.print(f"[red]No .trustchain/ directory found at {root}[/red]")
        console.print("[dim]Run 'tc init' to create one, or specify --dir[/dim]")
        raise typer.Exit(1)
    storage = FileStorage(str(root))
    return ChainStore(storage, root_dir=str(root))


def _get_tc(chain_dir: str = ".trustchain") -> TrustChain:
    """Load full TrustChain from chain dir (aligned with CLI file chain)."""
    root = _effective_chain_dir(chain_dir)
    return TrustChain(
        TrustChainConfig(
            enable_chain=True,
            chain_storage="file",
            chain_dir=str(root),
        )
    )


def _safe_ref_segment(name: str) -> str:
    """Sanitize user-supplied ref / checkpoint / branch label for filesystem."""
    s = name.strip().replace("..", "_")
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "_", s)
    if not s or s in (".", "_"):
        raise typer.BadParameter("invalid name: use letters, digits, ._-")
    return s[:120]


def _graph_prefixes(ops: list, *, newest_first: bool) -> list[str]:
    """Left column for ``tc log --graph`` (linear parent_signature chain).

    If the visible window skips ops or the chain forks inside the window,
    use ``| * `` to hint a non-linear step (как у ``git log --graph``).
    """
    n = len(ops)
    if n == 0:
        return []
    out: list[str] = []
    for i in range(n):
        if i == 0:
            out.append("* ")
            continue
        if newest_first:
            newer = ops[i - 1]
            older = ops[i]
            ok = newer.get("parent_signature") == older.get("signature")
        else:
            older = ops[i - 1]
            newer = ops[i]
            ok = newer.get("parent_signature") == older.get("signature")
        out.append("* " if ok else "| * ")
    return out


def _signature_to_op_map(ops: List[dict]) -> dict[str, dict]:
    m: dict[str, dict] = {}
    for o in ops:
        if isinstance(o, dict):
            sig = o.get("signature")
            if isinstance(sig, str) and sig:
                m[sig] = o
    return m


def _detach_ids_tip_down_to_target(
    sig_to_op: dict[str, dict], tip_sig: str, target_id: str
) -> Tuple[List[str], Optional[dict]]:
    """Ids strictly newer than ``target_id`` on the path from current tip (HEAD sig).

    Returns ``([], target_op)`` if tip is already the target. ``(None, None)``
    if ``target_id`` is not on the ancestry path from tip.
    """
    detach: List[str] = []
    cur: Optional[dict] = sig_to_op.get(tip_sig)
    if not cur:
        return detach, None
    while cur:
        oid = cur.get("id")
        if oid == target_id:
            return detach, cur
        detach.append(str(oid))
        parent = cur.get("parent_signature")
        if not isinstance(parent, str) or not parent:
            break
        cur = sig_to_op.get(parent)
    return [], None


def _truncate(s: Optional[str], n: int = 12) -> str:
    """Truncate a string for display."""
    if not s:
        return "[dim]---[/dim]"
    return s[:n] + "..." if len(s) > n else s


# ── Git-like chain commands ──


@app.command("log")
def log_cmd(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of operations to show"),
    tool: Optional[str] = typer.Option(
        None, "--tool", "-t", help="Filter by tool name"
    ),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
    reverse: bool = typer.Option(
        True, "--reverse/--chrono", help="Newest first (default) or chronological"
    ),
    graph: bool = typer.Option(
        False,
        "--graph",
        help="ASCII graph column (linear parent links; | * if window skips/forks)",
    ),
    v3: bool = typer.Option(
        False,
        "--v3",
        help="Показать v3 CAS-цепочку коммитов от refs/v3/main (после migrate-v3 --apply)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show full data"),
):
    """Show chain history (like `git log`).

    Examples:
        tc log                    # last 20 operations
        tc log -n 5               # last 5
        tc log --tool bash_tool   # only bash operations
        tc log --chrono            # oldest first
        tc log --graph             # визуализация цепи parent_signature
        tc log --v3               # v3 коммиты (CAS), линейные parents[]
    """
    root = _effective_chain_dir(chain_dir)

    if v3:
        from trustchain.v3.log_walk import v3_commits_newest_first

        if tool:
            console.print("[dim]--tool игнорируется для --v3[/dim]")
        ops = v3_commits_newest_first(root, limit=limit)
        if not ops:
            console.print(
                "[dim]Нет refs/v3/main или цепочка пуста. Сначала ``tc migrate-v3 --apply``.[/dim]"
            )
            return
        if not reverse:
            ops = list(reversed(ops))
    else:
        chain = _get_chain(chain_dir)

        if tool:
            ops = chain.blame(tool, limit=limit)
            if reverse:
                ops.reverse()
        elif reverse:
            ops = chain.log_reverse(limit=limit)
        else:
            ops = chain.log(limit=limit)

    if not ops:
        console.print("[dim]Empty chain. No operations recorded yet.[/dim]")
        return

    prefixes = _graph_prefixes(ops, newest_first=reverse) if graph else None
    head_idx = 0 if reverse else len(ops) - 1

    for i, op in enumerate(ops):
        op_id = op.get("id", "?")
        op_tool = op.get("tool", "unknown")
        sig = _truncate(op.get("signature"), 10)
        parent = _truncate(op.get("parent_signature"), 10)
        ts = op.get("timestamp", "")
        latency = op.get("latency_ms", 0)

        head_note = " (HEAD)" if graph and i == head_idx else ""

        # Commit line (like git log --oneline)
        header = Text()
        if prefixes is not None:
            pfx = prefixes[i]
            header.append(pfx, style="bold blue" if pfx.startswith("*") else "dim")
        header.append(f"  {op_id}", style="bold yellow")
        if head_note:
            header.append(head_note, style="bold magenta")
        header.append(f"  {op_tool}", style="bold cyan")
        header.append(f"  sig:{sig}", style="green")
        if op.get("parent_signature"):
            header.append(f"  parent:{parent}", style="dim")
        if latency:
            header.append(f"  {latency:.0f}ms", style="dim magenta")

        console.print(header)
        indent = "    " if prefixes is None else "      "
        console.print(f"{indent}[dim]{ts}[/dim]")

        if verbose:
            data = op.get("data", {})
            console.print(
                f"{indent}[dim]data: {json.dumps(data, default=str)[:120]}[/dim]"
            )
            if op.get("_v3_message"):
                console.print(f"{indent}[dim]v3 commit: {op.get('_v3_message')}[/dim]")

        console.print()


manifest_app = typer.Typer(
    name="manifest",
    help="Tool/skill manifest (canonical hash for tc.manifestHash).",
    add_completion=False,
    no_args_is_help=True,
)


@manifest_app.command("hash")
def manifest_hash_cmd(
    path: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to manifest.json",
    ),
):
    """Print lowercase SHA-256 of canonical JSON (sorted keys, ``separators``)."""
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except OSError as e:
        console.print(f"[red]Cannot read file: {e}[/red]")
        raise typer.Exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON: {e}[/red]")
        raise typer.Exit(1)
    if not isinstance(data, dict):
        console.print("[red]Manifest root must be a JSON object[/red]")
        raise typer.Exit(1)
    from trustchain.v3.manifest_hash import tool_manifest_sha256_hex

    console.print(tool_manifest_sha256_hex(data))


app.add_typer(manifest_app, name="manifest")


@app.command("status")
def status_cmd(
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Chain health summary (like `git status`)."""
    chain = _get_chain(chain_dir)
    s = chain.status()

    table = Table(title="TrustChain Status", show_header=False, border_style="blue")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Chain length", str(s["length"]))
    table.add_row("HEAD", _truncate(s.get("head"), 24))
    table.add_row("Storage", s.get("storage_backend", "?"))
    table.add_row("Root dir", s.get("root_dir", "?"))
    table.add_row("Avg latency", f"{s.get('avg_latency_ms', 0):.1f} ms")

    tools = s.get("tools", {})
    if tools:
        tool_str = ", ".join(
            f"{t}: {c}" for t, c in sorted(tools.items(), key=lambda x: -x[1])
        )
        table.add_row("Tools", tool_str)

    sessions = chain.sessions()
    if sessions:
        table.add_row("Sessions", f"{len(sessions)} ({', '.join(sessions[:5])})")

    root = _effective_chain_dir(chain_dir)
    v3ref = root / "refs" / "v3" / "main"
    if v3ref.is_file():
        v3tip = v3ref.read_text(encoding="utf-8").strip()
        table.add_row("v3/main", _truncate(v3tip, 28))

    console.print(table)


@app.command("chain-verify")
def chain_verify_cmd(
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show broken links detail"
    ),
):
    """Verify chain integrity (like `git fsck`).

    Checks that each operation's parent_signature matches the
    previous operation's signature.
    """
    chain = _get_chain(chain_dir)
    result = chain.verify()

    if result["valid"]:
        console.print(
            Panel(
                f"[bold green]Chain VALID[/bold green]\n"
                f"Length: {result['length']} operations\n"
                f"HEAD: {_truncate(result.get('head'), 24)}\n"
                f"Verified: {result.get('verified_at', '')}",
                title="tc verify",
                border_style="green",
            )
        )
    else:
        broken = result.get("broken_links", [])
        console.print(
            Panel(
                f"[bold red]Chain INVALID[/bold red]\n"
                f"Length: {result['length']} operations\n"
                f"Broken links: {len(broken)}",
                title="tc verify",
                border_style="red",
            )
        )
        if verbose:
            for bl in broken:
                console.print(
                    f"  [red]Break at {bl.get('id', bl.get('index'))}: expected {_truncate(bl.get('expected_parent'), 16)}, got {_truncate(bl.get('actual_parent'), 16)}[/red]"
                )
        raise typer.Exit(1)


@app.command("blame")
def blame_cmd(
    tool: str = typer.Argument(..., help="Tool name to investigate"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max results"),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Find all operations by a specific tool (like `git blame`).

    Forensic investigation: show every time the agent used a tool.

    Examples:
        tc blame bash_tool
        tc blame view_file --limit 10
    """
    chain = _get_chain(chain_dir)
    ops = chain.blame(tool, limit=limit)

    if not ops:
        console.print(f"[dim]No operations found for tool '{tool}'[/dim]")
        return

    console.print(
        f"[bold]Found {len(ops)} operations for [cyan]{tool}[/cyan]:[/bold]\n"
    )

    table = Table(show_header=True)
    table.add_column("ID", style="yellow")
    table.add_column("Timestamp", style="dim")
    table.add_column("Signature", style="green")
    table.add_column("Data (truncated)")

    for op in ops:
        data_str = json.dumps(op.get("data", {}), default=str)[:60]
        table.add_row(
            op.get("id", "?"),
            op.get("timestamp", "?")[:19],
            _truncate(op.get("signature"), 16),
            data_str,
        )

    console.print(table)


@app.command("show")
def show_cmd(
    op_id: str = typer.Argument(
        ...,
        help="v2: op_NNNN; v3 CAS: 64-символьный hex digest объекта в objects/",
    ),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Показать операцию v2 или JSON-объект v3 из CAS (commit/tree/blob).

    Examples:
        tc show op_0001
        tc show a1b2…   # 64 hex — объект из ``tc migrate-v3 --apply``
    """
    from trustchain.v3.cas_io import is_cas_sha256_hex, read_cas_json

    root = _effective_chain_dir(chain_dir)
    ref = op_id.strip()

    if is_cas_sha256_hex(ref):
        blob = read_cas_json(root, ref)
        if not blob:
            console.print(f"[red]CAS object not found: {ref[:16]}…[/red]")
            raise typer.Exit(1)
        kind = blob.get("type", "?")
        sub = ""
        if kind == "commit":
            sub = str(blob.get("message", ""))
        elif kind == "tree":
            sub = f"entries={len(blob.get('entries', {}))}"
        panel_kw: dict = {
            "title": f"tc show {ref[:16]}… (v3 {kind})",
            "border_style": "cyan",
        }
        if sub:
            panel_kw["subtitle"] = sub
        console.print(
            Panel(json.dumps(blob, indent=2, default=str), **panel_kw),
        )
        return

    chain = _get_chain(chain_dir)
    op = chain.show(ref)

    if not op:
        console.print(f"[red]Operation '{ref}' not found[/red]")
        raise typer.Exit(1)

    console.print(
        Panel(
            json.dumps(op, indent=2, default=str),
            title=f"tc show {ref}",
            border_style="cyan",
            subtitle=f"Tool: {op.get('tool', '?')} | {op.get('timestamp', '?')}",
        )
    )


@app.command("diff")
def diff_cmd(
    op_a: str = typer.Argument(..., help="First operation ID"),
    op_b: str = typer.Argument(..., help="Second operation ID"),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Compare two operations (like `git diff`).

    Examples:
        tc diff op_0001 op_0005
    """
    chain = _get_chain(chain_dir)
    result = chain.diff(op_a, op_b)

    if "error" in result:
        console.print(f"[red]{result['error']}[/red]")
        raise typer.Exit(1)

    a = result["a"]
    b = result["b"]

    console.print(f"\n[bold]--- {a['id']}[/bold] ({a.get('tool', '?')})")
    console.print(f"[bold]+++ {b['id']}[/bold] ({b.get('tool', '?')})")
    console.print(
        f"Same tool: {'[green]yes[/green]' if result.get('same_tool') else '[red]no[/red]'}"
    )
    td = result.get("time_delta_seconds")
    if td is not None:
        console.print(f"Time delta: {td:.1f}s")

    console.print(
        f"\n[dim]A data:[/dim] {json.dumps(a.get('data', {}), indent=2, default=str)}"
    )
    console.print(
        f"\n[dim]B data:[/dim] {json.dumps(b.get('data', {}), indent=2, default=str)}"
    )


@app.command("export")
def export_cmd(
    output: Path = typer.Argument(Path("chain_export.json"), help="Output file path"),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Export entire chain as JSON.

    Examples:
        tc export
        tc export audit_2026.json
    """
    chain = _get_chain(chain_dir)
    chain.export_json(str(output))
    console.print(f"[green]Exported {chain.length} operations to {output}[/green]")


# ── Original commands (preserved) ──


@app.command("export-key")
def export_key(
    format: str = typer.Option(
        "json", "--format", "-f", help="Output format: json, pem, base64, hex"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    key_file: Optional[Path] = typer.Option(
        None, "--key-file", "-k", help="Path to existing key file"
    ),
    pretty: bool = typer.Option(True, "--pretty/--no-pretty", help="Pretty print JSON"),
):
    """Export the public key for verification.

    Examples:
        tc export-key --format=json
        tc export-key --format=pem --output=public.pem
    """
    try:
        tc = TrustChain()
        public_key = tc.export_public_key()
        key_id = tc.get_key_id()

        if format == "json":
            data = {
                "public_key": public_key,
                "key_id": key_id,
                "algorithm": "ed25519",
                "version": __version__,
            }
            result = json.dumps(data, indent=2) if pretty else json.dumps(data)
        elif format == "base64":
            result = public_key
        elif format == "hex":
            import base64

            key_bytes = base64.b64decode(public_key)
            result = key_bytes.hex()
        elif format == "pem":
            result = (
                f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----\n"
            )
        else:
            console.print(f"[red]Unknown format: {format}[/red]")
            raise typer.Exit(1)

        if output:
            output.write_text(result)
            console.print(f"[green]Key exported to {output}[/green]")
        else:
            console.print(result)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("info")
def info():
    """Show TrustChain information and configuration."""
    tc = TrustChain()

    table = Table(title="TrustChain Info")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Version", __version__)
    table.add_row("Key ID", tc.get_key_id()[:16] + "...")
    table.add_row("Algorithm", "Ed25519")
    table.add_row("Public Key", tc.export_public_key()[:32] + "...")

    # Try to show chain info
    for chain_dir in [".trustchain", str(Path.home() / ".trustchain")]:
        if Path(chain_dir).exists():
            try:
                chain = _get_chain(chain_dir)
                s = chain.status()
                table.add_row("Chain length", str(s["length"]))
                table.add_row("Chain dir", chain_dir)
                break
            except SystemExit:
                pass

    console.print(table)


@app.command("verify")
def verify(
    file: Path = typer.Argument(..., help="JSON file with signed response"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Verify a signed response from a JSON file.

    Examples:
        tc verify response.json
        tc verify --verbose audit.json
    """
    try:
        data = json.loads(file.read_text())
        tc = TrustChain()
        is_valid = tc.verify(data)

        if is_valid:
            console.print("[green]Signature VALID[/green]")
            if verbose:
                console.print(f"  Tool ID: {data.get('tool_id', 'N/A')}")
                console.print(f"  Signature: {data.get('signature', '')[:32]}...")
        else:
            console.print("[red]Signature INVALID[/red]")
            raise typer.Exit(1)

    except FileNotFoundError:
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON: {e}[/red]")
        raise typer.Exit(1)


@app.command("config")
def config_show(
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Show environment-driven chain settings (CLI vs library).

    The ``tc`` commands always use the **file** ChainStore under the resolved
    directory (``--dir`` or ``TRUSTCHAIN_DIR``). Library defaults may differ
    (e.g. ``chain_storage=postgres``); see ``TrustChainConfig``."""
    root = _effective_chain_dir(chain_dir)
    cfg = TrustChainConfig(
        enable_chain=True,
        chain_storage=os.environ.get("TRUSTCHAIN_CHAIN_STORAGE", "postgres"),
        chain_dir=str(root),
        chain_dsn=os.environ.get("TC_VERIFIABLE_LOG_DSN"),
    )
    console.print(
        Panel.fit(f"[bold]CLI resolved chain dir[/bold]\n{root}", title="tc config")
    )
    console.print(
        "[dim]Relevant environment variables:[/dim]\n"
        f"  TRUSTCHAIN_DIR={os.environ.get('TRUSTCHAIN_DIR', '(unset)')}\n"
        f"  TRUSTCHAIN_CHAIN_STORAGE={os.environ.get('TRUSTCHAIN_CHAIN_STORAGE', '(unset)')}\n"
        f"  TC_VERIFIABLE_LOG_DSN={'(set)' if os.environ.get('TC_VERIFIABLE_LOG_DSN') else '(unset)'}\n"
    )
    console.print("[dim]TrustChainConfig (library) snapshot:[/dim]")
    console.print(
        json.dumps(
            {
                "chain_storage": cfg.chain_storage,
                "chain_dir": cfg.chain_dir,
                "chain_dsn_set": bool(
                    cfg.chain_dsn or os.environ.get("TC_VERIFIABLE_LOG_DSN")
                ),
            },
            indent=2,
        )
    )
    _warn_cli_storage_mismatch()


@cert_app.command("request")
def cert_request(
    platform: str = typer.Option(
        "https://keys.trust-chain.ai",
        "--platform",
        "-p",
        help="Public registry / onboarding base URL",
    ),
    scope: str = typer.Option(
        "chat,tool_execution",
        "--scope",
        "-s",
        help="Comma-separated capability labels for the future CSR",
    ),
):
    """Print the exact operator steps to obtain an agent leaf cert from Platform CA.

    Full automation (local key → CSR → signed PEM) is tracked with TrustChain_Platform
    admin + public APIs; this command is the **documented entrypoint** so scripts and
    README stay aligned.
    """
    base = platform.rstrip("/")
    console.print(
        Panel.fit(
            "[bold]Листовой сертификат агента — ручной путь (сейчас)[/bold]\n\n"
            "1. Сгенерируй или переиспользуй ключ Ed25519 для агента (тот же семейство, что и подпись инструментов).\n"
            "2. В админке TrustChain Platform: зарегистрируй агента и выпусти лист, подписанный промежуточным CA.\n"
            "3. Скачай PEM: [cyan]agent.crt[/cyan], [cyan]ca.pem[/cyan] (промежуточный), [cyan]root-ca.pem[/cyan].\n"
            "4. Зафиксируй корень для офлайн-верификаторов (см. TrustChain_Platform docs/PUBLIC_CERT_REGISTRY.md).\n\n"
            f"[dim]Запрошенный scope (для будущего CSR):[/dim] {scope}\n"
            f"[dim]База реестра:[/dim] {base}",
            title="tc cert request",
        )
    )
    console.print(
        "\n[bold]Черновик CSR (локально, до публичного enrollment API):[/bold]\n"
        '  [cyan]openssl req -new -key agent.key -out agent.csr -subj "/O=TrustChain/CN=trustchain-agent"[/cyan]\n'
        "  Дальше: отправить ``agent.csr`` оператору платформы или в будущий "
        "``POST …/enroll`` (см. ADR-SEC-003); пока — вручную.\n"
        f"  Проверка корня реестра: [dim]curl -fsS {base}/api/pub/root-ca | openssl x509 -text -noout[/dim]"
    )
    console.print(
        "\n[dim]Публичные read-only якоря (без API key):[/dim]\n"
        f"  GET {base}/api/pub/root-ca\n"
        f"  GET {base}/api/pub/ca\n"
        f"  GET {base}/api/pub/crl\n"
        f"  GET {base}/api/pub/agents/{{id}}/cert\n"
    )
    console.print(
        "\n[yellow]Автоматизация:[/yellow] после стабильного публичного enrollment в Platform "
        "появится неинтерактивный ``POST`` CSR; следи за ADR-SEC-003 в TrustChain_Platform."
    )


@cert_app.command("renew")
def cert_renew(
    days: int = typer.Option(
        30, "--within-days", help="Remind renewal when cert expires within N days"
    ),
):
    """Placeholder for scheduled leaf renewal (Platform-issued certs)."""
    console.print(
        f"[yellow]tc cert renew[/yellow] is not wired to local PEM paths yet. "
        f"Renew via Platform admin before expiry (within [bold]{days}[/bold] days recommended)."
    )
    console.print(
        "[dim]Store certs under a dedicated directory (e.g. trustchain_identity/) in your agent image.[/dim]"
    )
    raise typer.Exit(0)


app.add_typer(cert_app, name="cert")


@app.command("migrate-v3")
def migrate_v3_cmd(
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Записать CAS (objects/aa/…), v3/migration_state.json, refs/v3/main",
    ),
    max_ops: int = typer.Option(
        500_000,
        "--max-ops",
        help="Максимум v2-операций для скана",
    ),
):
    """Снимок линейной v2-цепи в v3 **Commit** (CAS), без удаления ``op_*.json``.

    По умолчанию только отчёт. С ``--apply`` пишутся blob'ы дерева и коммита на
    каждую операцию, линейные ``parents[]``, указатель ``refs/v3/main`` и
    ``v3/migration_state.json`` (карта ``op_id → commit``).

    Не поддерживается для verifiable / PG backend.
    """
    from trustchain.v3.migrate_v2 import migrate_v2_linear_to_v3

    _warn_cli_storage_mismatch()
    root = _effective_chain_dir(chain_dir)
    if not root.exists():
        console.print(f"[red]Нет каталога цепи: {root}[/red]")
        raise typer.Exit(1)

    try:
        report, warns = migrate_v2_linear_to_v3(root, apply=apply, max_ops=max_ops)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    for w in warns:
        console.print(f"[yellow]{w}[/yellow]")
    console.print(
        Panel.fit(
            json.dumps(report, indent=2, default=str),
            title="tc migrate-v3" + (" [apply]" if apply else " [dry-run]"),
        )
    )
    if not apply:
        console.print("[dim]Повтори с --apply чтобы записать объекты на диск.[/dim]")


@app.command("v3-merge")
def v3_merge_cmd(
    parent_a: str = typer.Argument(
        ..., metavar="PARENT_A", help="64 hex digest первого родителя (commit)"
    ),
    parent_b: str = typer.Argument(
        ..., metavar="PARENT_B", help="64 hex digest второго родителя (commit)"
    ),
    message: str = typer.Argument(..., metavar="MSG", help="Сообщение merge-коммита"),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Каталог цепи"),
    no_update_ref: bool = typer.Option(
        False,
        "--no-update-ref",
        help="Не обновлять refs/v3/main и не писать reflog",
    ),
):
    """Создать v3 **merge**-коммит: два родителя, пустое дерево, обновить ``refs/v3/main``."""
    from trustchain.v3.merge_commit import write_v3_merge_commit

    _warn_cli_storage_mismatch()
    root = _effective_chain_dir(chain_dir)
    if not root.exists():
        console.print(f"[red]Нет каталога цепи: {root}[/red]")
        raise typer.Exit(1)
    try:
        tip = write_v3_merge_commit(
            root,
            parent_a,
            parent_b,
            message,
            update_v3_main=not no_update_ref,
            append_reflog=not no_update_ref,
        )
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    console.print(
        Panel.fit(
            f"[bold]tip[/bold] {tip}\n"
            f"[dim]родители[/dim] {parent_a.strip().lower()[:16]}… + {parent_b.strip().lower()[:16]}…\n"
            + (
                "[green]refs/v3/main[/green] обновлён"
                if not no_update_ref
                else "[yellow]refs/v3/main не трогали[/yellow] (--no-update-ref)"
            ),
            title="tc v3-merge",
        )
    )


@app.command("checkpoint")
def checkpoint_cmd(
    name: str = typer.Argument(..., help="Named snapshot of current HEAD signature"),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Save current HEAD to ``refs/checkpoints/<name>.ref`` (git-like tag).

    Requires a non-empty HEAD (at least one signed operation on this chain).
    """
    _warn_cli_storage_mismatch()
    chain = _get_chain(chain_dir)
    h = chain.head()
    if not h:
        console.print(
            "[red]HEAD is empty — nothing to checkpoint. Sign at least one operation first.[/red]"
        )
        raise typer.Exit(1)
    root = _effective_chain_dir(chain_dir)
    seg = _safe_ref_segment(name)
    path = root / "refs" / "checkpoints" / f"{seg}.ref"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(h.strip() + "\n", encoding="utf-8")
    console.print(f"[green]checkpoint[/green] {seg} → HEAD {h[:40]}…")


@app.command("tag")
def tag_cmd(
    name: str = typer.Argument(..., help="Имя тега: файл refs/tags/<name>.ref"),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Сохранить текущий HEAD в ``refs/tags/<name>.ref`` (как лёгкий git tag)."""
    _warn_cli_storage_mismatch()
    chain = _get_chain(chain_dir)
    h = chain.head()
    if not h:
        console.print("[red]HEAD is empty — сначала подпиши операцию.[/red]")
        raise typer.Exit(1)
    root = _effective_chain_dir(chain_dir)
    seg = _safe_ref_segment(name)
    path = root / "refs" / "tags" / f"{seg}.ref"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(h.strip() + "\n", encoding="utf-8")
    console.print(f"[green]tag[/green] {seg} → HEAD {h[:40]}…")


@app.command("branch")
def branch_cmd(
    name: str = typer.Argument(
        ..., help="Branch label; stores current HEAD under refs/heads/"
    ),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Create ``refs/heads/<name>.ref`` pointing at the current HEAD (cheap branch pointer)."""
    _warn_cli_storage_mismatch()
    chain = _get_chain(chain_dir)
    h = chain.head()
    if not h:
        console.print("[red]HEAD is empty — create commits before branching.[/red]")
        raise typer.Exit(1)
    root = _effective_chain_dir(chain_dir)
    seg = _safe_ref_segment(name)
    path = root / "refs" / "heads" / f"{seg}.ref"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(h.strip() + "\n", encoding="utf-8")
    console.print(f"[green]branch[/green] {seg} @ HEAD {h[:40]}…")


@app.command("checkout")
def checkout_cmd(
    name: str = typer.Argument(
        ..., help="Имя ветки: файл refs/heads/<name>.ref (см. tc refs)"
    ),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Показать целевой HEAD без записи",
    ),
):
    """Переключить **HEAD** на подпись из ``refs/heads/<name>.ref`` (файловый стор).

    Подпись должна принадлежать одной из известных операций в цепи (скан как у ``tc reset``).
    Verifiable / PostgreSQL — не поддерживается.
    """
    _warn_cli_storage_mismatch()
    chain = _get_chain(chain_dir)
    if getattr(chain, "_vlog", None):
        console.print("[red]tc checkout не поддержан для verifiable / PG chain.[/red]")
        raise typer.Exit(1)

    root = _effective_chain_dir(chain_dir)
    seg = _safe_ref_segment(name)
    ref_path = root / "refs" / "heads" / f"{seg}.ref"
    if not ref_path.is_file():
        console.print(f"[red]Нет refs/heads/{seg}.ref — сначала tc branch {seg}[/red]")
        raise typer.Exit(1)

    lines = ref_path.read_text(encoding="utf-8").strip().splitlines()
    tip_sig = (lines[0] if lines else "").strip()
    if not tip_sig:
        console.print(f"[red]Пустой ref {ref_path.name}[/red]")
        raise typer.Exit(1)

    max_scan = int(os.environ.get("TC_RESET_MAX_SCAN", "50000"))
    chrono = chain.log(limit=max_scan, offset=0)
    sig_map = _signature_to_op_map([o for o in chrono if isinstance(o, dict)])
    if tip_sig not in sig_map:
        console.print(
            "[red]Подпись из ref не найдена среди операций цепи.[/red]\n"
            "[dim]Увеличь TC_RESET_MAX_SCAN или обнови ветку (tc branch).[/dim]"
        )
        raise typer.Exit(1)

    op = sig_map[tip_sig]
    op_id = str(op.get("id", "?"))

    if dry_run:
        console.print(
            Panel.fit(
                f"Ветка [bold]{seg}[/bold] → {op_id}\nHEAD …{tip_sig[:48]}…",
                title="tc checkout --dry-run",
            )
        )
        return

    old = chain.head() or ""
    head_path = root / "HEAD"
    head_path.parent.mkdir(parents=True, exist_ok=True)
    head_path.write_text(tip_sig + "\n", encoding="utf-8")

    reflog = root / "reflog.txt"
    line = (
        f"{datetime.now(timezone.utc).isoformat()}\tcheckout\t{seg}\t"
        f"{old[:64]}\t{tip_sig[:64]}\t{op_id}\n"
    )
    with reflog.open("a", encoding="utf-8") as rf:
        rf.write(line)

    console.print(
        f"[green]checkout[/green] {seg} → {op_id}  HEAD …{tip_sig[:40]}…\n"
        f"[dim]Строка в reflog.txt[/dim]"
    )


@app.command("refs")
def refs_cmd(
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """List checkpoint and heads ref files (first line = HEAD signature)."""
    root = _effective_chain_dir(chain_dir)
    if not root.exists():
        console.print(f"[red]No chain at {root}[/red]")
        raise typer.Exit(1)
    table = Table(title="refs", show_header=True, header_style="bold")
    table.add_column("kind", style="cyan")
    table.add_column("name", style="white")
    table.add_column("HEAD (trunc)", style="dim")

    for kind, sub in (
        ("checkpoint", "refs/checkpoints"),
        ("tag", "refs/tags"),
        ("head", "refs/heads"),
    ):
        d = root / sub
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.ref")):
            try:
                txt = f.read_text(encoding="utf-8").strip().splitlines()
                tip = (txt[0] if txt else "")[:48]
            except OSError:
                tip = "?"
            table.add_row(kind, f.stem, tip + ("…" if len(tip) == 48 else ""))

    v3d = root / "refs" / "v3"
    if v3d.is_dir():
        for f in sorted(v3d.iterdir()):
            if not f.is_file():
                continue
            try:
                txt = f.read_text(encoding="utf-8").strip().splitlines()
                tip = (txt[0] if txt else "")[:48]
            except OSError:
                tip = "?"
            table.add_row("v3", f.name, tip + ("…" if len(tip) == 48 else ""))

    if table.row_count == 0:
        console.print("[dim]No refs/checkpoints or refs/heads/*.ref yet.[/dim]")
    else:
        console.print(table)


@app.command("reset")
def reset_cmd(
    op: str = typer.Argument(
        ...,
        metavar="OP",
        help="``op_NNNN`` to move HEAD to (must be ancestor of current tip)",
    ),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
    soft: bool = typer.Option(
        False,
        "--soft",
        help="Only rewrite HEAD file to target op's signature (objects stay on disk)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show what would change; no writes",
    ),
):
    """Сдвинуть **HEAD** назад как ``git reset --soft`` (только файловый ChainStore).

    Файлы в ``objects/`` не трогаем. Следующий ``sign()`` возьмёт родителя с нового HEAD.
    Verifiable / PostgreSQL — не поддерживается.
    """
    if not soft and not dry_run:
        console.print(
            "[red]Specify --soft and/or --dry-run.[/red] "
            "[dim]Mixed/hard reset are not implemented yet.[/dim]"
        )
        raise typer.Exit(1)

    _warn_cli_storage_mismatch()
    chain = _get_chain(chain_dir)
    if getattr(chain, "_vlog", None):
        console.print(
            "[red]tc reset is not supported for this chain backend (verifiable / PG).[/red]\n"
            "[dim]Use a file-only .trustchain/ from ``tc init`` + file ChainStore.[/dim]"
        )
        raise typer.Exit(1)

    root = _effective_chain_dir(chain_dir)
    target_id = op.strip()
    if not target_id or target_id.upper() == "HEAD":
        console.print("[red]Pass a concrete op id (e.g. op_0002), not HEAD.[/red]")
        raise typer.Exit(1)

    shown = chain.show(target_id)
    if not isinstance(shown, dict):
        console.print(f"[red]Operation not found: {target_id!r}[/red]")
        raise typer.Exit(1)

    max_scan = int(os.environ.get("TC_RESET_MAX_SCAN", "50000"))
    chrono = chain.log(limit=max_scan, offset=0)
    if len(chrono) >= max_scan:
        console.print(
            f"[yellow]Warning:[/yellow] only scanned first {max_scan} ops "
            "(raise TC_RESET_MAX_SCAN if needed)."
        )

    tip_sig = chain.head()
    if not tip_sig:
        console.print("[red]HEAD is empty — nothing to reset.[/red]")
        raise typer.Exit(1)

    sig_map = _signature_to_op_map([o for o in chrono if isinstance(o, dict)])
    if tip_sig not in sig_map:
        console.print(
            "[red]HEAD signature not found among scanned operations.[/red]\n"
            "[dim]Try ``tc chain-verify``, increase TC_RESET_MAX_SCAN, or repair HEAD.[/dim]"
        )
        raise typer.Exit(1)

    detach_ids, target_op = _detach_ids_tip_down_to_target(sig_map, tip_sig, target_id)
    if target_op is None:
        console.print(
            f"[red]{target_id!r} is not on the ancestry path from current HEAD[/red]\n"
            "[dim]Only reset to an ancestor of the tip (linear parent_signature chain).[/dim]"
        )
        raise typer.Exit(1)

    new_head = target_op.get("signature")
    if not isinstance(new_head, str) or not new_head:
        console.print("[red]Target op has no signature[/red]")
        raise typer.Exit(1)

    if not detach_ids:
        console.print(
            Panel.fit(
                f"[bold]Already at[/bold] {target_id}\nHEAD already points to this commit.",
                title="tc reset",
            )
        )
        return

    summary = (
        f"HEAD {tip_sig[:48]}… → {new_head[:48]}…\n"
        f"Цель: [bold]{target_id}[/bold]\n"
        f"[dim]Записи после цели в objects/:[/dim] {len(detach_ids)} — "
        f"{', '.join(detach_ids[:12])}" + (" …" if len(detach_ids) > 12 else "")
    )

    if dry_run:
        console.print(Panel.fit(summary, title="tc reset --dry-run"))
        if soft:
            console.print("[dim]Убери --dry-run чтобы применить --soft.[/dim]")
        return

    # --soft
    head_path = root / "HEAD"
    head_path.parent.mkdir(parents=True, exist_ok=True)
    old_tip = tip_sig
    head_path.write_text(new_head.strip() + "\n", encoding="utf-8")

    reflog = root / "reflog.txt"
    line = (
        f"{datetime.now(timezone.utc).isoformat()}\treset-soft\t"
        f"{old_tip[:64]}\t{new_head[:64]}\t{target_id}\tafter={len(detach_ids)}\n"
    )
    with reflog.open("a", encoding="utf-8") as rf:
        rf.write(line)

    console.print(
        Panel.fit(
            summary + "\n\n[green]HEAD[/green] и строка в reflog.txt",
            title="tc reset --soft",
        )
    )


@app.command("revert")
def revert_cmd(
    op: str = typer.Argument(
        "HEAD",
        metavar="[OP|HEAD]",
        help="HEAD = newest operation; else concrete op id from ``tc log``",
    ),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print reverse mapping only; do not sign",
    ),
    reverse_tool: Optional[str] = typer.Option(
        None,
        "--reverse-tool",
        "-r",
        help="Override reverse tool id (skips reversibles.json / registry lookup)",
    ),
):
    """Append a signed **revert_intent** row (does not execute the reverse tool).

    Resolve ``forward_tool → reverse_tool`` via ``trustchain.v3.compensations`` or
    ``.trustchain/reversibles.json``. Your agent/runtime must still invoke the
    reverse tool to apply compensating side-effects.
    """
    _warn_cli_storage_mismatch()
    chain = _get_chain(chain_dir)
    root = _effective_chain_dir(chain_dir)

    target: Optional[dict] = None
    sel = (op or "HEAD").strip()
    if sel.upper() == "HEAD":
        ops = chain.log_reverse(limit=1)
        target = ops[0] if ops else None
    else:
        shown = chain.show(sel)
        if isinstance(shown, dict):
            target = shown
        else:
            for row in chain.log_reverse(limit=2000):
                if isinstance(row, dict) and row.get("id") == sel:
                    target = row
                    break

    if not target or not isinstance(target, dict):
        console.print(f"[red]Operation not found: {sel!r}[/red]")
        raise typer.Exit(1)

    forward_tool = str(target.get("tool") or target.get("tool_id") or "").strip()
    if not forward_tool:
        console.print("[red]Target op has no tool id[/red]")
        raise typer.Exit(1)

    rev = (reverse_tool or "").strip() or reverse_tool_for_chain(root, forward_tool)
    if not rev:
        console.print(
            f"[red]No reverse tool for {forward_tool!r}.[/red]\n"
            "[dim]Add .trustchain/reversibles.json (JSON object: forward_tool_id → reverse_tool_id) "
            "or pass --reverse-tool.[/dim]\n"
            "[dim]In-process: trustchain.v3.compensations.register_reversible(...)[/dim]"
        )
        raise typer.Exit(1)

    if dry_run:
        console.print(
            Panel.fit(
                f"[bold]Would sign[/bold] tool_id={rev!r}\n"
                f"forward_tool={forward_tool!r}\n"
                f"revert_of={target.get('id')!r}",
                title="tc revert --dry-run",
            )
        )
        return

    tc = _get_tc(chain_dir)
    out = tc.sign(
        rev,
        {
            "kind": "revert_intent",
            "revert_of": target.get("id"),
            "forward_tool": forward_tool,
            "note": "tc revert — execute reverse tool in runtime for real undo",
        },
    )
    console.print(
        f"[green]revert_intent signed[/green] reverse_tool={rev!r} revert_of={target.get('id')!r} "
        f"sig={str(out.signature)[:40]}…"
    )


@app.command("version")
def version():
    """Show TrustChain version."""
    console.print(f"TrustChain v{__version__}")


@app.command("init")
def init(
    output_dir: Path = typer.Option(
        Path("."), "--output", "-o", help="Directory for .trustchain/"
    ),
):
    """Initialize TrustChain in the current directory.

    Creates .trustchain/ with objects/, refs/, HEAD, config.
    """
    trustchain_dir = output_dir / ".trustchain"
    objects_dir = trustchain_dir / "objects"
    refs_dir = trustchain_dir / "refs" / "sessions"

    try:
        trustchain_dir.mkdir(exist_ok=True)
        objects_dir.mkdir(exist_ok=True)
        refs_dir.mkdir(parents=True, exist_ok=True)

        # HEAD
        head_file = trustchain_dir / "HEAD"
        if not head_file.exists():
            head_file.write_text("")

        # Config
        config_file = trustchain_dir / "config.json"
        if not config_file.exists():
            config_file.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "algorithm": "Ed25519",
                        "created_by": f"TrustChain CLI v{__version__}",
                    },
                    indent=2,
                )
            )

        console.print(
            f"[green]Initialized .trustchain/ in {trustchain_dir.resolve()}[/green]"
        )
        console.print("  objects/          # signed operations")
        console.print("  refs/sessions/    # session HEAD pointers")
        console.print("  refs/tags/        # immutable tags (tc tag)")
        console.print("  HEAD              # latest signature")
        console.print("  config.json       # chain metadata")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# `tc receipt …` — portable proof-of-signature (.tcreceipt)                   #
# --------------------------------------------------------------------------- #
#
# Exit-code matrix (stable contract — scripts and CI rely on this):
#
#   0  ok              — verified, signature + optional identity/witnesses all OK
#   1  usage error     — bad CLI args, missing file, etc.
#   2  tampered        — signature invalid (envelope doesn't match the key)
#   3  degraded        — signature OK but optional proof failed (identity/witness)
#   4  format error    — not a valid .tcreceipt document (wrong format/version)
#
receipt_app = typer.Typer(
    name="receipt",
    help="Portable proof-of-signature object (.tcreceipt): build / show / verify.",
    add_completion=False,
    no_args_is_help=True,
)


def _load_receipt_or_exit(path: Path):
    """Load a receipt file, mapping I/O and format errors to stable exit codes."""
    from trustchain.receipt import Receipt, ReceiptFormatError

    try:
        return Receipt.load(path)
    except FileNotFoundError:
        console.print(f"[red]File not found:[/red] {path}")
        raise typer.Exit(1)
    except ReceiptFormatError as exc:
        console.print(f"[red]Not a TrustChain receipt:[/red] {exc}")
        raise typer.Exit(4)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid JSON:[/red] {exc}")
        raise typer.Exit(4)


def _verify_exit_code(v) -> int:
    """Map :class:`ReceiptVerification` to the exit-code matrix above.

    * ``signature_ok is False``            → 2 (tampered).
    * identity / witness extras failed     → 3 (degraded).
    * any remaining ``v.errors`` with      → 2 (pin mismatch, freshness breach, …).
      ``v.valid is False``                   These are *not* degraded — the caller
                                             asked for a stronger guarantee and
                                             didn't get it, which is tamper-class.
    * otherwise                             → 0.
    """
    if not v.signature_ok:
        return 2
    if v.identity_ok is False or v.witnesses_ok is False:
        return 3
    if not v.valid:
        return 2
    return 0


@receipt_app.command("show")
def receipt_show(
    file: Path = typer.Argument(..., help="Path to .tcreceipt file"),
    json_output: bool = typer.Option(
        False, "--json", help="Machine-readable JSON instead of Rich panel"
    ),
):
    """Pretty-print a receipt: who signed, when, what, with which key."""
    receipt = _load_receipt_or_exit(file)

    if json_output:
        print(receipt.to_json())
        return

    env = receipt.envelope
    ts_iso = (receipt.summary or {}).get("timestamp_iso") or "-"
    identity_line = "—"
    if receipt.identity:
        identity_line = (
            f"{receipt.identity.get('subject_cn', '?')}"
            f" ← {receipt.identity.get('issuer_cn', '?')}"
        )
    witnesses_line = "—"
    if receipt.witnesses:
        witnesses_line = f"{len(receipt.witnesses)} co-sign(s)"

    body = (
        f"[bold]tool_id[/bold]    {env.get('tool_id', '?')}\n"
        f"[bold]timestamp[/bold]  {ts_iso}  (epoch {env.get('timestamp', '?')})\n"
        f"[bold]signature[/bold]  {receipt.signature_short}\n"
        f"[bold]key_id[/bold]     {receipt.key.get('key_id') or '—'}\n"
        f"[bold]algorithm[/bold]  {receipt.key.get('algorithm', 'ed25519')}\n"
        f"[bold]identity[/bold]   {identity_line}\n"
        f"[bold]witnesses[/bold]  {witnesses_line}\n"
        f"[bold]fingerprint[/bold] {receipt.fingerprint[:16]}…"
    )
    console.print(Panel(body, title=f"TrustChain Receipt v{receipt.version}"))


@receipt_app.command("verify")
def receipt_verify(
    file: Path = typer.Argument(..., help="Path to .tcreceipt file"),
    pin_key: Optional[str] = typer.Option(
        None,
        "--pin",
        help="Require exact match against this base64 Ed25519 public key",
    ),
    max_age: Optional[float] = typer.Option(
        None,
        "--max-age",
        help="Reject envelopes older than N seconds",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Fail on degraded state (identity/witnesses), not only on bad signature",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Machine-readable JSON output"
    ),
):
    """Verify a receipt end-to-end and exit with a stable code.

    Exit codes: 0=ok, 1=usage, 2=tampered, 3=degraded, 4=format.
    """
    receipt = _load_receipt_or_exit(file)
    v = receipt.verify(expected_public_key_b64=pin_key, max_age_seconds=max_age)
    code = _verify_exit_code(v)

    # `--strict` promotes degraded (code 3) into non-zero; by default we still
    # want code 3 for automation, but we keep the flag for explicit intent.
    if strict and code == 0 and not v.valid:
        code = 3

    if json_output:
        print(json.dumps(v.to_dict(), indent=2))
    else:
        if v.valid:
            console.print("[green]Receipt VALID[/green]")
        elif v.signature_ok:
            console.print(
                "[yellow]Receipt DEGRADED[/yellow] — signature OK, extras failed"
            )
        else:
            console.print("[red]Receipt INVALID[/red] — signature does not match")
        for err in v.errors:
            console.print(f"  [red]•[/red] {err}")
        for warn in v.warnings:
            console.print(f"  [yellow]•[/yellow] {warn}")

    raise typer.Exit(code)


@receipt_app.command("build")
def receipt_build(
    signed_file: Path = typer.Argument(..., help="JSON file with a SignedResponse"),
    public_key: str = typer.Option(
        ...,
        "--key",
        help="Base64 public key OR path to exported key JSON from `tc export-key`",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write receipt to this file instead of stdout"
    ),
    key_id: Optional[str] = typer.Option(
        None, "--key-id", help="Identifier of the key"
    ),
):
    """Wrap an existing SignedResponse JSON into a portable .tcreceipt."""
    from trustchain.receipt import build_receipt

    try:
        envelope = json.loads(signed_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        console.print(f"[red]File not found:[/red] {signed_file}")
        raise typer.Exit(1)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid JSON:[/red] {exc}")
        raise typer.Exit(1)

    # --key may be a literal base64 or a path to exported key file.
    pk_candidate = Path(public_key).expanduser()
    resolved_kid = key_id
    if pk_candidate.is_file():
        try:
            key_data = json.loads(pk_candidate.read_text(encoding="utf-8"))
            if "public_key" in key_data:
                pk_b64 = key_data["public_key"]
            elif "public_key_b64" in key_data:
                pk_b64 = key_data["public_key_b64"]
            else:
                console.print(
                    "[red]Key file has no public_key/public_key_b64 field[/red]"
                )
                raise typer.Exit(1)
            resolved_kid = resolved_kid or key_data.get("key_id")
        except json.JSONDecodeError:
            console.print(f"[red]--key points to non-JSON file:[/red] {pk_candidate}")
            raise typer.Exit(1)
    else:
        pk_b64 = public_key

    receipt = build_receipt(envelope, pk_b64, key_id=resolved_kid)
    text = receipt.to_json()
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"[green]Wrote receipt:[/green] {output}")
    else:
        print(text)


app.add_typer(receipt_app, name="receipt")


# --------------------------------------------------------------------------- #
# `tc standards …` — interoperability exports                                 #
# --------------------------------------------------------------------------- #

standards_app = typer.Typer(
    name="standards",
    help="Export TrustChain receipts to SCITT/W3C VC/in-toto JSON shapes.",
    add_completion=False,
    no_args_is_help=True,
)


def _write_json_document(document: dict[str, Any], output: Optional[Path]) -> None:
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
    if output:
        output.write_text(text + "\n", encoding="utf-8")
        console.print(f"[green]Wrote standards export:[/green] {output}")
    else:
        print(text)


@standards_app.command("export")
def standards_export(
    receipt_file: Path = typer.Argument(..., help="Path to .tcreceipt file"),
    format: str = typer.Option(
        "scitt",
        "--format",
        "-f",
        help="Export format: scitt, w3c-vc, or intoto",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write JSON to this file instead of stdout"
    ),
    agent_id: Optional[str] = typer.Option(
        None,
        "--agent-id",
        help="SCITT agent_id. Defaults to receipt key_id or tool_id.",
    ),
    sequence_number: int = typer.Option(
        0,
        "--sequence",
        min=0,
        help="SCITT sequence number for this record.",
    ),
    previous_chain_hash: Optional[str] = typer.Option(
        None,
        "--prev-chain-hash",
        help="SCITT previous chain hash, if known.",
    ),
    issuer: str = typer.Option(
        "did:web:trust-chain.ai",
        "--issuer",
        help="W3C VC issuer identifier.",
    ),
    subject_id: Optional[str] = typer.Option(
        None,
        "--subject-id",
        help="W3C VC credentialSubject.id. Defaults to a TrustChain tool subject.",
    ),
    subject_name: Optional[str] = typer.Option(
        None,
        "--subject-name",
        help="in-toto subject name. Defaults to trustchain:tool:<tool_id>.",
    ),
):
    """Export a native receipt into a standards-oriented JSON document.

    The native `.tcreceipt` remains the source of truth. These exports are
    interoperability envelopes for SCITT, W3C VC, and in-toto/Sigstore tooling.
    """
    receipt = _load_receipt_or_exit(receipt_file)
    fmt = format.strip().lower()
    env = receipt.envelope
    tool_id = str(env.get("tool_id") or "unknown")

    if fmt == "scitt":
        from trustchain.standards import to_scitt_air_json

        resolved_agent_id = agent_id or receipt.key.get("key_id") or f"tool:{tool_id}"
        document = to_scitt_air_json(
            receipt,
            agent_id=str(resolved_agent_id),
            sequence_number=sequence_number,
            previous_chain_hash=previous_chain_hash,
        )
    elif fmt in {"w3c-vc", "vc", "w3c"}:
        from trustchain.standards import to_w3c_vc

        document = to_w3c_vc(
            receipt,
            issuer=issuer,
            subject_id=subject_id or f"urn:trustchain:tool:{tool_id}",
        )
    elif fmt in {"intoto", "in-toto", "slsa"}:
        from trustchain.standards import to_intoto_statement

        document = to_intoto_statement(receipt, subject_name=subject_name)
    else:
        console.print(
            "[red]Unknown standards format:[/red] "
            f"{format}. Use scitt, w3c-vc, or intoto."
        )
        raise typer.Exit(1)

    _write_json_document(document, output)


app.add_typer(standards_app, name="standards")


# --------------------------------------------------------------------------- #
# `tc anchor …` — portable chain-head checkpoints                              #
# --------------------------------------------------------------------------- #

anchor_app = typer.Typer(
    name="anchor",
    help="Export/verify portable chain-head checkpoints for external anchoring.",
    add_completion=False,
    no_args_is_help=True,
)


def _chain_anchor_document(chain_dir: str) -> dict[str, Any]:
    chain = _get_chain(chain_dir)
    verify_result = chain.verify()
    ops = chain.log(limit=999999)
    canonical = json.dumps(
        ops,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    root = _effective_chain_dir(chain_dir)
    return {
        "format": "tc-anchor",
        "version": 1,
        "profile": "trustchain.anchor.chain-head.v1",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "chain_dir": str(root),
        "length": len(ops),
        "head": verify_result.get("head"),
        "chain_valid": bool(verify_result.get("valid")),
        "chain_sha256": hashlib.sha256(canonical).hexdigest(),
        "merkle_root": getattr(chain, "merkle_root", None),
    }


@anchor_app.command("export")
def anchor_export(
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write anchor JSON to this file instead of stdout"
    ),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Export the current chain HEAD and canonical chain digest.

    Store the resulting JSON outside the TrustChain directory: Git commit, ticket,
    S3 object lock, transparency log, timestamping service, or a customer system.
    Later, `tc anchor verify` can prove the local chain still matches that anchor.
    """
    document = _chain_anchor_document(chain_dir)
    if not document["chain_valid"]:
        console.print("[red]Cannot anchor an invalid chain. Run tc chain-verify.[/red]")
        raise typer.Exit(2)
    _write_json_document(document, output)


@anchor_app.command("verify")
def anchor_verify(
    anchor_file: Path = typer.Argument(
        ..., help="Anchor JSON created by tc anchor export"
    ),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
    json_output: bool = typer.Option(
        False, "--json", help="Machine-readable verification result"
    ),
):
    """Verify that the current chain still matches a previously exported anchor."""
    try:
        anchor = json.loads(anchor_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        console.print(f"[red]File not found:[/red] {anchor_file}")
        raise typer.Exit(1)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid anchor JSON:[/red] {exc}")
        raise typer.Exit(1)

    if anchor.get("format") != "tc-anchor" or int(anchor.get("version", 0)) != 1:
        console.print("[red]Not a TrustChain anchor v1 document[/red]")
        raise typer.Exit(1)

    current = _chain_anchor_document(chain_dir)
    checks = {
        "head": anchor.get("head") == current.get("head"),
        "length": anchor.get("length") == current.get("length"),
        "chain_sha256": anchor.get("chain_sha256") == current.get("chain_sha256"),
        "chain_valid": current.get("chain_valid") is True,
    }
    result = {
        "valid": all(checks.values()),
        "checks": checks,
        "anchor": anchor,
        "current": current,
    }

    if json_output:
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    elif result["valid"]:
        console.print("[green]Anchor VALID[/green] — current chain matches checkpoint")
    else:
        console.print(
            "[red]Anchor MISMATCH[/red] — current chain differs from checkpoint"
        )
        for name, ok in checks.items():
            if not ok:
                console.print(f"  [red]•[/red] {name}")

    raise typer.Exit(0 if result["valid"] else 2)


app.add_typer(anchor_app, name="anchor")


def main():
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
