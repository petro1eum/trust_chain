"""TrustChain CLI — Git-like interface for AI agent audit trails.

Usage:
    tc log                          # chain history (newest first)
    tc log --limit 5                # last 5 operations
    tc log --tool bash_tool         # filter by tool
    tc status                       # chain health summary
    tc chain-verify                 # verify chain integrity (fsck)
    tc blame bash_tool              # forensics: all ops by tool
    tc show op_0003                 # single commit detail
    tc diff op_0001 op_0005         # compare two operations
    tc export chain.json            # export full chain as JSON
    tc init                         # initialize .trustchain/ directory
    tc info                         # key + version info
    tc export-key --format=json     # export public key
    tc verify response.json         # verify a signed JSON file
"""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from trustchain import TrustChain, TrustChainConfig, __version__
from trustchain.v2.chain_store import ChainStore
from trustchain.v2.storage import FileStorage

app = typer.Typer(
    name="tc",
    help="TrustChain CLI — Git for AI Agents. Cryptographic audit trail for every tool call.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _get_chain(chain_dir: str = ".trustchain") -> ChainStore:
    """Load chain from the current directory's .trustchain/ folder."""
    root = Path(chain_dir).expanduser().resolve()
    if not root.exists():
        console.print(f"[red]No .trustchain/ directory found at {root}[/red]")
        console.print("[dim]Run 'tc init' to create one, or specify --dir[/dim]")
        raise typer.Exit(1)
    storage = FileStorage(str(root))
    return ChainStore(storage, root_dir=str(root))


def _get_tc(chain_dir: str = ".trustchain") -> TrustChain:
    """Load full TrustChain from chain dir."""
    return TrustChain(
        TrustChainConfig(
            enable_chain=True,
            chain_storage="file",
            chain_dir=chain_dir,
        )
    )


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
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show full data"),
):
    """Show chain history (like `git log`).

    Examples:
        tc log                    # last 20 operations
        tc log -n 5               # last 5
        tc log --tool bash_tool   # only bash operations
        tc log --chrono            # oldest first
    """
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

    for op in ops:
        op_id = op.get("id", "?")
        op_tool = op.get("tool", "unknown")
        sig = _truncate(op.get("signature"), 10)
        parent = _truncate(op.get("parent_signature"), 10)
        ts = op.get("timestamp", "")
        latency = op.get("latency_ms", 0)

        # Commit line (like git log --oneline)
        header = Text()
        header.append(f"  {op_id}", style="bold yellow")
        header.append(f"  {op_tool}", style="bold cyan")
        header.append(f"  sig:{sig}", style="green")
        if op.get("parent_signature"):
            header.append(f"  parent:{parent}", style="dim")
        if latency:
            header.append(f"  {latency:.0f}ms", style="dim magenta")

        console.print(header)
        console.print(f"    [dim]{ts}[/dim]")

        if verbose:
            data = op.get("data", {})
            console.print(f"    [dim]data: {json.dumps(data, default=str)[:120]}[/dim]")

        console.print()


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
    op_id: str = typer.Argument(..., help="Operation ID (e.g. op_0003)"),
    chain_dir: str = typer.Option(".trustchain", "--dir", "-d", help="Chain directory"),
):
    """Show a single commit in detail (like `git show <hash>`).

    Examples:
        tc show op_0001
        tc show op_0015
    """
    chain = _get_chain(chain_dir)
    op = chain.show(op_id)

    if not op:
        console.print(f"[red]Operation '{op_id}' not found[/red]")
        raise typer.Exit(1)

    console.print(
        Panel(
            json.dumps(op, indent=2, default=str),
            title=f"tc show {op_id}",
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
        console.print("  HEAD              # latest signature")
        console.print("  config.json       # chain metadata")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


def main():
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
