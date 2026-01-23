"""TrustChain CLI.

Command-line interface for TrustChain operations.

Usage:
    trustchain export-key --format=json
    trustchain export-key --format=pem --output=key.pem
    trustchain verify <file>
    trustchain info
"""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from trustchain import TrustChain, __version__

app = typer.Typer(
    name="trustchain",
    help="TrustChain CLI - Cryptographically signed AI tool responses",
    add_completion=False,
)
console = Console()


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
        trustchain export-key --format=json
        trustchain export-key --format=pem --output=public.pem
        trustchain export-key --format=base64
    """
    try:
        # Load or create TrustChain
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
            if pretty:
                result = json.dumps(data, indent=2)
            else:
                result = json.dumps(data)

        elif format == "base64":
            result = public_key

        elif format == "hex":
            import base64

            key_bytes = base64.b64decode(public_key)
            result = key_bytes.hex()

        elif format == "pem":
            # Create PEM format
            result = f"""-----BEGIN PUBLIC KEY-----
{public_key}
-----END PUBLIC KEY-----
"""
        else:
            console.print(f"[red]Unknown format: {format}[/red]")
            raise typer.Exit(1)

        # Output
        if output:
            output.write_text(result)
            console.print(f"[green]✓[/green] Key exported to {output}")
        else:
            console.print(result)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
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

    console.print(table)


@app.command("verify")
def verify(
    file: Path = typer.Argument(..., help="JSON file with signed response"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Verify a signed response from a JSON file.

    Examples:
        trustchain verify response.json
        trustchain verify --verbose audit.json
    """
    try:
        # Load JSON
        data = json.loads(file.read_text())

        # Create TrustChain (uses same key)
        tc = TrustChain()

        # Verify
        is_valid = tc.verify(data)

        if is_valid:
            console.print("[green]✓ Signature VALID[/green]")
            if verbose:
                console.print(f"  Tool ID: {data.get('tool_id', 'N/A')}")
                console.print(f"  Signature: {data.get('signature', '')[:32]}...")
        else:
            console.print("[red]✗ Signature INVALID[/red]")
            raise typer.Exit(1)

    except FileNotFoundError:
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Verification error: {e}[/red]")
        raise typer.Exit(1)


@app.command("version")
def version():
    """Show TrustChain version."""
    console.print(f"TrustChain v{__version__}")


@app.command("init")
def init(
    output_dir: Path = typer.Option(
        Path("."), "--output", "-o", help="Directory for config files"
    ),
):
    """Initialize TrustChain in the current directory.

    Creates:
        - .trustchain/config.yaml (optional config)
        - .trustchain/keys/ (for key storage)
    """
    trustchain_dir = output_dir / ".trustchain"
    keys_dir = trustchain_dir / "keys"

    try:
        trustchain_dir.mkdir(exist_ok=True)
        keys_dir.mkdir(exist_ok=True)

        # Create config
        config_file = trustchain_dir / "config.yaml"
        if not config_file.exists():
            config_file.write_text(
                """# TrustChain Configuration
algorithm: ed25519
enable_nonce: true
cache_ttl: 3600

# Certificate (optional)
# certificate:
#   owner: "My Agent"
#   organization: "Acme Corp"
#   tier: community
"""
            )

        console.print(f"[green]✓[/green] TrustChain initialized in {trustchain_dir}")
        console.print("  - Config: config.yaml")
        console.print("  - Keys: keys/")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


def main():
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
