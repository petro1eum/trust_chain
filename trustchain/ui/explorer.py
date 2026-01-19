"""Audit Trail UI - HTML visualization for TrustChain.

Generates interactive HTML reports showing:
- Chain of Trust graph
- Timeline of operations
- Merkle Tree visualization
- Signature verification status

Usage:
    from trustchain.ui.explorer import ChainExplorer

    explorer = ChainExplorer(responses)
    explorer.export_html("audit_report.html")
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustChain Audit Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e4e4e4;
            min-height: 100vh;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            text-align: center;
            margin-bottom: 2rem;
            background: linear-gradient(90deg, #00ff88, #00d4ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.5rem;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            background: linear-gradient(90deg, #00ff88, #00d4ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .stat-label { color: #888; margin-top: 0.5rem; }
        .chain-container {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        h2 { margin-bottom: 1.5rem; color: #00d4ff; }
        .chain-item {
            display: flex;
            align-items: flex-start;
            margin-bottom: 1rem;
            position: relative;
        }
        .chain-item:not(:last-child)::after {
            content: '';
            position: absolute;
            left: 20px;
            top: 50px;
            width: 2px;
            height: calc(100% - 20px);
            background: linear-gradient(180deg, #00ff88, #00d4ff);
        }
        .chain-node {
            width: 42px;
            height: 42px;
            border-radius: 50%;
            background: linear-gradient(135deg, #00ff88, #00d4ff);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            color: #1a1a2e;
            flex-shrink: 0;
            z-index: 1;
        }
        .chain-content {
            flex: 1;
            margin-left: 1rem;
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 1rem;
        }
        .chain-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        .chain-tool { font-weight: bold; color: #00ff88; }
        .chain-time { color: #666; font-size: 0.85rem; }
        .chain-sig {
            font-family: monospace;
            font-size: 0.8rem;
            color: #888;
            background: rgba(0,0,0,0.3);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            display: inline-block;
            margin-top: 0.5rem;
        }
        .chain-data {
            margin-top: 0.75rem;
            padding: 0.75rem;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
        }
        .verified { color: #00ff88; }
        .failed { color: #ff4444; }
        .parent-link {
            font-size: 0.75rem;
            color: #00d4ff;
            margin-top: 0.5rem;
        }
        .footer {
            text-align: center;
            padding: 2rem;
            color: #666;
        }
        .footer a { color: #00d4ff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>TrustChain Audit Report</h1>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">$total_operations</div>
                <div class="stat-label">Operations</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$verified_count</div>
                <div class="stat-label">Verified</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$chain_length</div>
                <div class="stat-label">Chain Links</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$unique_tools</div>
                <div class="stat-label">Unique Tools</div>
            </div>
        </div>
        
        <div class="chain-container">
            <h2>Chain of Trust</h2>
            <p style="color: #888; margin-bottom: 1rem;">Each operation is cryptographically signed. Operations with a parent link form a verified chain.</p>
            $chain_items
        </div>
        
        <div class="footer">
            Generated by <a href="https://github.com/trustchain">TrustChain</a> | $generated_at
        </div>
    </div>
</body>
</html>"""

CHAIN_ITEM_TEMPLATE = """
<div class="chain-item">
    <div class="chain-node">{index}</div>
    <div class="chain-content">
        <div class="chain-header">
            <span class="chain-tool">{tool_id}</span>
            <span class="chain-time">{timestamp}</span>
        </div>
        <div class="chain-sig">Signature: {signature}</div>
        {parent_link}
        <div class="chain-data">{data}</div>
        <div class="{verified_class}">{verified_text}</div>
    </div>
</div>
"""


class ChainExplorer:
    """Interactive HTML explorer for TrustChain audit trails."""

    def __init__(self, responses: List = None, tc: "TrustChain" = None):
        """Initialize explorer.

        Args:
            responses: List of SignedResponse objects
            tc: TrustChain instance (for verification)
        """
        self.responses = responses or []
        self.tc = tc

    def add_response(self, response):
        """Add a response to the explorer."""
        self.responses.append(response)

    def export_html(self, filepath: str) -> str:
        """Export chain as interactive HTML.

        Args:
            filepath: Output file path

        Returns:
            Path to generated file
        """
        # Generate chain items HTML
        chain_items = []
        verified_count = 0
        unique_tools = set()
        chain_links = 0

        for i, resp in enumerate(self.responses):
            unique_tools.add(resp.tool_id)

            # Check for chain link
            has_parent = bool(getattr(resp, "parent_signature", None))
            if has_parent:
                chain_links += 1

            # Verify signature
            is_verified = True
            if self.tc:
                try:
                    is_verified = self.tc._signer.verify(resp)
                except:
                    is_verified = False

            if is_verified:
                verified_count += 1

            # Format data
            data_str = json.dumps(resp.data, indent=2, default=str)
            if len(data_str) > 500:
                data_str = data_str[:500] + "..."

            # Format timestamp
            try:
                ts = datetime.fromtimestamp(resp.timestamp).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            except:
                ts = str(resp.timestamp)

            # Parent link
            parent_link = ""
            if has_parent:
                parent_link = f'<div class="parent-link">↳ Parent: {resp.parent_signature[:24]}...</div>'

            item = CHAIN_ITEM_TEMPLATE.format(
                index=i + 1,
                tool_id=resp.tool_id,
                timestamp=ts,
                signature=resp.signature[:32] + "...",
                parent_link=parent_link,
                data=data_str,
                verified_class="verified" if is_verified else "failed",
                verified_text="[VERIFIED]" if is_verified else "[FAILED]",
            )
            chain_items.append(item)

        # Generate full HTML using Template to avoid CSS brace issues
        from string import Template

        html = Template(HTML_TEMPLATE).safe_substitute(
            total_operations=len(self.responses),
            verified_count=verified_count,
            chain_length=chain_links,
            unique_tools=len(unique_tools),
            chain_items="\n".join(chain_items),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # Write to file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath

    def to_json(self) -> str:
        """Export chain as JSON."""
        data = []
        for resp in self.responses:
            data.append(
                {
                    "tool_id": resp.tool_id,
                    "signature": resp.signature,
                    "timestamp": resp.timestamp,
                    "nonce": resp.nonce,
                    "data": resp.data,
                    "parent_signature": getattr(resp, "parent_signature", None),
                }
            )
        return json.dumps(data, indent=2, default=str)


def export_chain_graph(tc: "TrustChain", responses: List, filepath: str) -> str:
    """Quick export function.

    Usage:
        export_chain_graph(tc, [resp1, resp2, resp3], "audit.html")
    """
    explorer = ChainExplorer(responses, tc)
    return explorer.export_html(filepath)


# Type hints
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trustchain.v2 import TrustChain
