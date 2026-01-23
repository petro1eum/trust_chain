"""TrustChain Session Management.

Provides automatic chain building for multi-step workflows.

Example:
    from trustchain import TrustChain
    from trustchain.v2.session import TrustChainSession

    tc = TrustChain()

    async with tc.session("agent_run_123") as session:
        session.sign("step_1", {"query": "search"})
        session.sign("step_2", {"results": [...]})  # auto-chains to previous
        session.sign("step_3", {"answer": "..."})

        chain = session.get_chain()
        session.export_html("audit.html")
"""

import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .signer import SignedResponse


class TrustChainSession:
    """Session for automatic chain building.

    Each sign() call automatically chains to the previous response,
    creating a cryptographically linked audit trail.

    Args:
        trustchain: TrustChain instance
        session_id: Unique identifier for this session
        metadata: Optional metadata to include in all responses
    """

    def __init__(
        self,
        trustchain,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.trustchain = trustchain
        self.session_id = session_id
        self.metadata = metadata or {}
        self._chain: List[SignedResponse] = []
        self._started_at = time.time()
        self._ended_at: Optional[float] = None

    def sign(
        self,
        tool_id: str,
        data: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SignedResponse:
        """Sign data and automatically chain to previous response.

        Args:
            tool_id: Tool identifier
            data: Data to sign
            metadata: Optional additional metadata for this step

        Returns:
            SignedResponse with parent_signature set if not first step
        """
        # Merge session metadata with step metadata
        step_metadata = {
            **self.metadata,
            "session_id": self.session_id,
            "step_index": len(self._chain),
            **(metadata or {}),
        }

        # Get parent signature if not first step
        parent_signature = None
        if self._chain:
            parent_signature = self._chain[-1].signature

        # Sign with parent chain
        signed = self.trustchain.sign(
            tool_id,
            data,
            metadata=step_metadata,
            parent_signature=parent_signature,
        )

        self._chain.append(signed)
        return signed

    def get_chain(self) -> List[SignedResponse]:
        """Get all signed responses in this session."""
        return self._chain.copy()

    def verify_chain(self) -> bool:
        """Verify the entire chain is valid and unbroken."""
        return self.trustchain.verify_chain(self._chain)

    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics."""
        return {
            "session_id": self.session_id,
            "steps": len(self._chain),
            "started_at": datetime.fromtimestamp(self._started_at).isoformat(),
            "ended_at": (
                datetime.fromtimestamp(self._ended_at).isoformat()
                if self._ended_at
                else None
            ),
            "duration_seconds": (self._ended_at or time.time()) - self._started_at,
            "tools_used": [r.tool_id for r in self._chain],
        }

    def export_json(self, filepath: Optional[str] = None) -> str:
        """Export chain as JSON.

        Args:
            filepath: Optional file path to write to

        Returns:
            JSON string
        """
        data = {
            "session_id": self.session_id,
            "metadata": self.metadata,
            "stats": self.get_stats(),
            "chain": [r.to_dict() for r in self._chain],
        }
        json_str = json.dumps(data, indent=2, default=str)

        if filepath:
            with open(filepath, "w") as f:
                f.write(json_str)

        return json_str

    def export_html(self, filepath: str) -> str:
        """Export chain as interactive HTML report.

        Args:
            filepath: File path to write to

        Returns:
            HTML string
        """
        # Use the existing HTML exporter from TrustChain
        try:
            from trustchain.ui.explorer import export_chain_html

            return export_chain_html(self._chain, filepath, session_id=self.session_id)
        except ImportError:
            # Fallback to simple HTML
            html = self._generate_simple_html()
            with open(filepath, "w") as f:
                f.write(html)
            return html

    def _generate_simple_html(self) -> str:
        """Generate simple HTML report."""
        steps_html = ""
        for i, response in enumerate(self._chain):
            verified = "✅" if self.trustchain.verify(response) else "❌"
            steps_html += f"""
            <div class="step">
                <h3>Step {i + 1}: {response.tool_id} {verified}</h3>
                <pre>{json.dumps(response.data, indent=2, default=str)}</pre>
                <small>Signature: {response.signature[:32]}...</small>
            </div>
            """

        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>TrustChain Session: {self.session_id}</title>
    <style>
        body {{ font-family: system-ui; max-width: 800px; margin: 0 auto; padding: 20px; }}
        .step {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 8px; }}
        pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; }}
        h3 {{ margin-top: 0; }}
    </style>
</head>
<body>
    <h1>TrustChain Session Report</h1>
    <p><strong>Session ID:</strong> {self.session_id}</p>
    <p><strong>Steps:</strong> {len(self._chain)}</p>
    <p><strong>Chain Valid:</strong> {"✅ Yes" if self.verify_chain() else "❌ No"}</p>
    <hr>
    {steps_html}
</body>
</html>
        """

    def close(self):
        """Close the session."""
        self._ended_at = time.time()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        self.close()
        return False

    def __enter__(self):
        """Sync context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Sync context manager exit."""
        self.close()
        return False


def create_session(trustchain, session_id: str, **kwargs) -> TrustChainSession:
    """Create a new TrustChain session.

    Args:
        trustchain: TrustChain instance
        session_id: Unique session identifier
        **kwargs: Additional session options

    Returns:
        TrustChainSession instance
    """
    return TrustChainSession(trustchain, session_id, **kwargs)
