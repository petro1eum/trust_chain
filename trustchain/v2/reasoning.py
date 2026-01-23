"""
TrustChain Reasoning Verification Module.

Cryptographic verification of AI reasoning chains (Chain of Thought).
Each reasoning step is signed and linked to the previous step,
creating an immutable audit trail of HOW the AI arrived at its answer.

Example:
    from trustchain import TrustChain
    from trustchain.v2.reasoning import ReasoningChain

    tc = TrustChain()
    rc = ReasoningChain(tc)

    # Add reasoning steps
    rc.add_step("Analyzing user query about stock valuation")
    rc.add_step("Current P/E ratio is 28, sector average is 25")
    rc.add_step("Strong cash position of $162B justifies premium")
    rc.set_conclusion("AAPL is fairly valued at current levels")

    # Verify entire chain
    assert rc.verify()  # True

    # Export for audit
    rc.export_html("reasoning_audit.html")
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trustchain.v2.core import TrustChain
    from trustchain.v2.signer import SignedResponse


@dataclass
class ReasoningStep:
    """A single step in the reasoning chain."""

    index: int
    content: str
    signed_response: SignedResponse
    timestamp: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)

    @property
    def signature(self) -> str:
        return self.signed_response.signature

    @property
    def is_verified(self) -> bool:
        return getattr(self.signed_response, "_verified", False)


class ReasoningChain:
    """
    Cryptographically signed chain of AI reasoning steps.

    Each step is signed with Ed25519 and linked to the previous step
    via parent_signature, creating a tamper-evident audit trail.

    Usage:
        tc = TrustChain()
        rc = ReasoningChain(tc)

        # Manual step addition
        rc.add_step("Step 1: Analyze the data")
        rc.add_step("Step 2: Found correlation of 0.85")
        rc.set_conclusion("Recommendation: Proceed with plan A")

        # Or parse from model output
        rc.parse_reasoning(model_response, format="deepseek")

        # Verify chain integrity
        assert rc.verify()  # All signatures valid and linked

        # Export for compliance
        rc.export_html("audit.html")
        rc.export_json("audit.json")
    """

    def __init__(
        self,
        trustchain: TrustChain,
        name: str = "reasoning",
        metadata: dict | None = None,
    ):
        """
        Initialize a new reasoning chain.

        Args:
            trustchain: TrustChain instance for signing
            name: Identifier for this reasoning chain
            metadata: Optional metadata (e.g., model name, prompt)
        """
        self.tc = trustchain
        self.name = name
        self.metadata = metadata or {}
        self.steps: list[ReasoningStep] = []
        self.conclusion: ReasoningStep | None = None
        self.created_at = time.time()

    def add_step(self, content: str, metadata: dict | None = None) -> ReasoningStep:
        """
        Add a reasoning step to the chain.

        The step is immediately signed and linked to the previous step.

        Args:
            content: The reasoning content (text)
            metadata: Optional metadata for this step

        Returns:
            ReasoningStep with signature
        """
        step_index = len(self.steps) + 1
        tool_id = f"{self.name}_step_{step_index}"

        # Get parent signature for chaining
        parent_sig = self.steps[-1].signature if self.steps else None

        # Sign the step
        signed = self.tc._signer.sign(
            tool_id,
            {"step": step_index, "content": content, "metadata": metadata or {}},
            parent_signature=parent_sig,
        )

        step = ReasoningStep(
            index=step_index,
            content=content,
            signed_response=signed,
            metadata=metadata or {},
        )

        self.steps.append(step)
        return step

    def set_conclusion(
        self, content: str, metadata: dict | None = None
    ) -> ReasoningStep:
        """
        Set the final conclusion, chained to all reasoning steps.

        Args:
            content: The conclusion/answer
            metadata: Optional metadata

        Returns:
            ReasoningStep for the conclusion
        """
        if not self.steps:
            raise ValueError("Cannot set conclusion without reasoning steps")

        tool_id = f"{self.name}_conclusion"

        # Chain to last reasoning step
        parent_sig = self.steps[-1].signature

        signed = self.tc._signer.sign(
            tool_id,
            {
                "conclusion": content,
                "reasoning_steps": len(self.steps),
                "metadata": metadata or {},
            },
            parent_signature=parent_sig,
        )

        self.conclusion = ReasoningStep(
            index=len(self.steps) + 1,
            content=content,
            signed_response=signed,
            metadata=metadata or {},
        )

        return self.conclusion

    def verify(self) -> bool:
        """
        Verify the entire reasoning chain.

        Checks:
        1. Each step has a valid signature
        2. Each step's parent_signature matches previous step's signature
        3. Conclusion is chained to last step

        Returns:
            True if chain is valid and unbroken
        """
        all_responses = [s.signed_response for s in self.steps]
        if self.conclusion:
            all_responses.append(self.conclusion.signed_response)

        if not all_responses:
            return True

        # Verify first response signature
        if not self.tc._signer.verify(all_responses[0]):
            return False

        # Verify chain links and signatures
        for i in range(1, len(all_responses)):
            current = all_responses[i]
            previous = all_responses[i - 1]

            # Check chain link
            if current.parent_signature != previous.signature:
                return False

            # Verify signature (without nonce check)
            if not self.tc._signer.verify(current):
                return False

        return True

    def parse_reasoning(
        self, content: str, format: str = "auto"
    ) -> list[ReasoningStep]:
        """
        Parse reasoning from model output and sign each step.

        Supports:
        - "deepseek": <think>...</think> tags
        - "numbered": 1. Step one\n2. Step two
        - "bullets": - Step one\n- Step two
        - "auto": Auto-detect format

        Args:
            content: Raw model output
            format: Parsing format

        Returns:
            List of signed ReasoningStep objects
        """
        if format == "auto":
            if "<think>" in content:
                format = "deepseek"
            elif re.search(r"^\d+\.", content, re.MULTILINE):
                format = "numbered"
            else:
                format = "bullets"

        # Extract reasoning content
        if format == "deepseek":
            match = re.search(r"<think>(.*?)</think>", content, re.DOTALL)
            reasoning_text = match.group(1) if match else content
        else:
            reasoning_text = content

        # Split into steps
        if format == "numbered":
            steps = re.split(r"\n(?=\d+[\.\)])", reasoning_text)
        elif format == "bullets":
            steps = re.split(r"\n(?=[-•*])", reasoning_text)
        else:
            # Split by sentences for other formats
            steps = re.split(r"(?<=[.!?])\s+", reasoning_text)

        # Filter and add steps
        for step_text in steps:
            step_text = step_text.strip()
            if step_text and len(step_text) > 10:  # Skip very short fragments
                self.add_step(step_text)

        return self.steps

    def export_json(self, filepath: str | None = None) -> dict:
        """
        Export reasoning chain as JSON for audit.

        Args:
            filepath: Optional path to save JSON file

        Returns:
            Dict with full chain data
        """
        data = {
            "name": self.name,
            "created_at": self.created_at,
            "metadata": self.metadata,
            "steps": [
                {
                    "index": s.index,
                    "content": s.content,
                    "signature": s.signature,
                    "parent_signature": s.signed_response.parent_signature,
                    "timestamp": s.timestamp,
                    "metadata": s.metadata,
                }
                for s in self.steps
            ],
            "conclusion": (
                {
                    "content": self.conclusion.content,
                    "signature": self.conclusion.signature,
                    "parent_signature": self.conclusion.signed_response.parent_signature,
                }
                if self.conclusion
                else None
            ),
            "verified": self.verify(),
            "total_steps": len(self.steps),
        }

        if filepath:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)

        return data

    def export_html(self, filepath: str) -> None:
        """
        Export reasoning chain as interactive HTML report.

        Args:
            filepath: Path to save HTML file
        """
        chain_data = self.export_json()
        verified = chain_data["verified"]

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reasoning Chain: {self.name}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f0f1a;
            color: #e0e0e0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #818cf8; margin-bottom: 0.5rem; }}
        .status {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: 600;
            margin-bottom: 2rem;
        }}
        .verified {{ background: #065f46; color: #34d399; }}
        .failed {{ background: #7f1d1d; color: #fca5a5; }}
        .step {{
            background: #1a1a2e;
            border: 1px solid #2a2a4a;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            position: relative;
        }}
        .step::before {{
            content: '';
            position: absolute;
            left: 50%;
            top: -1rem;
            width: 2px;
            height: 1rem;
            background: #818cf8;
        }}
        .step:first-child::before {{ display: none; }}
        .step-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }}
        .step-num {{
            background: #818cf8;
            color: white;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
        }}
        .step-content {{ color: #e0e0e0; }}
        .signature {{
            font-family: monospace;
            font-size: 0.75rem;
            color: #6b7280;
            margin-top: 1rem;
            word-break: break-all;
        }}
        .conclusion {{
            background: linear-gradient(135deg, #1e3a5f, #1a1a2e);
            border: 2px solid #818cf8;
        }}
        .chain-link {{
            text-align: center;
            color: #818cf8;
            font-size: 1.5rem;
            margin: 0.5rem 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🧠 Reasoning Chain: {self.name}</h1>
        <div class="status {'verified' if verified else 'failed'}">
            {'✅ VERIFIED' if verified else '❌ VERIFICATION FAILED'}
        </div>

        <div class="steps">
"""

        for step in self.steps:
            html += f"""
            <div class="step">
                <div class="step-header">
                    <div class="step-num">{step.index}</div>
                    <span style="color: #6b7280;">Reasoning Step</span>
                </div>
                <div class="step-content">{step.content}</div>
                <div class="signature">
                    🔐 {step.signature[:50]}...
                </div>
            </div>
            <div class="chain-link">⬇️</div>
"""

        if self.conclusion:
            html += f"""
            <div class="step conclusion">
                <div class="step-header">
                    <div class="step-num">✓</div>
                    <span style="color: #818cf8;">Conclusion</span>
                </div>
                <div class="step-content">{self.conclusion.content}</div>
                <div class="signature">
                    🔐 {self.conclusion.signature[:50]}...
                </div>
            </div>
"""

        html += """
        </div>
    </div>
</body>
</html>
"""

        with open(filepath, "w") as f:
            f.write(html)

    def __len__(self) -> int:
        return len(self.steps)

    def __repr__(self) -> str:
        return f"ReasoningChain(name={self.name!r}, steps={len(self.steps)}, verified={self.verify()})"
