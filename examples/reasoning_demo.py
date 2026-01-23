#!/usr/bin/env python3
"""
TrustChain + DeepSeek R1: Reasoning Verification Demo
======================================================

This demo shows how TrustChain can sign each step of AI reasoning,
making the "chain of thought" cryptographically verifiable.

DeepSeek R1 exposes its reasoning in <think>...</think> tags.
We extract each step and sign it, creating a verifiable reasoning chain.

Requirements:
    pip install openai python-dotenv

Usage:
    python examples/reasoning_demo.py

Get OpenRouter API key: https://openrouter.ai/
"""

import os
import re

# Load .env file automatically
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass  # dotenv not installed, rely on environment variables

from trustchain import TrustChain

# Initialize TrustChain
tc = TrustChain()


def extract_reasoning_steps(thinking_content: str) -> list[str]:
    """Extract individual reasoning steps from <think> content."""
    # Split by sentences or numbered steps
    steps = []

    # Try to split by numbered steps first (e.g., "1.", "Step 1:", etc.)
    numbered = re.split(r"\n(?=\d+[\.\):]|\bStep \d+)", thinking_content)
    if len(numbered) > 1:
        steps = [s.strip() for s in numbered if s.strip()]
    else:
        # Fall back to splitting by sentences
        sentences = re.split(r"(?<=[.!?])\s+", thinking_content)
        steps = [s.strip() for s in sentences if s.strip() and len(s) > 20]

    return steps


def simulate_deepseek_response() -> dict:
    """Simulate DeepSeek R1 response with reasoning.

    In production, this would be:

    from openai import OpenAI
    client = OpenAI(
        api_key=os.environ["DEEPSEEK_API_KEY"],
        base_url="https://api.deepseek.com"
    )
    response = client.chat.completions.create(
        model="deepseek-reasoner",
        messages=[{"role": "user", "content": "..."}]
    )
    """
    # Simulated response for demo (no API key needed)
    return {
        "thinking": """
Let me analyze this step by step.

Step 1: First, I need to understand what the user is asking about AAPL stock valuation.

Step 2: I should look at the current market data. AAPL is trading at $185 with a P/E ratio of 28.

Step 3: Comparing to the tech sector average P/E of 25, AAPL is slightly overvalued.

Step 4: However, Apple's strong cash position ($162B) and services growth (20% YoY) justify a premium.

Step 5: Considering all factors, I conclude that AAPL is fairly valued with moderate upside potential.
        """,
        "answer": "Based on my analysis, AAPL appears fairly valued at current levels. While the P/E ratio of 28 is above the sector average, Apple's strong fundamentals justify a premium valuation. I would rate it as a HOLD with a 12-month price target of $200.",
    }


def demo_with_live_api():
    """Demo with actual DeepSeek API call via OpenRouter."""
    try:
        from openai import OpenAI

        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            print("⚠️  OPENROUTER_API_KEY not set, using simulated response")
            return None

        client = OpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
        )

        print("🔄 Calling DeepSeek R1 via OpenRouter...")
        response = client.chat.completions.create(
            model="deepseek/deepseek-r1",
            messages=[
                {
                    "role": "user",
                    "content": "Should I buy AAPL stock? Analyze step by step briefly.",
                }
            ],
            max_tokens=500,
        )

        content = response.choices[0].message.content

        # DeepSeek R1 may return <think> tags or plain step-by-step
        think_match = re.search(r"<think>(.*?)</think>", content, re.DOTALL)
        if think_match:
            thinking = think_match.group(1)
            answer = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        else:
            # Split at "Final answer" or similar
            parts = re.split(
                r"(?:So,|Therefore,|In conclusion,|Final)", content, maxsplit=1
            )
            if len(parts) > 1:
                thinking = parts[0]
                answer = parts[1] if len(parts) > 1 else content
            else:
                thinking = content
                answer = "See reasoning above."

        return {"thinking": thinking, "answer": answer}

    except ImportError:
        print("⚠️  openai package not installed, using simulated response")
        return None
    except Exception as e:
        print(f"⚠️  API error: {e}, using simulated response")
        return None


def main():
    print("=" * 70)
    print("🧠 TrustChain + DeepSeek R1: REASONING VERIFICATION DEMO")
    print("=" * 70)

    # Try live API first, fall back to simulation
    response = demo_with_live_api() or simulate_deepseek_response()

    thinking = response["thinking"]
    answer = response["answer"]

    print("\n📝 RAW REASONING (from model):")
    print("-" * 50)
    print(thinking[:500] + "..." if len(thinking) > 500 else thinking)

    # Extract reasoning steps
    steps = extract_reasoning_steps(thinking)
    print(f"\n🔍 Extracted {len(steps)} reasoning steps")

    # =========================================
    # SIGN EACH REASONING STEP
    # =========================================
    print("\n" + "=" * 70)
    print("🔐 SIGNING EACH REASONING STEP")
    print("=" * 70)

    signed_chain = []

    for i, step in enumerate(steps, 1):
        # Sign this step, chaining to previous
        parent_sig = signed_chain[-1].signature if signed_chain else None

        signed_step = tc._signer.sign(
            f"reasoning_step_{i}",
            {"step": i, "content": step},
            parent_signature=parent_sig,
        )
        signed_chain.append(signed_step)

        print(f"\n✅ Step {i}:")
        print(f"   Content: {step[:60]}...")
        print(f"   Signature: {signed_step.signature[:30]}...")
        if parent_sig:
            print(f"   Chained to: {parent_sig[:30]}...")

    # =========================================
    # SIGN FINAL ANSWER (CHAINED TO REASONING)
    # =========================================
    print("\n" + "=" * 70)
    print("📋 SIGNING FINAL ANSWER (chained to all reasoning)")
    print("=" * 70)

    final_answer = tc._signer.sign(
        "final_answer",
        {"answer": answer, "reasoning_steps": len(steps)},
        parent_signature=signed_chain[-1].signature,
    )
    signed_chain.append(final_answer)

    print("\n✅ Final Answer signed!")
    print(f"   Answer: {answer[:100]}...")
    print(f"   Signature: {final_answer.signature[:40]}...")
    print(f"   Chained to last reasoning step: {signed_chain[-2].signature[:30]}...")

    # =========================================
    # VERIFY ENTIRE REASONING CHAIN
    # =========================================
    print("\n" + "=" * 70)
    print("🔍 VERIFYING ENTIRE REASONING CHAIN")
    print("=" * 70)

    chain_valid = tc.verify_chain(signed_chain)

    print(f"\n{'✅ CHAIN VERIFIED!' if chain_valid else '❌ CHAIN BROKEN!'}")
    print(f"   Total steps in chain: {len(signed_chain)}")
    print(f"   First step (reasoning): {signed_chain[0].tool_id}")
    print(f"   Last step (answer): {signed_chain[-1].tool_id}")

    # =========================================
    # SHOW TAMPER DETECTION
    # =========================================
    print("\n" + "=" * 70)
    print("🚨 TAMPER DETECTION: What if we modify a reasoning step?")
    print("=" * 70)

    # Create a tampered chain
    from trustchain.v2.signer import SignedResponse

    tampered_step = SignedResponse(
        data={
            "step": 3,
            "content": "I ignored all analysis and just guessed.",
        },  # TAMPERED!
        signature=signed_chain[2].signature,  # Keep original signature
        signature_id=signed_chain[2].signature_id,
        timestamp=signed_chain[2].timestamp,
        nonce=signed_chain[2].nonce + "_x",
        tool_id=signed_chain[2].tool_id,
        parent_signature=signed_chain[2].parent_signature,
    )

    # Replace step 3 with tampered version
    signed_chain[:2] + [tampered_step] + signed_chain[3:]

    print("\n🔴 Attacker modified Step 3:")
    print(f"   Original: '{steps[2][:50]}...'")
    print("   Tampered: 'I ignored all analysis and just guessed.'")

    # Verify tampered chain
    tampered_valid = tc._signer.verify(tampered_step)

    print(
        f"\n{'❌ TAMPERING DETECTED!' if not tampered_valid else '⚠️ Somehow passed?!'}"
    )
    print("   The signature doesn't match the modified content!")

    # =========================================
    # SUMMARY
    # =========================================
    print("\n" + "=" * 70)
    print("📊 SUMMARY")
    print("=" * 70)
    print(
        """
TrustChain Reasoning Verification:

1. ✅ Each reasoning step is cryptographically signed
2. ✅ Steps are chained together (parent_signature links)
3. ✅ Final answer is chained to all reasoning
4. ✅ Any modification to any step is detectable
5. ✅ Complete audit trail of AI's thinking process

Use Cases:
- Medical AI: Prove diagnosis reasoning chain
- Financial AI: Audit investment recommendations
- Legal AI: Verify contract analysis steps
- Any high-stakes AI: Accountability & compliance
"""
    )


if __name__ == "__main__":
    main()
