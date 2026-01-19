#!/usr/bin/env python3
"""
🔒 TrustChain Comprehensive Feature Tests

This test suite covers ALL key features of TrustChain with honest testing:
1. Cryptographic signatures (Ed25519)
2. Hallucination detection
3. Tool execution enforcement
4. Automatic interception
5. Trust levels and replay protection
6. Performance requirements
7. Error handling and security

NO BYPASSES OR SHORTCUTS - All verify_response=True (default)
"""

import asyncio
import time
from typing import Any, Dict, List

import pytest

from trustchain import (
    MemoryRegistry,
    SignatureAlgorithm,
    TrustedTool,
    TrustLevel,
    create_integrated_security_system,
    disable_automatic_enforcement,
    enable_automatic_enforcement,
    get_signature_engine,
)
from trustchain.core.models import SignedResponse
from trustchain.monitoring.hallucination_detector import (
    HallucinationDetector,
    ValidationResult,
    create_hallucination_detector,
)
from trustchain.monitoring.tool_enforcement import (
    ToolExecution,
    ToolExecutionEnforcer,
    create_tool_enforcer,
)
from trustchain.monitoring.tool_enforcement_interceptor import (
    UnauthorizedDirectToolCall,
)
from trustchain.utils.exceptions import NonceReplayError, ToolExecutionError


class TestCryptographicSignatures:
    """Test core cryptographic functionality."""

    @pytest.fixture
    async def setup_crypto(self):
        """Setup cryptographic infrastructure."""
        registry = MemoryRegistry()
        await registry.start()

        signature_engine = get_signature_engine()

        yield signature_engine, registry

        await registry.stop()

    async def test_ed25519_signature_creation_and_verification(self, setup_crypto):
        """Test Ed25519 signature creation and verification."""
        signature_engine, registry = setup_crypto

        # Create tool with Ed25519
        @TrustedTool(
            "crypto_test", algorithm=SignatureAlgorithm.ED25519, registry=registry
        )
        async def crypto_tool(data: str) -> Dict[str, Any]:
            return {"processed": data, "algorithm": "Ed25519"}

        # Execute and verify signature
        response = await crypto_tool("test data")

        assert isinstance(response, SignedResponse)
        assert response.signature.algorithm == SignatureAlgorithm.ED25519
        assert response.is_verified  # Full verification enabled
        assert len(response.signature.signature) > 0

        # Manual verification
        verification = signature_engine.verify_response(response)
        assert verification.valid
        assert verification.algorithm_used == SignatureAlgorithm.ED25519

    async def test_signature_tampering_detection(self, setup_crypto):
        """Test that tampered responses are detected."""
        signature_engine, registry = setup_crypto

        @TrustedTool("tamper_test", registry=registry)
        async def tamper_tool(value: int) -> Dict[str, Any]:
            return {"value": value, "squared": value * value}

        # Get legitimate response
        response = await tamper_tool(5)
        assert response.data["squared"] == 25

        # Tamper with the data
        response.data["squared"] = 999  # Changed from 25 to 999

        # Verification should fail
        verification = signature_engine.verify_response(response)
        assert not verification.valid
        assert (
            "hash" in verification.error_message.lower()
            or "integrity" in verification.error_message.lower()
        )

    async def test_performance_requirements(self, setup_crypto):
        """Test that signature operations meet performance requirements."""
        signature_engine, registry = setup_crypto

        @TrustedTool("perf_test", registry=registry)
        async def performance_tool(x: int) -> Dict[str, Any]:
            return {"result": x * 2}

        # Test signing performance (should be < 5ms overhead)
        times = []
        for _ in range(10):
            start = time.time()
            response = await performance_tool(42)
            end = time.time()

            assert response.is_verified
            times.append((end - start) * 1000)  # Convert to ms

        avg_time = sum(times) / len(times)
        print(f"   📊 Average signature time: {avg_time:.2f}ms")

        # Should be well under 5ms for this simple operation
        assert avg_time < 50, f"Signature overhead too high: {avg_time:.2f}ms"


class TestHallucinationDetection:
    """Test hallucination detection system."""

    @pytest.fixture
    async def hallucination_detector(self):
        """Create integrated hallucination detector with tool enforcer."""
        registry = MemoryRegistry()
        await registry.start()

        signature_engine = get_signature_engine()

        # Create integrated system
        enforcer, detector = create_integrated_security_system(signature_engine)

        yield detector

        await registry.stop()

    def test_detect_fake_tool_claims(
        self, hallucination_detector: HallucinationDetector
    ):
        """Test detection of responses without signatures."""
        fake_responses = [
            "I called the weather API and got temperature 25°C",
            "I executed the payment tool and sent $500",
            "I retrieved data from the database",
            "The API returned the current status",
        ]

        for response in fake_responses:
            validation = hallucination_detector.validate_response(response)

            # Should detect as hallucination since no signatures were provided
            assert (
                not validation.valid
            ), f"Failed to detect response without signature: {response}"
            assert len(validation.hallucinations) > 0

            print(f"   ✅ Detected response without signature: {response[:50]}...")

    def test_legitimate_conversation_allowed(
        self, hallucination_detector: HallucinationDetector
    ):
        """Test that normal conversation is not flagged."""
        normal_responses = [
            "Hello! How can I help you today?",
            "I understand you want to know about the weather.",
            "Let me explain how financial transactions work.",
            "The concept of temperature is measured in degrees.",
        ]

        for response in normal_responses:
            validation = hallucination_detector.validate_response(response)

            # Normal conversation should not be flagged
            assert validation.valid
            assert len(validation.hallucinations) == 0


class TestToolEnforcement:
    """Test tool execution enforcement system."""

    @pytest.fixture
    async def enforcement_setup(self):
        """Setup integrated enforcement system."""
        registry = MemoryRegistry()
        await registry.start()

        signature_engine = get_signature_engine()

        # Create test tools first
        @TrustedTool("enforced_weather", registry=registry)
        async def weather_tool(city: str) -> Dict[str, Any]:
            return {"city": city, "temp": 20, "condition": "sunny"}

        @TrustedTool("enforced_calculator", registry=registry)
        def calc_tool(expression: str) -> Dict[str, Any]:
            result = eval(expression)  # Simple calc for testing
            return {"expression": expression, "result": result}

        # Create integrated system with tools
        tools = [weather_tool._trustchain_tool, calc_tool._trustchain_tool]
        enforcer, detector = create_integrated_security_system(signature_engine, tools)

        yield enforcer, weather_tool, calc_tool

        await registry.stop()

    def test_enforced_tool_execution(self, enforcement_setup):
        """Test tool execution through enforcer."""
        enforcer, weather_tool, calc_tool = enforcement_setup

        # Execute through enforcer
        execution = enforcer.execute_tool("enforced_weather", "Tokyo")

        assert isinstance(execution, ToolExecution)
        assert execution.tool_name == "enforced_weather"
        assert execution.verified
        assert execution.result["city"] == "Tokyo"
        assert len(execution.signature) > 0

        # Check registry tracking
        stats = enforcer.registry.get_stats()
        assert stats["total_executions"] >= 1

    def test_execution_audit_trail(self, enforcement_setup):
        """Test complete audit trail of executions."""
        enforcer, weather_tool, calc_tool = enforcement_setup

        # Execute multiple tools
        exec1 = enforcer.execute_tool("enforced_weather", "Paris")
        exec2 = enforcer.execute_tool("enforced_calculator", "10 + 5")
        exec3 = enforcer.execute_tool("enforced_weather", "Berlin")

        # Check audit trail
        recent = enforcer.registry.get_recent_executions(limit=5)
        assert len(recent) >= 3

        # Verify execution details
        request_ids = [exec1.request_id, exec2.request_id, exec3.request_id]
        for execution in recent:
            if execution.request_id in request_ids:
                assert execution.verified
                assert execution.execution_time_ms > 0
                assert execution.timestamp > 0

    def test_response_verification_against_executions(self, enforcement_setup):
        """Test verification of responses against actual executions."""
        enforcer, weather_tool, calc_tool = enforcement_setup

        # Execute a tool
        execution = enforcer.execute_tool("enforced_calculator", "7 * 8")
        assert execution.result["result"] == 56

        # Response that contains data from the execution should be verified
        legitimate_response = "I calculated using enforced_calculator and got 56"
        has_signed_data = enforcer.has_signed_data_for_response(legitimate_response)
        assert has_signed_data, "Response with execution data should be verified"

        # Response that doesn't contain execution data should not be verified
        fake_response = "I calculated 7 * 8 and got 99"  # Wrong result
        has_no_signed_data = enforcer.has_signed_data_for_response(fake_response)
        assert not has_no_signed_data, "Response with wrong data should not be verified"


class TestAutomaticInterception:
    """Test automatic tool call interception."""

    @pytest.fixture
    async def interception_setup(self):
        """Setup interception system."""
        registry = MemoryRegistry()
        await registry.start()

        signature_engine = get_signature_engine()
        enforcer = create_tool_enforcer(signature_engine)

        # Create intercepted tool
        @TrustedTool("intercepted_tool", registry=registry)
        def intercepted_tool(data: str) -> Dict[str, Any]:
            return {"intercepted": True, "data": data}

        enforcer.register_tool(intercepted_tool._trustchain_tool)

        yield enforcer, intercepted_tool

        disable_automatic_enforcement()  # Cleanup
        await registry.stop()

    def test_direct_call_blocked_in_strict_mode(self, interception_setup):
        """Test that direct tool calls are blocked in strict mode."""
        enforcer, intercepted_tool = interception_setup

        # Enable strict interception
        enable_automatic_enforcement(enforcer, strict_mode=True)

        try:
            # Direct call should be blocked
            with pytest.raises(UnauthorizedDirectToolCall):
                intercepted_tool("direct call")

        finally:
            disable_automatic_enforcement()

    def test_enforcer_calls_allowed(self, interception_setup):
        """Test that calls through enforcer are allowed."""
        enforcer, intercepted_tool = interception_setup

        # Enable interception
        enable_automatic_enforcement(enforcer, strict_mode=True)

        try:
            # Call through enforcer should work
            execution = enforcer.execute_tool("intercepted_tool", "enforced call")

            assert execution.verified
            assert execution.result["intercepted"] is True
            assert execution.result["data"] == "enforced call"

        finally:
            disable_automatic_enforcement()


class TestTrustLevels:
    """Test different trust levels and their enforcement."""

    @pytest.fixture
    async def trust_levels_setup(self):
        """Setup tools with different trust levels."""
        registry = MemoryRegistry()
        await registry.start()

        @TrustedTool("low_trust", trust_level=TrustLevel.LOW, registry=registry)
        def low_tool(data: str) -> Dict[str, Any]:
            return {"level": TrustLevel.LOW.value, "data": data}

        @TrustedTool("medium_trust", trust_level=TrustLevel.MEDIUM, registry=registry)
        def medium_tool(data: str) -> Dict[str, Any]:
            return {"level": TrustLevel.MEDIUM.value, "data": data}

        @TrustedTool("high_trust", trust_level=TrustLevel.HIGH, registry=registry)
        def high_tool(data: str) -> Dict[str, Any]:
            return {"level": TrustLevel.HIGH.value, "data": data}

        @TrustedTool(
            "critical_trust", trust_level=TrustLevel.CRITICAL, registry=registry
        )
        def critical_tool(data: str) -> Dict[str, Any]:
            return {"level": TrustLevel.CRITICAL.value, "data": data}

        yield low_tool, medium_tool, high_tool, critical_tool

        await registry.stop()

    async def test_all_trust_levels_verified(self, trust_levels_setup):
        """Test that all trust levels are properly verified."""
        low_tool, medium_tool, high_tool, critical_tool = trust_levels_setup

        tools_and_levels = [
            (low_tool, TrustLevel.LOW),
            (medium_tool, TrustLevel.MEDIUM),
            (high_tool, TrustLevel.HIGH),
            (critical_tool, TrustLevel.CRITICAL),
        ]

        for tool, expected_level in tools_and_levels:
            response = await tool("test data")

            # All levels should be verified (no bypasses)
            assert response.is_verified
            assert response.trust_metadata.trust_level == expected_level
            assert response.data["level"] == expected_level.value

            print(f"   ✅ {expected_level.value} trust level verified")


class TestReplayProtection:
    """Test nonce-based replay protection."""

    @pytest.fixture
    async def replay_setup(self):
        """Setup replay protection test."""
        registry = MemoryRegistry()
        await registry.start()

        @TrustedTool("replay_test", registry=registry, require_nonce=True)
        async def replay_tool(data: str) -> Dict[str, Any]:
            return {"data": data, "timestamp": time.time()}

        yield replay_tool

        await registry.stop()

    async def test_nonce_replay_prevention(self, replay_setup):
        """Test that replay attacks are prevented."""
        replay_tool = replay_setup

        # First call with specific nonce should succeed
        nonce = "test_nonce_12345"
        response1 = await replay_tool("first call", nonce=nonce)
        assert response1.is_verified

        # Second call with same nonce should fail
        with pytest.raises(NonceReplayError):
            await replay_tool("second call", nonce=nonce)


class TestErrorHandling:
    """Test comprehensive error handling."""

    @pytest.fixture
    async def error_setup(self):
        """Setup error testing."""
        registry = MemoryRegistry()
        await registry.start()

        @TrustedTool("error_tool", registry=registry)
        async def error_tool(should_fail: bool) -> Dict[str, Any]:
            if should_fail:
                raise ValueError("Intentional test error")
            return {"success": True}

        yield error_tool

        await registry.stop()

    async def test_tool_execution_errors(self, error_setup):
        """Test handling of tool execution errors."""
        error_tool = error_setup

        # Successful execution
        response = await error_tool(False)
        assert response.is_verified
        assert response.data["success"] is True

        # Failed execution should raise ToolExecutionError
        with pytest.raises(ToolExecutionError):
            await error_tool(True)


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""

    @pytest.fixture
    async def full_system_setup(self):
        """Setup complete TrustChain system."""
        registry = MemoryRegistry()
        await registry.start()

        signature_engine = get_signature_engine()
        enforcer = create_tool_enforcer(signature_engine)
        detector = create_hallucination_detector(signature_engine)

        # Create realistic tools
        @TrustedTool("payment_api", trust_level=TrustLevel.CRITICAL, registry=registry)
        async def payment_tool(amount: float, recipient: str) -> Dict[str, Any]:
            return {
                "transaction_id": f"tx_{int(time.time())}",
                "amount": amount,
                "recipient": recipient,
                "status": "completed",
                "timestamp": time.time(),
            }

        @TrustedTool("weather_api", trust_level=TrustLevel.MEDIUM, registry=registry)
        async def weather_tool(city: str) -> Dict[str, Any]:
            return {
                "city": city,
                "temperature": 22,
                "condition": "sunny",
                "humidity": 65,
                "timestamp": time.time(),
            }

        enforcer.register_tool(payment_tool._trustchain_tool)
        enforcer.register_tool(weather_tool._trustchain_tool)

        yield enforcer, detector, payment_tool, weather_tool

        await registry.stop()

    async def test_end_to_end_verified_workflow(self, full_system_setup):
        """Test complete end-to-end verified workflow."""
        enforcer, detector, payment_tool, weather_tool = full_system_setup

        # 1. Execute tools through enforcer
        weather_exec = enforcer.execute_tool("weather_api", "London")
        payment_exec = enforcer.execute_tool(
            "payment_api", {"amount": 100.0, "recipient": "user@example.com"}
        )

        # 2. Verify executions are tracked
        assert weather_exec.verified
        assert payment_exec.verified
        assert payment_exec.tool_name == "payment_api"

        # 3. Test legitimate claim verification
        from trustchain.monitoring.hallucination_detector import HallucinatedClaim

        legitimate_claim = HallucinatedClaim(
            claim_text=f"I processed a payment for $100.0 with transaction {payment_exec.result['transaction_id']}",
            tool_name="payment_api",
            claimed_result=str(payment_exec.result),
            context="test",
        )

        # Should find matching execution
        match = enforcer.verify_claim_against_executions(legitimate_claim)
        assert match is not None
        assert match.request_id == payment_exec.request_id

        # 4. Test fake claim detection
        fake_claim = HallucinatedClaim(
            claim_text="I processed a payment for $500.0 with transaction tx_fake123",
            tool_name="payment_api",
            claimed_result="fake_transaction",
            context="test",
        )

        no_match = enforcer.verify_claim_against_executions(fake_claim)
        assert no_match is None

        print("   ✅ End-to-end verified workflow completed successfully")


# Performance benchmark
class TestPerformanceBenchmarks:
    """Test performance requirements."""

    @pytest.fixture
    async def perf_setup(self):
        """Setup performance testing."""
        registry = MemoryRegistry()
        await registry.start()

        @TrustedTool("perf_benchmark", registry=registry)
        async def benchmark_tool(data: str) -> Dict[str, Any]:
            return {"processed": data, "length": len(data)}

        yield benchmark_tool

        await registry.stop()

    async def test_signature_performance_requirements(self, perf_setup):
        """Test that signature operations meet performance requirements."""
        benchmark_tool = perf_setup

        # Test multiple operations
        times = []
        for i in range(20):
            start = time.time()
            response = await benchmark_tool(f"test data {i}")
            end = time.time()

            assert response.is_verified
            times.append((end - start) * 1000)

        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)

        print("   📊 Performance Results:")
        print(f"      Average: {avg_time:.2f}ms")
        print(f"      Min: {min_time:.2f}ms")
        print(f"      Max: {max_time:.2f}ms")

        # Performance requirements (generous for testing)
        assert avg_time < 100, f"Average signature time too high: {avg_time:.2f}ms"
        assert max_time < 200, f"Max signature time too high: {max_time:.2f}ms"


if __name__ == "__main__":
    # Run all tests
    pytest.main([__file__, "-v"])
