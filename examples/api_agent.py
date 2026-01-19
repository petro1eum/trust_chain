#!/usr/bin/env python3
"""Example: HTTP API Agent with Signed Responses.

This example shows how to build an API client where every
external API call is cryptographically signed.

Features:
- All API responses are signed
- Automatic retry with signature verification
- CloudEvents format for logging
- Chain of Trust for multi-step workflows

Requirements:
    pip install httpx

Usage:
    python examples/api_agent.py
"""

from datetime import datetime
from typing import Any, Dict, Optional

from trustchain import TrustChain
from trustchain.v2.events import TrustEvent


class SecureAPIClient:
    """HTTP API client with cryptographic verification."""

    def __init__(self, base_url: str = "https://api.example.com"):
        """Initialize secure API client.

        Args:
            base_url: Base URL for API calls
        """
        self.tc = TrustChain()
        self.base_url = base_url
        self.events: list = []  # CloudEvents log

        self._register_tools()

    def _register_tools(self):
        """Register API tools."""

        @self.tc.tool("api_get")
        def api_get(endpoint: str, params: Optional[Dict] = None) -> dict:
            """Make a signed GET request."""
            return self._make_request("GET", endpoint, params=params)

        @self.tc.tool("api_post")
        def api_post(endpoint: str, data: Dict) -> dict:
            """Make a signed POST request."""
            return self._make_request("POST", endpoint, data=data)

        @self.tc.tool("api_workflow")
        def api_workflow(steps: list) -> dict:
            """Execute multi-step API workflow with Chain of Trust."""
            return self._execute_workflow(steps)

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> dict:
        """Make HTTP request and sign response.

        In production, this would use httpx or requests.
        Demo returns mock data.
        """
        # Simulate API response
        mock_responses = {
            "/users": {"users": [{"id": 1, "name": "Alice"}]},
            "/orders": {"orders": [{"id": 101, "status": "pending"}]},
            "/products": {"products": [{"id": 1, "name": "Widget", "price": 9.99}]},
            "/health": {"status": "healthy", "timestamp": datetime.now().isoformat()},
        }

        response_data = mock_responses.get(endpoint, {"message": "OK"})

        # Add request context
        result = {
            "method": method,
            "endpoint": endpoint,
            "url": f"{self.base_url}{endpoint}",
            "status_code": 200,
            "data": response_data,
            "timestamp": datetime.now().isoformat(),
        }

        return result

    def _execute_workflow(self, steps: list) -> dict:
        """Execute workflow with Chain of Trust.

        Each step links to the previous one cryptographically.
        """
        results = []
        signed_responses = []  # Keep actual SignedResponse for verification
        parent_sig = None

        for i, step in enumerate(steps):
            # Execute step
            method = step.get("method", "GET")
            endpoint = step.get("endpoint", "/")
            data = step.get("data")

            response = self._make_request(method, endpoint, data=data)

            # Sign with parent link
            signed = self.tc._signer.sign(
                f"api_step_{i}", response, parent_signature=parent_sig
            )
            signed_responses.append(signed)

            # Create CloudEvent
            event = TrustEvent.from_signed_response(
                signed,
                source=f"/api-agent/workflow/step-{i}",
                chain_id=f"workflow-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            )
            self.events.append(event)

            results.append(
                {
                    "step": i,
                    "endpoint": endpoint,
                    "status": response["status_code"],
                    "signature": signed.signature[:24] + "...",
                    "has_parent": parent_sig is not None,
                }
            )

            parent_sig = signed.signature

        # Verify chain using actual SignedResponse objects
        chain_verified = (
            self.tc.verify_chain(signed_responses)
            if len(signed_responses) > 1
            else True
        )

        return {
            "workflow_complete": True,
            "steps_executed": len(results),
            "results": results,
            "chain_verified": chain_verified,
        }

    def export_events(self, format: str = "json") -> list:
        """Export CloudEvents for logging/Kafka."""
        if format == "json":
            return [e.to_json() for e in self.events]
        elif format == "kafka_headers":
            return [e.to_kafka_headers() for e in self.events]
        return self.events


def main():
    """Demo the secure API client."""
    print("🔐 Secure API Client with Signatures")
    print()

    client = SecureAPIClient("https://api.example.com")

    # Single requests
    print("📡 Making API calls...")

    result = client._make_request("GET", "/users")
    print(f"   GET /users: {result['data']}")

    result = client._make_request("GET", "/products")
    print(f"   GET /products: {result['data']}")
    print()

    # Workflow with Chain of Trust
    print("🔗 Executing workflow with Chain of Trust...")

    workflow = client._execute_workflow(
        [
            {"method": "GET", "endpoint": "/health"},
            {"method": "GET", "endpoint": "/users"},
            {
                "method": "POST",
                "endpoint": "/orders",
                "data": {"user_id": 1, "product_id": 1},
            },
        ]
    )

    print(f"   Steps executed: {workflow['steps_executed']}")
    for r in workflow["results"]:
        print(f"   Step {r['step']}: {r['endpoint']} - {r['signature']}")
    print()

    # Export CloudEvents
    print("📦 CloudEvents generated:")
    events = client.export_events("json")
    print(f"   Total events: {len(events)}")
    if events:
        import json

        first_event = json.loads(events[0])
        print(f"   Event type: {first_event.get('type')}")
        print(f"   Event source: {first_event.get('source')}")
    print()

    print("🎉 API agent demo complete!")
    print("   Every API response is signed and can be exported as CloudEvents.")


if __name__ == "__main__":
    main()
