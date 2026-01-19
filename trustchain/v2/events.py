"""CloudEvents format for TrustChain.

CloudEvents is a standard for describing events in a common way.
This enables interoperability with Kafka, MCP, and other systems.

See: https://cloudevents.io/

Usage:
    from trustchain.v2.events import TrustEvent

    # Convert SignedResponse to CloudEvent
    event = TrustEvent.from_signed_response(response, source="/agent/bot")

    # Send to Kafka
    producer.send("ai.tool.responses", value=event.to_json())
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class TrustEvent:
    """CloudEvents-compatible event for TrustChain responses.

    Follows CloudEvents spec v1.0:
    https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md
    """

    # Required CloudEvents attributes
    specversion: str = "1.0"
    type: str = "ai.tool.response.v1"
    source: str = ""  # URI of the agent/tool
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Optional CloudEvents attributes
    time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    datacontenttype: str = "application/json"
    subject: Optional[str] = None  # Tool ID

    # Event data
    data: Dict[str, Any] = field(default_factory=dict)

    # TrustChain extensions (prefixed with 'trustchain')
    trustchain_signature: Optional[str] = None
    trustchain_key_id: Optional[str] = None
    trustchain_nonce: Optional[str] = None
    trustchain_chain_id: Optional[str] = None
    trustchain_parent_signature: Optional[str] = None

    @classmethod
    def from_signed_response(
        cls,
        response: "SignedResponse",
        source: str,
        chain_id: Optional[str] = None,
    ) -> "TrustEvent":
        """Create TrustEvent from SignedResponse.

        Args:
            response: The signed response to convert
            source: URI identifying the source (e.g., "/agent/my-bot/tool/weather")
            chain_id: Optional chain identifier for linked events
        """
        return cls(
            id=response.nonce or str(uuid.uuid4()),
            source=source,
            subject=response.tool_id,
            time=datetime.fromtimestamp(response.timestamp, timezone.utc).isoformat(),
            data={"result": response.data},
            trustchain_signature=response.signature,
            trustchain_nonce=response.nonce,
            trustchain_chain_id=chain_id,
            trustchain_parent_signature=response.parent_signature,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (CloudEvents JSON format)."""
        result = {
            "specversion": self.specversion,
            "type": self.type,
            "source": self.source,
            "id": self.id,
            "time": self.time,
            "datacontenttype": self.datacontenttype,
            "data": self.data,
        }

        if self.subject:
            result["subject"] = self.subject

        # Add TrustChain extensions
        if self.trustchain_signature:
            result["trustchainsignature"] = self.trustchain_signature
        if self.trustchain_key_id:
            result["trustchainkeyid"] = self.trustchain_key_id
        if self.trustchain_nonce:
            result["trustchainnonce"] = self.trustchain_nonce
        if self.trustchain_chain_id:
            result["trustchainchainid"] = self.trustchain_chain_id
        if self.trustchain_parent_signature:
            result["trustchainparentsignature"] = self.trustchain_parent_signature

        return result

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    def to_kafka_headers(self) -> list:
        """Generate Kafka headers for quick filtering.

        Returns:
            List of (key, value) tuples for Kafka headers
        """
        headers = [
            ("ce_specversion", b"1.0"),
            ("ce_type", self.type.encode()),
            ("ce_source", self.source.encode()),
            ("ce_id", self.id.encode()),
        ]

        if self.subject:
            headers.append(("ce_subject", self.subject.encode()))
        if self.trustchain_signature:
            headers.append(("trustchain_sig", self.trustchain_signature[:32].encode()))
        if self.trustchain_chain_id:
            headers.append(("trustchain_chain", self.trustchain_chain_id.encode()))

        return headers

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrustEvent":
        """Create TrustEvent from dictionary."""
        return cls(
            specversion=data.get("specversion", "1.0"),
            type=data.get("type", "ai.tool.response.v1"),
            source=data.get("source", ""),
            id=data.get("id", str(uuid.uuid4())),
            time=data.get("time", datetime.now(timezone.utc).isoformat()),
            datacontenttype=data.get("datacontenttype", "application/json"),
            subject=data.get("subject"),
            data=data.get("data", {}),
            trustchain_signature=data.get("trustchainsignature"),
            trustchain_key_id=data.get("trustchainkeyid"),
            trustchain_nonce=data.get("trustchainnonce"),
            trustchain_chain_id=data.get("trustchainchainid"),
            trustchain_parent_signature=data.get("trustchainparentsignature"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "TrustEvent":
        """Create TrustEvent from JSON string."""
        return cls.from_dict(json.loads(json_str))


# Type hint for SignedResponse (avoid circular import)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .signer import SignedResponse
