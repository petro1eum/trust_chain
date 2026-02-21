"""OnaiDocs integration bridge for TrustChain OSS.

Provides a lightweight Python client for parity checks against
OnaiDocs MCP TrustChain endpoints.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Any


def _http_json(
    url: str, method: str = "GET", payload: dict | None = None
) -> dict[str, Any]:
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("URL must use http or https scheme")
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


@dataclass
class OnaiDocsTrustClient:
    base_url: str = "http://localhost:9323"

    def verify_response(
        self, tool_name: str, arguments: dict[str, Any], trustchain: dict[str, Any]
    ) -> dict[str, Any]:
        return _http_json(
            f"{self.base_url.rstrip('/')}/api/trustchain/verify-response",
            method="POST",
            payload={
                "name": tool_name,
                "arguments": arguments,
                "trustchain": trustchain,
            },
        )

    def export_session(
        self, session_id: str, fmt: str = "json", limit: int = 500
    ) -> Any:
        url = f"{self.base_url.rstrip('/')}/api/trustchain/session/{session_id}/export?format={fmt}&limit={limit}"
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError("URL must use http or https scheme")
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            text = resp.read().decode("utf-8")
            if fmt.lower() == "html":
                return text
            return json.loads(text)

    def get_events(
        self, limit: int = 100, session_id: str | None = None
    ) -> dict[str, Any]:
        extra = f"&session_id={session_id}" if session_id else ""
        return _http_json(
            f"{self.base_url.rstrip('/')}/api/trustchain/events?limit={limit}{extra}"
        )
