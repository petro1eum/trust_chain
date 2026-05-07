"""TrustChain MCP Proxy Integration.

This module acts as a Man-in-the-Middle proxy between an MCP client (e.g., Cursor, Claude Desktop)
and an MCP server. It intercepts JSON-RPC stdio traffic, cryptographically signs `tools/call`
responses, logs them to the TrustChain Verifiable Log, and injects the `_trustchain` receipt
into the JSON payload returned to the client.
"""

import asyncio
import json
import logging
import sys
from typing import Dict, List

from trustchain import TrustChain

logger = logging.getLogger(__name__)


class MCPProxy:
    """Zero-code integration proxy for standard MCP servers."""

    def __init__(self, tc: TrustChain, target_cmd: List[str]):
        """Initialize the MCP proxy.

        Args:
            tc: TrustChain instance for signing operations.
            target_cmd: The command and arguments to launch the target MCP server.
        """
        self.tc = tc
        self.target_cmd = target_cmd
        # Map of request ID -> tool name for pending tools/call requests
        self.pending_tool_calls: Dict[str, str] = {}

    async def _handle_client_to_server(self, proc: asyncio.subprocess.Process):
        """Read from stdin (Client) and forward to target process (Server)."""
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line = await reader.readline()
            if not line:
                break

            # Try to parse the JSON-RPC request to track tools/call
            try:
                line_str = line.decode("utf-8").strip()
                if line_str:
                    data = json.loads(line_str)
                    if data.get("method") == "tools/call":
                        req_id = data.get("id")
                        tool_name = data.get("params", {}).get("name", "unknown_tool")
                        if req_id is not None:
                            # Tracking by string to ensure matching works regardless of int/str
                            self.pending_tool_calls[str(req_id)] = tool_name
            except Exception as e:
                # If parsing fails, just forward it transparently
                logger.debug(f"Failed to parse client message: {e}")

            # Forward to target MCP server
            if proc.stdin:
                proc.stdin.write(line)
                await proc.stdin.drain()

    async def _handle_server_to_client(self, proc: asyncio.subprocess.Process):
        """Read from target process (Server) stdout and forward to client stdout."""
        if not proc.stdout:
            return

        while True:
            line = await proc.stdout.readline()
            if not line:
                break

            out_line = line
            try:
                line_str = line.decode("utf-8").strip()
                if line_str:
                    data = json.loads(line_str)
                    req_id = data.get("id")
                    str_req_id = str(req_id) if req_id is not None else None

                    # If this is a response to a tracked tools/call request
                    if str_req_id and str_req_id in self.pending_tool_calls:
                        tool_name = self.pending_tool_calls.pop(str_req_id)

                        # Extract the result content
                        result = data.get("result", {})
                        content = result.get("content", [])

                        # Sign the content. In MCP, content is a list of objects.
                        # We pass the entire content list to TrustChain for signing.
                        signed_response = self.tc.sign(tool_name, content)

                        receipt = {
                            "signature": signed_response.signature,
                            "signature_id": signed_response.signature_id,
                            "timestamp": signed_response.timestamp,
                            "nonce": signed_response.nonce,
                            "verified": True,
                        }

                        # Inject the receipt into the first TextContent block if possible
                        injected = False
                        if content and content[0].get("type") == "text":
                            text_val = content[0].get("text", "")
                            try:
                                # If the text is JSON, inject _trustchain cleanly
                                parsed_text = json.loads(text_val)
                                if isinstance(parsed_text, dict):
                                    parsed_text["_trustchain"] = receipt
                                    content[0]["text"] = json.dumps(parsed_text)
                                    injected = True
                            except json.JSONDecodeError:
                                pass

                        if not injected:
                            # If we couldn't inject cleanly into JSON, append a new block
                            content.append(
                                {
                                    "type": "text",
                                    "text": json.dumps({"_trustchain": receipt}),
                                }
                            )

                        # Serialize modified data back to line
                        modified_str = json.dumps(data, separators=(",", ":")) + "\n"
                        out_line = modified_str.encode("utf-8")

            except Exception as e:
                logger.debug(f"Failed to process server message: {e}")

            # Forward to client stdout
            sys.stdout.buffer.write(out_line)
            sys.stdout.buffer.flush()

    async def run(self):
        """Run the proxy indefinitely until the target server exits."""
        # Spawn target process
        proc = await asyncio.create_subprocess_exec(
            *self.target_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,  # Pass through stderr directly to the console
        )

        # Run stdio pipes concurrently
        tasks = [
            asyncio.create_task(self._handle_client_to_server(proc)),
            asyncio.create_task(self._handle_server_to_client(proc)),
        ]

        # Wait for either the process to exit or streams to close
        await proc.wait()
        for t in tasks:
            if not t.done():
                t.cancel()


def run_proxy(target_cmd: List[str]):
    """Entrypoint to run the MCP proxy synchronously.

    Args:
        target_cmd: The command list (e.g., ["npx", "-y", "@composio/mcp"])
    """
    if not target_cmd:
        raise ValueError("Target command cannot be empty.")

    tc = TrustChain()
    proxy = MCPProxy(tc, target_cmd)

    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        pass
