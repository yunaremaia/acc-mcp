"""Upstream transports for MCP JSON-RPC servers."""

from __future__ import annotations

import json
import shlex
import subprocess
from abc import ABC, abstractmethod
from typing import Any

import httpx


class MCPTransport(ABC):
    """Minimal request/notification interface used by the proxy."""

    @abstractmethod
    def request(self, message: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def notify(self, message: dict[str, Any]) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


class StdioTransport(MCPTransport):
    """Communicate with an MCP server using newline-delimited JSON on stdio."""

    def __init__(self, command: str | list[str]):
        args = shlex.split(command) if isinstance(command, str) else command
        self.process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
        )

    def _send(self, message: dict[str, Any]) -> None:
        if self.process.stdin is None:
            raise RuntimeError("MCP server stdin is unavailable")
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def request(self, message: dict[str, Any]) -> dict[str, Any]:
        self._send(message)
        if self.process.stdout is None:
            raise RuntimeError("MCP server stdout is unavailable")
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("MCP server exited before returning a response")
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                continue
            if response.get("id") == message.get("id"):
                return response

    def notify(self, message: dict[str, Any]) -> None:
        self._send(message)

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)


class StreamableHTTPTransport(MCPTransport):
    """Communicate with an MCP server over the MCP Streamable HTTP endpoint."""

    def __init__(self, url: str, timeout: float = 30.0):
        self.client = httpx.Client(timeout=timeout)
        self.url = url
        self.session_id: str | None = None

    def _post(self, message: dict[str, Any]) -> dict[str, Any] | None:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        response = self.client.post(self.url, json=message, headers=headers)
        response.raise_for_status()
        if session_id := response.headers.get("Mcp-Session-Id"):
            self.session_id = session_id
        if response.status_code == 202 or not response.content:
            return None
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    return json.loads(line[5:].strip())
            raise RuntimeError("MCP HTTP response contained no SSE data")
        return response.json()

    def request(self, message: dict[str, Any]) -> dict[str, Any]:
        response = self._post(message)
        if response is None:
            raise RuntimeError("MCP server returned no response to a request")
        return response

    def notify(self, message: dict[str, Any]) -> None:
        self._post(message)

    def close(self) -> None:
        self.client.close()
