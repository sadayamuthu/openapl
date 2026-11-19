# demo/agentgateway/mcp_client.py
"""Minimal MCP streamable-HTTP client for the demo (JSON or SSE responses)."""
import json
import urllib.error
import urllib.request


def _parse(body: bytes, ctype: str):
    text = body.decode("utf-8", "replace")
    if not text.strip():
        return None
    if "text/event-stream" in ctype:
        out = None
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    out = json.loads(line[5:].strip())
                except ValueError:
                    pass
        return out
    try:
        return json.loads(text)
    except ValueError:
        return None


class McpClient:
    def __init__(self, base_url: str, token: str | None):
        self.url = base_url.rstrip("/") + "/mcp" if not base_url.rstrip("/").endswith("/mcp") else base_url
        self.token = token
        self.session: str | None = None
        self._id = 0

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.session:
            h["Mcp-Session-Id"] = self.session
        return h

    def _post(self, data: bytes) -> tuple[int, bytes, dict[str, str]]:
        req = urllib.request.Request(self.url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read(), {k.lower(): v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            return e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}

    def post_raw(self, payload: bytes | dict | list) -> tuple[int, bytes]:
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        status, body, _ = self._post(data)
        return status, body

    def initialize(self) -> int:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "demo-client", "version": "0"}}}
        status, _, hdrs = self._post(json.dumps(msg).encode())
        if status != 200:
            return status
        self.session = hdrs.get("mcp-session-id")
        self._post(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode())
        return status

    def request(self, method: str, params: dict | None = None) -> tuple[int, dict | None, dict[str, str]]:
        self._id += 1
        msg: dict = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        status, body, hdrs = self._post(json.dumps(msg).encode())
        parsed = _parse(body, hdrs.get("content-type", ""))
        res = None
        if isinstance(parsed, dict):
            res = parsed.get("result", parsed.get("error", parsed))
        return status, res, hdrs

    def call(self, name: str, arguments: dict) -> tuple[int, dict | None, dict[str, str]]:
        return self.request("tools/call", {"name": name, "arguments": arguments})
