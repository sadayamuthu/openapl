# demo/agentgateway/mcp_client.py
"""Minimal MCP streamable-HTTP client for the demo (JSON or SSE responses)."""
import http.client
import json
import urllib.error
import urllib.request


def _sse_events(text: str) -> list[str]:
    """Split an SSE stream into events; join consecutive data: lines of one event."""
    events: list[str] = []
    cur: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            if cur:
                events.append("\n".join(cur))
                cur = []
        elif line.startswith("data:"):
            cur.append(line[5:].lstrip(" "))
    if cur:
        events.append("\n".join(cur))
    return events


def _parse(body: bytes, ctype: str, want_id=None):
    """Parse a JSON or SSE body; for SSE return the message whose id matches want_id."""
    text = body.decode("utf-8", "replace")
    if not text.strip():
        return None
    if "text/event-stream" in ctype:
        msgs = []
        for ev in _sse_events(text):
            try:
                msgs.append(json.loads(ev))
            except ValueError:
                pass
        for m in msgs:
            if isinstance(m, dict) and want_id is not None and m.get("id") == want_id:
                return m
        if want_id is not None:
            return None
        return msgs[-1] if msgs else None
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
        except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException) as e:
            # transport failure: status 0 with a clear error, never an exception
            return 0, f"transport error: {e}".encode(), {"x-transport-error": "1"}

    def post_raw(self, payload: bytes | dict | list) -> tuple[int, bytes]:
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        status, body, _ = self._post(data)
        return status, body

    def initialize(self) -> int:
        """Returns 200 on success; otherwise the failing status (0 = transport error, 599 = protocol error)."""
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "demo-client", "version": "0"}}}
        status, _, hdrs = self._post(json.dumps(msg).encode())
        if status != 200:
            return status
        self.session = hdrs.get("mcp-session-id")
        if not self.session:
            return 599  # 200 without Mcp-Session-Id is an error
        st, _, _ = self._post(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode())
        if not 200 <= st < 300:
            return st or 599
        return status

    def request(self, method: str, params: dict | None = None) -> tuple[int, dict | None, dict[str, str]]:
        self._id += 1
        msg: dict = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        status, body, hdrs = self._post(json.dumps(msg).encode())
        parsed = _parse(body, hdrs.get("content-type", ""), self._id)
        res = None
        if status == 0:
            return 0, {"error": body.decode()}, hdrs
        if isinstance(parsed, dict):
            res = parsed.get("result", parsed.get("error", parsed))
        return status, res, hdrs

    def call(self, name: str, arguments: dict) -> tuple[int, dict | None, dict[str, str]]:
        return self.request("tools/call", {"name": name, "arguments": arguments})
