# demo/agentgateway/tests/test_mcp_client.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp_client import McpClient, _parse  # noqa: E402


def test_sse_multiline_data_and_id_match():
    body = (b'event: message\ndata: {"jsonrpc":"2.0","id":9,"result":{"x":1}}\n\n'
            b'event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":5,\ndata: "result":{"ok":true}}\n\n'
            b'data: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n')
    assert _parse(body, "text/event-stream", 5)["result"] == {"ok": True}
    assert _parse(body, "text/event-stream", 7) is None


def test_transport_error_is_status_zero():
    c = McpClient("http://127.0.0.1:1/mcp", None)
    assert c.initialize() == 0
    st, res, _ = c.request("tools/list")
    assert st == 0 and "transport error" in res["error"]
    assert c.post_raw({"a": 1})[0] == 0
