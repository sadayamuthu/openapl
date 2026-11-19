# sidecar/tests/test_mcp.py
import json

import pytest

from openapl_sidecar.mcp import McpCall, McpParseError, tool_calls

PASS = frozenset({"initialize", "ping", "tools/list"})


def msg(method, **kw):
    return {"jsonrpc": "2.0", "id": 1, "method": method, **kw}


def enc(x):
    return json.dumps(x).encode()


def test_single_tools_call():
    body = enc(msg("tools/call", params={"name": "refund_order", "arguments": {"a": 1}}))
    assert tool_calls(body, PASS) == (McpCall("refund_order", {"a": 1}),)


def test_absent_arguments_is_empty():
    assert tool_calls(enc(msg("tools/call", params={"name": "x"})), PASS) == (McpCall("x", {}),)


def test_passthrough_only_batch_is_empty():
    body = enc([msg("initialize"), {"jsonrpc": "2.0", "method": "notifications/initialized"},
                msg("tools/list"), {"jsonrpc": "2.0", "id": 2, "result": {}}])
    assert tool_calls(body, PASS) == ()


def test_mixed_batch_returns_only_calls():
    body = enc([msg("tools/list"), msg("tools/call", params={"name": "a"}),
                msg("tools/call", params={"name": "b", "arguments": {"k": "v"}})])
    assert tool_calls(body, PASS) == (McpCall("a", {}), McpCall("b", {"k": "v"}))


@pytest.mark.parametrize("body", [
    b"", b"[]", b"{", b"\xff", b"5", b"[1]", b'{"method":"resources/read"}',
    b'{"method":"tools/call","params":{}}',
    b'{"method":"tools/call","params":{"name":"x","arguments":[]}}',
    b'{"method":"tools/call","params":{"name":""}}',
    b'{"id":1}',
])
def test_parse_errors(body):
    with pytest.raises(McpParseError):
        tool_calls(body, PASS)


def test_duplicate_method_rejected():
    body = (b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"},'
            b'"method":"ping"}')
    with pytest.raises(McpParseError, match="duplicate"):
        tool_calls(body, PASS)


def test_duplicate_key_inside_arguments_rejected():
    body = (b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            b'"params":{"name":"x","arguments":{"a":1,"a":2}}}')
    with pytest.raises(McpParseError, match="duplicate"):
        tool_calls(body, PASS)
