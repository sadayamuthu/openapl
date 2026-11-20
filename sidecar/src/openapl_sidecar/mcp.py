# sidecar/src/openapl_sidecar/mcp.py
from dataclasses import dataclass

from openapl_sidecar.jsonstrict import loads_strict


class McpParseError(ValueError):
    pass


@dataclass(frozen=True)
class McpCall:
    wire_name: str
    arguments: dict


def tool_calls(body: bytes, passthrough: frozenset[str]) -> tuple[McpCall, ...]:
    try:
        doc = loads_strict(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise McpParseError(f"body is not valid UTF-8 JSON: {e}") from None
    except RecursionError:
        raise McpParseError("body is nested too deeply") from None
    if isinstance(doc, dict):
        messages = [doc]
    elif isinstance(doc, list) and doc:
        messages = doc
    else:
        raise McpParseError("body must be a JSON-RPC object or a non-empty array")
    calls: list[McpCall] = []
    for m in messages:
        if not isinstance(m, dict):
            raise McpParseError("JSON-RPC message is not an object")
        method = m.get("method")
        if method is None:
            if "id" in m and ("result" in m or "error" in m):
                continue
            raise McpParseError("message has no method")
        if not isinstance(method, str):
            raise McpParseError("method is not a string")
        if method == "tools/call":
            params = m.get("params")
            if not isinstance(params, dict):
                raise McpParseError("tools/call params must be an object")
            name = params.get("name")
            if not isinstance(name, str) or not name:
                raise McpParseError("tools/call params.name must be a non-empty string")
            args = params.get("arguments", {})
            if not isinstance(args, dict):
                raise McpParseError("tools/call params.arguments must be an object")
            calls.append(McpCall(name, args))
        elif method in passthrough or method.startswith("notifications/"):
            continue
        else:
            raise McpParseError(f"method '{method}' not allowed")
    return tuple(calls)
