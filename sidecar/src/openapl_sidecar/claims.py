# sidecar/src/openapl_sidecar/claims.py
from google.protobuf.struct_pb2 import ListValue, Struct, Value


def _value(v: Value):
    kind = v.WhichOneof("kind")
    if kind == "number_value":
        n = v.number_value
        return int(n) if n == n and n not in (float("inf"), float("-inf")) and n == int(n) else n
    if kind == "string_value":
        return v.string_value
    if kind == "bool_value":
        return v.bool_value
    if kind == "struct_value":
        return struct_to_dict(v.struct_value)
    if kind == "list_value":
        return _list(v.list_value)
    return None


def _list(lv: ListValue) -> list:
    return [_value(v) for v in lv.values]


def struct_to_dict(s: Struct) -> dict:
    """Struct -> dict, undoing protobuf's float-only numbers (integral floats become int)."""
    return {k: _value(v) for k, v in s.fields.items()}


def claims_from_check(req, namespace: str, field: str | None) -> dict | None:
    fm = req.attributes.metadata_context.filter_metadata
    if namespace not in fm:
        return None
    ns = fm[namespace]
    if field is None:
        return struct_to_dict(ns)
    if field not in ns.fields:
        return None
    v = ns.fields[field]
    if v.WhichOneof("kind") != "struct_value":
        return None
    return struct_to_dict(v.struct_value)
