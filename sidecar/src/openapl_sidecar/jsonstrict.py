# sidecar/src/openapl_sidecar/jsonstrict.py
"""Strict JSON parsing: reject NaN/Infinity, overflowing numbers and duplicate keys."""
import json
import math
from typing import Any


def _reject_constant(name: str):
    raise ValueError(f"invalid JSON constant {name}")


def _finite_float(text: str) -> float:
    v = float(text)
    if not math.isfinite(v):
        raise ValueError(f"number out of range: {text}")
    return v


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def loads_strict(data: str | bytes) -> Any:
    return json.loads(data, parse_constant=_reject_constant, parse_float=_finite_float,
                      object_pairs_hook=_no_duplicates)
