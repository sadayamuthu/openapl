# sdk/src/openapl/approvals.py
"""Bound approval claims (design §4.3): canonical attribute hashing and claim parsing."""
import hashlib
import json

from openapl.model import Approval

_STR_FIELDS = (
    "entitlement_id", "approver", "action", "resource", "attributes_hash", "origin", "caller",
)


def attributes_hash(attributes: dict) -> str:
    canonical = json.dumps(attributes, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def approval_from_claim(item: dict) -> Approval:
    if not isinstance(item, dict):
        raise ValueError("approval claim item is not an object")
    for name in (*_STR_FIELDS, "exp"):
        if name not in item:
            raise ValueError(f"approval claim missing field {name!r}")
    for name in _STR_FIELDS:
        if not isinstance(item[name], str):
            raise ValueError(f"approval claim field {name!r} is not a string")
    exp = item["exp"]
    if isinstance(exp, bool) or not isinstance(exp, int):
        raise ValueError("approval claim field 'exp' is not an integer")
    return Approval(**{name: item[name] for name in _STR_FIELDS}, exp=exp)
