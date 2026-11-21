# bench/adapters/rego_input.py
"""OpenAPL case request -> OPA `input` document.

Nothing is precomputed: the chain is passed as the ordered list of {id, kind, claims} links,
claims verbatim, and every other request field as given. Absent optional fields stay absent."""
from common import Case

_OPTIONAL = ("purpose", "task_id", "iat", "directory")
PRECOMPUTED: tuple[str, ...] = ()  # nothing is computed outside OPA


def to_rego(case: Case) -> dict:
    req = case.request
    doc = {
        "chain": [{"id": link["id"], "kind": link["kind"], "claims": dict(link.get("claims") or {})}
                  for link in req["chain"]],
        "action": req["action"],
        "resource": req["resource"],
        "attributes": dict(req.get("attributes") or {}),
        "now": req.get("now", 0),
        "approvals": [dict(a) for a in req.get("approvals") or ()],
    }
    for key in _OPTIONAL:
        if req.get(key) is not None:
            doc[key] = req[key]
    return doc
