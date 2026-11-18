# sdk/src/openapl/chain.py
"""Build a delegation chain and a Request from gateway-verified JWT claims (RFC 8693)."""
from openapl.approvals import approval_from_claim
from openapl.model import Link, PolicySet, Request

MAX_ACT_DEPTH = 32


class ChainError(ValueError):
    pass


def _matches(identity: dict, act: dict) -> bool:
    sub = act["sub"]
    for key in ("spiffe", "oauth_client_id", "entra_app_id"):
        if identity.get(key) is not None and identity[key] == sub:
            return True
    jwt = identity.get("jwt")
    if isinstance(jwt, dict) and jwt.get("iss") is not None and jwt.get("sub") is not None:
        return jwt["iss"] == act.get("iss") and jwt["sub"] == sub
    return False


def _resolve(act: dict, ps: PolicySet) -> Link:
    found = [pid for pid, p in ps.principals.items() if isinstance(p.identity, dict) and _matches(p.identity, act)]
    # Zero or ambiguous matches both fail closed as an unknown principal.
    if len(found) == 1:
        return Link(found[0], ps.principals[found[0]].kind, {})
    return Link(f"unknown:{act['sub']}", "agent", {})


def chain_from_claims(claims: dict, ps: PolicySet) -> tuple[Link, ...]:
    if not isinstance(claims, dict):
        raise ChainError("claims is not an object")
    ident = claims.get("email") or claims.get("sub")
    if not ident or not isinstance(ident, str):
        raise ChainError("claims have neither email nor sub")
    origin = Link("user:" + ident, "human", {k: v for k, v in claims.items() if k != "act"})
    actors: list[dict] = []  # outermost (current caller) first
    node = claims.get("act")
    while node is not None:
        if not isinstance(node, dict):
            raise ChainError("act is not an object")
        if len(actors) >= MAX_ACT_DEPTH:
            raise ChainError(f"act nesting deeper than {MAX_ACT_DEPTH}")
        sub = node.get("sub")
        if not sub or not isinstance(sub, str):
            raise ChainError("actor has no sub")
        actors.append(node)
        node = node.get("act")
    return (origin, *(_resolve(a, ps) for a in reversed(actors)))


def chain_from_list(ids: list[str], ps: PolicySet, origin_claims: dict | None = None) -> tuple[Link, ...]:
    """Dev mode only: build a chain from explicit ids."""
    if not ids or not isinstance(ids[0], str) or not ids[0].startswith("user:"):
        raise ChainError("first chain entry must be user:<id>")
    links = [Link(ids[0], "human", dict(origin_claims or {}))]
    for pid in ids[1:]:
        p = ps.principals.get(pid)
        links.append(Link(pid, p.kind, {}) if p else Link(f"unknown:{pid}", "agent", {}))
    return tuple(links)


def request_from_claims(claims: dict, ps: PolicySet, action: str, resource: str,
                        attributes: dict, now: int) -> Request:
    c = claims if isinstance(claims, dict) else {}
    try:
        raw = c.get("openapl_approvals", [])
        if not isinstance(raw, list):
            raise ChainError("openapl_approvals is not a list")
        approvals = tuple(approval_from_claim(i) for i in raw)
        chain = chain_from_claims(claims, ps)
    except (ChainError, ValueError):
        chain, approvals = (), ()
    iat = c.get("iat")
    purpose, task_id = c.get("openapl_purpose"), c.get("openapl_task_id")
    return Request(
        chain=chain, action=action, resource=resource, attributes=attributes,
        purpose=purpose if isinstance(purpose, str) else None,
        task_id=task_id if isinstance(task_id, str) else None,
        token_iat=iat if isinstance(iat, int) and not isinstance(iat, bool) else None,
        now=now, approvals=approvals,
    )
