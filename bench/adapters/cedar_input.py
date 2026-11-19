# bench/adapters/cedar_input.py
"""OpenAPL case request -> Cedar request (principal, action, resource, context, entities).

Cedar has no ordered lists, no iteration, no string concatenation and no hash function, so
some values are computed here, outside the engine. Each one is listed in every translation's
README; a scenario whose decision depends on one of them is graded `workaround`.

Request shaping (no OpenAPL semantics):
  principal       the caller (last link): Agent::"<id>" or User::"<id>"
  resource        Resource::"<resource>" with attribute `path` (for `like`)
  context.origin  the origin human as a User entity, whose groups and roles claims become
                  Group/Role parents (a single-string claim becomes one parent)
  context.origin_agent  the origin when it is not human
  context.agents  the set of agent/service links (unordered)
  context.now, purpose, task_id, iat, attributes, active_owners (directory snapshot)

Precomputed (OpenAPL semantics Cedar cannot compute from the request):
  context.first_agent      the link after a human origin (position 1 of the ordered chain)
  context.hops             consecutive agent->agent pairs "prev>cur" (the chain's order)
  context.depth            len(chain) - 1 (Cedar sets have no size)
  context.attributes_hash  SHA-256 of the canonical attributes JSON (no hash in Cedar)
  approvals[].expired      exp < now, replacing exp (Cedar has no existential over a set,
                           so the policy matches a whole item record with `contains`)
  context.derived.<k>      string templates over attributes from the scenario's
                           cedar/derived.json (no string concatenation in Cedar)
"""
from dataclasses import dataclass, field

from common import Case
from openapl.approvals import attributes_hash


@dataclass(frozen=True)
class CedarRequest:
    principal: str
    action: str
    resource: str
    context: dict
    entities: list[dict] = field(default_factory=list)

    def request_json(self) -> dict:
        return {"principal": self.principal, "action": self.action,
                "resource": self.resource, "context": self.context}


def _etype(link_id: str, kind: str | None = None) -> str:
    if kind is not None:
        return "User" if kind == "human" else "Agent"
    return "User" if link_id.startswith("user:") else "Agent"


def _ref(link_id: str, kind: str | None = None) -> dict:
    return {"__entity": {"type": _etype(link_id, kind), "id": link_id}}


def _uid(link_id: str, kind: str | None = None) -> str:
    return f'{_etype(link_id, kind)}::"{link_id}"'


def _as_list(claim) -> list[str]:
    if isinstance(claim, str):
        return [claim]
    if isinstance(claim, list):
        return [c for c in claim if isinstance(c, str)]
    return []


def _user_entity(link: dict) -> dict:
    claims = link.get("claims") or {}
    parents = [{"type": "Group", "id": g} for g in _as_list(claims.get("groups"))]
    parents += [{"type": "Role", "id": r} for r in _as_list(claims.get("roles"))]
    return {"uid": {"type": "User", "id": link["id"]}, "attrs": {}, "parents": parents}


def _derive(templates: dict[str, str], attributes: dict) -> dict:
    out = {}
    for key, template in templates.items():
        try:
            out[key] = template.format(**{k: str(v) for k, v in attributes.items()})
        except KeyError:
            continue  # a referenced attribute is absent: the derived value is absent
    return out


def to_cedar(case: Case, derived: dict[str, str] | None = None) -> CedarRequest:
    req = case.request
    chain = req["chain"]
    human = [link["kind"] == "human" for link in chain]
    attributes = dict(req.get("attributes") or {})
    now = req.get("now", 0)
    context: dict = {
        "agents": [_ref(link["id"], link["kind"]) for link in chain if link["kind"] != "human"],
        "hops": [f'{chain[i - 1]["id"]}>{chain[i]["id"]}'
                 for i in range(1, len(chain)) if not human[i - 1]],
        "depth": len(chain) - 1,
        "now": now,
        "attributes": attributes,
        "attributes_hash": attributes_hash(attributes),
        "approvals": [
            {"entitlement_id": a["entitlement_id"], "approver": a["approver"],
             "action": a["action"], "resource": a["resource"],
             "attributes_hash": a["attributes_hash"],
             "origin": _ref(a["origin"]), "caller": _ref(a["caller"]),
             "expired": a["exp"] < now}
            for a in req.get("approvals") or ()
        ],
    }
    if human[0]:
        context["origin"] = _ref(chain[0]["id"], "human")
        if len(chain) > 1:
            context["first_agent"] = _ref(chain[1]["id"], chain[1]["kind"])
    else:
        context["origin_agent"] = _ref(chain[0]["id"], chain[0]["kind"])
    for key in ("purpose", "task_id", "iat"):
        if req.get(key) is not None:
            context[key] = req[key]
    if req.get("directory") is not None:
        context["active_owners"] = list(req["directory"].get("active") or ())
    if derived:
        context["derived"] = _derive(derived, attributes)
    entities = [_user_entity(link) for link in chain if link["kind"] == "human"]
    entities.append({"uid": {"type": "Resource", "id": req["resource"]},
                     "attrs": {"path": req["resource"]}, "parents": []})
    return CedarRequest(
        principal=_uid(chain[-1]["id"], chain[-1]["kind"]),
        action=f'Action::"{req["action"]}"',
        resource=f'Resource::"{req["resource"]}"',
        context=context,
        entities=entities,
    )
