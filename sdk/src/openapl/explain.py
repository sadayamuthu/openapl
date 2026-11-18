# sdk/src/openapl/explain.py
"""explain and inventory: what could a principal cause if it were hijacked."""
from dataclasses import dataclass

from openapl.match import match_action
from openapl.model import Edge, Entitlement, PolicySet, Principal


@dataclass(frozen=True)
class Reach:
    action: str
    resource: str
    via: tuple[str, ...]
    entitlement_id: str


@dataclass(frozen=True)
class Explanation:
    principal: Principal
    entitlements: tuple[Entitlement, ...]
    acts_for: tuple[Edge, ...]
    delegates_to: tuple[Edge, ...]
    delegated_from: tuple[tuple[str, Edge], ...]
    reach: tuple[Reach, ...]


def _grants_for(ps: PolicySet, pid: str) -> tuple[Entitlement, ...]:
    return tuple(e for e in ps.entitlements
                 if not e.deny and (pid in e.grant_to or "*" in e.grant_to))


def _covers(edge_actions: tuple[str, ...], grant_action: str) -> bool:
    return any(a == grant_action or match_action(a, grant_action) for a in edge_actions)


def explain(ps: PolicySet, principal_id: str, on_behalf_of: str | None = None) -> Explanation:
    principal = ps.principals[principal_id]  # KeyError for unknown ids
    delegated_from = tuple(sorted(
        ((pid, edge) for pid, p in ps.principals.items() for edge in p.may_delegate
         if edge.to == principal_id),
        key=lambda t: t[0]))

    # Hops are (edges so far); the first-hop filter for on_behalf_of is a list of allowed actions.
    allowed: tuple[str, ...] | None = None
    if on_behalf_of is not None:
        granted = [e for e in ps.entitlements if not e.deny and on_behalf_of in e.grant_to]
        allowed_set: list[str] = []
        for entry in principal.acts_for:
            if entry.who != on_behalf_of:
                continue
            for a in entry.actions:
                if any(_covers((a,), g.action) for g in granted) and a not in allowed_set:
                    allowed_set.append(a)
        allowed = tuple(allowed_set)

    reach: list[Reach] = []

    def keep(e: Entitlement, edges: list[Edge]) -> bool:
        if allowed is not None and not _covers(allowed, e.action):
            return False
        return all(_covers(edge.actions, e.action) for edge in edges)

    def walk(pid: str, path: tuple[str, ...], edges: list[Edge]) -> None:
        for e in _grants_for(ps, pid):
            if keep(e, edges):
                reach.append(Reach(e.action, e.resource, path, e.id))
        if len(edges) >= ps.max_depth:
            return
        node = ps.principals.get(pid)
        if node is None:
            return
        for edge in node.may_delegate:
            if edge.to is None or edge.to in path:  # cycle guard
                continue
            walk(edge.to, path + (edge.to,), edges + [edge])

    if allowed is None or allowed:
        walk(principal_id, (principal_id,), [])
    reach_sorted = tuple(sorted(set(reach), key=lambda r: (r.via, r.entitlement_id)))
    return Explanation(
        principal=principal,
        entitlements=_grants_for(ps, principal_id),
        acts_for=principal.acts_for,
        delegates_to=principal.may_delegate,
        delegated_from=delegated_from,
        reach=reach_sorted,
    )


def _edge_dict(edge: Edge) -> dict:
    d: dict = {"actions": list(edge.actions)}
    if edge.to is not None:
        d["to"] = edge.to
    if edge.who is not None:
        d["who"] = edge.who
    return d


def inventory(ps: PolicySet) -> list[dict]:
    rows = []
    for pid in sorted(ps.principals):
        p = ps.principals[pid]
        rows.append({
            "id": p.id,
            "kind": p.kind,
            "owner": p.owner,
            "identity": p.identity,
            "acts_for": [_edge_dict(e) for e in p.acts_for],
            "may_delegate": [_edge_dict(e) for e in p.may_delegate],
            "entitlements": [e.id for e in _grants_for(ps, pid)],
            "source_file": p.source_file,
        })
    return rows
