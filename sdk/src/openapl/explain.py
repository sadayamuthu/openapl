# sdk/src/openapl/explain.py
"""explain and inventory: what could a principal cause if it were hijacked."""
from dataclasses import dataclass

from openapl.match import actions_overlap
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
    return any(actions_overlap(a, grant_action) for a in edge_actions)


_HUMAN_PREFIXES = ("user:", "group:", "role:")
_GROUPISH = ("group:", "role:")


def _acts_for_may_apply(who: str | None, on_behalf_of: str) -> bool:
    """Could an acts_for entry for `who` cover a human described by `on_behalf_of`?"""
    if who is None:
        return False
    if who == on_behalf_of:
        return True
    if on_behalf_of.startswith("user:"):
        return who.startswith(_GROUPISH)  # the user may hold any group or role
    if on_behalf_of.startswith(_GROUPISH):
        return who.startswith("user:")  # any user may hold that group or role
    return False


def explain(ps: PolicySet, principal_id: str, on_behalf_of: str | None = None) -> Explanation:
    """Reach if hijacked. Conservative: may over-report, never under-reports.

    Plain explain allows max_depth agent hops; with on_behalf_of the acts_for hop
    counts, leaving max_depth - 1 agent hops. Actions are compared as glob overlap.
    """
    principal = ps.principals[principal_id]  # KeyError for unknown ids
    delegated_from = tuple(sorted(
        ((pid, edge) for pid, p in ps.principals.items() for edge in p.may_delegate
         if edge.to == principal_id),
        key=lambda t: t[0]))

    # R11: conservative. Over-reporting is allowed; under-reporting is not.
    depth = ps.max_depth
    acts_actions: tuple[str, ...] | None = None
    sel_actions: tuple[str, ...] = ()
    if on_behalf_of is not None:
        depth -= 1  # the acts_for hop counts toward max_depth
        # explain cannot know a human's memberships, so any acts_for entry or
        # human-selector grant that could also apply to that human counts.
        acts_actions = tuple(a for entry in principal.acts_for
                             if _acts_for_may_apply(entry.who, on_behalf_of)
                             for a in entry.actions)
        sel_actions = tuple(e.action for e in ps.entitlements
                            if not e.deny and any(s == "*" or s.startswith(_HUMAN_PREFIXES)
                                                  for s in e.grant_to))

    reach: list[Reach] = []

    def keep(e: Entitlement, edges: list[Edge]) -> bool:
        if acts_actions is not None and not (
                _covers(acts_actions, e.action) and _covers(sel_actions, e.action)):
            return False
        return all(_covers(edge.actions, e.action) for edge in edges)

    def walk(pid: str, path: tuple[str, ...], edges: list[Edge]) -> None:
        for e in _grants_for(ps, pid):
            if keep(e, edges):
                reach.append(Reach(e.action, e.resource, path, e.id))
        if len(edges) >= depth:
            return
        node = ps.principals.get(pid)
        if node is None:
            return
        for edge in node.may_delegate:
            if edge.to is None or edge.to in path:  # cycle guard
                continue
            walk(edge.to, path + (edge.to,), edges + [edge])

    if acts_actions is None or acts_actions:
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


def edge_dict(edge: Edge) -> dict:
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
            "acts_for": [edge_dict(e) for e in p.acts_for],
            "may_delegate": [edge_dict(e) for e in p.may_delegate],
            "entitlements": [e.id for e in _grants_for(ps, pid)],
            "source_file": p.source_file,
        })
    return rows
