# sdk/src/openapl/model.py
"""Frozen data model for a loaded OpenAPL policy directory."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Edge:
    actions: tuple[str, ...]
    to: str | None = None
    who: str | None = None


@dataclass(frozen=True)
class Principal:
    id: str
    kind: str
    identity: dict
    owner: str
    acts_for: tuple[Edge, ...]
    may_delegate: tuple[Edge, ...]
    source: str
    source_file: str


@dataclass(frozen=True)
class Entitlement:
    id: str
    grant_to: tuple[str, ...]
    action: str
    resource: str
    when: tuple[str, ...]
    purpose: str | None
    expires: str
    otherwise: str | None
    deny: bool
    source: str
    source_file: str


@dataclass(frozen=True)
class PolicySet:
    principals: dict[str, Principal]
    entitlements: tuple[Entitlement, ...]
    max_depth: int
    require_human_origin: bool
    groups_claim: str
    roles_claim: str
    frameworks: dict[str, tuple[str, ...]]
    active_humans: frozenset[str] | None


class PolicyLoadError(ValueError):
    pass


@dataclass(frozen=True)
class Link:
    principal_id: str
    kind: str
    claims: dict
