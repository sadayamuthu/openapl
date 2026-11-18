# sdk/src/openapl/model.py
"""Frozen data model for a loaded OpenAPL policy directory."""
from dataclasses import dataclass, field


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


@dataclass(frozen=True)
class Approval:
    entitlement_id: str
    approver: str
    action: str
    resource: str
    attributes_hash: str
    origin: str
    caller: str
    exp: int


@dataclass(frozen=True)
class Request:
    chain: tuple[Link, ...]
    action: str
    resource: str
    attributes: dict = field(default_factory=dict)
    purpose: str | None = None
    task_id: str | None = None
    token_iat: int | None = None
    now: int = 0
    approvals: tuple[Approval, ...] = ()
    dev_mode: bool = False


@dataclass(frozen=True)
class Decision:
    decision: str
    approvers: tuple[str, ...]
    chain: tuple[str, ...]
    action: str
    resource: str
    reasons: tuple[str, ...]
    matched: tuple[str, ...]
    grants: tuple[tuple[str, str], ...]
    policies: tuple[str, ...]
    controls: tuple[str, ...]
    dev_mode: bool
    decision_id: str
    timestamp: int

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "approvers": list(self.approvers),
            "chain": list(self.chain),
            "action": self.action,
            "resource": self.resource,
            "reasons": list(self.reasons),
            "matched": list(self.matched),
            "grants": [list(g) for g in self.grants],
            "policies": list(self.policies),
            "controls": list(self.controls),
            "dev_mode": self.dev_mode,
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
        }
