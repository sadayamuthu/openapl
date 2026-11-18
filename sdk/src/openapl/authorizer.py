# sdk/src/openapl/authorizer.py
"""Delegation-chain decision semantics (design §4.4). Pure: no I/O, no clock."""
import re
import uuid

from openapl.approvals import attributes_hash
from openapl.conditions import ConditionError, evaluate_conditions
from openapl.match import match_action, match_resource, selector_matches
from openapl.model import Decision, Entitlement, Link, PolicySet, Request
from openapl.policyset import load_policy_dir

# Control table (design §4.5). Moves to its own module in Task 9.
CONTROLS: dict[str, tuple[str, ...]] = {
    "NIST-800-53": ("NIST-800-53:AC-3", "NIST-800-53:AC-6"),
    "SOC2": ("SOC2:CC6.1", "SOC2:CC6.3"),
}

_DURATION = re.compile(r"^([0-9]+)([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_OTHERWISE = re.compile(r"^require_approval\(([^)]+)\)$")

GRANTED, NEEDS_APPROVAL, NONE = "GRANTED", "NEEDS_APPROVAL", "NONE"


def _link_view(link: Link) -> dict:
    # id and kind come from the verified chain and cannot be overridden by claims.
    return {**link.claims, "id": link.principal_id, "kind": link.kind}


def _approver(otherwise: str | None) -> str | None:
    if not otherwise:
        return None
    m = _OTHERWISE.match(otherwise)
    return m.group(1) if m else None


class Authorizer:
    def __init__(self, ps: PolicySet):
        self.ps = ps

    @classmethod
    def from_dir(cls, path: str, directory_snapshot: str | None = None) -> "Authorizer":
        return cls(load_policy_dir(path, directory_snapshot))

    def decide(self, request: Request) -> Decision:
        try:
            return self._decide(request)
        except Exception as e:  # fail closed: nothing escapes decide
            return self._internal_error(request, e)

    # -- helpers -----------------------------------------------------------

    def _decision(self, request: Request, decision: str, reasons, *, approvers=(),
                  matched=(), grants=(), policies=(), controls=()) -> Decision:
        return Decision(
            decision=decision,
            approvers=tuple(approvers),
            chain=tuple(link.principal_id for link in request.chain),
            action=request.action,
            resource=request.resource,
            reasons=tuple(reasons),
            matched=tuple(matched),
            grants=tuple(grants),
            policies=tuple(policies),
            controls=tuple(controls),
            dev_mode=request.dev_mode,
            decision_id=uuid.uuid4().hex,
            timestamp=request.now,
        )

    def _internal_error(self, request, e: Exception) -> Decision:
        try:
            chain = tuple(str(link.principal_id) for link in request.chain)
        except Exception:
            chain = ()
        now = getattr(request, "now", 0)
        return Decision(
            decision="DENY",
            approvers=(),
            chain=chain,
            action=str(getattr(request, "action", "")),
            resource=str(getattr(request, "resource", "")),
            reasons=(f"internal error: {type(e).__name__}",),
            matched=(),
            grants=(),
            policies=(),
            controls=(),
            dev_mode=bool(getattr(request, "dev_mode", False)),
            decision_id=uuid.uuid4().hex,
            timestamp=now if isinstance(now, int) else 0,
        )

    def _applies(self, ent: Entitlement, link: Link, request: Request) -> bool:
        return (
            any(selector_matches(sel, link, self.ps) for sel in ent.grant_to)
            and match_action(ent.action, request.action)
            and match_resource(ent.resource, request.resource, request.attributes)
        )

    def _expiry_ok(self, ent: Entitlement, request: Request) -> bool:
        if ent.expires == "never":
            return True
        if ent.expires == "task":
            return request.task_id is not None
        m = _DURATION.match(ent.expires)
        if not m or request.token_iat is None:
            return False
        return request.now - request.token_iat <= int(m.group(1)) * _UNITS[m.group(2)]

    def _has_edge(self, prev: Link, cur: Link, action: str) -> bool:
        if prev.kind == "human":
            target = self.ps.principals.get(cur.principal_id)
            edges = target.acts_for if target else ()
            return any(
                e.who is not None and selector_matches(e.who, prev, self.ps)
                and any(match_action(a, action) for a in e.actions)
                for e in edges
            )
        source = self.ps.principals.get(prev.principal_id)
        edges = source.may_delegate if source else ()
        return any(
            e.to == cur.principal_id and any(match_action(a, action) for a in e.actions)
            for e in edges
        )

    def _approval_satisfied(self, ent: Entitlement, approver: str, request: Request,
                            attrs_hash: str) -> bool:
        origin = request.chain[0].principal_id
        caller = request.chain[-1].principal_id
        return any(
            a.entitlement_id == ent.id
            and a.approver == approver
            and a.action == request.action
            and a.resource == request.resource
            and a.attributes_hash == attrs_hash
            and a.origin == origin
            and a.caller == caller
            and a.exp >= request.now
            for a in request.approvals
        )

    def _link_grant(self, link: Link, request: Request, base: dict, attrs_hash: str):
        """Return (state, approvers, matched ids, granted ids, reasons) for one link."""
        activation = {**base, "principal": _link_view(link)}
        granted: list[str] = []
        eligible: list[tuple[str, str]] = []
        matched: list[str] = []
        errors: list[str] = []
        for ent in self.ps.entitlements:
            if ent.deny or not self._applies(ent, link, request):
                continue
            if ent.purpose is not None and request.purpose != ent.purpose:
                continue
            if not self._expiry_ok(ent, request):
                continue
            try:
                ok = evaluate_conditions(ent.when, activation)
            except ConditionError:
                errors.append(f"condition error in {ent.id}")
                continue
            if ok:
                granted.append(ent.id)
                matched.append(ent.id)
                continue
            approver = _approver(ent.otherwise)
            if approver is None:
                continue
            matched.append(ent.id)
            if self._approval_satisfied(ent, approver, request, attrs_hash):
                granted.append(ent.id)
            else:
                eligible.append((ent.id, approver))
        if granted:
            return GRANTED, (), matched, granted, []
        if eligible:
            reasons = [f"{link.principal_id} needs approval for {eid}" for eid, _ in eligible]
            return NEEDS_APPROVAL, [a for _, a in eligible], matched, [], reasons
        reasons = [f"{link.principal_id} has no grant for {request.action} on {request.resource}"]
        return NONE, (), matched, [], reasons + errors

    # -- algorithm (design §4.4) ------------------------------------------

    def _decide(self, request: Request) -> Decision:
        ps = self.ps
        if not ps.principals and not ps.entitlements:
            return self._decision(request, "DENY", ["no policies loaded"])
        chain = request.chain
        if not chain:
            return self._decision(request, "DENY", ["empty chain"])

        reasons: list[str] = []

        # 2. Known principals and active owners.
        for link in chain:
            if link.kind == "human":
                continue
            p = ps.principals.get(link.principal_id)
            if p is None:
                reasons.append(f"unknown principal {link.principal_id}")
            elif ps.active_humans is not None and p.owner not in ps.active_humans:
                reasons.append(f"owner {p.owner} of {link.principal_id} not active")

        # 3. Origin, depth, humans only at the origin.
        if ps.require_human_origin and chain[0].kind != "human":
            reasons.append("human origin required")
        depth = len(chain) - 1
        if depth > ps.max_depth:
            reasons.append(f"chain depth {depth} exceeds {ps.max_depth}")
        if any(link.kind == "human" for link in chain[1:]):
            reasons.append("human in chain after origin")

        # 4. Delegation edges.
        for prev, cur in zip(chain, chain[1:]):
            if not self._has_edge(prev, cur, request.action):
                reasons.append(
                    f"no delegation edge {prev.principal_id} -> {cur.principal_id} for {request.action}"
                )

        base = {
            "request": request.attributes,
            "chain": {"origin": _link_view(chain[0]), "caller": _link_view(chain[-1]),
                      "depth": depth},
        }

        # 5. Denies match on any link.
        deny_ids: list[str] = []
        for ent in ps.entitlements:
            if not ent.deny:
                continue
            for link in chain:
                if not self._applies(ent, link, request):
                    continue
                try:
                    hit = evaluate_conditions(ent.when, {**base, "principal": _link_view(link)})
                except ConditionError:
                    reasons.append(f"denied by {ent.id} (condition error)")
                    deny_ids.append(ent.id)
                    break
                if hit:
                    reasons.append(f"denied by {ent.id}")
                    deny_ids.append(ent.id)
                    break

        # 6. Per-link grants: origin, then caller if it is a different link.
        attrs_hash = attributes_hash(request.attributes)
        links = [chain[0]] if len(chain) == 1 else [chain[0], chain[-1]]
        states: list[str] = []
        approvers: set[str] = set()
        matched: list[str] = []
        grants: list[tuple[str, str]] = []
        approval_notes: list[str] = []
        for link in links:
            state, link_approvers, link_matched, granted, link_reasons = self._link_grant(
                link, request, base, attrs_hash
            )
            states.append(state)
            matched.extend(link_matched)
            grants.extend((link.principal_id, eid) for eid in granted)
            if state == NONE:
                reasons.extend(link_reasons)
            elif state == NEEDS_APPROVAL:
                approvers.update(link_approvers)
                approval_notes.extend(link_reasons)
        matched.extend(deny_ids)
        matched = list(dict.fromkeys(matched))

        # 8. Evidence.
        by_id = {e.id: e for e in ps.entitlements}
        policies = sorted({by_id[m].source for m in matched})
        controls = sorted(
            {c for src in policies for fw in ps.frameworks.get(src, ()) for c in CONTROLS[fw]}
        )
        evidence = dict(matched=matched, grants=grants, policies=policies, controls=controls)

        # 7. Combine.
        if reasons:
            return self._decision(request, "DENY", reasons, **evidence)
        if NEEDS_APPROVAL in states:
            return self._decision(request, "REQUIRE_APPROVAL", approval_notes,
                                  approvers=sorted(approvers), **evidence)
        return self._decision(request, "ALLOW", [], **evidence)
