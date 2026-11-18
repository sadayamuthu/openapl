import json
import shutil
from dataclasses import replace

from tests.conftest import EXAMPLE
from openapl.approvals import attributes_hash
from openapl.authorizer import Authorizer
from openapl.model import Approval, Link, Request

alice = Link("user:alice@acme.com", "human", {"groups": ["support-staff"]})
sa = Link("support-agent", "agent", {})
ra = Link("refund-agent", "agent", {})
ATTRS = {"order_id": "123", "amount": 150, "account_status": "open"}
BASE = Request(
    (alice, sa, ra), "payments.refund", "order/123", ATTRS,
    purpose="customer-refund", task_id="t1", now=1000,
)


def _attrs(**kw):
    return {**ATTRS, **kw}


def _approval(attrs, resource="order/123", exp=2000):
    return Approval(
        entitlement_id="refund-small-orders",
        approver="role:support-manager",
        action="payments.refund",
        resource=resource,
        attributes_hash=attributes_hash(attrs),
        origin="user:alice@acme.com",
        caller="refund-agent",
        exp=exp,
    )


def _policy_dir(tmp_path, text):
    d = tmp_path / "p"
    d.mkdir()
    (d / "x.apl.yaml").write_text(text, encoding="utf-8")
    return Authorizer.from_dir(str(d))


def _has(d, fragment):
    return any(fragment in r for r in d.reasons)


def test_happy_chain_allows(authorizer):
    d = authorizer.decide(BASE)
    assert d.decision == "ALLOW", d.reasons
    assert d.reasons == ()
    assert d.matched == ("support-staff-refunds", "refund-small-orders")


def test_middle_agent_needs_no_grant(authorizer):
    d = authorizer.decide(BASE)
    assert d.decision == "ALLOW"
    assert all(link != "support-agent" for link, _ in d.grants)


def test_acts_for_required(authorizer):
    bob = Link("user:alice@acme.com", "human", {"groups": []})
    d = authorizer.decide(replace(BASE, chain=(bob, sa, ra)))
    assert d.decision == "DENY"
    assert _has(d, "no delegation edge user:alice@acme.com -> support-agent")


def test_missing_edge_denies(authorizer):
    d = authorizer.decide(replace(BASE, chain=(alice, ra)))
    assert d.decision == "DENY"
    assert _has(d, "no delegation edge user:alice@acme.com -> refund-agent")


def test_edge_action_must_match(authorizer):
    d = authorizer.decide(replace(BASE, action="payments.void"))
    assert d.decision == "DENY"
    assert _has(d, "no delegation edge user:alice@acme.com -> support-agent for payments.void")
    assert _has(d, "no delegation edge support-agent -> refund-agent for payments.void")


def test_over_limit_requires_approval(authorizer):
    d = authorizer.decide(replace(BASE, attributes=_attrs(amount=350)))
    assert d.decision == "REQUIRE_APPROVAL"
    assert d.approvers == ("role:support-manager",)
    assert d.matched == ("support-staff-refunds", "refund-small-orders")


def test_bound_approval_allows(authorizer):
    attrs = _attrs(amount=350)
    d = authorizer.decide(replace(BASE, attributes=attrs, approvals=(_approval(attrs),)))
    assert d.decision == "ALLOW", d.reasons
    assert ("refund-agent", "refund-small-orders") in d.grants


def test_approval_other_amount_rejected(authorizer):
    approval = _approval(_attrs(amount=300))
    d = authorizer.decide(replace(BASE, attributes=_attrs(amount=50000), approvals=(approval,)))
    assert d.decision == "REQUIRE_APPROVAL"


def test_approval_other_resource_rejected(authorizer):
    attrs = _attrs(amount=350)
    approval = _approval(attrs, resource="order/999")
    d = authorizer.decide(replace(BASE, attributes=attrs, approvals=(approval,)))
    assert d.decision == "REQUIRE_APPROVAL"


def test_approval_expired_rejected(authorizer):
    attrs = _attrs(amount=350)
    d = authorizer.decide(replace(BASE, attributes=attrs, approvals=(_approval(attrs, exp=999),)))
    assert d.decision == "REQUIRE_APPROVAL"


def test_deny_beats_approval(authorizer):
    d = authorizer.decide(
        replace(BASE, resource="order/bulk-1", attributes=_attrs(amount=350, order_id="bulk-1"))
    )
    assert d.decision == "DENY"
    assert d.approvers == ()
    assert _has(d, "denied by no-bulk-refunds")


def test_closed_account_denied(authorizer):
    d = authorizer.decide(replace(BASE, attributes=_attrs(account_status="closed")))
    assert d.decision == "DENY"
    assert "denied by no-refunds-on-closed-accounts" in d.reasons
    assert d.matched[-1] == "no-refunds-on-closed-accounts"


def test_deny_condition_missing_attr_fails_closed(authorizer):
    attrs = {"order_id": "123", "amount": 150}
    d = authorizer.decide(replace(BASE, attributes=attrs))
    assert d.decision == "DENY"
    assert "denied by no-refunds-on-closed-accounts (condition error)" in d.reasons


def test_grant_condition_missing_attr_no_grant(authorizer):
    attrs = {"order_id": "123", "account_status": "open"}
    d = authorizer.decide(replace(BASE, attributes=attrs))
    assert d.decision == "DENY"
    assert "condition error in refund-small-orders" in d.reasons
    assert _has(d, "refund-agent has no grant for payments.refund on order/123")


def test_purpose_mismatch_denies(authorizer):
    d = authorizer.decide(replace(BASE, purpose="marketing"))
    assert d.decision == "DENY"
    assert _has(d, "refund-agent has no grant")
    d = authorizer.decide(replace(BASE, purpose=None))
    assert d.decision == "DENY"


def test_task_expiry_needs_task_id(authorizer):
    d = authorizer.decide(replace(BASE, task_id=None))
    assert d.decision == "DENY"
    assert _has(d, "refund-agent has no grant")


DURATION_POLICY = """\
openapl: '0.1'
policy: p
version: 1.0.0
principals:
  bot:
    kind: agent
    identity: { oauth_client_id: bot }
    owner: priya@acme.com
    acts_for:
      - who: "user:h@acme.com"
        actions: [a.read]
entitlements:
  - id: everyone-reads
    grant_to: ["*"]
    action: a.read
    resource: "doc/*"
    expires: 15m
"""


def test_duration_expiry(tmp_path):
    authz = _policy_dir(tmp_path, DURATION_POLICY)
    h = Link("user:h@acme.com", "human", {})
    req = Request((h, Link("bot", "agent", {})), "a.read", "doc/1", token_iat=0, now=900)
    assert authz.decide(req).decision == "ALLOW"
    assert authz.decide(replace(req, now=901)).decision == "DENY"
    assert authz.decide(replace(req, token_iat=None)).decision == "DENY"


def test_agent_origin_rejected(authorizer):
    d = authorizer.decide(replace(BASE, chain=(sa, ra)))
    assert d.decision == "DENY"
    assert "human origin required" in d.reasons


def test_depth_limit(tmp_path):
    text = EXAMPLE.read_text(encoding="utf-8").replace("max_depth: 3", "max_depth: 1")
    authz = _policy_dir(tmp_path, text)
    d = authz.decide(BASE)
    assert d.decision == "DENY"
    assert "chain depth 2 exceeds 1" in d.reasons


def test_inactive_owner_denies(refund_dir, tmp_path):
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps({"active": []}), encoding="utf-8")
    d = Authorizer.from_dir(str(refund_dir), str(snap)).decide(BASE)
    assert d.decision == "DENY"
    assert "owner priya@acme.com of support-agent not active" in d.reasons
    snap.write_text(json.dumps({"active": ["priya@acme.com"]}), encoding="utf-8")
    assert Authorizer.from_dir(str(refund_dir), str(snap)).decide(BASE).decision == "ALLOW"


def test_unknown_principal_denies(authorizer):
    d = authorizer.decide(replace(BASE, chain=(alice, sa, Link("ghost", "agent", {}))))
    assert d.decision == "DENY"
    assert "unknown principal ghost" in d.reasons


def test_empty_policy_dir_denies(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    (d / "notes.md").write_text("x", encoding="utf-8")
    dec = Authorizer.from_dir(str(d)).decide(BASE)
    assert dec.decision == "DENY"
    assert dec.reasons == ("no policies loaded",)


def test_empty_chain_denies(authorizer):
    d = authorizer.decide(replace(BASE, chain=()))
    assert d.decision == "DENY"
    assert d.reasons == ("empty chain",)


def test_internal_error_denies(authorizer):
    d = authorizer.decide(replace(BASE, attributes=_attrs(blob=object())))
    assert d.decision == "DENY"
    assert d.reasons[0].startswith("internal error: ")


def test_decision_evidence(authorizer):
    d = authorizer.decide(BASE)
    assert d.decision == "ALLOW"
    assert d.grants == (
        ("user:alice@acme.com", "support-staff-refunds"),
        ("refund-agent", "refund-small-orders"),
    )
    assert d.policies == ("payments-access@1.2.0",)
    assert d.controls == ("NIST-800-53:AC-3", "NIST-800-53:AC-6", "SOC2:CC6.1", "SOC2:CC6.3")
    assert d.chain == ("user:alice@acme.com", "support-agent", "refund-agent")
    assert d.timestamp == 1000
    assert len(d.decision_id) == 32


def test_to_dict_keys(authorizer):
    d = authorizer.decide(BASE).to_dict()
    assert list(d) == [
        "decision", "approvers", "chain", "action", "resource", "reasons", "matched",
        "grants", "policies", "controls", "dev_mode", "decision_id", "timestamp",
    ]
    assert d["grants"] == [
        ["user:alice@acme.com", "support-staff-refunds"],
        ["refund-agent", "refund-small-orders"],
    ]
    assert isinstance(d["matched"], list)
