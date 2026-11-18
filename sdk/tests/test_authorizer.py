import json
import shutil
from dataclasses import replace

import pytest

from tests.conftest import EXAMPLE
from openapl.approvals import attributes_hash
from openapl.authorizer import Authorizer
from openapl.model import Approval, Edge, Entitlement, Link, PolicySet, Principal, Request

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


def test_internal_error_denies(authorizer, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(authorizer, "_has_edge", boom)
    d = authorizer.decide(BASE)
    assert d.decision == "DENY"
    assert d.reasons == ("internal error: RuntimeError",)
    assert d.chain == ("user:alice@acme.com", "support-agent", "refund-agent")


def test_human_spoof_as_caller_denied(authorizer):
    spoof = Link("refund-agent", "human", {})
    d = authorizer.decide(replace(BASE, chain=(alice, sa, spoof)))
    assert d.decision == "DENY"
    assert "malformed human link refund-agent" in d.reasons


def test_human_spoof_as_origin_denied(authorizer):
    spoof = Link("refund-agent", "human", {"groups": ["support-staff"]})
    d = authorizer.decide(replace(BASE, chain=(spoof, sa, ra)))
    assert d.decision == "DENY"
    assert "malformed human link refund-agent" in d.reasons


def test_agent_with_user_prefix_denied(authorizer):
    fake = Link("user:mallory@acme.com", "agent", {})
    d = authorizer.decide(replace(BASE, chain=(alice, sa, fake)))
    assert d.decision == "DENY"
    assert "malformed human link user:mallory@acme.com" in d.reasons


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


SECRET_POLICY = """\
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
deny:
  - id: no-secret-docs
    grant_to: ["*"]
    action: a.read
    resource: "doc/${request.doc_id}"
    when: ["request.secret == true"]
"""
H = Link("user:h@acme.com", "human", {})
BOT = Link("bot", "agent", {})


@pytest.mark.parametrize(
    "attrs, reason",
    [
        ({"doc_id": "1", "secret": True}, "denied by no-secret-docs"),
        ({"secret": True}, "denied by no-secret-docs"),
        ({"doc_id": "2", "secret": True}, "denied by no-secret-docs"),
        ({}, "denied by no-secret-docs (condition error)"),
    ],
)
def test_deny_interpolated_resource_not_bypassable(tmp_path, attrs, reason):
    authz = _policy_dir(tmp_path, SECRET_POLICY)
    d = authz.decide(Request((H, BOT), "a.read", "doc/1", attrs, now=1000))
    assert d.decision == "DENY"
    assert reason in d.reasons


def test_deny_interpolated_resource_not_secret_allows(tmp_path):
    authz = _policy_dir(tmp_path, SECRET_POLICY)
    d = authz.decide(Request((H, BOT), "a.read", "doc/1", {"secret": False}, now=1000))
    assert d.decision == "ALLOW", d.reasons


@pytest.mark.parametrize("now", [0, -5])
def test_request_time_not_set_denies(authorizer, now):
    d = authorizer.decide(replace(BASE, now=now))
    assert d.decision == "DENY"
    assert "request time not set" in d.reasons


def test_default_request_now_denies(authorizer):
    d = authorizer.decide(Request(BASE.chain, BASE.action, BASE.resource, ATTRS,
                                  purpose="customer-refund", task_id="t1"))
    assert d.decision == "DENY"
    assert "request time not set" in d.reasons


def test_duration_expiry_future_iat_fails(tmp_path):
    authz = _policy_dir(tmp_path, DURATION_POLICY)
    h = Link("user:h@acme.com", "human", {})
    req = Request((h, Link("bot", "agent", {})), "a.read", "doc/1", token_iat=1001, now=1000)
    d = authz.decide(req)
    assert d.decision == "DENY"
    assert _has(d, "has no grant")


@pytest.mark.parametrize(
    "field, value",
    [
        ("entitlement_id", "support-staff-refunds"),
        ("approver", "role:intern"),
        ("action", "payments.void"),
        ("resource", "order/999"),
        ("attributes_hash", "0" * 64),
        ("origin", "user:bob@acme.com"),
        ("caller", "support-agent"),
    ],
)
def test_approval_field_mismatch_not_allowed(authorizer, field, value):
    attrs = _attrs(amount=350)
    approval = replace(_approval(attrs), **{field: value})
    d = authorizer.decide(replace(BASE, attributes=attrs, approvals=(approval,)))
    assert d.decision != "ALLOW"
    assert d.decision == "REQUIRE_APPROVAL"


def test_approval_exp_equal_now_allows(authorizer):
    attrs = _attrs(amount=350)
    d = authorizer.decide(replace(BASE, attributes=attrs, approvals=(_approval(attrs, exp=1000),)))
    assert d.decision == "ALLOW", d.reasons


def test_approval_hash_reordered_keys_allows(authorizer):
    attrs = _attrs(amount=350)
    reordered = dict(reversed(list(attrs.items())))
    assert list(reordered) != list(attrs)
    d = authorizer.decide(replace(BASE, attributes=attrs, approvals=(_approval(reordered),)))
    assert d.decision == "ALLOW", d.reasons


def test_p1_literal_counterexample_relay_supplies_missing_edge():
    # Found by hypothesis (task 6) against the literal design §4.4 P1 wording. With
    # origin and caller fixed, inserting a0 turns DENY into ALLOW, because the relay
    # supplies the direct edge user:h -> a1 that is missing. The longer chain meets
    # every clause of §4.4, so this is the semantics, not an engine bug; P1 holds
    # when the insertion splits an edge that exists (tests/test_properties.py).
    src = "p.apl.yaml"
    a0 = Principal("a0", "agent", {}, "user:owner",
                   (Edge(("a.read",), who="group:g2"),), (Edge(("a.read",), to="a1"),), src, src)
    a1 = Principal("a1", "agent", {}, "user:owner", (), (), src, src)
    grant = Entitlement("p0", ("*",), "a.read", "r/1", (), None, "never", None, False, src, src)
    ps = PolicySet({"a0": a0, "a1": a1}, (grant,), 2, True, "groups", "roles", {}, None)
    h = Link("user:h", "human", {"groups": ["g2"]})
    direct = Request((h, Link("a1", "agent", {})), "a.read", "r/1", {"n": 0}, now=1000)
    relayed = replace(direct, chain=(h, Link("a0", "agent", {}), Link("a1", "agent", {})))
    d = Authorizer(ps).decide(direct)
    assert d.decision == "DENY"
    assert d.reasons == ("no delegation edge user:h -> a1 for a.read",)
    assert Authorizer(ps).decide(relayed).decision == "ALLOW"
