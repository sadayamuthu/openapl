# demo/agentgateway/tests/test_policy.py
import sys
from pathlib import Path

import jwt
import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import issuer  # noqa: E402
from openapl import Authorizer  # noqa: E402
from openapl.chain import request_from_claims  # noqa: E402

NOW = 1_000_000
SUPPORT = "spiffe://acme.com/agents/support-agent"
REFUND_CHAIN = [SUPPORT, "refund-agent"]


@pytest.fixture(scope="module")
def az():
    return Authorizer.from_dir(str(HERE / "policies"), str(HERE / "directory.json"))


@pytest.fixture
def out(tmp_path):
    issuer.make_keys(str(tmp_path))
    return str(tmp_path)


def decide(az, out, *, email="alice@acme.com", actors=REFUND_CHAIN, action="payments.refund",
           order="A1", amount=100, status="open", approvals=None, groups=("support-staff",),
           resource=None):
    tok = issuer.mint(out, email=email, groups=list(groups), actors=actors, approvals=approvals, now=NOW)
    claims = jwt.decode(tok, options={"verify_signature": False})
    attrs = {"order_id": order, "amount": amount, "account_status": status} if action == "payments.refund" else {}
    res = resource or f"order/{order}"
    ps = az.ps
    return az.decide(request_from_claims(claims, ps, action, res, attrs, NOW + 1))


def reasons(d):
    return " | ".join(str(r) for r in d.reasons)


def test_small_refund_allow(az, out):
    assert decide(az, out).decision == "ALLOW"


def test_three_hop_deny(az, out):
    d = decide(az, out, actors=[SUPPORT, "triage-agent", "refund-agent"])
    assert d.decision == "DENY" and "chain depth 3 exceeds 2" in reasons(d)


def test_orphan_deny(az, out):
    d = decide(az, out, actors=["legacy-agent"])
    assert d.decision == "DENY" and "owner bob@acme.com of legacy-agent not active" in reasons(d)


def test_crm_export_deny(az, out):
    d = decide(az, out, actors=[SUPPORT], action="crm.export", resource="crm/customers")
    assert d.decision == "DENY"
    assert "user:alice@acme.com has no grant for crm.export on crm/customers" in reasons(d)


def test_void_via_refund_chain_deny(az, out):
    d = decide(az, out, action="payments.void", resource="payment/P1")
    assert d.decision == "DENY"
    assert "no delegation edge support-agent -> refund-agent for payments.void" in reasons(d)


def test_350_requires_approval(az, out):
    assert decide(az, out, amount=350).decision == "REQUIRE_APPROVAL"


def _approval(amount):
    return issuer.approval_item(
        entitlement_id="refund-small-orders", approver="role:support-manager",
        action="payments.refund", resource="order/A1",
        attributes={"order_id": "A1", "amount": amount, "account_status": "open"},
        origin="user:alice@acme.com", caller="refund-agent", exp=NOW + 600)


def test_350_with_matching_approval_allow(az, out):
    assert decide(az, out, amount=350, approvals=[_approval(350)]).decision == "ALLOW"


def test_360_with_replayed_approval_requires_approval(az, out):
    assert decide(az, out, amount=360, approvals=[_approval(350)]).decision == "REQUIRE_APPROVAL"
