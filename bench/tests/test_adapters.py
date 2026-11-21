# bench/tests/test_adapters.py
"""The Cedar and Rego adapters carry the request as data: chain order, approvals, attributes."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adapters.cedar_input import CedarRequest, to_cedar  # noqa: E402
from adapters.rego_input import to_rego  # noqa: E402
from common import Case  # noqa: E402

APPROVAL = {
    "entitlement_id": "payment-small", "approver": "role:finance-lead",
    "action": "payments.pay", "resource": "payment/p1",
    "attributes_hash": "7ff01fba53f82af324888a9a67db0707d64f89034991cf2ce0998e2562d25fac",
    "origin": "user:alice@acme.com", "caller": "payments-agent", "exp": 2000,
}
CHAIN = [
    {"id": "user:alice@acme.com", "kind": "human", "claims": {"groups": "sre", "roles": ["oncall"]}},
    {"id": "agent-a", "kind": "agent"},
    {"id": "agent-b", "kind": "agent"},
    {"id": "agent-c", "kind": "agent"},
]


def _case(**request) -> Case:
    base = {"chain": CHAIN, "action": "payments.pay", "resource": "payment/p1",
            "attributes": {"amount": 350, "payment_id": "p1"}, "now": 1000,
            "approvals": [APPROVAL]}
    return Case(id="c", request={**base, **request}, expect="ALLOW")


def _ref(t: str, i: str) -> dict:
    return {"__entity": {"type": t, "id": i}}


# --- Rego -----------------------------------------------------------------------------------

def test_rego_chain_order_preserved():
    doc = to_rego(_case())
    assert [link["id"] for link in doc["chain"]] == [link["id"] for link in CHAIN]
    assert all(set(link) == {"id", "kind", "claims"} for link in doc["chain"])
    assert doc["chain"][0]["claims"] == {"groups": "sre", "roles": ["oncall"]}  # verbatim
    assert doc["chain"][1]["claims"] == {}


def test_rego_carries_approvals_attributes_and_claims_fields():
    doc = to_rego(_case(purpose="p", task_id="t", iat=900, directory={"active": ["x"]}))
    assert doc["approvals"] == [APPROVAL]
    assert doc["attributes"] == {"amount": 350, "payment_id": "p1"}
    assert (doc["purpose"], doc["task_id"], doc["iat"], doc["now"]) == ("p", "t", 900, 1000)
    assert doc["directory"] == {"active": ["x"]}
    assert (doc["action"], doc["resource"]) == ("payments.pay", "payment/p1")


def test_rego_absent_fields_stay_absent():
    doc = to_rego(_case(purpose=None, approvals=None))
    assert "purpose" not in doc and "task_id" not in doc and "iat" not in doc
    assert doc["approvals"] == []


# --- Cedar ----------------------------------------------------------------------------------

def test_cedar_principal_is_caller_and_origin_in_context():
    r = to_cedar(_case())
    assert isinstance(r, CedarRequest)
    assert r.principal == 'Agent::"agent-c"'
    assert r.action == 'Action::"payments.pay"'
    assert r.resource == 'Resource::"payment/p1"'
    assert r.context["origin"] == _ref("User", "user:alice@acme.com")
    assert r.context["first_agent"] == _ref("Agent", "agent-a")


def test_cedar_chain_order_preserved_as_consecutive_hops():
    r = to_cedar(_case())
    assert r.context["hops"] == ["agent-a>agent-b", "agent-b>agent-c"]
    assert r.context["depth"] == 3
    assert r.context["agents"] == [_ref("Agent", i) for i in ("agent-a", "agent-b", "agent-c")]
    reversed_chain = [CHAIN[0], CHAIN[3], CHAIN[2], CHAIN[1]]
    assert to_cedar(_case(chain=reversed_chain)).context["hops"] == ["agent-c>agent-b",
                                                                      "agent-b>agent-a"]


def test_cedar_carries_approvals_and_attributes():
    r = to_cedar(_case())
    assert r.context["attributes"] == {"amount": 350, "payment_id": "p1"}
    assert r.context["attributes_hash"] == APPROVAL["attributes_hash"]
    (item,) = r.context["approvals"]
    assert item == {
        "entitlement_id": "payment-small", "approver": "role:finance-lead",
        "action": "payments.pay", "resource": "payment/p1",
        "attributes_hash": APPROVAL["attributes_hash"],
        "origin": _ref("User", "user:alice@acme.com"), "caller": _ref("Agent", "payments-agent"),
        "expired": False,
    }
    assert to_cedar(_case(now=2001)).context["approvals"][0]["expired"] is True


def test_cedar_human_claims_become_entity_parents():
    r = to_cedar(_case())
    users = [e for e in r.entities if e["uid"]["type"] == "User"]
    assert users == [{
        "uid": {"type": "User", "id": "user:alice@acme.com"}, "attrs": {},
        "parents": [{"type": "Group", "id": "sre"}, {"type": "Role", "id": "oncall"}],
    }]
    res = [e for e in r.entities if e["uid"]["type"] == "Resource"]
    assert res == [{"uid": {"type": "Resource", "id": "payment/p1"},
                    "attrs": {"path": "payment/p1"}, "parents": []}]


def test_cedar_optional_claims_and_directory_and_derived():
    r = to_cedar(_case(purpose="p", iat=900, directory={"active": ["priya@acme.com"]},
                       attributes={"order_id": "123"}),
                 derived={"order_resource": "order/{order_id}", "missing": "x/{nope}"})
    assert (r.context["purpose"], r.context["iat"], r.context["now"]) == ("p", 900, 1000)
    assert "task_id" not in r.context
    assert r.context["active_owners"] == ["priya@acme.com"]
    assert r.context["derived"] == {"order_resource": "order/123"}  # absent attribute: absent


def test_cedar_single_link_agent_origin():
    r = to_cedar(_case(chain=[{"id": "unknown:x", "kind": "agent"}]))
    assert r.principal == 'Agent::"unknown:x"'
    assert "origin" not in r.context and "first_agent" not in r.context
    assert r.context["origin_agent"] == _ref("Agent", "unknown:x")
    assert r.context["hops"] == [] and r.context["depth"] == 0
