import pytest

from openapl.approvals import approval_from_claim, attributes_hash

CLAIM = {
    "entitlement_id": "refund-small-orders",
    "approver": "role:support-manager",
    "action": "payments.refund",
    "resource": "order/123",
    "attributes_hash": "abc",
    "origin": "user:alice@acme.com",
    "caller": "refund-agent",
    "exp": 2000,
}


def test_hash_key_order_independent():
    a = {"order_id": "123", "amount": 300, "account_status": "open"}
    b = {"account_status": "open", "amount": 300, "order_id": "123"}
    assert attributes_hash(a) == attributes_hash(b)


def test_hash_value_sensitive():
    assert attributes_hash({"amount": 300}) != attributes_hash({"amount": 50000})


def test_claim_missing_field_raises():
    assert approval_from_claim(CLAIM).exp == 2000
    item = dict(CLAIM)
    del item["attributes_hash"]
    with pytest.raises(ValueError):
        approval_from_claim(item)
