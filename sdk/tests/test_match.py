# sdk/tests/test_match.py
from openapl.match import match_action, match_deny_resource, match_resource, selector_matches
from openapl.model import Link


def test_resource_interpolation():
    assert match_resource("order/${request.order_id}", "order/123", {"order_id": "123"})


def test_resource_glob_in_attr_does_not_widen():
    assert not match_resource("order/${request.order_id}", "order/999", {"order_id": "*"})


def test_resource_missing_attr_false():
    assert not match_resource("order/${request.order_id}", "order/1", {})


def test_action_glob():
    assert match_action("mcp.tools.call:payments/*", "mcp.tools.call:payments/refund")


def test_action_exact_and_mismatch():
    assert match_action("a:b", "a:b")
    assert not match_action("a:b", "a:c")


def test_group_selector(ps):
    alice = Link("user:alice@acme.com", "human", {"groups": ["support-staff"]})
    agent = Link("refund-agent", "agent", {})
    assert selector_matches("group:support-staff", alice, ps)
    assert not selector_matches("group:support-staff", agent, ps)
    assert not selector_matches("group:other", alice, ps)


def test_role_selector(ps):
    alice = Link("user:alice@acme.com", "human", {"roles": ["approver"]})
    assert selector_matches("role:approver", alice, ps)
    assert not selector_matches("role:admin", alice, ps)


def test_star_matches_agent_and_human(ps):
    assert selector_matches("*", Link("refund-agent", "agent", {}), ps)
    assert selector_matches("*", Link("user:a@b.c", "human", {}), ps)


def test_user_selector_only_matches_humans(ps):
    assert selector_matches("user:a@b.c", Link("user:a@b.c", "human", {}), ps)
    assert not selector_matches("user:a@b.c", Link("user:a@b.c", "agent", {}), ps)
    assert not selector_matches("user:a@b.c", Link("user:x@b.c", "human", {}), ps)


def test_bare_name_matches_principal_id(ps):
    assert selector_matches("refund-agent", Link("refund-agent", "agent", {}), ps)
    assert not selector_matches("refund-agent", Link("other", "agent", {}), ps)


def test_non_list_claims_do_not_match(ps):
    assert not selector_matches("group:g", Link("user:a@b.c", "human", {"groups": 5}), ps)
    assert not selector_matches("group:g", Link("user:a@b.c", "human", {"groups": {"g": 1}}), ps)


def test_deny_resource_placeholder_is_wildcard():
    assert match_deny_resource("doc/${request.doc_id}", "doc/1")
    assert match_deny_resource("doc/${request.doc_id}/v${request.v}", "doc/1/v2")
    assert not match_deny_resource("doc/${request.doc_id}", "page/1")
    assert match_deny_resource("order/bulk-*", "order/bulk-7")
    assert not match_deny_resource("order/bulk-*", "order/7")


def test_actions_overlap():
    from openapl.match import actions_overlap as o
    assert o("payments.refund", "payments.refund")
    assert not o("payments.refund", "payments.void")
    assert o("payments.*", "payments.refund") and o("payments.refund", "payments.*")
    assert o("payments.*", "*.refund")
    assert o("*", "x.y")
    assert not o("payments.*", "orders.*")
    assert not o("*.refund", "*.void")
    assert o("pay*", "payments.*")
