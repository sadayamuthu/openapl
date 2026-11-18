# sdk/tests/test_explain.py
from openapl.explain import Reach, explain, inventory
from openapl.model import Edge
from openapl.policyset import load_policy_dir

REACH = Reach("payments.refund", "order/${request.order_id}",
              ("support-agent", "refund-agent"), "refund-small-orders")


def test_explain_support_agent_reach(ps):
    assert explain(ps, "support-agent").reach == (REACH,)


def test_explain_acts_for(ps):
    assert explain(ps, "support-agent").acts_for == (Edge(("payments.refund",), who="group:support-staff"),)


def test_explain_delegated_from(ps):
    e = explain(ps, "refund-agent")
    assert e.delegated_from == (("support-agent", Edge(("payments.refund",), to="refund-agent")),)
    assert e.delegates_to == ()


def test_explain_cycle_terminates(tmp_path):
    (tmp_path / "c.apl.yaml").write_text(
        "openapl: '0.1'\npolicy: c\nversion: 1.0.0\n"
        "principals:\n"
        "  a:\n    kind: agent\n    identity: {oauth_client_id: a}\n    owner: o@x.com\n"
        "    may_delegate: [{to: b, actions: ['*']}]\n"
        "  b:\n    kind: agent\n    identity: {oauth_client_id: b}\n    owner: o@x.com\n"
        "    may_delegate: [{to: a, actions: ['*']}]\n"
        "entitlements:\n"
        "  - id: g\n    grant_to: [b]\n    action: x.y\n    resource: 'r/*'\n")
    e = explain(load_policy_dir(str(tmp_path)), "a")
    assert [r.via for r in e.reach] == [("a", "b")]


def test_explain_unknown_raises(ps):
    import pytest
    with pytest.raises(KeyError):
        explain(ps, "nobody")


def test_explain_on_behalf_of(ps):
    assert explain(ps, "support-agent", on_behalf_of="group:support-staff").reach == (REACH,)
    assert explain(ps, "support-agent", on_behalf_of="group:marketing").reach == ()


def test_explain_on_behalf_of_ungranted_selector(ps):
    # refund-agent has no acts_for, so nothing is reachable on behalf of anyone
    assert explain(ps, "refund-agent", on_behalf_of="group:support-staff").reach == ()


def test_inventory_rows(ps):
    rows = inventory(ps)
    assert [r["id"] for r in rows] == ["refund-agent", "support-agent"]
    assert rows[0]["entitlements"] == ["refund-small-orders"]
    assert rows[1]["owner"] == "priya@acme.com"
