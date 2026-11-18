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
    assert e.reach == (Reach("x.y", "r/*", ("a", "b"), "g"),)


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


def _ps(tmp_path, agents, ents, max_depth=3):
    """agents: {id: [(to, [actions])]}; may_delegate edges. acts_for added via ents key."""
    lines = ["openapl: '0.1'", "policy: t", "version: 1.0.0", "principals:"]
    for pid, spec in agents.items():
        edges, acts = spec
        lines += [f"  {pid}:", "    kind: agent", f"    identity: {{oauth_client_id: {pid}}}",
                  "    owner: o@x.com"]
        if acts:
            lines.append("    acts_for:")
            lines += [f"      - {{who: {w}, actions: {a!r}}}" for w, a in acts]
        if edges:
            lines.append("    may_delegate:")
            lines += [f"      - {{to: {t}, actions: {a!r}}}" for t, a in edges]
    lines.append("entitlements:")
    for i, (to, action) in enumerate(ents):
        lines += [f"  - id: g{i}", f"    grant_to: [{to}]", f"    action: '{action}'", "    resource: 'r/*'"]
    lines += ["delegation:", f"  max_depth: {max_depth}"]
    (tmp_path / "t.apl.yaml").write_text("\n".join(lines) + "\n")
    return load_policy_dir(str(tmp_path))


def _chain(n):
    return {f"a{i}": ([(f"a{i + 1}", ["*"])] if i < n else [], []) for i in range(n + 1)}


def test_three_hop_path_and_max_depth_cutoff(tmp_path):
    ps = _ps(tmp_path, _chain(4), [("a3", "x.y"), ("a4", "x.z")], max_depth=3)
    assert [r.via for r in explain(ps, "a0").reach] == [("a0", "a1", "a2", "a3")]


def test_on_behalf_of_depth_counts_acts_for_hop(tmp_path):
    agents = _chain(4)
    agents["a0"] = (agents["a0"][0], [("group:g", ["*"])])
    ps = _ps(tmp_path, agents, [("a2", "x.y"), ("a3", "x.z"), ("group:g", "*")], max_depth=3)
    got = explain(ps, "a0", on_behalf_of="group:g").reach
    assert [r.via for r in got] == [("a0", "a1", "a2")]  # a3 would need 3 agent hops


def test_star_grant_to(tmp_path):
    ps = _ps(tmp_path, {"a": ([], [])}, [("'*'", "x.y")])
    assert [r.entitlement_id for r in explain(ps, "a").reach] == ["g0"]


def test_glob_edge_and_glob_grant(tmp_path):
    agents = {"a": ([("b", ["payments.*"])], []), "b": ([], [])}
    assert len(explain(_ps(tmp_path, agents, [("b", "payments.refund")]), "a").reach) == 1
    agents = {"a": ([("b", ["payments.refund"])], []), "b": ([], [])}
    assert len(explain(_ps(tmp_path, agents, [("b", "payments.*")]), "a").reach) == 1
    assert explain(_ps(tmp_path, agents, [("b", "orders.*")]), "a").reach == ()


def test_sibling_paths_to_same_node(tmp_path):
    agents = {"a": ([("b", ["*"]), ("c", ["*"])], []), "b": ([("d", ["*"])], []),
              "c": ([("d", ["*"])], []), "d": ([], [])}
    got = explain(_ps(tmp_path, agents, [("d", "x.y")]), "a").reach
    assert [r.via for r in got] == [("a", "b", "d"), ("a", "c", "d")]


def test_on_behalf_of_glob_and_overreport(tmp_path):
    agents = {"a": ([("b", ["*"])], [("group:g", ["payments.*"])]), "b": ([], [])}
    ents = [("group:g", "payments.refund"), ("b", "payments.refund"), ("b", "payments.void")]
    got = explain(_ps(tmp_path, agents, ents), "a", on_behalf_of="group:g").reach
    assert [r.action for r in got] == ["payments.refund"]


def test_on_behalf_of_requires_exact_who(tmp_path):
    agents = {"a": ([], [("group:g", ["*"])])}
    ps = _ps(tmp_path, agents, [("a", "x.y"), ("group:h", "*")])
    assert explain(ps, "a", on_behalf_of="group:h").reach == ()
