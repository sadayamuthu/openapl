# sdk/tests/test_policyset.py
import json

import pytest

from openapl.model import Edge, PolicyLoadError
from openapl.policyset import load_policy_dir


def write(d, name, text):
    (d / name).write_text(text)


def doc(policy="p", body=""):
    return f"openapl: '0.1'\npolicy: {policy}\nversion: 1.0.0\n{body}"


AGENT = "principals:\n  a1:\n    kind: agent\n    identity: {oauth_client_id: a1}\n    owner: o@x.com\n"
ENT = "entitlements:\n  - id: e1\n    grant_to: [a1]\n    action: x.y\n    resource: 'r/*'\n"


def test_loads_refund_example(ps):
    assert set(ps.principals) == {"support-agent", "refund-agent"}
    assert ps.principals["support-agent"].acts_for == (Edge(("payments.refund",), who="group:support-staff"),)
    assert ps.principals["support-agent"].may_delegate == (Edge(("payments.refund",), to="refund-agent"),)
    assert ps.principals["support-agent"].owner == "priya@acme.com"
    assert [e.id for e in ps.entitlements if e.deny] == ["no-refunds-on-closed-accounts", "no-bulk-refunds"]
    assert ps.max_depth == 3 and ps.require_human_origin is True
    assert ps.frameworks["payments-access@1.2.0"] == ("NIST-800-53", "SOC2")
    assert ps.active_humans is None


def test_duplicate_principal_across_files_errors(refund_dir):
    text = (refund_dir / "refund-delegation.apl.yaml").read_text().replace("policy: payments-access", "policy: other")
    write(refund_dir, "b.apl.yaml", text)
    with pytest.raises(PolicyLoadError) as ei:
        load_policy_dir(str(refund_dir))
    assert "b.apl.yaml" in str(ei.value) and "refund-delegation.apl.yaml" in str(ei.value)


def test_duplicate_entitlement_id_errors(tmp_path):
    write(tmp_path, "a.apl.yaml", doc("a", AGENT + ENT))
    write(tmp_path, "b.apl.yaml", doc("b", ENT))
    with pytest.raises(PolicyLoadError) as ei:
        load_policy_dir(str(tmp_path))
    assert "a.apl.yaml" in str(ei.value) and "b.apl.yaml" in str(ei.value)


def test_delegation_block_twice_errors(tmp_path):
    d = "delegation: {max_depth: 2}\n"
    write(tmp_path, "a.apl.yaml", doc("a", d))
    write(tmp_path, "b.apl.yaml", doc("b", d))
    with pytest.raises(PolicyLoadError) as ei:
        load_policy_dir(str(tmp_path))
    assert "a.apl.yaml" in str(ei.value) and "b.apl.yaml" in str(ei.value)


def test_defaults_when_no_delegation_block(tmp_path):
    write(tmp_path, "a.apl.yaml", doc("a", AGENT))
    ps = load_policy_dir(str(tmp_path))
    assert ps.max_depth == 3 and ps.require_human_origin is True
    assert ps.groups_claim == "groups" and ps.roles_claim == "roles"


def test_task_expiry_without_purpose_errors(tmp_path):
    write(tmp_path, "a.apl.yaml", doc("a", AGENT + ENT + "    expires: task\n"))
    with pytest.raises(PolicyLoadError, match="purpose"):
        load_policy_dir(str(tmp_path))


def test_unknown_delegate_target_errors(tmp_path):
    body = AGENT + "    may_delegate:\n      - to: ghost\n        actions: [x.y]\n"
    write(tmp_path, "a.apl.yaml", doc("a", body))
    with pytest.raises(PolicyLoadError, match="ghost"):
        load_policy_dir(str(tmp_path))


def test_empty_owner_errors(tmp_path):
    write(tmp_path, "a.apl.yaml", doc("a", AGENT.replace("o@x.com", "''")))
    with pytest.raises(PolicyLoadError, match="has no owner"):
        load_policy_dir(str(tmp_path))


def test_ignores_other_files_and_empty_dir(tmp_path):
    write(tmp_path, "README.md", "# hi")
    write(tmp_path, "x.gpl", "garbage: [")
    ps = load_policy_dir(str(tmp_path))
    assert ps.principals == {} and ps.entitlements == ()


def test_directory_snapshot_loaded(refund_dir, tmp_path):
    snap = tmp_path / "dir.json"
    snap.write_text(json.dumps({"active": ["priya@acme.com"]}))
    ps = load_policy_dir(str(refund_dir), str(snap))
    assert ps.active_humans == frozenset({"priya@acme.com"})


def _rule(key, eid, grant_to, resource="'r/*'", when=None):
    text = (f"{key}:\n  - id: {eid}\n    grant_to: {grant_to}\n    action: x.y\n"
            f"    resource: {resource}\n")
    if when is not None:
        text += f"    when: {when}\n"
    return text


@pytest.mark.parametrize("key", ["entitlements", "deny"])
@pytest.mark.parametrize("resource", [
    "'doc/${args.doc_id}'", "'doc/${request.doc_id'", "'doc/${ request.doc_id }'",
    "'doc/${request.}'", "'doc/${request.a b}'", "'doc/${request.${request.x}}'",
])
def test_malformed_placeholder_is_load_error(tmp_path, key, resource):
    write(tmp_path, "a.apl.yaml", doc("a", AGENT + _rule(key, "r1", "[a1]", resource)))
    with pytest.raises(PolicyLoadError, match=r"a\.apl\.yaml.*'r1'.*placeholder"):
        load_policy_dir(str(tmp_path))


def test_valid_placeholders_load(tmp_path):
    write(tmp_path, "a.apl.yaml",
          doc("a", AGENT + _rule("deny", "r1", "[a1]", "'doc/${request.a_b.c-1}/${request.X9}'")))
    assert [e.id for e in load_policy_dir(str(tmp_path)).entitlements] == ["r1"]


@pytest.mark.parametrize("key", ["entitlements", "deny"])
@pytest.mark.parametrize("selector", ["agent:bot", "bott", "'group:'", "'user:'", "'role:'", "''", "'group:x '", "' group:x'"])
def test_unknown_selector_is_load_error(tmp_path, key, selector):
    write(tmp_path, "a.apl.yaml", doc("a", AGENT + _rule(key, "r1", f"[a1, {selector}]")))
    with pytest.raises(PolicyLoadError, match=r"a\.apl\.yaml.*'r1'.*selector"):
        load_policy_dir(str(tmp_path))


def test_valid_selectors_load(tmp_path):
    write(tmp_path, "a.apl.yaml", doc("a", AGENT))
    # a principal defined in a later file is still a defined principal id
    write(tmp_path, "b.apl.yaml", doc("b", _rule(
        "deny", "r1", "['*', 'user:u@x.com', 'group:g', 'role:r', a1]")))
    assert [e.id for e in load_policy_dir(str(tmp_path)).entitlements] == ["r1"]


@pytest.mark.parametrize("key", ["entitlements", "deny"])
@pytest.mark.parametrize("expr", ["request.x ==", "(", "request.x ++ 1"])
def test_uncompilable_when_is_load_error(tmp_path, key, expr):
    write(tmp_path, "a.apl.yaml", doc("a", AGENT + _rule(key, "r1", "[a1]", when=f"[{expr!r}]")))
    with pytest.raises(PolicyLoadError, match=r"a\.apl\.yaml.*'r1'.*does not compile"):
        load_policy_dir(str(tmp_path))


def test_compilable_when_loads(tmp_path):
    write(tmp_path, "a.apl.yaml",
          doc("a", AGENT + _rule("deny", "r1", "[a1]", when="[\"request.x == 'y'\"]")))
    assert load_policy_dir(str(tmp_path)).entitlements[0].when == ("request.x == 'y'",)


def test_duplicate_policy_version_keeps_compliance(tmp_path):
    write(tmp_path, "a.apl.yaml", doc("p", "compliance: [SOC2]\n" + AGENT))
    write(tmp_path, "b.apl.yaml", doc("p", ENT))
    assert load_policy_dir(str(tmp_path)).frameworks["p@1.0.0"] == ("SOC2",)
    write(tmp_path, "c.apl.yaml", doc("p", "compliance: [NIST-800-53, SOC2]\n"))
    assert load_policy_dir(str(tmp_path)).frameworks["p@1.0.0"] == ("SOC2", "NIST-800-53")
