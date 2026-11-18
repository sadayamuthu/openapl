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
