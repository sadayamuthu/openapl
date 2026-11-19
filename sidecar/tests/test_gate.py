# sidecar/tests/test_gate.py
import json

from openapl.decision_log import read_log


def call(**args):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "refund_order", "arguments": args}}).encode()


def batch(*calls):
    return ("[" + ",".join(c.decode() for c in calls) + "]").encode()


OPEN = dict(order_id="123", amount=150, account_status="open")


def test_allow_small_refund(gate, alice_claims):
    r = gate.check_mcp("POST", call(**OPEN), alice_claims)
    assert r.decision == "ALLOW" and len(r.decision_ids) == 1


def test_over_limit_requires_approval(gate, alice_claims):
    r = gate.check_mcp("POST", call(**{**OPEN, "amount": 350}), alice_claims)
    assert (r.decision, r.approvers) == ("REQUIRE_APPROVAL", ("role:support-manager",))


def test_bulk_denied(gate, alice_claims):
    r = gate.check_mcp("POST", call(**{**OPEN, "order_id": "bulk-1"}), alice_claims)
    assert r.decision == "DENY"


def test_batch_one_deny_denies_all(gate, alice_claims):
    body = batch(call(**OPEN), call(**{**OPEN, "order_id": "bulk-1", "amount": 10}))
    r = gate.check_mcp("POST", body, alice_claims)
    assert r.decision == "DENY" and len(r.decision_ids) == 2


def test_batch_approval_union(gate, alice_claims):
    body = batch(call(**OPEN), call(**{**OPEN, "amount": 350}))
    r = gate.check_mcp("POST", body, alice_claims)
    assert r.decision == "REQUIRE_APPROVAL" and r.approvers == ("role:support-manager",)


def test_no_claims_denies(gate):
    assert gate.check_mcp("POST", call(**OPEN), None).decision == "DENY"


def test_dev_chain_ignored_outside_dev_mode(gate, alice_claims):
    r = gate.check_mcp("POST", call(**OPEN), None, dev_chain=["user:alice@acme.com"])
    assert r.decision == "DENY"


def test_dev_chain_used_in_dev_mode(dev_gate, alice_claims, tmp_path):
    claims = {k: v for k, v in alice_claims.items() if k != "act"}
    r = dev_gate.check_mcp("POST", call(**OPEN), claims,
                           dev_chain=["user:alice@acme.com", "agent:refund-agent"])
    assert len(r.decision_ids) == 1
    recs, _ = read_log(str(tmp_path / "dev.jsonl"))
    assert recs[0]["dev_mode"] is True


def test_bad_dev_chain_denies(dev_gate, alice_claims):
    assert dev_gate.check_mcp("POST", call(**OPEN), alice_claims, dev_chain=["nope"]).decision == "DENY"


def test_get_and_delete_pass(gate):
    for m in ("GET", "DELETE"):
        r = gate.check_mcp(m, b"", None)
        assert (r.decision, r.reasons, r.approvers, r.decision_ids) == ("ALLOW", (), (), ())


def test_put_denied(gate, alice_claims):
    r = gate.check_mcp("PUT", call(**OPEN), alice_claims)
    assert r.decision == "DENY" and "http method PUT not allowed" in r.reasons


def test_parse_error_denies(gate, alice_claims):
    r = gate.check_mcp("POST", b"{", alice_claims)
    assert r.decision == "DENY" and r.decision_ids == ()


def test_empty_batch_denies(gate, alice_claims):
    assert gate.check_mcp("POST", b"[]", alice_claims).decision == "DENY"


def test_passthrough_only_allows(gate, alice_claims):
    body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
    assert gate.check_mcp("POST", body, alice_claims).decision == "ALLOW"


def test_unbound_placeholder_denies(gate, alice_claims):
    r = gate.check_mcp("POST", call(order_id="123", amount=150), alice_claims)
    assert r.decision == "DENY" and r.decision_ids == ()


def test_every_decision_logged(gate_with_log, alice_claims, tmp_path):
    gate_with_log.check_mcp("POST", batch(call(**OPEN), call(**OPEN)), alice_claims)
    recs, bad = read_log(str(tmp_path / "log.jsonl"))
    assert len(recs) == 2 and bad == 0


def test_log_failure_denies(gate_factory, alice_claims, tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    r = gate_factory(d).check_mcp("POST", call(**OPEN), alice_claims)
    assert r.decision == "DENY" and "decision log write failed" in r.reasons
