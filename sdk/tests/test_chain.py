# sdk/tests/test_chain.py
import pytest

from openapl.approvals import attributes_hash
from openapl.chain import ChainError, chain_from_claims, chain_from_list, request_from_claims

NOW = 1_700_000_000


def _ids(chain):
    return [l.principal_id for l in chain]


def test_rfc8693_nested_act_order(ps):
    claims = {"sub": "alice", "email": "alice@acme.com", "groups": ["support-staff"],
              "act": {"sub": "refund-agent", "act": {"sub": "spiffe://acme.com/agents/support-agent"}}}
    chain = chain_from_claims(claims, ps)
    assert _ids(chain) == ["user:alice@acme.com", "support-agent", "refund-agent"]
    assert chain[0].kind == "human"
    assert chain[0].claims["groups"] == ["support-staff"]
    assert "act" not in chain[0].claims
    assert chain[1].kind == "agent"


def test_no_act_is_single_human_link(ps):
    chain = chain_from_claims({"sub": "alice"}, ps)
    assert _ids(chain) == ["user:alice"]
    assert chain[0].kind == "human"


def test_missing_sub_and_email_raises(ps):
    with pytest.raises(ChainError):
        chain_from_claims({"groups": []}, ps)


def test_non_dict_act_raises(ps):
    with pytest.raises(ChainError):
        chain_from_claims({"sub": "a", "act": "refund-agent"}, ps)
    with pytest.raises(ChainError):
        chain_from_claims({"sub": "a", "act": {"sub": "refund-agent", "act": 5}}, ps)


def test_actor_without_sub_raises(ps):
    with pytest.raises(ChainError):
        chain_from_claims({"sub": "a", "act": {"iss": "x"}}, ps)


def test_jwt_identity_resolution(ps):
    import dataclasses
    p = dataclasses.replace(ps.principals["refund-agent"], identity={"jwt": {"iss": "https://i", "sub": "s1"}})
    ps2 = dataclasses.replace(ps, principals={**ps.principals, "refund-agent": p})
    chain = chain_from_claims({"sub": "a", "act": {"iss": "https://i", "sub": "s1"}}, ps2)
    assert _ids(chain) == ["user:a", "refund-agent"]


def test_unknown_actor_denied(ps, authorizer):
    claims = {"sub": "alice", "email": "alice@acme.com", "act": {"sub": "mystery-bot"}}
    chain = chain_from_claims(claims, ps)
    assert chain[1].principal_id == "unknown:mystery-bot"
    d = authorizer.decide(request_from_claims(claims, ps, "payments.refund", "orders/1", {}, NOW))
    assert d.decision == "DENY"
    assert any("unknown principal unknown:mystery-bot" in r for r in d.reasons)


def test_deep_act_raises_chain_error(ps, authorizer):
    act = {"sub": "refund-agent"}
    for _ in range(1000):
        act = {"sub": "refund-agent", "act": act}
    claims = {"sub": "alice", "act": act}
    with pytest.raises(ChainError):
        chain_from_claims(claims, ps)
    d = authorizer.decide(request_from_claims(claims, ps, "payments.refund", "orders/1", {}, NOW))
    assert d.decision == "DENY"


def test_request_reads_purpose_from_claims_only(ps):
    claims = {"sub": "alice", "openapl_purpose": "refund", "openapl_task_id": "t1", "iat": 123}
    r = request_from_claims(claims, ps, "a", "r", {"purpose": "x", "task_id": "evil"}, NOW)
    assert r.purpose == "refund"
    assert r.task_id == "t1"
    assert r.token_iat == 123
    assert r.now == NOW
    r2 = request_from_claims({"sub": "alice"}, ps, "a", "r", {"purpose": "x"}, NOW)
    assert r2.purpose is None and r2.task_id is None and r2.token_iat is None


def test_iat_must_be_int(ps):
    for bad in ("123", 1.5, True, None):
        r = request_from_claims({"sub": "alice", "iat": bad}, ps, "a", "r", {}, NOW)
        assert r.token_iat is None


def _approval(**over):
    item = {"entitlement_id": "e1", "approver": "bob@acme.com", "action": "payments.refund",
            "resource": "orders/1", "attributes_hash": attributes_hash({"amount": 350}),
            "origin": "user:alice@acme.com", "caller": "refund-agent", "exp": NOW + 60}
    item.update(over)
    return item


def test_request_parses_approvals(ps):
    claims = {"sub": "alice", "openapl_approvals": [_approval()]}
    r = request_from_claims(claims, ps, "a", "r", {}, NOW)
    assert len(r.approvals) == 1 and r.approvals[0].approver == "bob@acme.com"
    assert len(r.chain) == 1


def test_request_bad_approval_gives_empty_chain(ps):
    bad = _approval()
    del bad["exp"]
    r = request_from_claims({"sub": "alice", "openapl_approvals": [bad]}, ps, "a", "r", {}, NOW)
    assert r.chain == ()


def test_non_list_approvals_gives_empty_chain(ps):
    for bad in ({"a": 1}, "x", 5):
        r = request_from_claims({"sub": "alice", "openapl_approvals": bad}, ps, "a", "r", {}, NOW)
        assert r.chain == ()


def test_request_chain_error_gives_empty_chain(ps, authorizer):
    claims = {"act": {"sub": "refund-agent"}}
    r = request_from_claims(claims, ps, "a", "r", {}, NOW)
    assert r.chain == ()
    d = authorizer.decide(r)
    assert d.decision == "DENY" and any("empty chain" in x for x in d.reasons)


def test_chain_from_list(ps):
    chain = chain_from_list(["user:alice@acme.com", "support-agent", "refund-agent"], ps)
    assert _ids(chain) == ["user:alice@acme.com", "support-agent", "refund-agent"]
    assert [l.kind for l in chain] == ["human", "agent", "agent"]


def test_chain_from_list_unknown_and_origin_claims(ps):
    chain = chain_from_list(["user:a", "ghost"], ps, {"groups": ["g"]})
    assert chain[0].claims == {"groups": ["g"]}
    assert chain[1].principal_id == "unknown:ghost"


def test_chain_from_list_requires_user_origin(ps):
    with pytest.raises(ChainError):
        chain_from_list(["support-agent"], ps)
    with pytest.raises(ChainError):
        chain_from_list([], ps)
