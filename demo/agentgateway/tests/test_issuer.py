# demo/agentgateway/tests/test_issuer.py
import json
import os
import stat
import sys
from pathlib import Path

import jwt
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import issuer  # noqa: E402
from openapl.approvals import attributes_hash  # noqa: E402

SUPPORT = "spiffe://acme.com/agents/support-agent"


@pytest.fixture
def out(tmp_path):
    issuer.make_keys(str(tmp_path))
    return str(tmp_path)


def test_jwks_verifies_token(out):
    tok = issuer.mint(out, email="alice@acme.com", groups=["support-staff"], actors=[SUPPORT], now=1000)
    jwks = json.loads((Path(out) / "jwks.json").read_text())
    key = jwt.PyJWK(jwks["keys"][0])
    assert jwks["keys"][0]["kid"] == "demo-1"
    claims = jwt.decode(tok, key.key, algorithms=["RS256"], audience="agentgateway-demo",
                        issuer="https://issuer.demo.openapl.local",
                        options={"verify_exp": False, "verify_iat": False})
    assert claims["email"] == "alice@acme.com"
    assert claims["groups"] == ["support-staff"]
    assert claims["openapl_purpose"] == "customer-refund"
    assert claims["openapl_task_id"] == "t1"
    assert claims["exp"] == 1600 and claims["iat"] == 1000


def test_act_nesting_order(out):
    tok = issuer.mint(out, email="alice@acme.com", groups=[], actors=[SUPPORT, "refund-agent"])
    c = jwt.decode(tok, options={"verify_signature": False})
    assert c["act"]["sub"] == "refund-agent"
    assert c["act"]["act"]["sub"] == SUPPORT
    assert "act" not in c["act"]["act"]


def test_no_actors_no_act(out):
    c = jwt.decode(issuer.mint(out, email="a@b.c", groups=[], actors=[]),
                   options={"verify_signature": False})
    assert "act" not in c


def test_private_key_mode_0600(out):
    mode = stat.S_IMODE(os.stat(Path(out) / "private.pem").st_mode)
    assert mode == 0o600


def test_approval_hash_matches_sdk():
    attrs = {"order_id": "A1", "amount": 350, "account_status": "open"}
    item = issuer.approval_item(entitlement_id="refund-small-orders", approver="role:support-manager",
                                action="payments.refund", resource="order/A1", attributes=attrs,
                                origin="user:alice@acme.com", caller="refund-agent", exp=2000)
    assert item["attributes_hash"] == attributes_hash(attrs)
    assert item["exp"] == 2000 and item["caller"] == "refund-agent"


def test_token_cli_prints_scenario_jwt(out, capsys):
    scenarios = Path(__file__).resolve().parents[1] / "scenarios.yaml"
    assert issuer.main(["token", "--scenario", "approved-retry", "--scenarios", str(scenarios),
                        "--out-dir", out]) == 0
    c = jwt.decode(capsys.readouterr().out.strip(), options={"verify_signature": False})
    assert c["email"] == "alice@acme.com" and c["act"]["sub"] == "refund-agent"
    item = c["openapl_approvals"][0]
    assert item["origin"] == "user:alice@acme.com" and item["caller"] == "refund-agent"
    assert item["attributes_hash"] == attributes_hash({"order_id": "123", "amount": 350, "account_status": "open"})


def test_token_cli_unknown_and_tokenless(out, capsys):
    scenarios = str(Path(__file__).resolve().parents[1] / "scenarios.yaml")
    assert issuer.main(["token", "--scenario", "nope", "--scenarios", scenarios, "--out-dir", out]) == 2
    assert issuer.main(["token", "--scenario", "no-token", "--scenarios", scenarios, "--out-dir", out]) == 2
