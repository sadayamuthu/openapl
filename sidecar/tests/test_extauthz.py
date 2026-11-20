# sidecar/tests/test_extauthz.py
import json
import logging
import re

import grpc
import pytest
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from google.protobuf.struct_pb2 import Struct
from openapl import Authorizer

from openapl_sidecar.bindings import load_bindings
from openapl_sidecar.config import Settings
from openapl_sidecar.extauthz import grpc_address, make_extauthz_server
from openapl_sidecar.gate import Gate

NS = "envoy.filters.http.jwt_authn"
OPEN = dict(order_id="123", amount=150, account_status="open")


def call(**args):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "refund_order", "arguments": args}}).encode()


def make_settings(dev_mode=False):
    return Settings(policy_dir="", bindings_path=None, decision_log=None, pdp_token=None,
                    dev_mode=dev_mode, bind_host="127.0.0.1", authzen_port=0, extauthz_port=0,
                    claims_namespace=NS, claims_field="jwt_payload", pdp_base_url=None)


@pytest.fixture
def serve():
    started = []

    def start(gate, dev_mode=False):
        server, port = make_extauthz_server(gate, make_settings(dev_mode), port=0)
        server.start()
        channel = grpc.insecure_channel(f"127.0.0.1:{port}")
        started.append((server, channel))
        stub = external_auth_pb2_grpc.AuthorizationStub(channel)

        def check(body, claims, method="POST", headers=None, pack_bytes=False):
            req = external_auth_pb2.CheckRequest()
            http = req.attributes.request.http
            http.method = method
            for k, v in (headers or {}).items():
                http.headers[k] = v
            if pack_bytes:
                http.raw_body = body
            else:
                http.body = body.decode("utf-8", errors="replace")
            if claims is not None:
                s = Struct()
                s.update({"jwt_payload": claims})
                req.attributes.metadata_context.filter_metadata[NS].CopyFrom(s)
            return stub.Check(req, timeout=5)
        return check

    yield start
    for server, channel in started:
        channel.close()
        server.stop(grace=None).wait()


def hdrs(resp):
    return {h.header.key: h.header.value for h in resp.denied_response.headers}


def test_allow_returns_ok(serve, gate, alice_claims):
    resp = serve(gate)(call(**OPEN), alice_claims)
    assert resp.status.code == 0
    assert resp.HasField("ok_response")
    md = resp.dynamic_metadata["openapl"]
    assert md["decision"] == "ALLOW" and len(md["decision_ids"]) == 1


def test_approval_returns_403_with_headers(serve, gate, alice_claims):
    resp = serve(gate)(call(**{**OPEN, "amount": 350}), alice_claims)
    assert resp.status.code == 7
    assert resp.denied_response.status.code == 403
    h = hdrs(resp)
    assert h["x-openapl-decision"] == "REQUIRE_APPROVAL"
    assert h["content-type"] == "application/json"
    body = json.loads(resp.denied_response.body)
    assert body["approvers"] == ["role:support-manager"]
    assert h["x-openapl-decision-id"] == body["decision_id"] == body["decision_ids"][0]


def test_raw_body_used(serve, gate, alice_claims):
    resp = serve(gate)(call(**OPEN), alice_claims, pack_bytes=True)
    assert resp.status.code == 0


def test_iat_survives_struct(serve, refund_dir, bindings_file, alice_claims):
    f = refund_dir / "refund-delegation.apl.yaml"
    text = f.read_text()
    new, n = re.subn(r"expires: task", "expires: 1h", text, count=1)
    assert n == 1
    f.write_text(new)
    gate = Gate(Authorizer.from_dir(str(refund_dir)), load_bindings(bindings_file), None,
                False, clock=lambda: 1000)
    resp = serve(gate)(call(**OPEN), alice_claims)
    assert resp.status.code == 0, resp.denied_response.body


def test_unparseable_body_403(serve, gate, alice_claims):
    resp = serve(gate)(b"{not json", alice_claims)
    assert resp.status.code == 7 and resp.denied_response.status.code == 403
    assert hdrs(resp)["x-openapl-decision"] == "DENY"
    assert hdrs(resp)["x-openapl-decision-id"] == ""


def test_internal_error_403(serve, gate, alice_claims, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(gate, "check_mcp", boom)
    resp = serve(gate)(call(**OPEN), alice_claims)
    assert resp.status.code == 7 and resp.denied_response.status.code == 403
    body = json.loads(resp.denied_response.body)
    assert body["decision"] == "DENY" and body["reasons"] == ["internal error"]


CHAIN = {"x-openapl-chain": "user:alice@acme.com, support-agent, refund-agent"}


def test_dev_header_ignored_without_dev_mode(serve, gate, alice_claims):
    claims = {**alice_claims, "act": {"sub": "unknown-agent"}}
    resp = serve(gate)(call(**OPEN), claims, headers=CHAIN)
    assert resp.status.code == 7
    assert hdrs(resp)["x-openapl-decision"] == "DENY"


def test_dev_header_used_in_dev_mode(serve, dev_gate, alice_claims):
    claims = {**alice_claims, "act": {"sub": "unknown-agent"}}
    resp = serve(dev_gate, dev_mode=True)(call(**OPEN), claims, headers=CHAIN)
    assert resp.status.code == 0


def test_internal_error_is_logged(serve, gate, alice_claims, monkeypatch, caplog):
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(gate, "check_mcp", boom)
    with caplog.at_level(logging.ERROR, logger="openapl_sidecar"):
        serve(gate)(call(**OPEN), alice_claims)
    assert any(r.name == "openapl_sidecar" and r.exc_info for r in caplog.records)


def test_grpc_address_brackets_ipv6():
    assert grpc_address("0.0.0.0", 9000) == "0.0.0.0:9000"
    assert grpc_address("::", 9000) == "[::]:9000"
    assert grpc_address("::1", 1) == "[::1]:1"
