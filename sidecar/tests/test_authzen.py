# sidecar/tests/test_authzen.py
import dataclasses
import json
import logging
import threading
import urllib.error
import urllib.request

import pytest

from openapl_sidecar.authzen import make_authzen_server
from openapl_sidecar.config import Settings

BASE = "https://pdp.example.com"


def make_settings(token="t", base_url=BASE, dev_mode=False):
    return Settings(policy_dir="", bindings_path=None, decision_log=None, pdp_token=token,
                    dev_mode=dev_mode, bind_host="127.0.0.1", authzen_port=0, extauthz_port=0,
                    claims_namespace="ns", claims_field=None, pdp_base_url=base_url)


@pytest.fixture
def serve():
    started = []

    def start(gate, **kw):
        server = make_authzen_server(gate, make_settings(**kw), port=0)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        started.append((server, t))
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server, t in started:
        server.shutdown()
        server.server_close()
        t.join()


def http(url, path, body=None, method=None, headers=None, raw=None):
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    h = dict(headers or {})
    if data is not None:
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, dict(r.headers), json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read() or b"null")


AUTH = {"Authorization": "Bearer t"}


def evaluation(claims, amount=150, rid="123"):
    return {
        "subject": {"type": "user", "id": "alice@acme.com"},
        "action": {"name": "payments.refund"},
        "resource": {"type": "order", "id": rid,
                     "properties": {"order_id": rid, "amount": amount,
                                    "account_status": "open"}},
        "context": {"claims": claims},
    }


def post(url, body, path="/access/v1/evaluation", headers=AUTH):
    return http(url, path, body, headers=headers)


def test_healthz_no_auth(serve, gate):
    assert http(serve(gate), "/healthz")[::2] == (200, {"status": "ok"})


def test_well_known_404_without_base_url(serve, gate):
    assert http(serve(gate, base_url=None), "/.well-known/authzen-configuration")[0] == 404


def test_well_known_fields(serve, gate):
    status, _, body = http(serve(gate), "/.well-known/authzen-configuration")
    assert status == 200
    assert body["policy_decision_point"] == BASE
    assert body["access_evaluation_endpoint"] == BASE + "/access/v1/evaluation"
    assert body["access_evaluations_endpoint"] == BASE + "/access/v1/evaluations"


def test_unknown_route_404(serve, gate):
    assert http(serve(gate), "/nope")[0] == 404


def test_missing_token_401_with_www_authenticate(serve, gate, alice_claims):
    status, headers, body = post(serve(gate), evaluation(alice_claims), headers={})
    assert status == 401
    assert headers["WWW-Authenticate"] == "Bearer"
    assert body == {"error": "unauthorized"}


def test_wrong_token_401(serve, gate, alice_claims):
    status, _, _ = post(serve(gate), evaluation(alice_claims),
                        headers={"Authorization": "Bearer nope"})
    assert status == 401


def test_allow_true(serve, gate, alice_claims):
    status, _, body = post(serve(gate), evaluation(alice_claims))
    assert status == 200
    assert body["decision"] is True
    assert body["context"]["openapl"]["decision"] == "ALLOW"


def test_require_approval_is_false_with_openapl_context(serve, gate, alice_claims):
    status, _, body = post(serve(gate), evaluation(alice_claims, amount=350))
    assert status == 200
    assert body["decision"] is False
    o = body["context"]["openapl"]
    assert o["decision"] == "REQUIRE_APPROVAL"
    assert o["approvers"] == ["role:support-manager"]
    assert o["decision_id"]


def test_missing_resource_400(serve, gate, alice_claims):
    ev = evaluation(alice_claims)
    del ev["resource"]
    assert post(serve(gate), ev)[0] == 400


def test_non_json_content_type_400(serve, gate, alice_claims):
    status, _, _ = http(serve(gate), "/access/v1/evaluation", evaluation(alice_claims),
                        headers={**AUTH, "Content-Type": "text/plain"})
    assert status == 400


def test_invalid_json_and_non_object_400(serve, gate):
    url = serve(gate)
    assert http(url, "/access/v1/evaluation", raw=b"{nope", headers=AUTH)[0] == 400
    assert http(url, "/access/v1/evaluation", raw=b"[1]", headers=AUTH)[0] == 400


def test_body_over_1mib_413(serve, gate):
    status, _, _ = http(serve(gate), "/access/v1/evaluation", raw=b" " * (1024 * 1024 + 1),
                        headers=AUTH)
    assert status == 413


def test_attribute_twice_400(serve, gate, alice_claims):
    ev = evaluation(alice_claims)
    ev["context"]["attributes"] = {"amount": 1}
    status, _, body = post(serve(gate), ev)
    assert status == 400
    assert "attribute 'amount' given twice" in json.dumps(body)


def test_subject_mismatch_400(serve, gate, alice_claims):
    ev = evaluation(alice_claims)
    ev["subject"]["id"] = "mallory@acme.com"
    status, _, body = post(serve(gate), ev)
    assert status == 400
    assert "subject.id does not match claims" in json.dumps(body)


def test_request_id_echoed(serve, gate, alice_claims):
    url = serve(gate)
    _, h, _ = post(url, evaluation(alice_claims), headers={**AUTH, "X-Request-ID": "rid-1"})
    assert h["X-Request-ID"] == "rid-1"
    _, h, _ = http(url, "/healthz", headers={"X-Request-ID": "rid-2"})
    assert h["X-Request-ID"] == "rid-2"
    _, h, _ = post(url, {}, headers={"X-Request-ID": "rid-3"})  # 401
    assert h["X-Request-ID"] == "rid-3"


def test_unexpected_exception_denies(serve, gate, alice_claims):
    def boom(*a, **k):
        raise RuntimeError("x")
    gate.decide = boom
    status, _, body = post(serve(gate), evaluation(alice_claims))
    assert status == 200
    assert body["decision"] is False
    assert "internal error" in body["context"]["openapl"]["reasons"]


def test_batch_defaults_and_override(serve, gate, alice_claims):
    body = evaluation(alice_claims)
    body["evaluations"] = [{"resource": {"type": "order", "id": "1",
                                         "properties": {"order_id": "1", "amount": 150,
                                                        "account_status": "open"}}},
                           {"resource": {"type": "order", "id": "2",
                                         "properties": {"order_id": "2", "amount": 350,
                                                        "account_status": "open"}}}]
    status, _, out = post(serve(gate), body, "/access/v1/evaluations")
    assert status == 200
    assert "decision" not in out
    assert [e["decision"] for e in out["evaluations"]] == [True, False]
    assert out["evaluations"][1]["context"]["openapl"]["decision"] == "REQUIRE_APPROVAL"


def _batch(claims, amounts, semantic=None):
    body = evaluation(claims)
    body["evaluations"] = [{"resource": {"type": "order", "id": str(i),
                                         "properties": {"order_id": str(i), "amount": a,
                                                        "account_status": "open"}}}
                           for i, a in enumerate(amounts)]
    if semantic:
        body["options"] = {"evaluations_semantic": semantic}
    return body


def test_batch_deny_on_first_deny_truncates(serve, gate, alice_claims):
    _, _, out = post(serve(gate), _batch(alice_claims, [150, 350, 150], "deny_on_first_deny"),
                     "/access/v1/evaluations")
    assert [e["decision"] for e in out["evaluations"]] == [True, False]


def test_batch_permit_on_first_permit_truncates(serve, gate, alice_claims):
    _, _, out = post(serve(gate), _batch(alice_claims, [350, 150, 150], "permit_on_first_permit"),
                     "/access/v1/evaluations")
    assert [e["decision"] for e in out["evaluations"]] == [False, True]


def test_batch_item_error_in_place(serve, gate, alice_claims):
    body = _batch(alice_claims, [150, 150, 150])
    body["evaluations"][1]["resource"] = {"type": "", "id": "x"}
    status, _, out = post(serve(gate), body, "/access/v1/evaluations")
    assert status == 200
    d = [e["decision"] for e in out["evaluations"]]
    assert d == [True, False, True]
    assert out["evaluations"][1]["context"]["error"]["status"] == 400


def test_batch_error_counts_as_deny(serve, gate, alice_claims):
    body = _batch(alice_claims, [150, 150, 150], "deny_on_first_deny")
    body["evaluations"][1]["resource"] = {"type": "", "id": "x"}
    _, _, out = post(serve(gate), body, "/access/v1/evaluations")
    assert len(out["evaluations"]) == 2


def test_batch_item_exception_is_500_item(serve, gate, alice_claims):
    def boom(*a, **k):
        raise RuntimeError("x")
    gate.decide = boom
    _, _, out = post(serve(gate), _batch(alice_claims, [150]), "/access/v1/evaluations")
    e = out["evaluations"][0]
    assert e["decision"] is False and e["context"]["error"]["status"] == 500


def test_batch_without_evaluations_is_single_shape(serve, gate, alice_claims):
    _, _, out = post(serve(gate), evaluation(alice_claims), "/access/v1/evaluations")
    assert out["decision"] is True


def test_batch_over_100_400(serve, gate, alice_claims):
    body = _batch(alice_claims, [150] * 101)
    assert post(serve(gate), body, "/access/v1/evaluations")[0] == 400


def test_unknown_semantic_400(serve, gate, alice_claims):
    assert post(serve(gate), _batch(alice_claims, [150], "bogus"),
                "/access/v1/evaluations")[0] == 400


CHAIN = ["user:alice@acme.com", "support-agent", "refund-agent"]


def test_dev_mode_context_chain_used(serve, dev_gate):
    claims = {"email": "alice@acme.com", "groups": ["support-staff"],
              "openapl_purpose": "customer-refund", "openapl_task_id": "t1", "iat": 900}
    ev = evaluation(claims)
    ev["context"]["chain"] = CHAIN
    status, _, body = post(serve(dev_gate, token=None), ev, headers={})
    assert status == 200 and body["decision"] is True


ROGUE = ["user:alice@acme.com", "rogue-agent"]
PLAIN = {"email": "alice@acme.com", "groups": ["support-staff"],
         "openapl_purpose": "customer-refund", "openapl_task_id": "t1", "iat": 900}


def test_dev_mode_rogue_chain_denied(serve, dev_gate):
    ev = evaluation(PLAIN)
    ev["context"]["chain"] = ROGUE
    _, _, body = post(serve(dev_gate, token=None), ev, headers={})
    assert body["decision"] is False


def test_context_chain_ignored_outside_dev_mode(serve, gate):
    ev = evaluation(PLAIN)
    ev["context"]["chain"] = ROGUE
    _, _, body = post(serve(gate), ev)
    assert body["decision"] is True  # chain ignored; claims-derived chain used


def test_nan_rejected_400(serve, gate):
    raw = (b'{"subject":{"type":"user","id":"a"},"action":{"name":"x"},'
           b'"resource":{"type":"o","id":"1","properties":{"amount":NaN}}}')
    assert http(serve(gate), "/access/v1/evaluation", raw=raw, headers=AUTH)[0] == 400
    assert http(serve(gate), "/access/v1/evaluation", raw=raw.replace(b"NaN", b"-Infinity"),
                headers=AUTH)[0] == 400


def test_subject_checked_against_email_first(serve, gate):
    ev = evaluation({"email": "mallory@x", "sub": "alice@acme.com",
                     "openapl_purpose": "customer-refund", "openapl_task_id": "t1", "iat": 900})
    assert post(serve(gate), ev)[0] == 400


def test_sub_only_claims_matching_evaluated(serve, gate):
    ev = evaluation({"sub": "alice@acme.com"})
    status, _, body = post(serve(gate), ev)
    assert status == 200 and "openapl" in body["context"]


def test_slow_client_disconnected(serve, gate, monkeypatch):
    import socket

    import openapl_sidecar.authzen as az
    monkeypatch.setattr(az, "REQUEST_TIMEOUT", 0.5)
    url = serve(gate)
    host, port = url[len("http://"):].split(":")
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(b"POST /access/v1/evaluation HTTP/1.1\r\nContent-Le")
    assert s.recv(10) == b""  # server closed after timeout
    s.close()


def test_bad_content_length_400(serve, gate):
    status, _, _ = http(serve(gate), "/access/v1/evaluation", raw=b"{}",
                        headers={**AUTH, "Content-Length": "+2"})
    assert status == 400


def test_transfer_encoding_400(serve, gate):
    # A raw socket avoids a client-side EPIPE race: the server rejects the request
    # and closes without reading the body.
    import socket
    port = int(serve(gate).rsplit(":", 1)[1])
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(b"POST /access/v1/evaluation HTTP/1.1\r\nHost: x\r\n"
                  b"Authorization: Bearer t\r\nContent-Type: application/json\r\n"
                  b"Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
        first = s.recv(64)
    assert first.startswith(b"HTTP/1.0 400") or first.startswith(b"HTTP/1.1 400")


def _raw_eval(claims, **over):
    return json.dumps({**evaluation(claims), **over})


@pytest.mark.parametrize("big", ["1e999", "-1e999"])
@pytest.mark.parametrize("where", ["properties", "attributes", "claims"])
def test_overflowing_number_400(serve, gate, alice_claims, big, where):
    ev = evaluation(alice_claims)
    text = json.dumps(ev)
    if where == "properties":
        text = text.replace('"amount": 150', f'"amount": {big}')
    elif where == "attributes":
        text = text.replace('"claims"', f'"attributes": {{"amount2": {big}}}, "claims"')
    else:
        text = text.replace('"claims": {', f'"claims": {{"x": {big}, ')
    assert big in text
    status, _, _ = http(serve(gate), "/access/v1/evaluation", raw=text.encode(), headers=AUTH)
    assert status == 400


def test_duplicate_key_in_properties_400(serve, gate, alice_claims):
    text = json.dumps(evaluation(alice_claims)).replace(
        '"amount": 150', '"amount": 150, "amount": 5')
    status, _, _ = http(serve(gate), "/access/v1/evaluation", raw=text.encode(), headers=AUTH)
    assert status == 400


def test_duplicate_top_level_key_400(serve, gate, alice_claims):
    text = json.dumps(evaluation(alice_claims))[:-1] + ', "action": {"name": "x"}}'
    status, _, _ = http(serve(gate), "/access/v1/evaluation", raw=text.encode(), headers=AUTH)
    assert status == 400


def test_authzen_internal_error_is_logged(serve, gate, alice_claims, caplog):
    def boom(*a, **k):
        raise RuntimeError("x")
    gate.decide = boom
    with caplog.at_level(logging.ERROR, logger="openapl_sidecar"):
        post(serve(gate), evaluation(alice_claims))
    assert any(r.name == "openapl_sidecar" and r.exc_info for r in caplog.records)
