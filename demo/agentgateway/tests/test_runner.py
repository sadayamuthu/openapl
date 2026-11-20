# demo/agentgateway/tests/test_runner.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_scenarios as rs  # noqa: E402

CALL = {"id": "x", "tool": "payments_refund_order", "expect": {"status": 200}}
LIST = {"id": "y", "method": "tools/list", "expect": {"status": 200}}


def _run(sc, res, decision=""):
    got = {"status": 200, "decision": decision, "reasons": [], "note": rs.ok_note(sc, res, decision)}
    return rs.check(sc, got)


def test_good_results_pass():
    assert _run(CALL, {"content": [{"type": "text", "text": "{}"}], "isError": False}) == []
    assert _run(LIST, {"tools": [{"name": "a"}]}) == []


def test_is_error_fails():
    assert _run(CALL, {"content": [], "isError": True})


def test_none_result_fails():
    assert _run(CALL, None) and _run(LIST, None)


def test_jsonrpc_error_at_200_fails():
    assert _run(CALL, {"code": -32602, "message": "bad"})


def test_deny_header_on_200_fails():
    assert _run(CALL, {"content": []}, decision="DENY")


def test_void_log_fails_closed(tmp_path):
    log = tmp_path / "d.jsonl"
    assert rs.void_log_note(log)  # missing
    log.write_text("")
    assert rs.void_log_note(log)  # empty
    log.write_text("not json\n")
    assert rs.void_log_note(log)  # no valid record
    log.write_text('{"decision": "ALLOW", "action": "payments.void"}\n')
    assert "ALLOW" in rs.void_log_note(log)
    log.write_text('garbage\n{"decision": "ALLOW", "action": "payments.refund"}\n'
                   '{"decision": "DENY", "action": "payments.void"}\n')
    assert rs.void_log_note(log) == ""


def test_empty_scenarios_exit_1(tmp_path, monkeypatch):
    f = tmp_path / "s.yaml"
    f.write_text("scenarios: []\n")
    monkeypatch.setattr(rs, "wait_for_gateway", lambda *a, **k: True)
    assert rs.main(["--scenarios", str(f), "--out", str(tmp_path)]) == 1


class FakeClient:
    def __init__(self, status):
        self.status, self.sent = status, []

    def request(self, method, params=None):
        self.sent.append(method)
        return self.status, None, {}

    def call(self, name, arguments):
        self.sent.append(name)
        return self.status, None, {}


NOTOKEN = {"id": "n", "method": "tools/list", "expect": {"status": 401}}


def test_no_token_sends_scenario_request():
    c = FakeClient(401)
    got = rs.no_token_result(NOTOKEN, c, 401)
    assert c.sent == ["tools/list"] and got["status"] == 401 and rs.check(NOTOKEN, got) == []


def test_no_token_list_succeeding_fails():
    got = rs.no_token_result(NOTOKEN, FakeClient(200), 401)
    assert rs.check(NOTOKEN, got)


def test_no_token_initialize_200_fails():
    assert rs.check(NOTOKEN, rs.no_token_result(NOTOKEN, FakeClient(401), 200))


def test_never_executed_drives_log_check():
    sc = {"id": "b", "expect": {"status": [400, 403], "never_executed": True}}
    base = {"status": 403, "decision": "", "reasons": [], "note": ""}
    assert rs.check(sc, {**base, "void_log": ""}) == []
    assert rs.check(sc, {**base, "void_log": "decision log holds an ALLOW for payments.void"})
    assert rs.check(sc, base)  # not checked -> failure
    sc2 = {"id": "b", "expect": {"status": [400, 403]}}
    assert rs.check(sc2, {**base, "void_log": "x"}) == []
