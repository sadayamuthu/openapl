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


def test_void_allowed(tmp_path):
    log = tmp_path / "d.jsonl"
    log.write_text('{"decision": "DENY", "action": "payments.void"}\n')
    assert not rs.void_allowed(log)
    log.write_text('{"decision": "ALLOW", "action": "payments.void"}\n')
    assert rs.void_allowed(log)
    assert not rs.void_allowed(tmp_path / "missing")


def test_empty_scenarios_exit_1(tmp_path):
    f = tmp_path / "s.yaml"
    f.write_text("scenarios: []\n")
    # gateway wait is skipped by an unreachable URL only after 60s, so patch it
    rs.wait_for_gateway = lambda *a, **k: True
    assert rs.main(["--scenarios", str(f), "--out", str(tmp_path)]) == 1
