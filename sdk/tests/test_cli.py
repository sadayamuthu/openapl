# sdk/tests/test_cli.py
from click.testing import CliRunner

from openapl.cli import main


def test_cli_validate_ok(refund_dir):
    r = CliRunner().invoke(main, ["validate", str(refund_dir)])
    assert r.exit_code == 0
    assert "2 principals, 2 entitlements, 2 denies from 1 files" in r.output


def test_cli_validate_error_exit_1(tmp_path):
    (tmp_path / "bad.apl.yaml").write_text("openapl: '0.1'\n")
    r = CliRunner().invoke(main, ["validate", str(tmp_path)])
    assert r.exit_code == 1
    assert r.output.startswith("✗")


ALLOW_ARGS = [
    "--chain", "user:alice@acme.com,support-agent,refund-agent",
    "--action", "payments.refund", "--resource", "order/123",
    "--attr", "order_id=123", "--attr", "account_status=open",
    "--purpose", "customer-refund", "--task-id", "t1", "--now", "1000",
    "--origin-claims", '{"groups":["support-staff"]}',
]


def _decide(refund_dir, amount, *extra):
    return CliRunner().invoke(
        main, ["decide", str(refund_dir), *ALLOW_ARGS, "--attr", f"amount={amount}", *extra])


def test_cli_decide_allow(refund_dir):
    r = _decide(refund_dir, 150)
    assert r.exit_code == 0, r.output
    assert "DECISION: ALLOW" in r.output


def test_cli_decide_approval_exit_4(refund_dir):
    r = _decide(refund_dir, 350)
    assert r.exit_code == 4, r.output
    assert "DECISION: REQUIRE_APPROVAL" in r.output


def test_cli_decide_json_controls(refund_dir):
    import json
    r = _decide(refund_dir, 150, "--json")
    assert r.exit_code == 0, r.output
    assert json.loads(r.output)["controls"] == [
        "NIST-800-53:AC-3", "NIST-800-53:AC-6", "SOC2:CC6.1", "SOC2:CC6.3"]


def test_cli_decide_writes_log(refund_dir, tmp_path):
    import json
    log = tmp_path / "log.jsonl"
    r = _decide(refund_dir, 150, "--log", str(log))
    assert r.exit_code == 0, r.output
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["decision"] == "ALLOW"


def test_cli_decide_unwritable_log_exit_1(refund_dir, tmp_path):
    r = _decide(refund_dir, 150, "--log", str(tmp_path / "missing" / "log.jsonl"))
    assert r.exit_code == 1
    assert "DECISION: ALLOW" in r.output
    assert "cannot write decision log" in r.output
