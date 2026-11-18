# sdk/tests/test_cli.py
import json

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


import pytest

from openapl.cli import _parse_value


@pytest.mark.parametrize("text,expected", [
    ("150", 150), ("-3", -3), ("2.5", 2.5),
    ("nan", "nan"), ("inf", "inf"), ("-inf", "-inf"), ("infinity", "infinity"),
    ("1_000", "1_000"), ("+5", "+5"), (" 12 ", " 12 "), ("123abc", "123abc"),
    ("١٢٣", "١٢٣"), ("1e3", "1e3"),
])
def test_parse_value_strict(text, expected):
    got = _parse_value(text)
    assert got == expected and type(got) is type(expected)


def test_cli_decide_bad_approval_exit_1(refund_dir):
    assert _decide(refund_dir, 150, "--approval", "{nope").exit_code == 1
    assert _decide(refund_dir, 150, "--approval", '{"exp": 1}').exit_code == 1


def test_cli_decide_bad_origin_claims_exit_1(refund_dir):
    args = [a if not a.startswith('{"groups') else "{bad" for a in ALLOW_ARGS]
    r = CliRunner().invoke(main, ["decide", str(refund_dir), *args, "--attr", "amount=1"])
    assert r.exit_code == 1


def test_cli_decide_deny_exit_3(refund_dir):
    args = [a if a != "account_status=open" else "account_status=closed" for a in ALLOW_ARGS]
    r = CliRunner().invoke(main, ["decide", str(refund_dir), *args, "--attr", "amount=150"])
    assert r.exit_code == 3, r.output
    assert "DECISION: DENY" in r.output


def test_cli_explain_text(refund_dir):
    r = CliRunner().invoke(main, ["explain", str(refund_dir), "support-agent"])
    assert r.exit_code == 0
    assert "REACH IF COMPROMISED" in r.output
    assert "support-agent → refund-agent" in r.output


def test_cli_explain_unknown_principal(refund_dir):
    r = CliRunner().invoke(main, ["explain", str(refund_dir), "nobody"])
    assert r.exit_code == 1
    assert "✗ unknown principal nobody" in r.output


def test_cli_explain_on_behalf_of_json(refund_dir):
    r = CliRunner().invoke(main, ["explain", str(refund_dir), "support-agent", "--json",
                                  "--on-behalf-of", "group:marketing"])
    assert r.exit_code == 0
    assert json.loads(r.output)["reach"] == []


def test_cli_inventory_json(refund_dir):
    r = CliRunner().invoke(main, ["inventory", str(refund_dir), "--json"])
    assert r.exit_code == 0
    assert [row["id"] for row in json.loads(r.output)] == ["refund-agent", "support-agent"]


def test_cli_inventory_table(refund_dir):
    r = CliRunner().invoke(main, ["inventory", str(refund_dir)])
    assert r.exit_code == 0
    assert "support-agent" in r.output and "refund-small-orders" in r.output
