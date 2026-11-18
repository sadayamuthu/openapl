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
