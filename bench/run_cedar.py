# bench/run_cedar.py
"""Decide every scenario case with the Cedar CLI (bench/bin/cedar, cedar-policy-cli 4.15.0).

Usage: python bench/run_cedar.py --out bench/results/cedar.json
Per scenario: `cedar validate` against the schema, then one `cedar authorize -v` per case.
Cedar has two decisions. REQUIRE_APPROVAL is encoded as a reason: a permit whose @id starts
with `needs-approval:` marks the approval path, and an ALLOW determined only by such permits
is reported as REQUIRE_APPROVAL. Any CLI failure, schema violation or policy evaluation error
is a mismatch with the CLI output attached. Exits 1 on any mismatch."""
import json
import shutil
import sys
import tempfile
from pathlib import Path

BENCH = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH))

from adapters.cedar_input import to_cedar  # noqa: E402
from common import Scenario  # noqa: E402
from engine_common import call, main as engine_main, row, unsupported_cases  # noqa: E402

CLI = str(BENCH / "bin" / "cedar")
FILES = ("policies.cedar", "schema.cedarschema", "entities.json")
APPROVAL_PREFIX = "needs-approval:"
TOOL = {"cli": "cedar-policy-cli 4.15.0", "wrapper": "bench/bin/cedar"}


def parse(code: int, out: str, err: str) -> tuple[str | None, list[str], str | None]:
    """-> (decision, determining policy ids + evaluation errors, error)."""
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if code not in (0, 2) or not lines or lines[0] not in ("ALLOW", "DENY"):
        return None, [], f"cedar exit {code}: {err.strip() or out.strip()}"
    eval_errors = [ln for ln in lines if ln.startswith("error while evaluating policy")]
    policies: list[str] = []
    if "note: this decision was due to the following policies:" in lines:
        policies = lines[lines.index("note: this decision was due to the following policies:")
                         + 1:]
        policies = [p for p in policies if not p.startswith(("error", "note:"))]
    if eval_errors or err.strip():
        return None, policies + eval_errors, "; ".join(eval_errors) or err.strip()
    decision = lines[0]
    if decision == "ALLOW" and policies and all(p.startswith(APPROVAL_PREFIX) for p in policies):
        decision = "REQUIRE_APPROVAL"
    return decision, policies, None


def run(scenarios: list[Scenario]) -> list[dict]:
    rows = []
    for s in scenarios:
        src = Path(s.path) / "cedar"
        unsupported = unsupported_cases(s, "cedar")
        derived_file = src / "derived.json"
        derived = json.loads(derived_file.read_text()) if derived_file.is_file() else None
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            missing = [f for f in FILES if not (src / f).is_file()]
            for f in FILES:
                if (src / f).is_file():
                    shutil.copy(src / f, work / f)
            setup_error = f"missing translation files {missing}" if missing else None
            if setup_error is None:
                code, out, err = call([CLI, "validate", "--schema", "schema.cedarschema",
                                       "--policies", "policies.cedar"], work)
                if code != 0:
                    setup_error = f"cedar validate exit {code}: {(out + err).strip()}"
            static = json.loads((work / "entities.json").read_text()) if not missing else []
            for c in s.cases:
                if c.id in unsupported:
                    rows.append(row(s, c, None, [], None, unsupported[c.id]))
                    continue
                if setup_error is not None:
                    rows.append(row(s, c, None, [], setup_error))
                    continue
                req = to_cedar(c, derived)
                (work / "case.entities.json").write_text(json.dumps(static + req.entities))
                (work / "case.request.json").write_text(json.dumps(req.request_json()))
                got, reasons, error = parse(*call(
                    [CLI, "authorize", "-v", "--schema", "schema.cedarschema",
                     "--policies", "policies.cedar", "--entities", "case.entities.json",
                     "--request-json", "case.request.json"], work))
                rows.append(row(s, c, got, reasons, error))
    return rows


def main(argv: list[str] | None = None) -> int:
    return engine_main("cedar", "bench/run_cedar.py", run, argv, TOOL)


if __name__ == "__main__":
    sys.exit(main())
