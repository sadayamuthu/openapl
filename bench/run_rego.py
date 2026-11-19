# bench/run_rego.py
"""Decide every scenario case with OPA (bench/bin/opa, openpolicyagent/opa:1.22.4-static).

Usage: python bench/run_rego.py --out bench/results/rego.json
One `opa eval` of `data.openapl.decision` per case, with the case as `input`. The decision is
one of "ALLOW", "DENY", "REQUIRE_APPROVAL". A compile error, an undefined or other decision,
or a failing CLI is a mismatch with the CLI output attached. Exits 1 on any mismatch."""
import json
import shutil
import sys
import tempfile
from pathlib import Path

BENCH = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH))

from adapters.rego_input import to_rego  # noqa: E402
from common import Scenario  # noqa: E402
from engine_common import (  # noqa: E402
    DECISIONS, call, main as engine_main, recorded_tools, row, unsupported_cases)

CLI = str(BENCH / "bin" / "opa")
QUERY = "data.openapl.decision"


def parse(code: int, out: str, err: str) -> tuple[str | None, str | None]:
    if code != 0:
        return None, f"opa exit {code}: {(out + err).strip()}"
    try:
        doc = json.loads(out)
        value = doc["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None, f"{QUERY} undefined or unreadable: {(out + err).strip()}"
    if value not in DECISIONS:
        return None, f"{QUERY} = {value!r} is not a decision"
    return value, None


def run(scenarios: list[Scenario]) -> list[dict]:
    rows = []
    for s in scenarios:
        policy = Path(s.path) / "rego" / "policy.rego"
        unsupported = unsupported_cases(s, "rego")
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            if policy.is_file():
                shutil.copy(policy, work / "policy.rego")
            for c in s.cases:
                if c.id in unsupported:
                    rows.append(row(s, c, None, [], None, unsupported[c.id]))
                    continue
                if not policy.is_file():
                    rows.append(row(s, c, None, [], f"missing {policy}"))
                    continue
                (work / "input.json").write_text(json.dumps(to_rego(c)))
                got, error = parse(*call([CLI, "eval", "--format", "json", "-d", "policy.rego",
                                          "-i", "input.json", QUERY], work))
                rows.append(row(s, c, got, [], error))
    return rows


def main(argv: list[str] | None = None) -> int:
    return engine_main("rego", "bench/run_rego.py", run, argv,
                       recorded_tools("opa", "bench/bin/opa"))


if __name__ == "__main__":
    sys.exit(main())
