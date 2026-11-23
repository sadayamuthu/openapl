# bench/engine_common.py
"""Shared runner plumbing for the CLI engines (Cedar, OPA): verdicts, rows and the CLI main."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

from common import Case, Scenario, load_scenarios

DECISIONS = ("ALLOW", "DENY", "REQUIRE_APPROVAL")
TIMEOUT_S = 120


def unsupported_cases(scenario: Scenario, engine: str) -> dict[str, str]:
    """The engine's `unsupported: {case id: reason}` from the scenario's verdict.yaml."""
    path = Path(scenario.path) / "verdict.yaml"
    if not path.is_file():
        return {}
    entry = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get(engine) or {}
    return dict(entry.get("unsupported") or {})


def call(argv: list[str], cwd: Path) -> tuple[int, str, str]:
    """Run a CLI; a missing binary or a timeout is reported like a failing exit."""
    try:
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", f"{type(e).__name__}: {e}"
    return p.returncode, p.stdout, p.stderr


def row(scenario: Scenario, case: Case, got: str | None, reasons: list[str],
        error: str | None, unsupported: str | None = None) -> dict:
    if unsupported is not None:
        ok = None
    elif error is not None:
        got, ok = "ERROR", False  # an engine error is a mismatch, never a skip
    else:
        ok = got == case.expect
    return {"scenario": scenario.id, "case": case.id, "expect": case.expect, "got": got,
            "ok": ok, "reasons": reasons, "error": error, "unsupported": unsupported}


def recorded_tools(engine: str, wrapper: str) -> dict:
    """The engine's entry in bench/results/env.json `tools` (written by bench/tools.sh)."""
    path = Path(__file__).resolve().parent / "results" / "env.json"
    env = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    entry = (env.get("tools") or {}).get(engine)
    if entry is None:
        return {"wrapper": wrapper, "error": "no tools entry in env.json; run bench/tools.sh"}
    return {**entry, "wrapper": wrapper}


def main(engine: str, script: str, run, argv: list[str] | None, tools: dict) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    rows = run(load_scenarios())
    bad = [r for r in rows if r["ok"] is False]
    skipped = [r for r in rows if r["ok"] is None]
    out = {"command": f"python {script} " + " ".join(sys.argv[1:] if argv is None else argv),
           "engine": engine, "tool": tools, "total": len(rows),
           "matched": sum(1 for r in rows if r["ok"] is True), "mismatches": len(bad),
           "unsupported": len(skipped), "rows": rows}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    for r in bad:
        print(f"MISMATCH {r['scenario']}/{r['case']}: expected {r['expect']}, got {r['got']}: "
              f"{r['error'] or r['reasons']}", file=sys.stderr)
    print(f"{out['matched']}/{len(rows)} cases match, {len(bad)} mismatched, "
          f"{len(skipped)} unsupported")
    return 1 if bad else 0
