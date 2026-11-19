# bench/run_openapl.py
"""Golden runner: decide every scenario case with the OpenAPL reference Authorizer.

Usage: python bench/run_openapl.py --out bench/results/openapl.json
Exits 1 on any mismatch (including an engine error)."""
import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import Case, Scenario, load_scenarios  # noqa: E402
from openapl.authorizer import Authorizer  # noqa: E402
from openapl.model import Approval, Decision, Link, Request  # noqa: E402


def build_request(raw: dict) -> Request:
    # Copied from sdk/tests/test_conformance.py::_request (same request shape).
    chain = tuple(Link(e["id"], e["kind"], dict(e.get("claims") or {})) for e in raw["chain"])
    return Request(
        chain=chain,
        action=raw["action"],
        resource=raw["resource"],
        attributes=dict(raw.get("attributes") or {}),
        purpose=raw.get("purpose"),
        task_id=raw.get("task_id"),
        token_iat=raw.get("iat"),
        now=raw.get("now", 0),
        approvals=tuple(Approval(**a) for a in raw.get("approvals") or ()),
    )


def build_authorizer(scenario: Scenario, case: Case, workdir: Path) -> Authorizer:
    # Adapted from sdk/tests/test_conformance.py::_authorizer: copy policies, write the snapshot.
    pdir = workdir / "policies"
    pdir.mkdir(parents=True, exist_ok=True)
    for f in sorted((Path(scenario.path) / "openapl").glob("*.apl.yaml")):
        shutil.copy(f, pdir / f.name)
    snapshot = None
    if "directory" in case.request:
        snapshot = workdir / "directory.json"
        snapshot.write_text(json.dumps(case.request["directory"]), encoding="utf-8")
    return Authorizer.from_dir(str(pdir), str(snapshot) if snapshot else None)


def decide_case(scenario: Scenario, case: Case, workdir: Path) -> Decision:
    return build_authorizer(scenario, case, workdir).decide(build_request(case.request))


def run(scenarios: list[Scenario]) -> list[dict]:
    rows = []
    for s in scenarios:
        for c in s.cases:
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    d = decide_case(s, c, Path(tmp))
                got, reasons = d.decision, list(d.reasons)
            except Exception as e:  # an engine error is a mismatch, never a skip
                got, reasons = "ERROR", [f"{type(e).__name__}: {e}"]
            ok = got == c.expect and all(f in reasons for f in c.reasons_include)
            rows.append({"scenario": s.id, "case": c.id, "expect": c.expect, "got": got,
                         "ok": ok, "reasons": reasons})
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    rows = run(load_scenarios())
    bad = [r for r in rows if not r["ok"]]
    out = {"command": "python bench/run_openapl.py " + " ".join(sys.argv[1:] if argv is None else argv),
           "engine": "openapl-sdk", "total": len(rows), "mismatches": len(bad), "rows": rows}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    for r in bad:
        print(f"MISMATCH {r['scenario']}/{r['case']}: expected {r['expect']}, got {r['got']}: "
              f"{r['reasons']}", file=sys.stderr)
    print(f"{len(rows) - len(bad)}/{len(rows)} cases match")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
