# bench/analyze.py
"""Fold every bench result file into bench/results/summary.json, the key paths a paper cites.

Usage: python bench/analyze.py [--results bench/results] [--scenarios bench/scenarios]
                               [--out bench/results/summary.json]
Keys: suite.*, engines.<e>.{matched,mismatched,unsupported}, grades.<e>.{native,workaround,
not_expressible,unknown}, latency.target, latency.grid.<PxE>.*, gateway.*, env.*.
A missing result file is an error, never a silent gap."""
import argparse
import json
import sys
from pathlib import Path

import yaml

BENCH = Path(__file__).resolve().parent
ENGINES = ("openapl", "cedar", "rego")
GRADED = ("openapl", "cedar", "rego", "xacml", "gapl")
GRADES = ("native", "workaround", "not_expressible", "unknown")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _grade(entry) -> str:
    raw = entry if isinstance(entry, str) else entry["grade"]
    raw = raw.strip().replace("-", "_")
    return "unknown" if raw.startswith("unknown") else raw


def analyze(results: Path, scenarios: Path) -> dict:
    suite = {"scenarios": 0, "cases": 0, "allow": 0, "deny": 0, "require_approval": 0}
    grades = {e: dict.fromkeys(GRADES, 0) for e in GRADED}
    for d in sorted(p for p in scenarios.iterdir() if (p / "cases.yaml").is_file()):
        suite["scenarios"] += 1
        for case in yaml.safe_load((d / "cases.yaml").read_text(encoding="utf-8"))["cases"]:
            suite["cases"] += 1
            suite[case["expect"].lower()] += 1
        verdict = yaml.safe_load((d / "verdict.yaml").read_text(encoding="utf-8"))
        for e in GRADED:
            g = _grade(verdict[e])
            if g not in GRADES:
                raise ValueError(f"{d.name}: {e}: unrecognised grade {g!r}")
            grades[e][g] += 1
    engines = {}
    for e in ENGINES:
        rows = _load(results / f"{e}.json")["rows"]
        engines[e] = {"matched": sum(r["ok"] is True for r in rows),
                      "mismatched": sum(r["ok"] is False for r in rows),
                      "unsupported": sum(r["ok"] is None for r in rows)}
    lat = _load(results / "latency.json")
    grid = {p["point"]: {k: p[k] for k in ("p50_us", "p99_us", "load_ms", "n", "principals",
                                           "entitlements")} for p in lat["points"]}
    gw = _load(results / "gateway.json")
    gateway = {"openapl": {k: gw["openapl"][k] for k in ("p50_us", "p99_us", "n")},
               "baseline": {k: gw["baseline"][k] for k in ("p50_us", "p99_us", "n")},
               "delta": {k: gw["delta"][k] for k in (
                   "p50_us", "p99_us", "batch_median_spread_us", "batch_p99_spread_us",
                   "paired_batches")},
               "sidecar_decisions": {"count": gw["sidecar_decisions"]["count"]}}
    return {"suite": suite, "engines": engines, "grades": grades,
            "latency": {"target": lat["target"], "grid": grid}, "gateway": gateway,
            "env": _load(results / "env.json")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(BENCH / "results"))
    ap.add_argument("--scenarios", default=str(BENCH / "scenarios"))
    ap.add_argument("--out", default=str(BENCH / "results" / "summary.json"))
    a = ap.parse_args(argv)
    summary = analyze(Path(a.results), Path(a.scenarios))
    summary = {"command": "python bench/analyze.py", **summary}
    Path(a.out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
