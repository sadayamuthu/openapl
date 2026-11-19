# bench/tests/test_analyze.py
"""analyze.py folds fixture result files into the stable key paths a paper cites."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyze import analyze, main  # noqa: E402


def _scenario(root: Path, sid: str, expects: list[str], verdict: str) -> None:
    d = root / sid
    d.mkdir(parents=True)
    cases = "".join(f"  - id: c{i}\n    expect: {e}\n" for i, e in enumerate(expects))
    (d / "cases.yaml").write_text(f"scenario: {sid}\ntitle: t\ncases:\n{cases}")
    (d / "verdict.yaml").write_text(verdict)


def _engine(rows: list[tuple[bool | None]]) -> dict:
    return {"rows": [{"scenario": "s", "case": f"c{i}", "ok": ok} for i, ok in enumerate(rows)]}


@pytest.fixture
def fx(tmp_path):
    sc, res = tmp_path / "scenarios", tmp_path / "results"
    res.mkdir()
    _scenario(sc, "a", ["ALLOW", "DENY", "DENY"],
              "openapl: native\ncedar: {grade: native}\nrego: {grade: workaround}\n"
              "xacml: {grade: native}\ngapl: {grade: unknown (not documented)}\n")
    _scenario(sc, "b", ["REQUIRE_APPROVAL"],
              "openapl: native\ncedar: {grade: not-expressible}\nrego: {grade: native}\n"
              "xacml: {grade: workaround}\ngapl: {grade: workaround}\n")
    for name, rows in {"openapl": [True] * 4, "cedar": [True, True, False, None],
                       "rego": [True] * 4}.items():
        (res / f"{name}.json").write_text(json.dumps(_engine(rows)))
    point = lambda p, e, p99: {"point": p, "n": 20000, "p50_us": 1.5, "p99_us": p99,  # noqa: E731
                               "load_ms": 3.0, "principals": 1, "entitlements": e,
                               "p95_us": 2.0, "max_us": 9.0, "mean_us": 1.7, "warmup": 1000,
                               "request_pool": 2000, "seed": 1,
                               "decision_mix": {"ALLOW": 1, "DENY": 1}}
    (res / "latency.json").write_text(json.dumps({
        "points": [point("10x100", 100, 600.0), point("100x1000", 1000, 2300.0)],
        "target": {"point": "100x1000", "p99_us": 2300.0, "met": True}}))
    arm = lambda a, b: {"n": 1000, "p50_us": a, "p99_us": b}  # noqa: E731
    (res / "gateway.json").write_text(json.dumps({
        "openapl": arm(2500.0, 3500.0), "baseline": arm(1400.0, 2100.0),
        "delta": {"p50_us": 1100.0, "p99_us": 1400.0, "paired_batches": 5,
                  "batch_median_spread_us": 249.0, "batch_p99_spread_us": 1381.0},
        "sidecar_decisions": {"count": 1100}}))
    (res / "env.json").write_text(json.dumps({"tools": {"opa": {"version": "1"}}}))
    return sc, res


def test_key_paths(fx):
    sc, res = fx
    s = analyze(res, sc)
    assert s["suite"] == {"scenarios": 2, "cases": 4, "allow": 1, "deny": 2,
                          "require_approval": 1}
    assert s["engines"]["openapl"] == {"matched": 4, "mismatched": 0, "unsupported": 0}
    assert s["engines"]["cedar"] == {"matched": 2, "mismatched": 1, "unsupported": 1}
    assert s["grades"]["cedar"] == {"native": 1, "workaround": 0, "not_expressible": 1,
                                    "unknown": 0}
    assert s["grades"]["rego"] == {"native": 1, "workaround": 1, "not_expressible": 0,
                                   "unknown": 0}
    assert s["grades"]["gapl"] == {"native": 0, "workaround": 1, "not_expressible": 0,
                                   "unknown": 1}
    assert s["grades"]["xacml"]["native"] == 1
    assert s["latency"]["target"] == {"point": "100x1000", "p99_us": 2300.0, "met": True}
    assert s["latency"]["grid"]["100x1000"] == {
        "p50_us": 1.5, "p99_us": 2300.0, "load_ms": 3.0, "n": 20000,
        "principals": 1, "entitlements": 1000, "p95_us": 2.0, "max_us": 9.0, "mean_us": 1.7,
        "decision_mix": {"ALLOW": 1, "DENY": 1}, "warmup": 1000, "request_pool": 2000,
        "seed": 1, "met_5ms": True}
    assert s["latency"]["grid"]["10x100"]["met_5ms"] is True
    assert "not evidence" in s["grades"]["openapl_note"]
    assert s["gateway"]["openapl"]["p99_us"] == 3500.0
    assert s["gateway"]["baseline"]["p50_us"] == 1400.0
    assert s["gateway"]["delta"]["batch_median_spread_us"] == 249.0
    assert s["gateway"]["delta"]["paired_batches"] == 5
    assert s["gateway"]["sidecar_decisions"]["count"] == 1100
    assert s["env"] == {"tools": {"opa": {"version": "1"}}}


def test_main_writes_file(fx, tmp_path):
    sc, res = fx
    out = tmp_path / "summary.json"
    assert main(["--results", str(res), "--scenarios", str(sc), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["suite"]["cases"] == 4


def test_missing_results_fails(fx):
    sc, res = fx
    (res / "gateway.json").unlink()
    with pytest.raises(FileNotFoundError):
        analyze(res, sc)


def test_case_count_mismatch_fails(fx):
    sc, res = fx
    (res / "rego.json").write_text(json.dumps(_engine([True] * 3)))
    with pytest.raises(ValueError, match="rego"):
        analyze(res, sc)
