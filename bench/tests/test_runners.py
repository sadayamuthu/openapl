# bench/tests/test_runners.py
"""Cedar and Rego runners: engine errors are mismatches, every case is decided or listed
unsupported, and every verdict line reference exists. Runs the real CLIs (bench/bin/*)."""
import re
import shutil
import sys
from pathlib import Path

import pytest
import yaml

BENCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCH))

import run_cedar  # noqa: E402
import run_rego  # noqa: E402
from common import load_scenarios  # noqa: E402

ENGINES = {"cedar": run_cedar, "rego": run_rego}
GRADES = {"native", "workaround", "not-expressible"}


def _mini_scenario(root: Path, engine: str) -> Path:
    """Copy glob-resource and break its translation for one engine."""
    src = BENCH / "scenarios" / "glob-resource"
    dst = root / "glob-resource"
    shutil.copytree(src, dst)
    if engine == "rego":
        (dst / "rego" / "policy.rego").write_text("package openapl\n\ndecision := \n")
    else:
        # Parses, but fails schema validation: NoSuchType is not declared.
        p = dst / "cedar" / "policies.cedar"
        p.write_text(p.read_text() + '\npermit (principal is NoSuchType, action, resource);\n')
    return root


@pytest.mark.parametrize("engine", sorted(ENGINES))
def test_engine_error_is_mismatch(tmp_path, engine):
    rows = ENGINES[engine].run(load_scenarios(str(_mini_scenario(tmp_path, engine))))
    assert rows, "no rows"
    for r in rows:
        assert r["ok"] is False, r
        assert r["got"] == "ERROR", r
        assert r["error"], r


@pytest.mark.parametrize("engine", sorted(ENGINES))
def test_missing_cli_is_mismatch(engine, monkeypatch):
    monkeypatch.setattr(ENGINES[engine], "CLI", "/nonexistent/bin/engine")
    rows = ENGINES[engine].run(load_scenarios()[:1])
    assert rows and all(r["ok"] is False and r["error"] for r in rows)


@pytest.fixture(scope="module")
def all_rows():
    scenarios = load_scenarios()
    return scenarios, {name: mod.run(scenarios) for name, mod in ENGINES.items()}


@pytest.mark.parametrize("engine", sorted(ENGINES))
def test_every_case_decided_or_unsupported(all_rows, engine):
    scenarios, rows_by_engine = all_rows
    rows = {(r["scenario"], r["case"]): r for r in rows_by_engine[engine]}
    expected = {(s.id, c.id) for s in scenarios for c in s.cases}
    assert set(rows) == expected  # no case silently dropped
    for s in scenarios:
        verdict = yaml.safe_load((Path(s.path) / "verdict.yaml").read_text())
        unsupported = verdict[engine].get("unsupported") or {}
        assert set(unsupported) <= {c.id for c in s.cases}, s.id
        for c in s.cases:
            r = rows[(s.id, c.id)]
            if c.id in unsupported:
                assert r["got"] is None and r["ok"] is None and r["unsupported"], r
            else:
                assert r["error"] is None, r
                assert r["got"] in ("ALLOW", "DENY", "REQUIRE_APPROVAL"), r
                assert r["ok"] is True, r  # a mismatch is a translation bug


_LINE_REF = re.compile(r"^(?P<file>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$")


@pytest.mark.parametrize("scenario", load_scenarios(), ids=lambda s: s.id)
def test_verdict_lines_exist(scenario):
    verdict = yaml.safe_load((Path(scenario.path) / "verdict.yaml").read_text())
    assert verdict["openapl"] == "native"
    for engine in ENGINES:
        v = verdict[engine]
        assert v["grade"] in GRADES and v["why"].strip(), (scenario.id, engine)
        assert v["lines"], (scenario.id, engine)
        for ref in v["lines"]:
            m = _LINE_REF.match(ref)
            assert m, ref
            path = Path(scenario.path) / m["file"]
            assert path.is_file(), ref
            assert path.parts[-2] == engine, ref  # cites that engine's translation
            n = len(path.read_text().splitlines())
            start, end = int(m["start"]), int(m["end"] or m["start"])
            assert 1 <= start <= end <= n, (ref, n)
