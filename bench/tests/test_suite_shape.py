# bench/tests/test_suite_shape.py
"""Structural checks on the scenario suite, so a constant engine cannot pass it."""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import load_scenarios  # noqa: E402

IDS = {
    "confused-deputy", "attenuation-3hop", "relay-adds-edge", "prompt-injected-escalation",
    "over-deep-delegation", "orphaned-agent", "expired-task-grant", "forged-purpose",
    "deny-overrides", "threshold-approval", "approval-bound", "glob-resource",
    "group-and-role", "unknown-principal",
}
THREATS = {
    None, "confused deputy", "prompt-injected escalation", "over-deep delegation",
    "orphaned agent", "expired task grant", "forged purpose via tool arguments",
}


def test_ids_match_table():
    assert {s.id for s in load_scenarios()} == IDS
    assert len(load_scenarios()) == 14


def test_min_cases():
    scenarios = load_scenarios()
    assert all(len(s.cases) >= 2 for s in scenarios)
    assert sum(len(s.cases) for s in scenarios) >= 30


def test_suite_not_constant():
    # Review Focus 2: an always-ALLOW or always-DENY engine must fail the suite.
    counts = Counter(c.expect for s in load_scenarios() for c in s.cases)
    assert counts["ALLOW"] >= 8 and counts["DENY"] >= 8, counts
    assert set(counts) <= {"ALLOW", "DENY", "REQUIRE_APPROVAL"}
    assert counts["REQUIRE_APPROVAL"] >= 1


def test_every_scenario_has_readme():
    for s in load_scenarios():
        readme = Path(s.path) / "README.md"
        assert readme.is_file(), s.id
        assert len(readme.read_text(encoding="utf-8").strip()) > 40, s.id
        assert list((Path(s.path) / "openapl").glob("*.apl.yaml")), s.id
        assert s.threat in THREATS, (s.id, s.threat)


def test_case_ids_unique_and_expectations_checked():
    for s in load_scenarios():
        ids = [c.id for c in s.cases]
        assert len(ids) == len(set(ids)), s.id
        assert any(c.expect == "ALLOW" for c in s.cases) or any(
            c.expect == "REQUIRE_APPROVAL" for c in s.cases
        ), f"{s.id} has no positive case"
        assert any(c.expect == "DENY" for c in s.cases) or any(
            c.expect == "REQUIRE_APPROVAL" for c in s.cases
        ), f"{s.id} has no negative case"
