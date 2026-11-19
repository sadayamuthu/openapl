# bench/common.py
"""Load the benchmark scenario suite (bench/scenarios/<id>/cases.yaml)."""
from dataclasses import dataclass
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTATIONS = ("ALLOW", "DENY", "REQUIRE_APPROVAL")
# The conformance-suite request shape (spec/conformance/*.yaml, SPEC.md §10.1), plus the
# optional per-case directory snapshot, which the conformance format keeps beside the request.
REQUEST_KEYS = {"chain", "action", "resource", "attributes", "purpose", "task_id", "iat",
                "now", "approvals", "directory"}


@dataclass(frozen=True)
class Case:
    id: str
    request: dict
    expect: str
    reasons_include: tuple[str, ...] = ()
    reasons_exclude: tuple[str, ...] = ()  # fragments that must NOT appear, to isolate one reason


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    threat: str | None
    path: str
    cases: tuple[Case, ...]


def load_scenarios(root: str = "bench/scenarios") -> list[Scenario]:
    base = Path(root)
    if not base.is_absolute():
        base = REPO_ROOT / base
    scenarios = []
    for cases_file in sorted(base.glob("*/cases.yaml")):
        doc = yaml.safe_load(cases_file.read_text(encoding="utf-8"))
        sid = cases_file.parent.name
        assert doc["scenario"] == sid, f"{cases_file}: scenario id {doc['scenario']!r} != {sid!r}"
        defaults = (doc.get("defaults") or {}).get("request") or {}
        cases = []
        for raw in doc["cases"]:
            request = {**defaults, **(raw.get("request") or {})}  # shallow merge, as in §10.1
            unknown = set(request) - REQUEST_KEYS
            assert not unknown, f"{sid}/{raw['id']}: unknown request keys {unknown}"
            assert raw["expect"] in EXPECTATIONS, f"{sid}/{raw['id']}: bad expect {raw['expect']!r}"
            cases.append(Case(
                id=raw["id"], request=request, expect=raw["expect"],
                reasons_include=tuple(raw.get("reasons_include") or ()),
                reasons_exclude=tuple(raw.get("reasons_exclude") or ()),
            ))
        scenarios.append(Scenario(
            id=sid, title=doc["title"], threat=doc.get("threat"),
            path=str(cases_file.parent), cases=tuple(cases),
        ))
    return scenarios
