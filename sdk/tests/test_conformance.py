# sdk/tests/test_conformance.py
"""Run every case in spec/conformance/*.yaml against Authorizer (format: SPEC.md §10)."""
import json
import shutil
from pathlib import Path

import pytest
import yaml

from openapl.authorizer import Authorizer
from openapl.model import Approval, Link, Request

CONFORMANCE = Path(__file__).resolve().parents[2] / "spec" / "conformance"
_REQUEST_KEYS = {"chain", "action", "resource", "attributes", "purpose", "task_id", "iat",
                 "now", "approvals"}
_EXPECT_KEYS = {"decision", "approvers", "reasons", "reasons_include", "matched"}


def _cases():
    for path in sorted(CONFORMANCE.glob("*.yaml")):
        suite = yaml.safe_load(path.read_text(encoding="utf-8"))
        for case in suite["cases"]:
            yield pytest.param(path, suite, case, id=f"{suite['suite']}/{case['id']}")


def _request(raw: dict) -> Request:
    unknown = set(raw) - _REQUEST_KEYS
    assert not unknown, f"unknown request keys {unknown}"
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


def _authorizer(tmp_path: Path, suite_path: Path, suite: dict, case: dict) -> Authorizer:
    pdir = tmp_path / "policies"
    pdir.mkdir()
    for i, entry in enumerate(suite["policies"]):
        target = pdir / f"{i:02d}.apl.yaml"
        if "file" in entry:
            shutil.copy(suite_path.parent / entry["file"], target)
        else:
            target.write_text(entry["inline"], encoding="utf-8")
    snapshot = None
    if "directory" in case:
        snapshot = tmp_path / "directory.json"
        snapshot.write_text(json.dumps(case["directory"]), encoding="utf-8")
    return Authorizer.from_dir(str(pdir), str(snapshot) if snapshot else None)


def test_suite_has_cases():
    assert sum(1 for _ in _cases()) >= 20


@pytest.mark.parametrize("suite_path, suite, case", list(_cases()))
def test_conformance_case(tmp_path, suite_path, suite, case):
    assert suite["openapl_conformance"] == "0.1"
    raw = {**(suite.get("defaults") or {}).get("request", {}), **(case.get("request") or {})}
    expect = case["expect"]
    assert not set(expect) - _EXPECT_KEYS, f"unknown expect keys {set(expect) - _EXPECT_KEYS}"

    d = _authorizer(tmp_path, suite_path, suite, case).decide(_request(raw))

    assert d.decision == expect["decision"], d.reasons
    if "approvers" in expect:
        assert list(d.approvers) == expect["approvers"]
    if "reasons" in expect:
        assert list(d.reasons) == expect["reasons"]
    for fragment in expect.get("reasons_include", ()):
        assert fragment in d.reasons, d.reasons
    if "matched" in expect:
        assert list(d.matched) == expect["matched"]
