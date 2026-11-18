# sdk/tests/test_evidence.py
import json
from dataclasses import replace

from click.testing import CliRunner

from openapl.cli import main
from openapl.decision_log import DecisionLog, read_log
from openapl.evidence import assessment_results
from openapl.model import Link, Request
from tests import oscal_schema

NOW = "2026-11-18T12:00:00Z"
alice = Link("user:alice@acme.com", "human", {"groups": ["support-staff"]})
sa = Link("support-agent", "agent", {})
ra = Link("refund-agent", "agent", {})
BASE = Request(
    (alice, sa, ra), "payments.refund", "order/123",
    {"order_id": "123", "amount": 150, "account_status": "open"},
    purpose="customer-refund", task_id="t1", now=1000,
)


def _log(authorizer, tmp_path):
    """Three decisions from the example policy: ALLOW, REQUIRE_APPROVAL, DENY."""
    path = str(tmp_path / "log.jsonl")
    log = DecisionLog(path)
    variants = [
        BASE,
        replace(BASE, attributes={**BASE.attributes, "amount": 350}, now=1001),
        replace(BASE, attributes={**BASE.attributes, "account_status": "closed"}, now=1002),
    ]
    for req in variants:
        log.append(authorizer.decide(req))
    return path


def _doc(authorizer, tmp_path, now=NOW):
    records, _ = read_log(_log(authorizer, tmp_path))
    assert [r["decision"] for r in records] == ["ALLOW", "REQUIRE_APPROVAL", "DENY"]
    return assessment_results(records, title="Refund log", since=0, until=2000, now=now), records


def test_evidence_validates_against_oscal(authorizer, tmp_path):
    doc, _ = _doc(authorizer, tmp_path)
    assert oscal_schema.validate(doc, "assessment-results") == []


def test_one_observation_per_decision(authorizer, tmp_path):
    doc, records = _doc(authorizer, tmp_path)
    obs = doc["assessment-results"]["results"][0]["observations"]
    assert len(obs) == 3
    assert len({o["uuid"] for o in obs}) == 3
    first = {p["name"]: p["value"] for p in obs[0]["props"]}
    assert first["decision"] == "ALLOW"
    assert first["action"] == "payments.refund"
    assert first["resource"] == "order/123"
    assert first["chain"] == ",".join(records[0]["chain"])
    assert obs[0]["collected"] == "1970-01-01T00:16:40Z"


def test_findings_per_control(authorizer, tmp_path):
    doc, _ = _doc(authorizer, tmp_path)
    result = doc["assessment-results"]["results"][0]
    obs_ids = [o["uuid"] for o in result["observations"]]
    by_control = {f["props"][0]["value"]: f for f in result["findings"]}
    assert set(by_control) == {
        "NIST-800-53:AC-3", "NIST-800-53:AC-6", "SOC2:CC6.1", "SOC2:CC6.3",
        "NIST-800-53:AU-2", "NIST-800-53:AU-3"}
    cc61 = by_control["SOC2:CC6.1"]
    assert cc61["related-observations"] == [{"observation-uuid": u} for u in obs_ids]
    assert cc61["target"]["target-id"] == "SOC2-CC6.1"  # OSCAL tokens exclude ':'
    assert cc61["target"]["status"]["state"] == "satisfied"
    assert "1 ALLOW, 1 DENY, 1 REQUIRE_APPROVAL" in cc61["description"]


def test_deterministic_uuids(authorizer, tmp_path):
    records, _ = read_log(_log(authorizer, tmp_path))
    kw = dict(title="t", since=0, until=2000, now=NOW)
    assert assessment_results(records, **kw) == assessment_results(records, **kw)


def test_no_compliance_claims(authorizer, tmp_path):
    doc, _ = _doc(authorizer, tmp_path)
    text = json.dumps(doc).lower()
    for word in ("compliant", "meets", "certif"):
        assert word not in text


def test_cli_evidence_empty_window_exit_1(authorizer, tmp_path):
    path = _log(authorizer, tmp_path)
    r = CliRunner().invoke(main, ["evidence", path, "--since", "5000", "--until", "6000"])
    assert r.exit_code == 1


def test_cli_evidence_writes_document(authorizer, tmp_path, monkeypatch):
    path = _log(authorizer, tmp_path)
    out = tmp_path / "ar.json"
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1000")
    r = CliRunner().invoke(main, ["evidence", path, "--since", "0", "--until", "2000", "-o", str(out)])
    assert r.exit_code == 0, r.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["assessment-results"]["metadata"]["last-modified"] == "1970-01-01T00:16:40Z"
    assert oscal_schema.validate(doc, "assessment-results") == []
