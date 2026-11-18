# sdk/tests/test_decision_log.py
import json

import pytest

from openapl.decision_log import DecisionLog, read_log
from openapl.model import Decision


def _dec(ts: int, value: str = "ALLOW") -> Decision:
    return Decision(value, (), ("user:a",), "x.y", "r/1", ("why",), (), (), (), (),
                    False, f"id{ts}", ts)


def test_log_append_and_read(tmp_path):
    p = str(tmp_path / "d.jsonl")
    log = DecisionLog(p)
    log.append(_dec(1))
    log.append(_dec(2, "DENY"))
    recs, skipped = read_log(p)
    assert [r["timestamp"] for r in recs] == [1, 2]
    assert recs[1]["decision"] == "DENY"
    assert skipped == 0


def test_read_log_window_and_malformed(tmp_path):
    p = tmp_path / "d.jsonl"
    log = DecisionLog(str(p))
    for ts in (10, 20, 30):
        log.append(_dec(ts))
    with open(p, "a", encoding="utf-8") as f:
        f.write("garbage{\n")
    recs, skipped = read_log(str(p), since=15, until=30)
    assert [r["timestamp"] for r in recs] == [20, 30]
    assert skipped == 1


def test_read_log_invalid_utf8_and_non_dict(tmp_path):
    p = tmp_path / "d.jsonl"
    log = DecisionLog(str(p))
    log.append(_dec(10))
    with open(p, "ab") as f:
        f.write(b"\xff\xfe bad\n[1]\n")
    log.append(_dec(20))
    recs, skipped = read_log(str(p))
    assert [r["timestamp"] for r in recs] == [10, 20]
    assert skipped == 2


def test_read_log_boundaries_inclusive(tmp_path):
    p = str(tmp_path / "d.jsonl")
    log = DecisionLog(p)
    for ts in (10, 20, 30):
        log.append(_dec(ts))
    recs, _ = read_log(p, since=20, until=20)
    assert [r["timestamp"] for r in recs] == [20]


def test_log_lone_surrogate_round_trips(tmp_path):
    from openapl.authorizer import Authorizer
    from openapl.model import Link, Request
    from openapl.policyset import load_policy_dir
    pdir = tmp_path / "p"
    pdir.mkdir()
    (pdir / "p.apl.yaml").write_text(
        "openapl: '0.1'\npolicy: p\nversion: 1.0.0\nprincipals:\n  bot:\n    kind: agent\n"
        "    identity: {oauth_client_id: bot}\n    owner: o@x.com\n"
        "    acts_for: [{who: 'user:h', actions: [a.read]}]\n"
        "entitlements:\n  - {id: e, grant_to: ['*'], action: a.read, resource: 'order/*'}\n")
    chain = (Link("user:h", "human", {}), Link("bot", "agent", {}))
    d = Authorizer(load_policy_dir(str(pdir))).decide(
        Request(chain, "a.read", "order/1\ud800", now=1000))
    assert d.decision == "ALLOW"
    p = tmp_path / "d.jsonl"
    DecisionLog(str(p)).append(d)
    assert p.read_bytes().isascii()
    recs, skipped = read_log(str(p))
    assert skipped == 0 and recs[0]["resource"] == "order/1\ud800"
    assert recs[0]["decision_id"] == d.decision_id


@pytest.mark.parametrize("line", [
    {"timestamp": 5},
    {"decision_id": "x", "decision": "ALLOW", "action": "a", "timestamp": 5},
    {"decision_id": "x", "decision": "ALLOW", "resource": "r", "timestamp": 5},
    {"decision_id": "x", "action": "a", "resource": "r", "timestamp": 5},
    {"decision": "ALLOW", "action": "a", "resource": "r", "timestamp": 5},
    {"decision_id": "x", "decision": "ALLOW", "action": "a", "resource": "r"},
    {"decision_id": "x", "decision": "ALLOW", "action": "a", "resource": "r", "timestamp": "5"},
    {"decision_id": ["x"], "decision": "ALLOW", "action": "a", "resource": "r", "timestamp": 5},
])
def test_read_log_skips_incomplete_lines(tmp_path, line):
    p = tmp_path / "d.jsonl"
    DecisionLog(str(p)).append(_dec(10))
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")
    recs, skipped = read_log(str(p))
    assert [r["timestamp"] for r in recs] == [10] and skipped == 1
