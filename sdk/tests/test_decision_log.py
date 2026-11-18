# sdk/tests/test_decision_log.py
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
