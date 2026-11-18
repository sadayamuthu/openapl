# sdk/src/openapl/decision_log.py
"""Append-only JSON-lines decision log."""
import json

from openapl.model import Decision


class DecisionLog:
    def __init__(self, path: str):
        self.path = path

    def append(self, decision: Decision) -> None:
        """Append one JSON line and flush. Raises OSError on write failure."""
        line = json.dumps(decision.to_dict(), ensure_ascii=False)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()


def read_log(path: str, since: int | None = None,
             until: int | None = None) -> tuple[list[dict], int]:
    """Return records with since <= timestamp <= until, and the malformed-line count."""
    records: list[dict] = []
    skipped = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                ts = rec["timestamp"]
                if not isinstance(rec, dict) or isinstance(ts, bool) or not isinstance(ts, int):
                    raise ValueError("bad record")
            except (ValueError, KeyError, TypeError):
                skipped += 1
                continue
            if since is not None and ts < since:
                continue
            if until is not None and ts > until:
                continue
            records.append(rec)
    return records, skipped
