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
    with open(path, "rb") as f:
        for raw in f:
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw.decode("utf-8"))
                if not isinstance(rec, dict):
                    raise ValueError("not an object")
                ts = rec["timestamp"]
                if isinstance(ts, bool) or not isinstance(ts, int):
                    raise ValueError("bad timestamp")
            except (ValueError, KeyError):
                skipped += 1
                continue
            if since is not None and ts < since:
                continue
            if until is not None and ts > until:
                continue
            records.append(rec)
    return records, skipped
