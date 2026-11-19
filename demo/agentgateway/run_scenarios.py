# demo/agentgateway/run_scenarios.py
"""Run the data-driven scenarios against the gateway; exit non-zero on any mismatch."""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import issuer  # noqa: E402
from mcp_client import McpClient  # noqa: E402

HERE = Path(__file__).resolve().parent


def expand(v):
    """Expand {repeat: [text, n]} placeholders so big payloads stay readable in the YAML."""
    if isinstance(v, dict):
        if set(v) == {"repeat"}:
            text, n = v["repeat"]
            return text * n
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def wait_for_gateway(base_url: str, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        st, _ = McpClient(base_url, None).post_raw({"jsonrpc": "2.0", "id": 0, "method": "ping"})
        if st != 0:
            return True
        time.sleep(1)
    return False


def parse_body(body: bytes):
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None


def ok_note(sc: dict, res, decision: str) -> str:
    """For a 200: return a failure note unless there is a real result (no error, isError not true)."""
    if decision in ("DENY", "REQUIRE_APPROVAL"):
        return f"200 carried decision header {decision}"
    if not isinstance(res, dict):
        return "200 without a matching JSON-RPC result"
    if "code" in res and "message" in res and "content" not in res and "tools" not in res:
        return f"JSON-RPC error at 200: {res.get('message')}"
    if "tool" in sc:
        if res.get("isError") is True:
            return "tool reported isError"
        if "content" not in res:
            return "tools/call result has no content"
    elif not isinstance(res.get("tools"), list):
        return "tools/list result has no tools list"
    return ""


def void_log_note(log_path: Path) -> str:
    """Failure note for the batch check; empty means the log has records and none is an ALLOW on payments.void.
    Fails closed: a missing, unreadable or record-less log is a failure."""
    try:
        lines = log_path.read_text().splitlines()
    except OSError:
        return "decision log missing or unreadable"
    valid = 0
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        valid += 1
        if rec.get("decision") == "ALLOW" and rec.get("action") == "payments.void":
            return "decision log holds an ALLOW for payments.void"
    return "" if valid else "decision log missing or empty"


def run_one(sc: dict, base_url: str, out_dir: str) -> dict:
    """Returns {status, decision, reasons, note, detail}; a non-empty note is a failure."""
    token = issuer.token_from_spec(out_dir, sc["token"]) if sc.get("token") else None
    c = McpClient(base_url, token)
    init = c.initialize()
    if init != 200:
        return {"status": init, "decision": "", "reasons": [], "note": "", "detail": f"initialize failed ({init})"}
    if "batch" in sc:
        payload = [{"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call",
                    "params": {"name": b["tool"], "arguments": expand(b["args"])}}
                   for i, b in enumerate(sc["batch"])]
        status, body = c.post_raw(payload)
        note = void_log_note(Path(out_dir) / "decisions.jsonl")
        return {"status": status, "decision": "", "reasons": [], "note": note,
                "detail": body.decode("utf-8", "replace")[:60].replace("\n", " ")}
    if "tool" in sc:
        status, res, hdrs = c.call(sc["tool"], expand(sc.get("args", {})))
    else:
        status, res, hdrs = c.request(sc["method"])
    reasons = res.get("reasons", []) if isinstance(res, dict) and status == 403 else []
    decision = hdrs.get("x-openapl-decision", "")
    note = ok_note(sc, res, decision) if status == 200 else ""
    return {"status": status, "decision": decision, "reasons": reasons, "note": note, "detail": ""}


def check(sc: dict, got: dict) -> list[str]:
    exp = sc["expect"]
    errs = []
    allowed = exp["status"] if isinstance(exp["status"], list) else [exp["status"]]
    if got["status"] not in allowed:
        errs.append(f"status {got['status']} not in {allowed}")
    if got["status"] == 200 and 200 not in allowed:
        errs.append("allowed when it must not be")
    if got.get("note"):
        errs.append(got["note"])
    if "decision" in exp and got["decision"] != exp["decision"]:
        errs.append(f"decision {got['decision']!r} != {exp['decision']!r}")
    for r in exp.get("reasons_include", []):
        if not any(r in x for x in got["reasons"]):
            errs.append(f"reason missing: {r!r}")
    return errs


def cli(*args: str, env: dict | None = None) -> str:
    p = subprocess.run([sys.executable, "-c", "from openapl.cli import main; main()", *args], capture_output=True, text=True,
                       env={**os.environ, **(env or {})})
    if p.returncode != 0:
        raise RuntimeError(f"openapl {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:3000/mcp")
    ap.add_argument("--out", default="out")
    ap.add_argument("--scenarios", default=str(HERE / "scenarios.yaml"))
    ap.add_argument("--policies", default=str(HERE / "policies"))
    a = ap.parse_args(argv)
    start = int(time.time())
    if not wait_for_gateway(a.base_url):
        print("gateway did not become reachable", file=sys.stderr)
        return 1
    rows = []
    failures = 0
    scenarios = issuer.load_scenarios(a.scenarios)
    if not scenarios:
        print("no scenarios defined", file=sys.stderr)
        return 1
    for sc in scenarios:
        try:
            got = run_one(sc, a.base_url, a.out)
            errs = check(sc, got)
        except Exception as e:  # a scenario must fail, never crash the runner
            got, errs = {"status": 0, "decision": "", "reasons": [], "note": str(e), "detail": ""}, [f"error: {e}"]
        failures += bool(errs)
        exp = sc["expect"]
        exps = "/".join(map(str, exp["status"])) if isinstance(exp["status"], list) else str(exp["status"])
        if exp.get("decision"):
            exps += " " + exp["decision"]
        gots = str(got["status"]) + (" " + got["decision"] if got["decision"] else "")
        rows.append((sc["id"], exps, gots, got["decision"] or "-", "; ".join(got["reasons"]) or "-",
                     "PASS" if not errs else "FAIL: " + "; ".join(errs), got.get("detail", "") or "-"))
    headers = ("id", "expected", "got", "decision header", "reasons", "result", "note")
    widths = [max(len(str(r[i])) for r in [headers, *rows]) for i in range(7)]
    print("\n== scenarios ==")
    for r in [headers, *rows]:
        print(" | ".join(str(x).ljust(w) for x, w in zip(r, widths)).rstrip())
    print(f"\n{len(rows) - failures}/{len(rows)} scenarios passed")

    log_path = Path(a.out) / "decisions.jsonl"
    print("\n== decision log ==")
    print(log_path.read_text() if log_path.exists() else "(no decision log)")
    for extra in ([], ["--on-behalf-of", "group:support-staff"]):
        print("== openapl explain policies support-agent " + " ".join(extra) + " ==")
        try:
            print(cli("explain", a.policies, "support-agent", *extra))
        except RuntimeError as e:
            print(e)
            failures += 1
    print("== openapl evidence out/decisions.jsonl ==")
    try:
        ev = cli("evidence", str(log_path), "--since", str(start - 5), "--until", str(int(time.time()) + 5),
                 "-o", str(Path(a.out) / "evidence.json"), env={"SOURCE_DATE_EPOCH": str(start)})
        print(ev, end="")
        doc = json.loads((Path(a.out) / "evidence.json").read_text())
        res = doc["assessment-results"]["results"][0]
        obs = res["observations"]
        counts: dict[str, int] = {}
        for o in obs:
            for p in o.get("props", []):
                if p["name"] == "decision":
                    counts[p["value"]] = counts.get(p["value"], 0) + 1
        ctl = [c["control-id"] for sel in res["reviewed-controls"]["control-selections"]
               for c in sel["include-controls"]]
        print(f"evidence: {len(obs)} observations {counts}; window {res['start']} .. {res['end']}")
        print(f"evidence: controls {', '.join(ctl)}; written to {Path(a.out) / 'evidence.json'}")
    except (RuntimeError, OSError, ValueError) as e:
        print(e)
        failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
