# demo/agentgateway/probe_checks.py
"""Run the six Task 2 checks against a running compose.probe.yaml stack; print evidence."""
import json
import os
import sys
import time
import urllib.request

import issuer
from mcp_client import McpClient

BASE = "http://127.0.0.1:3000"
LOG = "out/checks.jsonl"


def checks() -> list[dict]:
    if not os.path.exists(LOG):
        return []
    with open(LOG, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def mark(label: str) -> int:
    time.sleep(0.7)
    n = len(checks())
    print(f"\n=== {label} (checks so far: {n})")
    return n


def new(since: int) -> list[dict]:
    time.sleep(0.7)
    return checks()[since:]


def short(c: dict) -> dict:
    d = dict(c)
    d["headers"] = {k: (v if len(v) < 60 else v[:30] + "...") for k, v in c["headers"].items()
                    if k in (":method", ":path", "content-type", "mcp-session-id", "authorization", "accept")}
    if len(d["body"]) > 600:
        d["body"] = d["body"][:300] + f"...[{len(c['body'])} chars]"
    if len(d["raw_body"]) > 600:
        d["raw_body"] = d["raw_body"][:100] + "..."
    return d


tok = issuer.mint("out", email="alice@acme.com", groups=["support", "finance"],
                  actors=["spiffe://acme.com/agents/support-agent", "oauth_client_id: triage-agent",
                          "oauth_client_id: refund-agent"])

# 1 per-message
n = mark("1 per-message")
c = McpClient(BASE, tok)
print("initialize ->", c.initialize())
print("tools/list ->", c.request("tools/list")[0])
st, res, _ = c.call("payments_refund_order", {"order_id": "o-1", "amount": 350, "account_status": "active"})
print("tools/call ->", st, json.dumps(res)[:200])
for x in new(n):
    print(json.dumps(short(x), indent=1))
print("COUNT:", len(new(n)), [json.loads(x["body"]).get("method") if x["body"] else None for x in new(n)])
n = mark("1b GET SSE")
req = urllib.request.Request(BASE + "/mcp", headers={"Authorization": f"Bearer {tok}", "Mcp-Session-Id": c.session,
                                                     "Accept": "text/event-stream"})
try:
    r = urllib.request.urlopen(req, timeout=3)
    print("GET status", r.status)
    r.read(10)
except Exception as e:  # timeout is fine: stream stays open
    print("GET outcome:", type(e).__name__, e)
g = new(n)
print("GET checks:", len(g))
for x in g:
    print(json.dumps(short(x), indent=1))

# 3 claims (from the tools/call check above, printed in full)
n = mark("2/3 body + claims")
c.call("payments_refund_order", {"order_id": "o-2", "amount": 350, "account_status": "active"})
t = [x for x in new(n) if "tools/call" in x["body"]][-1]
print("body:", t["body"])
print("raw_body_len:", t["raw_body_len"])
print("metadata namespaces:", list(t["metadata_context"]))
print("jwt_payload:", json.dumps(t["metadata_context"]["envoy.filters.http.jwt_authn"]["jwt_payload"], indent=1))

# 4 batch
n = mark("4 batch")
batch = [{"jsonrpc": "2.0", "id": 90, "method": "tools/list"},
         {"jsonrpc": "2.0", "id": 91, "method": "tools/call",
          "params": {"name": "payments_refund_order", "arguments": {"order_id": "o-3", "amount": 1, "account_status": "active"}}}]
st, body = c.post_raw(batch)
print("batch status:", st, body[:300])
for x in new(n):
    print(json.dumps(short(x), indent=1))
print("batch checks:", len(new(n)))

# 5 oversize
n = mark("5 oversize")
big = "x" * 70000
st, res, h = c.call("payments_refund_order", {"order_id": big, "amount": 1, "account_status": "active"})
print("oversize status:", st, json.dumps(res)[:300])
o = new(n)
print("oversize checks:", len(o))
for x in o:
    print(json.dumps(short(x), indent=1))
# near-limit control: just under 65536
st, res, h = c.call("payments_refund_order", {"order_id": "y" * 65000, "amount": 1, "account_status": "active"})
print("under-limit status:", st)
o2 = new(n)
print("checks after under-limit:", len(o2), [len(x["body"]) for x in o2])

# 6 no token
n = mark("6 no token")
nt = McpClient(BASE, None)
print("initialize:", nt.initialize())
print("tools/list:", nt.request("tools/list")[0])
print("tools/call:", nt.call("payments_refund_order", {"order_id": "o", "amount": 1, "account_status": "a"})[0])
bad = McpClient(BASE, tok[:-4] + "AAAA")
print("bad-signature initialize:", bad.initialize())
print("no-token checks:", len(new(n)))
