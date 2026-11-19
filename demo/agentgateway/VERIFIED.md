# agentgateway v1.7.0 ext_authz wire facts (recorded 2026-11-19)

Observed by running `ghcr.io/agentgateway/agentgateway:v1.7.0` with `gateway.yaml` against the recording
probe (`probe/probe.py`, always answers OK, appends each `CheckRequest` to `out/checks.jsonl`). Reproduce:

```bash
source ../../sidecar/.venv/bin/activate
python issuer.py keys out/ && rm -f out/checks.jsonl
docker compose -f compose.probe.yaml up -d --build
python probe_checks.py          # prints all evidence below
docker compose -f compose.probe.yaml down -v
```

`gateway.yaml` was accepted by the gateway unchanged (no key changes were needed). The gateway logs a harmless
warning that it cannot write a generated session key to the read-only `/config` mount.
JWT claims (alice, groups support+finance, three-hop `act`) came from `issuer.mint`.

## 1. Per message: MATCHES
Command: `initialize`, `notifications/initialized`, `tools/list`, `tools/call` via `McpClient`; then a `GET /mcp` SSE stream.
Evidence: 4 checks, in order, all `POST /mcp`, bodies' `method` = `['initialize', 'notifications/initialized', 'tools/list', 'tools/call']`.
The `GET /mcp` (accept `text/event-stream`, `mcp-session-id` set) produced 1 further check with `method: GET`, `body: ""`
(the sidecar allows GET without a decision; claims are present on it too).

## 2. Body: MATCHES
Evidence (`tools/call`, `attributes.request.http.body`; `raw_body` is empty, length 0, so the sidecar must read `body`, which it does):
```
{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "payments_refund_order", "arguments": {"order_id": "o-2", "amount": 350, "account_status": "active"}}}
```
Tool name is exactly `payments_refund_order` (`<target>_<tool>` with `prefixMode: always`). Body is the verbatim client text (original spacing).

## 3. Claims: MATCHES
Evidence: `metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]["jwt_payload"]` (the only namespace present):
```
{"email": "alice@acme.com", "openapl_task_id": "t1", "openapl_purpose": "customer-refund",
 "act": {"sub": "oauth_client_id: refund-agent",
         "act": {"sub": "oauth_client_id: triage-agent",
                 "act": {"sub": "spiffe://acme.com/agents/support-agent"}}},
 "aud": "agentgateway-demo", "iss": "https://issuer.demo.openapl.local",
 "exp": 1795067952.0, "iat": 1795067352.0, "groups": ["support", "finance"]}
```
The probe used a prefixed `sub` (`oauth_client_id: ...`); the policy matches the bare identity value (e.g. `refund-agent`), and a prefixed `sub` is denied as an unknown principal.
Three-level `act` intact, outermost = current caller (refund-agent), as minted. Numbers are floats (`iat`, `exp`), as the sidecar README expects.
Present on every check (initialize, notifications, tools/list, tools/call, GET, batch).

## 4. Batch: DIFFERS (documented, non-blocking)
Command: `POST /mcp` with a JSON array `[tools/list, tools/call payments_refund_order]`.
Evidence: gateway answered `400 fail to deserialize request body: unrecognized JSON-RPC message`, but ext_authz ran first:
1 check whose `body` was the complete array text (`[{"jsonrpc": "2.0", "id": 90, "method": "tools/list"}, {... "tools/call" ...}]`).
So the gateway does not forward or split a batch; it rejects it after the sidecar saw it. The sidecar's batch handling
is therefore never needed against this gateway version, and a batch cannot bypass the policy (it is rejected anyway).

## 5. Size: MATCHES
Command: `tools/call` with `order_id` of 70000 chars (body about 70 KB, over 65536).
Evidence: gateway status `413`, **0** checks recorded: the oversize body never reaches ext_authz (no partial body).
Control: `order_id` of 65000 chars (body 65168 chars) gives status `200` and 1 check whose `body` is the full 65168 chars.

## 6. No token: MATCHES
Command: `initialize`, `tools/list` and `tools/call` with no `Authorization`; and `initialize` with a token whose signature was corrupted.
Evidence: all `401`; 0 checks recorded (jwtAuth strict runs before ext_authz).
