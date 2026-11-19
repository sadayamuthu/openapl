# openapl-sidecar

A small policy decision point (PDP) that puts the OpenAPL SDK behind two
interfaces:

- **Envoy `ext_authz` (gRPC, port 9000)**, for agentgateway or Envoy. It
  inspects MCP `tools/call` requests and returns allow or deny.
- **AuthZEN 1.0 (HTTP, port 8081)**, for any AuthZEN-capable caller.

The sidecar contains no decision logic. Every decision comes from
`openapl.Authorizer.decide`; the sidecar only extracts verified claims,
maps the request onto an action, resource and attributes, and fails closed
on anything unexpected (parse error, unknown method, unbound placeholder,
decision-log write failure, internal error). Only `tools/call` needs
claims (missing claims deny it). Passthrough MCP methods, notifications,
responses and GET/DELETE are allowed without claims, so agentgateway JWT
authentication must be mandatory (strict) on the MCP route.

Purpose, task id, approvals and `iat` come only from verified JWT claims
(`openapl_purpose`, `openapl_task_id`, `openapl_approvals`, `iat`), never
from tool arguments or AuthZEN properties.

## Run

```bash
pip install ./sdk ./sidecar
OPENAPL_POLICY_DIR=spec/examples OPENAPL_PDP_TOKEN=secret openapl-sidecar serve
openapl-sidecar --version
```

Container (build from the repository root; the image is not published):

```bash
docker build -f sidecar/Dockerfile -t openapl-sidecar:dev .
docker run -d -p 127.0.0.1:8081:8081 -e OPENAPL_PDP_TOKEN=secret \
  -v "$PWD/spec/examples:/policies:ro" openapl-sidecar:dev
```

The image runs as user `openapl` (uid 10001), exposes 8081 and 9000, and has
a health check on `/healthz`. Startup errors (bad configuration, policies or
bindings) print `openapl-sidecar: <message>` to stderr and exit 2 before any
port is opened; the same applies to an unwritable decision log and to a
port that cannot be bound. SIGTERM and SIGINT shut down both listeners and exit 0.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OPENAPL_POLICY_DIR` | required | policy directory |
| `OPENAPL_BINDINGS` | unset: default bindings | bindings YAML |
| `OPENAPL_DECISION_LOG` | unset: no log | JSONL path |
| `OPENAPL_PDP_TOKEN` | required unless dev mode | AuthZEN bearer token |
| `OPENAPL_DEV_MODE` | `0` | `1` enables dev mode |
| `OPENAPL_BIND_HOST` | `0.0.0.0` | both listeners |
| `OPENAPL_AUTHZEN_PORT` | `8081` | |
| `OPENAPL_EXTAUTHZ_PORT` | `9000` | |
| `OPENAPL_CLAIMS_METADATA` | `envoy.filters.http.jwt_authn/jwt_payload` | `namespace[/field]` |
| `OPENAPL_PDP_BASE_URL` | unset: no well-known doc | https base URL |
| `OPENAPL_DIRECTORY_SNAPSHOT` | unset: no directory | JSON `{"active": [emails]}`; owners not listed make their agents orphans; a bad file exits 2 |

## Bindings

A bindings file maps an MCP tool call onto the action, resource and
attributes the policy sees. See `examples/refund-bindings.yaml`.

```yaml
version: 1
targets: [payments]          # MCP target names known to the gateway
prefix_mode: conditional     # conditional | always | never (mirrors agentgateway prefixMode)
passthrough_methods: [initialize, ping, tools/list]
default_action: "mcp.tools.call:${target}/${tool}"
default_resource: "tool:${target}/${tool}"
tools:
  - tool: refund_order
    target: payments
    action: payments.refund
    resource: "order/${args.order_id}"
    attributes: { order_id: "${args.order_id}", amount: "${args.amount}" }
```

- Bindings may set only `action`, `resource` and `attributes`. Placeholders
  are `${target}`, `${tool}` and `${args.<name>}`.
- A whole-placeholder attribute keeps its JSON type (`amount: 150` stays a
  number). A missing or non-scalar argument for a placeholder denies
  (unbound placeholder), as do tool arguments containing non-finite numbers.
- agentgateway names multiplexed tools `<target>_<tool>` (split on the first
  `_`), so target names must not contain `_`.
- On an MCP `POST`, `tools/call` is evaluated against the policy. The
  passthrough methods (default `initialize`, `ping`, `tools/list`),
  `notifications/*` and JSON-RPC responses pass through without a decision.
  Any other method (for example `resources/read` or `prompts/get`) is
  denied; extend the passthrough list with `passthrough_methods` in the
  bindings file.
- A JSON-RPC batch is allowed only if every `tools/call` in it is allowed
  (each is decided and logged separately); one denied call denies the whole
  request. A batch of only passthrough messages is allowed. An empty batch,
  a non-JSON or truncated body, or a malformed message denies.
- MCP bodies with NaN, Infinity, overflowing numbers or duplicate JSON keys
  are denied.
- A binding's `action` and `default_action` may not use `${args.*}`
  placeholders (rejected at load), so a caller never chooses the action.
- A decision id in a response may have no log record when the decision log
  write failed (the decision is then DENY).
- HTTP `GET` (SSE) and `DELETE` on the MCP endpoint are allowed without a
  decision. Any HTTP method other than `POST`, `GET` and `DELETE` is denied.

## ext_authz response contract

- ALLOW (including pass-through requests): gRPC status `OK` with an empty
  `OkHttpResponse` and dynamic metadata `openapl: {decision, decision_ids}`.
- DENY and REQUIRE_APPROVAL: gRPC status `PERMISSION_DENIED` with an HTTP
  403 `DeniedHttpResponse`. The JSON body has `decision`, `reasons`,
  `approvers`, `decision_id` (the first) and `decision_ids`; the headers
  are `x-openapl-decision`, `x-openapl-decision-id` and
  `content-type: application/json`. If a batch mixes DENY and
  REQUIRE_APPROVAL, DENY wins.
- Anything unexpected is a 403 deny.

Verified claims are read from the check request's filter metadata
(`OPENAPL_CLAIMS_METADATA`; default the `jwt_payload` field of
`envoy.filters.http.jwt_authn`). Protobuf turns every number into a float;
integral floats are converted back to ints. The request body is read from
`attributes.request.http.body` or `raw_body`.

## AuthZEN mapping

- `POST /access/v1/evaluation`: `subject{type,id}`, `action{name}` and
  `resource{type,id}` are required (400 otherwise); `resource.properties`
  become attributes. `context.attributes` is merged with
  `resource.properties` (a key in both is a 400). Response: `{"decision": bool, "context": {"openapl": ...}}`.
  A deny is `200 {"decision": false}`. `X-Request-ID` is echoed.
- Verified claims travel in `context.claims`. `subject.id` must equal the
  claims identity (`email`, else `sub`).
- `POST /access/v1/evaluations`: an `evaluations` array whose items override
  the top-level defaults, with `options.evaluations_semantic` of
  `execute_all` (default), `deny_on_first_deny` or `permit_on_first_permit`.
  Results are returned in request order. **Truncation:** `deny_on_first_deny`
  and `permit_on_first_permit` return only the evaluations performed up to
  and including the short-circuit item (AuthZEN 1.0 is silent on this).
- `GET /.well-known/authzen-configuration` is served only when
  `OPENAPL_PDP_BASE_URL` is set. `GET /healthz` needs no token.
- Hardening: a missing or wrong bearer token is 401 with `WWW-Authenticate`
  (constant-time compare); NaN, Infinity and numbers that overflow to infinity are rejected (400);
  duplicate JSON keys are rejected (400); bodies over
  1 MiB are 413; `Transfer-Encoding` is rejected; each socket read has a 10 s
  timeout.

## agentgateway settings

A deployment needs:

- JWT authentication, so the verified payload reaches the sidecar as
  `jwt_payload` metadata;
- the ext_authz policy with `includeRequestBody` and a `maxRequestBytes`
  large enough for tool calls (the default 8192 is small);
- `allowPartialMessage: false`;
- `failureMode: deny`.

Do not gate the ext_authz policy on `has(mcp.tool)`. An unresolvable tool
prefix leaves it unset and would skip the sidecar (fail open); the sidecar
must see every MCP POST.

## Security

- **Port 9000 trusts its caller's claims metadata** and cannot authenticate
  the caller in v0.1. Anyone who can reach it can forge claims. It must be
  reachable only by the gateway: a private network, no published port. The
  container does not publish it by default.
- **Port 8081 requires the bearer token** (`OPENAPL_PDP_TOKEN`), compared in
  constant time. Treat it as a secret, and use TLS in front of it.
- **Dev mode** (`OPENAPL_DEV_MODE=1`) takes the chain from the
  `x-openapl-chain` header (ext_authz) or `context.chain` (AuthZEN), and
  lets AuthZEN run without a token. It prints `WARNING: dev mode` at start
  and every dev-mode request is marked as such. Never use it outside local
  development. See the OpenAPL design document for the rationale.

## Verified against agentgateway

Checked against agentgateway v1.7.0: per-message ext_authz on MCP streamable
HTTP, the request body, the `jwt_payload` claims with `act` intact, the
`maxRequestBytes` limit and the no-token case. See the
[integration guide](../docs/integrations/agentgateway.md) and
[`demo/agentgateway/VERIFIED.md`](../demo/agentgateway/VERIFIED.md).

One difference: agentgateway v1.7.0 never forwards a JSON-RPC batch to the
MCP server. It answers 400 after ext_authz has seen the array. The sidecar
still decides the array first and denies it (403) if any call in it is
denied, which the demo's `batch` scenario exercises.
