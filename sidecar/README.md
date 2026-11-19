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
missing claims, decision-log write failure, internal error).

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
port is opened. SIGTERM and SIGINT shut down both listeners and exit 0.

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
- MCP methods other than `tools/call` are denied unless listed in
  `passthrough_methods` (default `initialize`, `ping`, `tools/list`).
  `notifications/*` and JSON-RPC responses are denied. A JSON-RPC batch is
  allowed only if every message is allowed; an empty or truncated body
  denies.

## ext_authz response contract

- ALLOW: gRPC `OK` with an `OkResponse`.
- DENY and REQUIRE_APPROVAL: HTTP 403 `DeniedResponse` with a JSON body and
  the headers `x-openapl-decision`, `x-openapl-decision-id` and
  `content-type: application/json`.
- Anything unexpected is a 403 deny.

Verified claims are read from the check request's filter metadata
(`OPENAPL_CLAIMS_METADATA`; default the `jwt_payload` field of
`envoy.filters.http.jwt_authn`). Protobuf turns every number into a float;
integral floats are converted back to ints. The request body is read from
`attributes.request.http.body` or `raw_body`.

## AuthZEN mapping

- `POST /access/v1/evaluation`: `subject{type,id}`, `action{name}` and
  `resource{type,id}` are required (400 otherwise); `resource.properties`
  become attributes. Response: `{"decision": bool, "context": {"openapl": ...}}`.
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
  (constant-time compare); NaN and Infinity are rejected (400); bodies over
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

## Not yet verified against a running agentgateway

Per-message ext_authz on MCP streamable HTTP, and JSON-RPC batches. The
integration demo (plan 2b) checks these, along with the `maxRequestBytes`
needed for a `tools/call` and that `act` reaches `jwt_payload` intact.
