# OpenAPL x agentgateway demo

This demo puts the OpenAPL sidecar behind [agentgateway](https://agentgateway.dev)
v1.7.0 as an `ext_authz` policy decision point, in front of two small MCP
servers. Every `tools/call` is decided by OpenAPL over the whole delegation
chain (the human, each agent, the calling agent), and the gateway enforces the
result.

```
client -> agentgateway (jwtAuth strict) -> ext_authz -> openapl-sidecar -> policy
                   '-> payments-mcp / crm-mcp
```

The client sends a bearer JWT with `email`, `groups`, `openapl_purpose`,
`openapl_task_id`, `openapl_approvals` and a nested `act` claim (the outermost
`act` is the current caller). agentgateway verifies it (`jwtAuth`, strict),
then calls the sidecar on gRPC port 9000 with the verified claims as metadata
and the request body. The sidecar maps the call onto an action, resource and
attributes using `bindings.yaml`, and decides with `policies/demo.apl.yaml`.
A deny or a `REQUIRE_APPROVAL` comes back to the client as HTTP 403 with an
`x-openapl-decision` header.

## Prerequisites

- Docker with Compose v2 (needs the `ghcr.io/agentgateway/agentgateway:v1.7.0` image).
- Python 3.11 with the SDK, the sidecar and the demo requirements. `run.sh`
  uses `sidecar/.venv` if it exists, otherwise `python3`; set `PYTHON` to override.

```bash
python3.11 -m venv sidecar/.venv
sidecar/.venv/bin/pip install ./sdk ./sidecar -r demo/agentgateway/requirements.txt
```

## Run

```bash
./demo/agentgateway/run.sh
```

`run.sh` regenerates the issuer keys, recreates `out/`, brings the stack up,
runs the 13 scenarios, prints the results and always tears the stack down
(also on failure). It exits non-zero if any scenario does not match its
expectation. The gateway listens on `127.0.0.1:3000`; the sidecar ports are
not published.

## Scenarios

Expectations are data in `scenarios.yaml`; the runner checks each one.

| Scenario | Expected | What it proves |
|---|---|---|
| `list-tools` | 200 | `tools/list` passes through the sidecar without a decision. |
| `allow-small-refund` | 200 | A refund of 150 through support-agent then refund-agent is allowed; the call reaches the MCP server. |
| `deny-attenuation` | 403 DENY | Attenuation: refund-agent has no delegation edge from support-agent for `payments.void`, so the chain cannot do more than its narrowest link. |
| `approval-required` | 403 REQUIRE_APPROVAL | A refund of 350 needs `role:support-manager` approval. |
| `approved-retry` | 200 | The same call with a matching approval claim in the token is allowed. |
| `approval-replay` | 403 REQUIRE_APPROVAL | Approvals are bound to attributes: the same approval used for amount 360 does not apply. |
| `orphan-agent` | 403 DENY | `legacy-agent`'s owner is not active in the directory snapshot, so the agent is denied. |
| `over-deep-chain` | 403 DENY | A three-agent chain exceeds the depth limit (`chain depth 3 exceeds 2`). |
| `prompt-injected-export` | 403 DENY | P2, no confused deputy: support-agent, acting for alice, cannot call `crm.export`, which alice's grants do not cover. |
| `wrong-group` | 403 DENY | carol (group `marketing`) cannot use the support delegation. |
| `no-token` | 401 | Gateway rejection: `jwtAuth` strict stops the request before the sidecar sees it. |
| `oversize-args` | 413 or 403 | Gateway rejection: a body over `maxRequestBytes` (65536) never reaches the sidecar as a partial body; either the gateway refuses it (413, observed) or the sidecar denies it. |
| `batch` | 400 or 403 | A JSON-RPC batch holding one allowed and one denied call never executes the denied call. agentgateway would answer 400 to the array after ext_authz saw it; the sidecar denies the array first (403, observed) because one call is denied. |

`act.sub` values are the bare identity values: `refund-agent`,
`triage-agent`, `legacy-agent` and `spiffe://acme.com/agents/support-agent`.

## Output

`run.sh` prints, in order: the scenario table, the decision log lines, two
`openapl explain` outputs (what the support agent can reach, and on behalf of
`group:support-staff`) and an OSCAL evidence summary. Files land in
`demo/agentgateway/out/` (git-ignored):

| File | Content |
|---|---|
| `decisions.jsonl` | One JSON line per decision (chain, action, resource, reasons, matched grants, controls, `decision_id`). |
| `evidence.json` | The full OSCAL evidence document built from the log. |
| `jwks.json`, `private.pem` | The demo issuer's keys, regenerated on every run. |
| `compose.log` | Container logs, written only when a run fails. |

## The issuer is a demo stand-in

`issuer.py` plays the identity provider: it signs the demo tokens with a key
generated into `out/` at run time. A real deployment would use an IdP. Keycloak
is a later follow-up, because Keycloak 26.7 does not issue nested `act`
delegation tokens. The private key in `out/` and the sidecar token
`demo-token` in `compose.yaml` are demo-only: they protect nothing, and the
key never leaves your machine.

## More

- [Integration guide](../../docs/integrations/agentgateway.md): how to wire any agentgateway to the sidecar.
- [VERIFIED.md](VERIFIED.md): what agentgateway v1.7.0 was observed to send.
- [Sidecar reference](../../sidecar/README.md).
