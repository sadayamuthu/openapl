# OpenAPL

**Access Policy Language for humans and AI agents — an IAM policy layer for agentic systems.**

> **Who can do what, for whom — and the proof of it.**

OpenAPL is an open, declarative, vendor-neutral language for access
decisions about humans, agents and services, which any gateway can
enforce. It evaluates the whole delegation chain (the human who started
the work, every agent it passed through, and the agent calling the tool)
and returns `ALLOW`, `DENY` or `REQUIRE_APPROVAL`, with the entitlements,
policies and control references that produced the decision. Decisions are
deterministic: there is no LLM or probabilistic component in the decision
path.

<sub>Not related to the APL programming language. "APL" here stands for
<b>Access Policy Language</b>.</sub>

[Specification](./spec/SPEC.md) · [Schema](./spec/schemas/openapl-v0.1.json) ·
[Example](./spec/examples/refund-delegation.apl.yaml) ·
[Conformance cases](./spec/conformance/) · [Changelog](./spec/CHANGELOG.md) ·
[Python SDK](./sdk/README.md)

## OpenAPL and OpenGPL

| | **OpenGPL** — Governance Policy Language | **OpenAPL** — Access Policy Language |
|---|---|---|
| Question | Is the AI behaving acceptably? | May this principal do this action, for whom, on what? |
| Contents | input/output/model controls, audit, compliance mapping | principals, owners, entitlements, delegation, decisions |
| How it decides | probabilistic detectors allowed (PII, injection) | strictly deterministic and explainable; no LLM |
| Enforced at | SDK/sidecar around the model call | gateway, at the tool or agent call |
| Peers | guardrail products | Cedar, OPA/Rego, XACML, Gravitee GAPL |

Neither depends on the other at runtime.

## Quick start

Requires Python 3.11 or later.

```bash
pip install -e sdk
openapl validate spec/examples
```

```
✓ 2 principals, 2 entitlements, 2 denies from 1 files
```

Decide one request (dev mode: the chain is given as a list, human first):

```bash
openapl decide spec/examples \
  --chain user:alice@acme.com,support-agent,refund-agent \
  --origin-claims '{"groups": ["support-staff"]}' \
  --action payments.refund --resource order/123 \
  --attr order_id=123 --attr amount=150 --attr account_status=open \
  --purpose customer-refund --task-id t1 --now 1000
```

```
DECISION: ALLOW
```

With `--attr amount=350` the refund agent's entitlement falls through to
its `otherwise`, and the decision is `REQUIRE_APPROVAL` by
`role:support-manager`. `decide` exits 0 for `ALLOW`, 3 for `DENY` and 4
for `REQUIRE_APPROVAL`; add `--json` for the full decision record.

What could the support agent cause if it were hijacked?

```bash
openapl explain spec/examples support-agent
```

```
PRINCIPAL
  support-agent (agent)
OWNER
  priya@acme.com
ACTS FOR
  group:support-staff: payments.refund
ENTITLEMENTS
  (none)
CAN DELEGATE
  refund-agent: payments.refund
DELEGATED FROM
  (none)
REACH IF COMPROMISED
  payments.refund  order/${request.order_id}  via support-agent → refund-agent
```

`explain` is conservative: it may over-report reach, but never
under-reports what the engine could allow.

## Sidecar

`sidecar/` is a policy decision point that puts the SDK behind Envoy
`ext_authz` (gRPC, port 9000) and AuthZEN 1.0 (HTTP, port 8081), so a
gateway such as agentgateway can enforce OpenAPL on MCP tool calls.

```bash
docker build -f sidecar/Dockerfile -t openapl-sidecar:dev .
docker run -d -p 127.0.0.1:8081:8081 -e OPENAPL_PDP_TOKEN=secret \
  -v "$PWD/spec/examples:/policies:ro" openapl-sidecar:dev
curl -s -H 'Authorization: Bearer secret' -H 'Content-Type: application/json' \
  -d @sidecar/tests/data/authzen-allow.json \
  http://127.0.0.1:8081/access/v1/evaluation
```

Port 9000 must be reachable only by the gateway. See
[sidecar/README.md](./sidecar/README.md) for configuration and security.

## Demo

`demo/agentgateway/` runs OpenAPL behind agentgateway v1.7.0 as `ext_authz`
in front of two MCP servers: `./demo/agentgateway/run.sh` plays 13 scenarios
(attenuation, approvals bound to attributes, orphan agents, depth limit,
gateway rejections) and prints the decision log, `explain` output and an OSCAL
evidence summary. See the [demo README](./demo/agentgateway/README.md) and the
[agentgateway integration guide](./docs/integrations/agentgateway.md).

## Repository

- `spec/`: the specification, JSON Schema, example policy and conformance
  cases.
- `sdk/`: the `openapl` Python package (engine and CLI).
- `sidecar/`: the `openapl-sidecar` AuthZEN and ext_authz service.

## License

The OpenAPL specification text (spec/SPEC.md and spec/CHANGELOG.md) is
licensed under CC BY 4.0 (spec/LICENSE-SPEC). Code, schemas, scripts,
example policies and conformance data (sdk/, spec/schemas/, spec/scripts/,
spec/examples/ and spec/conformance/) are licensed under Apache-2.0
(spec/LICENSE-CODE).

## Tests

```bash
cd sdk && pytest -q && python ../spec/scripts/validate_examples.py
cd sidecar && pytest -q
```
