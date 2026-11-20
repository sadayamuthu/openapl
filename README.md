# OpenAPL

[![CI](https://github.com/sadayamuthu/openapl/actions/workflows/ci.yml/badge.svg)](https://github.com/sadayamuthu/openapl/actions/workflows/ci.yml)
[![Spec](https://img.shields.io/badge/spec-v0.1.0--draft-orange)](spec/SPEC.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Access Policy Language for humans and AI agents — an IAM policy layer for agentic systems.**

> **Who can do what, for whom — and the proof of it.**

OpenAPL is an open, declarative, vendor-neutral language for access
decisions about humans, agents and services, which any gateway can
enforce. It evaluates the whole delegation chain (the human who started
the work, every agent it passed through, and the agent calling the tool)
and returns `ALLOW`, `DENY` or `REQUIRE_APPROVAL`, with the entitlements,
policies and control references that produced the decision.

Decisions are deterministic: there is no LLM or probabilistic component in
the decision path. Errors fail closed: a malformed request, an unknown
principal or an internal error is a `DENY` with a reason. The OSCAL evidence
OpenAPL exports records decisions as observations and never claims a
control is met.

<sub>Not related to the APL programming language. "APL" here stands for
<b>Access Policy Language</b>.</sub>

## What a policy looks like

A support agent acts for support staff and delegates refunds to a refund
agent ([`spec/examples/refund-delegation.apl.yaml`](spec/examples/refund-delegation.apl.yaml)):

```yaml
openapl: '0.1'
policy: payments-access
version: 1.2.0
description: Refund delegation from support staff through a support agent to a refund agent.
compliance: [NIST-800-53, SOC2]

principals:
  support-agent:
    kind: agent
    identity: { spiffe: "spiffe://acme.com/agents/support-agent" }
    owner: priya@acme.com
    acts_for:
      - who: group:support-staff
        actions: [payments.refund]
    may_delegate:
      - to: refund-agent
        actions: [payments.refund]
  refund-agent:
    kind: agent
    identity: { oauth_client_id: "refund-agent" }
    owner: priya@acme.com

humans:
  source: idp
  match: { groups_claim: groups, roles_claim: roles }

entitlements:
  - id: refund-small-orders
    grant_to: [refund-agent]
    action: payments.refund
    resource: "order/${request.order_id}"
    when:
      - "request.amount <= 200"
      - "'support-staff' in chain.origin.groups"
    purpose: customer-refund
    expires: task
    otherwise: require_approval(role:support-manager)
  - id: support-staff-refunds
    grant_to: ["group:support-staff"]
    action: payments.refund
    resource: "order/*"

deny:
  - id: no-refunds-on-closed-accounts
    grant_to: ["*"]
    action: payments.refund
    resource: "order/*"
    when: ["request.account_status == 'closed'"]
  - id: no-bulk-refunds
    grant_to: ["*"]
    action: payments.refund
    resource: "order/bulk-*"

delegation:
  max_depth: 3
  require_human_origin: true
```

For the chain `user:alice@acme.com → support-agent → refund-agent`
([SPEC §7.4](spec/SPEC.md#74-example-non-normative)):

| Request | Decision | Why |
|---|---|---|
| `amount: 150` | `ALLOW` | Alice is granted by `support-staff-refunds`, the refund agent by `refund-small-orders`, and both delegation edges exist |
| `amount: 350` | `REQUIRE_APPROVAL(role:support-manager)` | The refund agent's `when` is false and its entitlement has `otherwise` |
| `amount: 350` with a bound approval | `ALLOW` | The approval grants the refund agent |
| `account_status: closed` | `DENY` | `no-refunds-on-closed-accounts` matches; a deny beats any grant or approval |
| chain `user:alice@acme.com → refund-agent` | `DENY` | `refund-agent` has no `acts_for` |

## What it does

| | Today, in `openapl` 0.1.0 and `openapl-sidecar` 0.1.0 |
|---|---|
| **Validate** | Every `*.apl.yaml` file in a directory is checked against the [JSON Schema](spec/schemas/openapl-v0.1.json) and loaded as one policy set (`openapl validate`) |
| **Decide** | `Authorizer.decide` evaluates the whole chain: the origin and the caller must both be granted, every edge must carry the action, and any matching deny at any link wins. It does no network or file I/O, never reads the clock and never raises |
| **Delegate** | The chain comes from nested RFC 8693 `act` claims in a gateway-verified JWT; purpose, task id, approvals and `iat` come only from verified claims, never from tool arguments |
| **Explain** | `openapl explain` lists what a principal could cause if it were hijacked. It may over-report reach but never under-reports it |
| **Record** | Each decision names the matched entitlements, per-link grants, `policy@version` values and control references, and can be appended to a JSON Lines decision log |
| **Evidence** | `openapl evidence` exports a log window as an OSCAL 1.2.3 assessment-results document holding observations only: no findings, no compliance determination |
| **Enforce** | The sidecar puts the SDK behind Envoy `ext_authz` (gRPC, port 9000) and AuthZEN 1.0 (HTTP, port 8081), so a gateway such as agentgateway can enforce OpenAPL on MCP tool calls |
| **Conform** | Nine conformance suites in [`spec/conformance/`](spec/conformance/) define the expected decisions; the reference engine runs all of them |

OpenAPL decides; it does not authenticate. The gateway verifies tokens, and
the identity provider issues the `act` chain. See
[Known limitations](spec/SPEC.md#12-known-limitations) and
[SECURITY.md](SECURITY.md) for what that means in a deployment.

## OpenAPL and OpenGPL

| | **OpenGPL** — Governance Policy Language | **OpenAPL** — Access Policy Language |
|---|---|---|
| Question | Is the AI behaving acceptably? | May this principal do this action, for whom, on what? |
| Contents | input/output/model controls, audit, compliance mapping | principals, owners, entitlements, delegation, decisions |
| How it decides | probabilistic detectors allowed (PII, injection) | strictly deterministic and explainable; no LLM |
| Enforced at | SDK/sidecar around the model call | gateway, at the tool or agent call |
| Peers | guardrail products | Cedar, OPA/Rego, XACML, Gravitee GAPL |

Neither depends on the other at runtime.

## Install

OpenAPL needs **Python 3.11 or newer**. Nothing is published to PyPI or a
container registry yet; install from a clone of this repository.

```sh
pip install -e sdk                  # the openapl package and CLI
pip install -e sdk -e sidecar       # and the openapl-sidecar service
```

The sidecar container is built locally from the repository root:

```sh
docker build -f sidecar/Dockerfile -t openapl-sidecar:dev .
```

## Quick start

```sh
openapl validate spec/examples
#   ✓ 2 principals, 2 entitlements, 2 denies from 1 files
```

Decide one request (dev mode: the chain is given as a list, human first):

```sh
openapl decide spec/examples \
  --chain user:alice@acme.com,support-agent,refund-agent \
  --origin-claims '{"groups": ["support-staff"]}' \
  --action payments.refund --resource order/123 \
  --attr order_id=123 --attr amount=150 --attr account_status=open \
  --purpose customer-refund --task-id t1 --now 1000
#   DECISION: ALLOW
```

With `--attr amount=350` the refund agent's entitlement falls through to
its `otherwise`, and the decision is `REQUIRE_APPROVAL` by
`role:support-manager`. `decide` exits 0 for `ALLOW`, 3 for `DENY` and 4
for `REQUIRE_APPROVAL`; add `--json` for the full decision record, and
`--log decisions.jsonl` to append it to a decision log.

What could the support agent cause if it were hijacked?

```sh
openapl explain spec/examples support-agent
```

```text
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

Export the decisions in a time window as OSCAL evidence:

```sh
openapl evidence decisions.jsonl --since 0 --until 2000 -o evidence.json
```

In your application, build the request from the claims your gateway has
verified, and log every decision:

```python
import time
from openapl import Authorizer
from openapl.chain import request_from_claims
from openapl.decision_log import DecisionLog

authz = Authorizer.from_dir("spec/examples")
log = DecisionLog("decisions.jsonl")

request = request_from_claims(
    verified_claims, authz.ps, "payments.refund", "order/123",
    {"order_id": "123", "amount": 150, "account_status": "open"},
    now=int(time.time()),
)
decision = authz.decide(request)
log.append(decision)
if decision.decision != "ALLOW":
    ...  # refuse, or route to decision.approvers
```

[sdk/README.md](sdk/README.md) covers the library API.

### Sidecar

```sh
docker run -d -p 127.0.0.1:8081:8081 -e OPENAPL_PDP_TOKEN=secret \
  -v "$PWD/spec/examples:/policies:ro" openapl-sidecar:dev
curl -s -H 'Authorization: Bearer secret' -H 'Content-Type: application/json' \
  -d @sidecar/tests/data/authzen-allow.json \
  http://127.0.0.1:8081/access/v1/evaluation
```

Port 9000 (`ext_authz`) must be reachable only by the gateway. See
[sidecar/README.md](sidecar/README.md) for configuration, bindings and
security.

### Demo

`demo/agentgateway/` runs OpenAPL behind agentgateway v1.7.0 as `ext_authz`
in front of two MCP servers: `./demo/agentgateway/run.sh` plays 13 scenarios
(attenuation, approvals bound to attributes, orphan agents, depth limit,
gateway rejections) and prints the decision log, `explain` output and an OSCAL
evidence summary. See the [demo README](demo/agentgateway/README.md) and the
[agentgateway integration guide](docs/integrations/agentgateway.md).

## Documentation

- [Specification](spec/SPEC.md), [JSON Schema](spec/schemas/openapl-v0.1.json)
  and the [spec changelog](spec/CHANGELOG.md)
- [Example policy](spec/examples/refund-delegation.apl.yaml) and
  [conformance suites](spec/conformance/)
- [Python SDK](sdk/README.md): the library API
- [Sidecar](sidecar/README.md): configuration, bindings, the ext_authz and
  AuthZEN contracts, and security
- [agentgateway integration guide](docs/integrations/agentgateway.md) and the
  [demo](demo/agentgateway/README.md)

## Development

```sh
pip install -e "sdk[dev]" -e "sidecar[dev]"
(cd sdk && pytest -q)                        # engine, CLI and conformance suites
(cd sidecar && pytest -q)                    # sidecar
python spec/scripts/validate_examples.py     # example policies are valid
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the layout, the invariants and
how to change the conformance suites. Report security issues privately; see
[SECURITY.md](SECURITY.md).

## License

Code, schemas, examples and conformance data: [Apache License 2.0](LICENSE).
The specification text ([SPEC.md](spec/SPEC.md) and
[CHANGELOG.md](spec/CHANGELOG.md)): [CC BY 4.0](spec/LICENSE-SPEC).
