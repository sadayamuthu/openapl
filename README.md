# OpenAPL

**Access Policy Language for humans and AI agents.**

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
  --purpose customer-refund --task-id t1
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

## Repository

- `spec/`: the specification, JSON Schema, example policy and conformance
  cases. License CC BY 4.0.
- `sdk/`: the `openapl` Python package (engine and CLI). License
  Apache 2.0.

## Tests

```bash
cd sdk && pytest -q && python ../spec/scripts/validate_examples.py
```
