# Contributing to OpenAPL

Thanks for helping. OpenAPL decides whether an agent may act, and its
decisions and evidence go to security engineers and assessors, so five
things have to hold, and most of this guide is about keeping them:

1. **Decisions are deterministic.** `Authorizer.decide` is a pure function
   of the policy set, the optional directory snapshot and the request. It
   does no network or file I/O, never reads the clock (the time arrives as
   `now`) and calls no LLM or probabilistic detector
   ([SPEC §3](spec/SPEC.md#3-design-principles)).
2. **Errors fail closed.** A parse error, unknown principal, inactive owner,
   condition error, malformed request or internal error is a `DENY` with a
   reason. No exception escapes the decision function, and the sidecar
   denies on anything it doesn't expect, including a decision-log write
   failure.
3. **Denies win.** A matching deny at any link of the chain gives `DENY`,
   and a `DENY` beats `REQUIRE_APPROVAL`, for one decision and across a
   JSON-RPC batch. Nothing an intermediary adds gives the caller more than
   both the origin and the caller are granted
   ([SPEC §7.5](spec/SPEC.md#75-required-properties)).
4. **No overclaiming.** OSCAL evidence holds observations only: no findings
   and no statement that a control is satisfied or not. That judgement stays
   with the assessor.
5. **Untrusted claims and tool arguments stay data.** Purpose, task id,
   approvals and `iat` come only from verified claims, never from tool
   arguments or AuthZEN properties. Bindings may set only the action,
   resource and attributes, and an action can't be built from `${args.*}`.
   Nothing in a policy, claim or request is run as code.

This guide covers the code: the SDK, the sidecar and the demo. Changes to
the specification itself, including the schema and the expected decisions in
the conformance suites, follow the process in
[spec/CONTRIBUTING.md](spec/CONTRIBUTING.md), which includes a 30-day public
comment period for normative changes.

- [Ways to help](#ways-to-help)
- [Development setup](#development-setup)
- [Code layout](#code-layout)
- [Adding or changing a conformance case](#adding-or-changing-a-conformance-case)
- [Adding or changing an example policy](#adding-or-changing-an-example-policy)
- [Pull requests](#pull-requests)
- [Security](#security)
- [License](#license)

## Ways to help

- **Report a wrong decision.** A request that the engine decides
  differently from [SPEC §7.3](spec/SPEC.md#73-decision-algorithm) is the
  most serious kind of bug. Give the policy, the request and both decisions,
  ideally as a conformance case (below).
- **Report a fail-open path.** Any input that reaches `ALLOW` without a
  decision, or a sidecar request that passes through when it should be
  decided, belongs here. If it can be exploited, report it privately; see
  [SECURITY.md](SECURITY.md).
- **Add conformance cases** for behaviour the
  [suites](spec/conformance/) don't cover yet.
- **Write an example policy** for a delegation pattern the
  [examples](spec/examples/) don't show.
- **Work on a known limitation** in
  [SPEC §12](spec/SPEC.md#12-known-limitations). These change decision
  semantics, so they start as an issue.

For anything larger than a small fix, open an issue first so we can agree on
the approach before you write the code.

## Development setup

You need Python 3.11 or newer.

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e "sdk[dev]" -e "sidecar[dev]"
(cd sdk && pytest -q)
(cd sidecar && pytest -q)
python spec/scripts/validate_examples.py
npx markdownlint-cli2 README.md CONTRIBUTING.md SECURITY.md spec/CONTRIBUTING.md
```

`sdk/tests/test_conformance.py` runs every case in `spec/conformance/`, and
`sdk/tests/test_properties.py` checks properties P1 to P5 with Hypothesis.

To try the sidecar, build it from the repository root:

```sh
docker build -f sidecar/Dockerfile -t openapl-sidecar:dev .
```

The agentgateway demo needs Docker with Compose v2 and pulls
`ghcr.io/agentgateway/agentgateway:v1.7.0`:

```sh
pip install -r demo/agentgateway/requirements.txt
pytest -q demo/agentgateway/tests
./demo/agentgateway/run.sh
```

`run.sh` uses `sidecar/.venv` if it exists, otherwise `python3`; set
`PYTHON` to choose another interpreter.

## Code layout

```text
sdk/src/openapl/
  authorizer.py               Authorizer: the decision algorithm (SPEC §7.3)
  chain.py                    the chain and Request from verified RFC 8693 claims
  approvals.py                bound approval claims and attributes_hash
  conditions.py               CEL `when` conditions
  match.py                    action, resource and selector matching
  model.py                    the frozen data model: Request, Link, Decision, ...
  policyset.py, schema.py     loading a policy directory and JSON Schema validation
  schemas/openapl-v0.1.json   the bundled schema, a byte-identical copy of spec/schemas/
  controls.py                 the framework-to-control table (SPEC §9.2)
  decision_log.py             the JSON Lines decision log
  evidence.py                 OSCAL assessment results from the log
  explain.py                  explain and inventory
  cli.py                      the openapl command
sidecar/src/openapl_sidecar/
  gate.py                     claims and bindings to a decision, failing closed
  extauthz.py, authzen.py     the Envoy ext_authz (gRPC) and AuthZEN (HTTP) servers
  mcp.py, bindings.py         MCP message parsing and tool-call bindings
  claims.py, jsonstrict.py    claims metadata and strict JSON parsing
  config.py, server.py        environment settings and the openapl-sidecar command
spec/                         the specification, schema, example, conformance suites
demo/agentgateway/            the agentgateway demo
docs/integrations/            gateway integration guides
```

## Adding or changing a conformance case

Suites live in `spec/conformance/*.yaml`, in the format of
[SPEC §10.1](spec/SPEC.md#101-case-file-format). Each file is one policy set
and its cases; `sdk/tests/test_conformance.py` picks up every file, so a new
suite needs no test code. Run them with:

```sh
(cd sdk && pytest -q tests/test_conformance.py)
```

- `decision`, `approvers` and `matched` are normative; `reasons` and
  `reasons_include` check the reference engine's wording. Prefer
  `reasons_include` when only one reason matters.
- A new suite also gets a row in the table in
  [SPEC §10.2](spec/SPEC.md#102-suites-in-v01).
- Adding a case that the engine already passes documents existing behaviour.
  Changing an expected decision, or adding a case the engine fails, changes
  the semantics: open an issue and follow
  [spec/CONTRIBUTING.md](spec/CONTRIBUTING.md).
- If a property test finds a counterexample, keep it as a regression test
  and, where it is about semantics, as a conformance case.

## Adding or changing an example policy

Example policies are `spec/examples/*.apl.yaml`. Each must validate against
the schema (`python spec/scripts/validate_examples.py`). The
`refund-delegation` example is quoted in the specification and the README and
is the policy set of `spec/conformance/refund-delegation.yaml`, so a change to
it must keep all three in step.

The schema exists twice, in `spec/schemas/` and in
`sdk/src/openapl/schemas/`. Change both; `sdk/tests/test_schema.py` fails if
they differ.

## Pull requests

- Keep each pull request to one change, with tests. CI runs the SDK tests
  and the example check on Python 3.11 to 3.13, the sidecar tests on the same
  versions, a sidecar image build and smoke test, and the agentgateway demo.
- A change to decision semantics, the schema or the conformance expectations
  also updates [spec/SPEC.md](spec/SPEC.md) and
  [spec/CHANGELOG.md](spec/CHANGELOG.md).
- Write commit messages in the present tense ("Add a depth-limit case"), and
  sign them off for the DCO: `git commit -s`.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). A
`REQUIRE_APPROVAL` or `DENY` where you expected `ALLOW` is a normal bug, not a
vulnerability.

## License

By contributing, you agree that your code, schemas, examples and conformance
data are licensed under the [Apache License 2.0](LICENSE), and changes to the
specification text under [CC BY 4.0](spec/LICENSE-SPEC).
