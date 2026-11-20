# Contributing to the OpenAPL specification

Thank you for your interest in contributing to OpenAPL, the Access Policy
Language for humans and AI agents.

This document explains how to contribute to the specification
([`SPEC.md`](./SPEC.md)), the JSON Schema, the example policies and the
conformance suites. Changes to the SDK, the sidecar and the demo follow the
[repository guide](../CONTRIBUTING.md).

---

## Ways to Contribute

### 1. Specification Feedback

- File a [GitHub Issue](https://github.com/sadayamuthu/openapl/issues) for
  spec clarifications, errors, gaps or questions
- Submit a Pull Request for non-normative fixes (typos, formatting,
  non-normative sections, example corrections that don't change a decision)

### 2. Policy Examples

Contributions to the [`examples/`](./examples/) directory are especially welcome:

- Delegation patterns the current example doesn't show (agent-to-agent
  hand-offs, services as origins, approvals by different roles)
- Use cases from other domains (finance, healthcare, government, internal
  tooling)
- Edge cases (deep chains, wildcard denies, directory snapshots with
  inactive owners)

### 3. Conformance Cases

- New cases in [`conformance/`](./conformance/) for behaviour the suites
  don't cover yet, in the format of §10.1
- Regression cases for counterexamples found by property testing

### 4. Schema Contributions

- Bug fixes in schema validation rules
- Stricter patterns for ids, selectors and action names

### 5. Integration Guides

- Walkthroughs for gateways other than agentgateway
- Mapping of identity providers' token-exchange output onto §8.2

---

## Governance

The governance model is intentionally lightweight at this stage:

| Change Type | Process | Timeline |
|---|---|---|
| **Normative** (schema, decision semantics, claims, conformance expectations) | Issue → Draft PR → 30-day comment → Review → Merge | ~6–8 weeks |
| **Non-normative** (examples, non-normative sections, docs, typos) | PR → Review → Merge | ~1–2 weeks |
| **PATCH clarification** | Issue → PR → Quick review | ~1 week |

A change is normative if it can change a decision, the decision record, what
a policy document may contain, or what a conforming engine must do (the
MUST and SHOULD rules in [`SPEC.md`](./SPEC.md)). Changing the expected
`decision`, `approvers` or `matched` of a conformance case is normative.

All **normative changes** require:

1. A GitHub Issue describing the problem and proposed solution
2. A minimum **30-day public comment period**
3. No unresolved objections from active contributors
4. Updated conformance cases, an entry in [`CHANGELOG.md`](./CHANGELOG.md),
   and a version change in [`VERSION`](./VERSION) as described in §13

> Community governance will be formalized at v1.0 when OpenAPL reaches stable status.

---

## Pull Request Guidelines

- Keep PRs focused — one change per PR
- For spec changes, reference the GitHub Issue number
- For examples, ensure the policy validates against the JSON Schema
  (`python spec/scripts/validate_examples.py`)
- For schema changes, update both `schemas/openapl-v0.1.json` and the copy in
  `sdk/src/openapl/schemas/`; a test fails if they differ
- For conformance changes, ensure the reference engine passes them
  (`cd sdk && pytest -q tests/test_conformance.py`)
- Use present tense in commit messages: "Add a depth-limit case" not "Added"
- Sign your commits with DCO: `git commit -s`

---

## Code of Conduct

OpenAPL follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

---

## License

By contributing to OpenAPL you agree that your contributions will be licensed under:

- **Specification text** (`SPEC.md`, `CHANGELOG.md`): Creative Commons CC BY 4.0
  ([`LICENSE-SPEC`](./LICENSE-SPEC))
- **Code, schemas, examples and conformance data**: Apache License 2.0
  ([`LICENSE`](../LICENSE))

---

## Questions?

- GitHub Issues: [github.com/sadayamuthu/openapl/issues](https://github.com/sadayamuthu/openapl/issues)
