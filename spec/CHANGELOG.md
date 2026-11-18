# Changelog

All notable changes to the OpenAPL specification are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
OpenAPL uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-draft] — 2026-11-18

### Added
- Specification text (`SPEC.md`): document shape and directory-wide
  policy sets; principals, owners and `acts_for`; entitlements, denies,
  CEL conditions, purpose, stateless expiry, `otherwise` and bound
  approval claims; delegation-chain semantics with per-link grades and
  properties P1–P5; decision records and the control table.
- JSON Schema `schemas/openapl-v0.1.json` and the example
  `examples/refund-delegation.apl.yaml`.
- Conformance suites `conformance/*.yaml` and their file format.
- Rules settled during review of the reference engine: human links are
  `user:<id>` and malformed links are denied; deny resources treat
  `${...}` as `*`; every request carries `now`, and `iat > now` fails
  duration expiry; P1 stated as an endpoint bound plus relay
  monotonicity; no `chain.depth` in conditions; `explain` is
  conservative; evidence contains observations only.
