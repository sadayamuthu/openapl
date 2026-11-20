# Security Policy

## Reporting a vulnerability

Please don't report security problems in a public issue or pull request.
Use
[**Report a vulnerability**](https://github.com/sadayamuthu/openapl/security/advisories/new)
on the repository's Security tab instead. Only the maintainer can see the
report.

Include what you can of:

- the commit you ran (`git rev-parse HEAD`), the package versions
  (`pip show openapl openapl-sidecar`, or `openapl-sidecar --version`), your
  Python version and OS
- how OpenAPL was run: the Python SDK, the `openapl` CLI or the sidecar (and
  for the sidecar, whether through `ext_authz` or AuthZEN, the gateway and
  its version, and whether `OPENAPL_DEV_MODE` was set)
- the policy files and bindings file involved, reduced to the smallest set
  that shows the problem
- the request or token claims, with made-up identities and no real tokens
- steps to reproduce, and the decision you got compared with the one you
  expected

You'll get a reply when the report has been read, and again when a fix is
ready. The advisory names you unless you'd rather it didn't.

## Supported versions

OpenAPL is pre-1.0 and has no releases yet. Fixes land on `main`; please
reproduce on the latest `main` before reporting.

## What counts

OpenAPL decides whether an agent may call a tool, and the sidecar is a
network service that a gateway trusts with that decision. Anything that
breaks one of these promises is a security issue:

- **Errors fail closed.** `Authorizer.decide` never raises: a malformed
  request, a malformed human link, an unknown principal, an inactive owner,
  a condition error, an unset request time or an internal error is a `DENY`
  with a reason. A malformed `act` chain or approval claim gives an empty
  chain, which is denied. An input that makes the engine raise, or reach
  `ALLOW` without satisfying [SPEC §7.3](spec/SPEC.md#73-decision-algorithm),
  is in scope.
- **Denies and attenuation hold.** A matching deny at any link gives
  `DENY`; `DENY` beats `REQUIRE_APPROVAL`; a chain never gives the caller
  more than both the origin and the caller are granted
  ([SPEC §7.5](spec/SPEC.md#75-required-properties)). A request that gets
  around a deny or gains a permission through an intermediary is in scope.
- **Request context comes from verified claims only.** Purpose, task id,
  approvals and `iat` are read from the claims, never from tool arguments or
  AuthZEN properties, and a binding's action can't contain `${args.*}`. An
  approval is bound to the request's attributes by `attributes_hash`. A tool
  call that sets its own purpose, approval or action, or replays an approval
  for different attributes, is in scope.
- **The sidecar fails closed.** A parse error, unknown MCP method, unbound
  placeholder, decision-log write failure or internal error is a deny. MCP
  bodies with NaN, Infinity, overflowing numbers or duplicate JSON keys are
  denied; one denied call denies a whole JSON-RPC batch; any HTTP method
  other than `POST`, `GET` and `DELETE` is denied. A `tools/call` that
  reaches the MCP server without an `ALLOW` is in scope.
- **The AuthZEN port checks its caller and its input.** Every `POST`
  (the evaluation endpoints) needs the `OPENAPL_PDP_TOKEN` bearer token,
  compared in constant time; bodies over
  1 MiB are rejected (413), as are `Transfer-Encoding`, duplicate JSON keys,
  non-finite numbers and batches of more than 100 evaluations; each socket
  read times out after 10 seconds. A way past these checks is in scope.
- **The decision log holds the decision record only.** Each line is the
  [SPEC §9.1](spec/SPEC.md#91-decision-record) record: the decision, chain
  ids, action, resource, reasons, matched entitlements, grants, policies,
  controls, dev-mode flag, id and time. It does not hold the token, the
  claims, the approval items or the request attributes. Any of those
  appearing in a record is in scope.
- **OSCAL evidence holds observations only.** `openapl evidence` writes one
  observation per decision and per-control summaries, with no findings and
  no statement that a control is satisfied. Output that claims a control is
  met is in scope.
- **Untrusted input stays data.** Policies and bindings are parsed with
  `yaml.safe_load`, conditions are CEL evaluated by `cel-python`, and the
  decision path does no network or file I/O. A policy, bindings file, claim
  set, request or decision log that makes the SDK, CLI or sidecar run a
  command, or read or write outside the paths it was given, is in scope.

These are known limits, not vulnerabilities:

- **The `ext_authz` caller is not authenticated.** Port 9000 trusts the
  claims metadata in each check request; anyone who can reach it can forge
  claims. Run the sidecar on a private network that only the gateway can
  reach, and don't publish port 9000. The container doesn't publish it by
  default.
- **The gateway must verify tokens.** OpenAPL decides on claims it is
  given; it does not verify JWT signatures, audiences or expiry. Passthrough
  MCP methods, notifications, responses, `GET` and `DELETE` are allowed
  without claims, so JWT authentication on the MCP route must be mandatory
  (strict). See [sidecar/README.md](sidecar/README.md) for the required
  agentgateway settings.
- **The identity provider must issue correct `act` chains.** The chain is
  taken from nested RFC 8693 `act` claims as issued. An IdP that lets a
  client claim an actor it isn't, or omits actors, gives OpenAPL a wrong
  chain. The origin is `user:<email>` without an `email_verified` check
  ([SPEC §12](spec/SPEC.md#12-known-limitations)), so the IdP must only issue
  verified email addresses.
- **Prior actors are a trust assumption.** RFC 8693 §4.1 treats nested
  `act` claims for prior actors as informational only, while OpenAPL makes
  access decisions on them: every edge of the chain must exist. OpenAPL
  therefore trusts the IdP that issued the token to have checked each
  delegation step.
- **Tool arguments are attacker-controlled.** Bindings turn tool arguments
  into the resource and attributes the policy sees, and a hijacked agent
  chooses its arguments. A deny or `when` condition on such an attribute
  (for example `request.account_status == 'closed'`) holds only against an
  agent that reports the attribute honestly; base denies that must hold
  against a hostile agent on the action, the chain or verified claims.
- **The demo issuer is not an IdP.** `demo/agentgateway/issuer.py` signs demo
  tokens with a key generated at run time, and `demo-token` in the demo's
  `compose.yaml` is a fixed sidecar token. Neither protects anything; don't
  reuse them.
- **Dev mode trusts the caller's chain.** With `OPENAPL_DEV_MODE=1` the chain
  comes from the `x-openapl-chain` header or AuthZEN `context.chain`, and
  AuthZEN runs without a token when none is set. Decisions are flagged
  `dev_mode: true`. Never use it outside local development.
- **Approval items carry no link.** One approval item can satisfy both the
  origin's and the caller's `otherwise` for the same entitlement and
  approver ([SPEC §12](spec/SPEC.md#12-known-limitations)).
- **The decision log is not protected by OpenAPL.** It is created with your
  process's default permissions and is not signed. Records hold chain ids
  (which can be email addresses) and resources, which can include values
  from tool arguments. Restrict the directory, and protect the log's
  integrity yourself if it is used as evidence.
- **Policy authors are trusted.** A policy can grant anything, and OpenAPL
  sets no cost limit on its CEL conditions.
