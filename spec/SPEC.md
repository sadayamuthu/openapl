# OpenAPL v0.1 Specification

**Access Policy Language for humans and AI agents**

| | |
|---|---|
| Version | 0.1.0-draft |
| Date | 2026-11-18 |
| Status | Draft |
| Document key | `openapl: '0.1'` |
| Policy files | `*.apl.yaml` |
| Schema | [`schemas/openapl-v0.1.json`](./schemas/openapl-v0.1.json) |
| Reference engine | `openapl` Python SDK 0.1.0 ([`../sdk`](../sdk)) |
| License | Specification text CC BY 4.0 ([`LICENSE-SPEC`](./LICENSE-SPEC)); code, schemas, scripts, examples and conformance data Apache-2.0 ([`LICENSE-CODE`](./LICENSE-CODE)) |

OpenAPL is not related to the APL programming language. "APL" here stands
for **Access Policy Language**.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as
described in RFC 2119. Sections marked *non-normative* are explanations
only.

## Table of contents

1. [Abstract](#1-abstract)
2. [Relationship to OpenGPL](#2-relationship-to-opengpl)
3. [Design principles](#3-design-principles)
4. [Document shape and policy sets](#4-document-shape-and-policy-sets)
5. [Principals, humans and `acts_for`](#5-principals-humans-and-acts_for)
6. [Entitlements and denies](#6-entitlements-and-denies)
7. [Delegation semantics](#7-delegation-semantics)
8. [Requests and claims](#8-requests-and-claims)
9. [Decisions](#9-decisions)
10. [Conformance](#10-conformance)
11. [Tooling (non-normative)](#11-tooling-non-normative)
12. [Known limitations](#12-known-limitations)
13. [Versioning](#13-versioning)

---

## 1. Abstract

AI agents call tools, APIs and other agents on behalf of people. Whether a
given agent may perform an action, on a resource, for a given person, is
an access decision. OpenAPL is an open, declarative, vendor-neutral
language for writing those decisions down, and a deterministic semantics
for evaluating them over a **delegation chain**: the human who started the
work, every agent the work passed through, and the agent now calling the
gateway.

Within identity and access management (IAM) for agentic systems, OpenAPL
is the access policy layer. Identity is established upstream, by OAuth
clients and RFC 8693 token exchange; OpenAPL decides what each identity in
the chain may do. It does not authenticate principals or manage accounts.

> **Who can do what, for whom — and the proof of it.**

A conforming engine returns exactly one of `ALLOW`, `DENY` or
`REQUIRE_APPROVAL`, and every decision names the entitlements, policies
and control references that produced it.

## 2. Relationship to OpenGPL

OpenAPL and OpenGPL are two languages in one family.

| | **OpenGPL** — Governance Policy Language | **OpenAPL** — Access Policy Language |
|---|---|---|
| Question | Is the AI behaving acceptably? | May this principal do this action, for whom, on what? |
| Contents | input/output/model controls, audit, compliance mapping | principals, owners, entitlements, delegation, decisions |
| How it decides | probabilistic detectors allowed (PII, injection) | strictly deterministic and explainable; no LLM |
| Enforced at | SDK/sidecar around the model call | gateway, at the tool or agent call |
| Peers | guardrail products | Cedar, OPA/Rego, XACML, Gravitee GAPL |

- OpenGPL v0.1 is not changed by OpenAPL.
- OpenGPL's `model_controls.allow_tools` / `deny_tools` stay as they are.
  Fine-grained tool and agent access belongs in OpenAPL.
- OpenAPL does not read OpenGPL files, and neither depends on the other at
  runtime. The OpenAPL engine does not import OpenGPL code.
- The two share identity fields (`spiffe`, `oauth_client_id`,
  `entra_app_id`, `jwt`) and compliance framework identifiers, so a
  deployment can run both.
- A future OpenGPL version may reference an OpenAPL policy by name. That
  is not specified here.

## 3. Design principles

**Deterministic.** A decision is a pure function of the policy set, the
optional directory snapshot and the request. The engine MUST NOT perform
network or file I/O while deciding, MUST NOT read the clock (the decision
time arrives in the request as `now`), and MUST NOT call an LLM or any
probabilistic detector.

**Fail-closed.** A parse error, unknown principal, inactive owner,
condition error, malformed request or unexpected internal error MUST
produce `DENY` with a reason. No error escapes the decision function.

**Evidence-producing.** Every decision carries the matched entitlement
ids, the per-link grants, the contributing `policy@version` values and the
control references of the frameworks those policies name (§9).

**Gateway-neutral.** The language describes principals, actions,
resources and request attributes. How a gateway maps a tool call onto an
action, resource and attributes (bindings) is adapter configuration, not
policy language.

## 4. Document shape and policy sets

The example used throughout this specification is
[`examples/refund-delegation.apl.yaml`](./examples/refund-delegation.apl.yaml).
Its top level:

```yaml
openapl: '0.1'
policy: payments-access
version: 1.2.0
description: Refund delegation from support staff through a support agent to a refund agent.
compliance: [NIST-800-53, SOC2]

principals: { ... }   # §5
humans: { ... }       # §5
entitlements: [ ... ] # §6
deny: [ ... ]         # §6
delegation: { ... }   # §7
```

| Key | Required | Meaning |
|---|---|---|
| `openapl` | yes | MUST be the string `'0.1'`. |
| `policy` | yes | Policy name, `^[a-z0-9][a-z0-9-]*$`. |
| `version` | yes | Policy version string. |
| `description` | no | Free text. |
| `metadata` | no | Free-form object, ignored by the engine. |
| `compliance` | no | List of framework names from §9.2. Any other name is a load error. |
| `principals` | no | Map of principal id to principal (§5). |
| `humans` | no | Claim names used to match humans (§5). Directory-wide. |
| `entitlements` | no | List of grants (§6). |
| `deny` | no | List of deny rules (§6). |
| `delegation` | no | Chain limits (§7). Directory-wide. |

No other top-level keys are allowed.

### 4.1 Policy sets

A **policy set** is a directory. Loading it MUST follow these rules:

1. Only files whose names end in `.apl.yaml` are read. Every other file is
   ignored. Files are read in ascending name order. A file MAY hold
   several YAML documents; each document is a policy document.
2. Each document MUST be a mapping that validates against the JSON Schema.
3. Principal ids and entitlement ids are global across the directory.
   Grants and denies share one id space. Defining the same principal id or
   entitlement id twice is a load error.
4. `delegation` and `humans` are settings for the whole directory. Each
   MAY appear in at most one document; a second occurrence is a load
   error. Defaults when absent: `max_depth: 3`,
   `require_human_origin: true`, `groups_claim: groups`,
   `roles_claim: roles`.
5. `compliance` is per document. It identifies the document by
   `policy@version`. When several documents share a `policy@version`,
   its frameworks are the ordered union of their `compliance` lists.
6. Every principal MUST have a non-empty `owner`.
7. An entitlement with `expires: task` MUST have a `purpose`.
8. Every `may_delegate.to` MUST name a principal defined in the set.
9. Every `grant_to` selector of a grant or deny MUST be `*`,
   `user:<id>`, `group:<name>` or `role:<name>` with a non-empty name, or
   a principal id defined in the set (§5.2).
10. Every `${` in a grant or deny `resource` MUST begin a placeholder of
    the form `${request.<key>}`, where `<key>` matches
    `[A-Za-z0-9_.-]+` (§6.2).
11. Every `when` expression of a grant or deny MUST compile (§6.3).
12. A load error rejects the whole set. An engine MUST NOT decide
    against a partially loaded set.

An empty set (a directory with no `*.apl.yaml` file, or files defining no
principals and no entitlements) loads successfully, and every decision
against it is `DENY` with the single reason `no policies loaded`.

### 4.2 Directory snapshot

A deployment MAY supply a directory snapshot: a JSON document
`{"active": ["<owner>", ...]}` listing the owners that are currently
active (for example exported from SCIM). When a snapshot is supplied, an
agent or service whose `owner` string is not in `active` is denied
(§7.3). The comparison is exact string equality against the `owner`
value as written in the policy.

## 5. Principals, humans and `acts_for`

```yaml
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
```

- **Kinds.** Policy files declare only principals of `kind: agent` or
  `kind: service`. Humans are never enumerated in policy; they come from
  verified token claims.
- **Identity.** At least one of `spiffe`, `oauth_client_id`,
  `entra_app_id` or `jwt: {iss, sub}`. Identity is used to resolve RFC 8693
  actors to principals (§8.2).
- **Owner.** Required for every principal. There are no orphaned agents.
- **`acts_for`** lists the humans who may hand this agent work and for
  which actions. `who` is a `user:<id>`, `group:<name>` or `role:<name>`
  selector. This is the human→agent edge (§7). An agent with no
  `acts_for` cannot be the first agent after a human.
- **`may_delegate`** lists the agent→agent edges: `to` names a principal
  and `actions` the actions it may pass on.
- **`humans`** names the token claims holding group and role lists
  (`groups_claim`, `roles_claim`). `source` is `idp`.

### 5.1 Links and human ids

A request's chain is a sequence of **links**. Each link has an id, a kind
(`human`, `agent` or `service`) and a claims object.

- A human link's id MUST be `user:<id>`. A link of kind `human` whose id
  does not start with `user:`, and a link of any other kind whose id does
  start with `user:`, is **malformed** and MUST be denied with the reason
  `malformed human link <id>`.
- An agent or service link's id is a principal id from the policy set.

### 5.2 Selectors

Selectors appear in `grant_to`, `acts_for.who` and `otherwise`. A selector
matches a link as follows:

| Selector | Matches |
|---|---|
| `*` | every link |
| `user:<id>` | a human link whose id equals the selector exactly |
| `group:<name>` | a human link whose groups claim (named by `groups_claim`) contains `<name>` |
| `role:<name>` | a human link whose roles claim (named by `roles_claim`) contains `<name>` |
| anything else | a link whose id equals the selector (a principal id) |

A group or role claim that is a single string is treated as a one-item
list. A claim that is absent or neither a string nor a list matches
nothing. `group:` and `role:` selectors never match an agent or service.
In `grant_to`, any other selector (for example `agent:bot`, `group:` or
an undefined principal id) is a load error (§4.1).

## 6. Entitlements and denies

```yaml
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
```

An **entitlement** has `id`, `grant_to` (selectors), `action`, `resource`
and optionally `when`, `purpose`, `expires` and `otherwise`. A **deny
rule** has `id`, `grant_to`, `action`, `resource` and optionally `when`;
it cannot carry `purpose`, `expires` or `otherwise`.

### 6.1 Actions

Actions are namespaced strings (for example `payments.refund`; MCP calls
conventionally `mcp.tools.call:<target>/<tool>`, HTTP calls
`http.<METHOD>:<route>`). An `action` pattern matches a request action if
it is equal to it or matches it as a case-sensitive glob, where `*`
matches any run of characters, `?` one character and `[...]` a character
class. The same rule applies to the actions listed on `acts_for` and
`may_delegate` edges.

### 6.2 Resources

A resource pattern is a glob (same syntax as actions; `*` also matches
`/`) that MAY contain placeholders `${request.<key>}`, where `<key>` is a
request attribute name.

**Grants: strict interpolation.** Each placeholder is replaced by the
string form of `request.attributes[<key>]`, with every glob character
(`*`, `?`, `[`) in the value escaped so the value is matched literally.
An attribute value such as `"*"` therefore cannot widen a grant. If any
referenced attribute is absent, the entitlement does not apply. Policy
authors SHOULD interpolate only string attributes; the string form of
numbers and booleans is that of the reference engine (Python `str`, for
example `True`, `1.0`).

**Denies: wildcard form.** In a deny rule, every `${request.<key>}`
placeholder is treated as `*`, whatever the request attributes are. A
request attribute can therefore never narrow or skip a deny. Narrowing a
deny by attribute belongs in its `when`, which fails closed (§6.3). For
example, with the deny resource `doc/${request.doc_id}` and the request
resource `doc/1`, the deny matches when `doc_id` is `1`, `2` or absent.

A `${` that does not begin a placeholder of the exact form
`${request.<key>}`, with `<key>` matching `[A-Za-z0-9_.-]+` (for example
`${req.x}`, `${ request.x }` or an unclosed `${request.x`), is a load
error (§4.1).

### 6.3 Conditions (`when`)

Conditions are [CEL](https://github.com/google/cel-spec) expressions. The
reference engine uses `cel-python`.

**Activation.** Every condition is evaluated against exactly these
variables:

| Variable | Value |
|---|---|
| `request` | the request attributes (a map) |
| `chain.origin` | the origin link's view |
| `chain.caller` | the caller link's view |
| `principal` | the view of the link being evaluated (the origin or the caller for grants; each link in turn for denies) |

A link's **view** is its claims object with `id` (the link id) and `kind`
added; `id` and `kind` cannot be overridden by claims. The origin human's
claims are its verified token claims except `act`. Agent and service
links carry no claims, so their view is `{id, kind}`.

There is no `chain.depth` and no access to intermediaries. A condition
that references them is a condition error. Depth limits are expressed
only by `delegation.max_depth`. This keeps each endpoint's grade
independent of the intermediaries, which P1(a) needs (§7.5).

**Evaluation.** A `when` list is a conjunction evaluated **in order**:

1. An absent or empty list is true.
2. Each expression MUST compile; an expression that does not compile is
   a load error (§4.1). Each expression MUST evaluate to a boolean;
   otherwise the result is a condition error.
3. Evaluation stops at the first expression that is false, and the list
   is false. Later expressions are not evaluated. So `[false_expr,
   erroring_expr]` is **false**, not an error, while `[erroring_expr,
   false_expr]` is an **error**. This matters for approval eligibility:
   a false list makes `otherwise` apply; an error does not (§6.6).
4. If every expression is true, the list is true.

**Error absorption.** Within one expression, CEL's commutative logical
operators absorb errors: `request.missing || true` evaluates to `true`
and `request.missing && false` to `false`, even though
`request.missing` alone is an error (the attribute is absent). Policy
authors relying on fail-closed behaviour for a missing attribute MUST NOT
combine it with `||` in a way that absorbs the error.

**Errors fail closed.**
- On a grant, a condition error means the entitlement does not grant and
  its `otherwise` does not apply. The reason `condition error in <id>` is
  reported if the link ends with no grant.
- On a deny, a condition error means **the deny fires**, with the reason
  `denied by <id> (condition error)`.

### 6.4 Purpose

If an entitlement names a `purpose`, it applies only when the request's
purpose (from the verified `openapl_purpose` claim, §8.1) is present and
equal to it. If the request has no purpose or a different one, the
entitlement does not apply at all, including its `otherwise`.

### 6.5 Expiry

Expiry is stateless. `expires` is one of:

- `never` (the default): no expiry check.
- `task`: applies only when the request carries a task id (the
  `openapl_task_id` claim). Because `expires: task` requires a `purpose`
  (§4.1) and the purpose check (§6.4) requires the `openapl_purpose`
  claim to equal it, a task grant needs both claims. The token issuer
  ties them together by minting them in the same token when the task
  starts; the engine checks only that both are present and the purpose
  matches.
- `<n><unit>` with unit `s`, `m`, `h` or `d` (for example `15m`):
  applies only when the request carries the token's issue time `iat`,
  `iat <= now`, and `now - iat <= n × unit` (the bound is inclusive). A
  token issued after the decision time (`iat > now`) fails.

An entitlement whose expiry check fails does not apply, including its
`otherwise`.

### 6.6 `otherwise` and approvals

`otherwise: require_approval(<selector>)` (selector `user:`, `group:` or
`role:`) changes what happens when the entitlement applies (selector,
action, resource, purpose and expiry all match) but its `when` list is
**false**: instead of not matching, the entitlement makes the link
eligible for approval by `<selector>`. A `when` that **errors** never
makes a link eligible. `otherwise` works the same on the origin's and the
caller's entitlements.

**Approval items.** An approved retry carries the verified claim
`openapl_approvals`, a list of items:

| Field | Type | Must equal |
|---|---|---|
| `entitlement_id` | string | the entitlement's `id` |
| `approver` | string | the selector inside `require_approval(...)`, as written |
| `action` | string | the request action |
| `resource` | string | the request resource |
| `attributes_hash` | string | SHA-256 of the canonical JSON of the request attributes, lowercase hex |
| `origin` | string | the origin link's id |
| `caller` | string | the caller link's id |
| `exp` | integer | `exp >= now` (inclusive) |

The canonical JSON is the attributes object serialised with keys sorted,
no whitespace (separators `,` and `:`), non-ASCII characters unescaped,
encoded as UTF-8. For example `{"account_status":"open","amount":350,"order_id":"123"}`
hashes to `4a606d0f23427518a1955becd0631fcd27add350802d8edc21933ac60e263415`.
Key order in the request does not matter; any change of value does.

An eligible entitlement is **granted** if any item matches every field.
This stops an approval for a $300 refund on `order/1` from being replayed
for $50,000 on `order/2`. The engine trusts the issuer (gateway or
approval service) to have checked that the approver held the named role.

### 6.7 Denies

A deny rule matches a link when its `grant_to` selects the link, its
action matches, its resource matches in wildcard form (§6.2) and its
`when` is true or errors. Denies are checked on **every** link of the
chain (origin, intermediaries and caller), with `principal` bound to that
link. Any matching deny makes the decision `DENY` (P3).

## 7. Delegation semantics

A request carries a chain `[p0, p1, …, pn]`. `p0` is the **origin**
(usually a human) and `pn` is the **caller** reaching the gateway. When
the chain has one link, origin and caller are the same link.

```yaml
delegation:
  max_depth: 3
  require_human_origin: true
```

`max_depth` (1 to 10, default 3) is the maximum number of hops after the
origin, `len(chain) - 1`. `require_human_origin` (default `true`)
requires `p0` to be a human link.

### 7.1 Formal rule

```
allowed(chain, action, resource, ctx) =
      no deny matches any link
  AND some entitlement grants p0 (the origin) (action, resource) under ctx
  AND some entitlement grants pn (the caller) (action, resource) under ctx
  AND for every i > 0: edge(p(i-1), pi) exists and its actions include
      action, where
        edge(h, a) for a human h = an entry in a.acts_for whose selector
                                   matches h's claims
        edge(x, y) otherwise    = an entry in x.may_delegate with to: y
  AND len(chain) - 1 <= max_depth
  AND (not require_human_origin OR p0.kind == human)
  AND every agent/service link has a valid owner
```

Intermediate agents do not need to hold the permission themselves; they
need only a delegation edge naming the action. Because the action must
appear on every edge, an intermediary can only pass on what it was given.
The caller's effective permission is the **intersection** of the
origin's grants, its own grants and every edge.

### 7.2 Per-link grades

The origin and the caller (each once; one link if the chain has one link)
are graded to one of:

- `GRANTED`: some applicable entitlement has a true `when`, or is
  eligible for approval and a matching approval item is present.
- `NEEDS_APPROVAL(approvers)`: no entitlement is granted, but at least one
  is eligible through `otherwise`.
- `NONE`: neither.

A fully matching entitlement wins over an `otherwise` match on the same
link. Intermediaries are not graded.

### 7.3 Decision algorithm

An engine MUST produce the same decision as this procedure. Reasons are
collected; the decision is not cut short after the first failure except
in steps 1 and 2.

1. If the policy set has no principals and no entitlements: `DENY`,
   reasons `[no policies loaded]`.
2. If the chain is empty: `DENY`, reasons `[empty chain]`.
3. If `now <= 0`: reason `request time not set`.
4. For each link: if malformed (§5.1), reason `malformed human link <id>`.
   Otherwise, for a non-human link: if its id is not a principal, reason
   `unknown principal <id>`; else if a directory snapshot is loaded and
   the principal's owner is not in it, reason
   `owner <owner> of <id> not active`.
5. If `require_human_origin` and `p0` is not human: `human origin
   required`. If `len(chain) - 1 > max_depth`: `chain depth <d> exceeds
   <max>`. If any link after the origin is human: `human in chain after
   origin`.
6. For each consecutive pair, if the edge (§7.1) is missing or does not
   list the action: `no delegation edge <prev> -> <cur> for <action>`.
   For a human `prev`, the edge is an `acts_for` entry on `cur` whose
   `who` selects `prev`. Otherwise it is a `may_delegate` entry on `prev`
   with `to` equal to `cur`'s id.
7. For each deny rule, for each link in order: if it matches (§6.7),
   reason `denied by <id>` (or `denied by <id> (condition error)`), and
   go to the next deny rule.
8. Grade the origin and the caller (§7.2). A `NONE` link adds
   `<id> has no grant for <action> on <resource>` and any
   `condition error in <entitlement>` reasons for that link.
9. Combine:
   1. Any reason from steps 3–8 ⇒ `DENY` with every reason. Approvers are
      empty.
   2. Otherwise, any `NEEDS_APPROVAL` link ⇒ `REQUIRE_APPROVAL`, approvers
      the sorted union over links, reasons
      `<link> needs approval for <entitlement>`.
   3. Otherwise ⇒ `ALLOW` with no reasons.

Any error inside the procedure yields `DENY` with the reason
`internal error: <type>`.

### 7.4 Example *(non-normative)*

With the example policy, `alice` (group `support-staff`), purpose
`customer-refund`, a task id, and attributes
`{order_id: "123", amount: 150, account_status: open}`:

| Chain | Decision | Why |
|---|---|---|
| `[user:alice, support-agent, refund-agent]` | `ALLOW` | origin granted by `support-staff-refunds`, caller by `refund-small-orders`, both edges exist |
| same, `amount: 350` | `REQUIRE_APPROVAL(role:support-manager)` | the caller's `when` is false and it has `otherwise` |
| same, `amount: 350`, a bound approval item | `ALLOW` | the approval grants the caller |
| `[user:alice, refund-agent]` | `DENY` | `refund-agent` has no `acts_for` |
| `account_status: closed` | `DENY` | `no-refunds-on-closed-accounts` |

### 7.5 Required properties

These are proven on paper and enforced by property-based tests in the
reference engine.

- **P1 Attenuation**, in two parts:
  - **(a) Bound.** A decision is never better than the worse of the
    origin's and the caller's per-link grades
    (ALLOW > REQUIRE_APPROVAL > DENY, mapping `GRANTED`, `NEEDS_APPROVAL`
    and `NONE`). Those grades do not depend on intermediaries (§6.3), so
    no chain gives the caller anything that either endpoint is not
    granted.
  - **(b) Relay monotonicity.** Replacing an existing edge
    `p(i-1) → p(i)` with a relay `p(i-1) → x → p(i)` never raises the
    decision.
  - **Not claimed:** "inserting any intermediary never raises the
    decision". That is false under these rules, because an intermediary
    can supply a delegation edge the shorter chain lacked. In the example
    policy, `[user:alice, refund-agent]` is `DENY` (refund-agent has no
    `acts_for`), while `[user:alice, support-agent, refund-agent]` is
    `ALLOW`. That is intended: the longer chain is a permitted path.
    Property testing found this counterexample, and it is kept as a
    regression test and as conformance cases.
- **P2 No confused deputy.** An agent cannot do for a human what that
  human cannot do: the origin must itself be granted.
- **P3 Deny-overrides.** Any matching deny at any link ⇒ `DENY`.
- **P4 Determinism.** The same policy set, directory snapshot and request
  give the same decision. `decision_id` is the only field allowed to
  differ (§9).
- **P5 Fail-closed.** An unparseable chain, unknown principal, inactive
  owner, malformed link, unset request time or evaluation error ⇒ `DENY`.

## 8. Requests and claims

A request has: the chain, `action`, `resource`, `attributes` (a map),
`purpose`, `task_id`, `iat`, `now`, `approvals` and a `dev_mode` flag.

### 8.1 Claims

Purpose, task id, approvals and token time come **from verified claims
only, never from tool arguments**. A hijacked agent controls its tool
arguments, so a purpose read from them would protect nothing. Bindings
can set only action, resource and attributes.

| Claim | Request field | Accepted form |
|---|---|---|
| `openapl_purpose` | `purpose` | string; any other type is ignored |
| `openapl_task_id` | `task_id` | string; any other type is ignored |
| `openapl_approvals` | `approvals` | list of approval items (§6.6) |
| `iat` | `iat` | integer; any other type (including boolean) is ignored |

If `openapl_approvals` is present but is not a list, or any item lacks a
field or has a field of the wrong type, the request is built with an
empty chain and is denied (`empty chain`).

### 8.2 The chain from RFC 8693 `act` claims

The primary chain source is the nested `act` claim (OAuth 2.0 Token
Exchange, RFC 8693) in a JWT the gateway has verified:

- The origin is a human link `user:<email>` if the token has an `email`
  claim, else `user:<sub>`. Its claims are the token claims without
  `act`. A token with neither `email` nor `sub` is rejected.
- The outermost `act` is the current caller; each nested `act` is the
  actor before it. The chain is the origin followed by the actors from
  innermost to outermost.
- Each actor MUST be an object with a string `sub`. It resolves to the
  principal whose identity has `spiffe`, `oauth_client_id` or
  `entra_app_id` equal to `sub`, or whose `jwt` has equal `iss` and
  `sub`. Zero or several matches give the link `unknown:<sub>`, which is
  denied as an unknown principal.
- `act` nesting deeper than 32 levels is rejected. The walk is iterative.
- Any malformed chain gives an empty chain, which is denied.

**Dev mode.** A plain list of ids (AuthZEN `context.chain`, the
`X-OpenAPL-Chain` header, or the CLI `--chain` option) MAY be used for
development only. Its first entry MUST be `user:<id>`. Decisions built
this way are flagged `dev_mode: true`.

### 8.3 Request time

Every request MUST carry the decision time `now` (Unix seconds), set by
the caller of the engine. A request with `now <= 0` is denied with the
reason `request time not set`. The engine never reads the clock itself.

## 9. Decisions

### 9.1 Decision record

```json
{
  "decision": "REQUIRE_APPROVAL",
  "approvers": ["role:support-manager"],
  "chain": ["user:alice@acme.com", "support-agent", "refund-agent"],
  "action": "payments.refund",
  "resource": "order/123",
  "reasons": ["refund-agent needs approval for refund-small-orders"],
  "matched": ["support-staff-refunds", "refund-small-orders"],
  "grants": [["user:alice@acme.com", "support-staff-refunds"]],
  "policies": ["payments-access@1.2.0"],
  "controls": ["NIST-800-53:AC-3", "NIST-800-53:AC-6", "SOC2:CC6.1", "SOC2:CC6.3"],
  "dev_mode": false,
  "decision_id": "…",
  "timestamp": 1000
}
```

| Field | Meaning |
|---|---|
| `decision` | exactly `ALLOW`, `DENY` or `REQUIRE_APPROVAL` |
| `approvers` | sorted union of approver selectors; empty unless `REQUIRE_APPROVAL` |
| `chain` | link ids, origin first |
| `reasons` | every reason (§7.3); empty for `ALLOW` |
| `matched` | the origin's matched entitlement ids, then the caller's, then the matched deny ids, de-duplicated keeping the first occurrence. An entitlement is matched if it granted or was eligible through `otherwise` |
| `grants` | `[link id, entitlement id]` pairs that granted |
| `policies` | sorted `policy@version` of the documents defining the `matched` ids |
| `controls` | sorted union of §9.2 controls over the frameworks in those documents' `compliance` lists |
| `dev_mode` | whether the chain came from a dev-mode source |
| `decision_id` | a fresh random id (32 hex characters in the reference engine) |
| `timestamp` | the request's `now` |

A `DENY` at any link beats `REQUIRE_APPROVAL`. If several links need
approval, all approvers are listed.

### 9.2 Control table

OpenAPL keeps its own control table; it does not reuse OpenGPL's.

| `compliance` framework | Controls cited by every decision whose contributing documents name it |
|---|---|
| `NIST-800-53` | `NIST-800-53:AC-3` (access enforcement), `NIST-800-53:AC-6` (least privilege) |
| `SOC2` | `SOC2:CC6.1`, `SOC2:CC6.3` |

Any other framework name is a load error. The decision log itself bears
on `NIST-800-53:AU-2` and `NIST-800-53:AU-3`; evidence export (§11.3)
cites those in addition.

### 9.3 Decision log

The reference engine logs decisions as append-only JSON Lines, one §9.1
record per line. Lines are written ASCII-escaped, so any request string
(for example one holding a lone UTF-16 surrogate) can be recorded. A
reader skips, and counts as malformed, any line that is not a JSON object
with an integer `timestamp` and string `decision_id`, `decision`,
`action` and `resource`.

## 10. Conformance

An engine conforms to OpenAPL v0.1 if it loads policy sets as in §4,
decides as in §7, and passes every case in
[`conformance/*.yaml`](./conformance/). The reference engine runs them in
`sdk/tests/test_conformance.py`.

### 10.1 Case file format

Each file is one **suite**: one policy set and a list of cases. This
excerpt is from
[`conformance/refund-delegation.yaml`](./conformance/refund-delegation.yaml):

```yaml
openapl_conformance: '0.1'
suite: refund-delegation
policies:
  - file: ../examples/refund-delegation.apl.yaml
defaults:
  request:
    chain:
      - { id: "user:alice@acme.com", kind: human, claims: { groups: [support-staff] } }
      - { id: support-agent, kind: agent }
      - { id: refund-agent, kind: agent }
    action: payments.refund
    resource: order/123
    attributes: { order_id: "123", amount: 150, account_status: open }
    purpose: customer-refund
    task_id: t1
    now: 1000
cases:
  - id: over-limit-requires-approval
    request:
      attributes: { order_id: "123", amount: 350, account_status: open }
    expect:
      decision: REQUIRE_APPROVAL
      approvers: ["role:support-manager"]
      reasons: ["refund-agent needs approval for refund-small-orders"]
      matched: [support-staff-refunds, refund-small-orders]
```

| Key | Meaning |
|---|---|
| `openapl_conformance` | `'0.1'` |
| `suite` | suite name; case ids are reported as `<suite>/<id>` |
| `policies` | the policy set, in order. Each entry is `file:` (a path relative to the suite file) or `inline:` (the document text). An empty list is an empty set |
| `defaults.request` | request fields shared by every case |
| `cases[].id` | unique within the suite |
| `cases[].description` | optional, free text |
| `cases[].directory` | optional directory snapshot (§4.2) for this case |
| `cases[].request` | request fields; each top-level key replaces the default key of the same name (a shallow merge). `null` means absent |
| `cases[].expect` | expected decision (below) |

**Request fields:** `chain` (a list of `{id, kind, claims?}` links,
origin first, given directly as links, not as claims), `action`,
`resource`, `attributes`, `purpose`, `task_id`, `iat`, `now` (absent
means 0) and `approvals` (a list of §6.6 items with literal
`attributes_hash` values).

**Expectations:**

| Key | Check | Normative |
|---|---|---|
| `decision` | equal | MUST |
| `approvers` | equal, as a sorted list | MUST |
| `matched` | equal, in order | MUST |
| `reasons` | equal, in order | SHOULD (reason wording) |
| `reasons_include` | each string is one of the reasons | SHOULD (reason wording) |

An engine MAY word its reasons differently and still conform, provided
`decision`, `approvers` and `matched` agree.

### 10.2 Suites in v0.1

| File | Covers |
|---|---|
| `refund-delegation.yaml` | allow; missing `acts_for` and edges; edge actions; require-approval; bound approvals and every replay variant; deny paths; denies beating approval; condition errors on grants and denies; purpose; task expiry; human origin; depth limit; human after origin; unknown principal; empty chain; malformed human links (R6); unset request time |
| `directory-snapshot.yaml` | inactive and active owners |
| `duration-expiry.yaml` | duration windows, missing `iat`, `iat > now` |
| `deny-resource-wildcard.yaml` | deny resources in wildcard form: a missing or mismatched attribute cannot bypass a deny |
| `conditions.yaml` | ordered short-circuit, error absorption (`||` and `&&`), activation shape, no `chain.depth` |
| `agent-origin-allowed.yaml` | `require_human_origin: false` lets an agent or service be the origin |
| `agent-origin-default.yaml` | the same chain under the default `require_human_origin: true` |
| `delegation-settings.yaml` | custom `max_depth: 1`; custom `humans.match.groups_claim` |
| `empty-policy-set.yaml` | `no policies loaded` |

## 11. Tooling (non-normative)

### 11.1 `openapl validate`, `decide`, `inventory`

`validate` loads a directory as in §4. `decide` builds a dev-mode request
and prints the decision; its exit code is 0 for `ALLOW`, 3 for `DENY` and
4 for `REQUIRE_APPROVAL`. `inventory` lists every principal, kind, owner,
entitlements and edges.

### 11.2 `openapl explain`

`explain <dir> <principal> [--on-behalf-of <selector>]` lists what a
principal could cause if it were hijacked: the entitlements it and the
agents it can reach by `may_delegate` hold, as far as the depth limit
allows.

`explain` is **conservative**: it MAY over-report reach, and it MUST
NEVER under-report what the engine could allow. Concretely:

- Action coverage uses glob **overlap** (two patterns could match a common
  action), not one-directional matching.
- Plain `explain` allows `max_depth` agent hops.
- With `--on-behalf-of`, the `acts_for` hop counts toward `max_depth`
  (leaving `max_depth − 1` agent hops), and a reported grant must overlap
  both some action of an `acts_for` entry that could apply to that human
  and some action that could be granted to that human. `explain` does not
  know a human's group or role memberships, so:
  - an `acts_for` entry could apply if its `who` is the selector itself;
    for a `user:` selector, also any `group:` or `role:` entry; for a
    `group:` or `role:` selector, any `user:`, `group:` or `role:` entry
    (a member may hold other groups and roles too);
  - an action could be granted to the human if any grant whose
    `grant_to` contains `*` or any `user:`, `group:` or `role:` selector
    carries it.
- Conditions, purposes, expiry and denies are not evaluated, so reach
  shows what could be allowed, not what will be.
- Reach counts only grants, never denies.

### 11.3 `openapl evidence`

`evidence <log> --since --until` exports the decisions in a time window
as an OSCAL 1.2.3 assessment-results document.

The evidence document contains **observations only**. It contains no
`findings` and no compliance determination: OpenAPL never claims a
control is satisfied or not satisfied. There is one observation per
decision, and for each control in the union of the records' controls and
`NIST-800-53:AU-2` / `NIST-800-53:AU-3`, one summary observation titled
"Decisions recorded for <control>" carrying the control, the count per
decision value and references to the per-decision observations.
`reviewed-controls` lists the controls in scope. Empty property values
are omitted. A decision recorded with `dev_mode: true` carries a
`dev-mode` property with value `true`, and each summary states how many
of its decisions were in dev mode.

## 12. Known limitations

- **Approval items carry no link.** An approval item names the
  entitlement and approver but not which link (origin or caller) it is
  for. One item can therefore satisfy both the origin's and the caller's
  `otherwise` for the same entitlement and approver.
- **Human identity uses `email` without `email_verified`.** The origin id
  is `user:<email>` when an `email` claim is present, and
  `email_verified` is not checked. Deployments MUST use an IdP that only
  issues verified email addresses.
- **A malformed `${` placeholder is a load error.** A resource `${` that
  does not begin a `${request.<key>}` placeholder rejects the policy set
  at load (§4.1, §6.2), so a deny can never silently stop firing because
  of a placeholder typo.
- **Interpolated non-string values.** The string form of a number or
  boolean interpolated into a grant resource follows the reference
  engine (§6.2).

## 13. Versioning

OpenAPL follows semantic versioning for the specification:

- **MAJOR**: breaking changes to the schema or to decision semantics.
- **MINOR**: new fields, values or claims that are backward-compatible.
- **PATCH**: clarifications and corrections without semantic change.

The `openapl` key in policy documents names `MAJOR.MINOR` only (`'0.1'`).
The conformance suites are versioned with the specification
(`openapl_conformance: '0.1'`). The current specification version is in
[`VERSION`](./VERSION); changes are listed in
[`CHANGELOG.md`](./CHANGELOG.md).
