# bench/analysis/gapl.md

# Gravitee GAPL: written expressiveness analysis

**Source and status.** This analysis is based only on Gravitee's public vendor documentation and
blog (entries G1–G16 in [`sources.md`](sources.md)), fetched on 2026-11-19. Nothing was run: no
Gravitee software was installed, and no GAPL policy was evaluated. Every claim below cites the
documentation page that supports it. Where the documentation does not support a claim, the grade
would be `unknown (not documented)`. No scenario needed that grade. Each one turned either
on a feature the GAPL reference documents, or on the absence of an operator, function or method.
Those absences are inferred from the operators page [G5], which presents itself as listing
"Every GAPL operator, method, and expression form", and from the extension-function list [G6].
Only "GAPL has no division" is stated explicitly [G5]. Third-party pages
that describe GAPL (the `gravitee.io/corpus/...` pages and others) were not used. See
`sources.md`.

**Grading rule.** This is the same rule as for Cedar, Rego and XACML (ruling R7). A scenario is
`native` when a GAPL policy decides every case from a request that carries the given data
unchanged. If anything must be computed outside the engine, the scenario is `workaround`, and
`why` names what. Grades are relative to the suite's cases. Each scenario is encoded in full.

## What the documentation establishes

- **Statements and decisions.**
  - A policy holds `permit` and `forbid` statements. Each has a principal, action and resource
    scope and optional `when` and `unless` conditions [G3].
  - A matching `forbid` gives **Forbid**. Otherwise a matching `permit` gives **Permit**, and
    otherwise the result is **Not applicable**, which is denied (AuthZEN `decision` `false`)
    [G8]. The order of statements does not matter [G8].
  - The gateway's PEP lets a request through only on Permit [G10].
  - No third decision is documented.
- **Skipped statements.**
  - A statement that fails to evaluate is skipped. Causes include a missing context key, an
    operator applied to the wrong type and a method that does not exist [G8].
  - A skipped `forbid` denies nothing, so optional data must be guarded with `has` [G8].
  - Every forbid below is written with such guards.
- **Values.**
  - The types are Bool, Long, String, Entity, `Set` ("Unordered, without duplicates") and Record
    [G4].
  - In requests, a JSON array becomes a `Set`, an object becomes a Record, and `null` leaves the
    key out [G7].
  - Sets and records compare by value [G4, G5].
- **Operators** [G5, which describes itself as "Every GAPL operator, method, and expression form"].
  - `==`/`!=` work on any types. Values of different types are unequal, and comparing them is not
    an error.
  - `<`, `<=`, `>`, `>=` compare Long, datetime or duration values. `+ - *` work on Long.
  - `&&`/`||` short-circuit.
  - `in` follows the entity hierarchy, `has` tests for a field, and `is` tests a type.
  - `like` matches a string literal pattern where `*` "stands for any sequence of characters".
  - The set methods are `contains`, `containsAll`, `containsAny` and `isEmpty`.
  - `if … then … else`.
- **What the documentation does not list.**
  - G5 lists no string concatenation, no set size, no iteration or quantifier over a set, and no
    hash function.
  - The only extension functions are `ip`, `decimal`, `datetime` and `duration` [G6].
- **Request building at the Gravitee gateway** [G10].
  - `principal`, `action` and `resource` come from configured expressions, and resource and
    principal attributes from EL-mapped properties.
  - `context` gets the gateway's keys plus EL-mapped context and action properties.
  - With agent identity resolution on, the gateway sets:
    - `context.agent` (the calling agent);
    - `context.agent_origin` ("the agent the call started from");
    - `context.agent_chain` ("a `Set` of `AgentIdentity` entities").
  - Properties sent with the action replace a context key of the same name [G7, G10].
- **Annotations.** `@id` and `@reason` annotations name a statement in the decision and set its
  reason. The AuthZEN response returns them as `context.matchedPolicies[].policyName` and
  `context.reason` [G3].
- **Outside GAPL.**
  - Human-in-the-Loop approval holds MCP tool calls that match approval rules (a tool glob plus
    argument conditions) until a person decides. It is configured in Agent Management, not in
    GAPL [G12].
  - Access Management's token exchange enforces a per-domain "Maximum Delegation Depth" on nested
    `act` claims [G13].

## Common encoding

The request is built the way the Cedar adapter builds it, which a Gravitee deployment would
configure with EL mappings [G10]:
- `principal` is the caller agent.
- `context.origin` is a record with `id`, `groups` and `roles` (arrays become Sets [G7]).
- `context.agents` is the Set of agent-link ids, the same information as the gateway's own
  `agent_chain` Set [G10].
- `resource` has a `path` attribute, set through the PEP's resource properties [G10].
- `context.attributes` holds the tool arguments as a record.
- `context.purpose`, `context.task_id`, `context.iat` and `context.now` are Long or String.
- `context.active_owners` holds the directory snapshot.

OpenAPL's conjunction (origin grant, caller grant and edges) is one `permit` with `when`
conditions. An OpenAPL `deny` is a guarded `forbid`, and a forbid always wins [G8].

**Chains with relays.** GAPL receives the chain only as a Set. The Set is unordered and drops
duplicates [G4, G7], and so is the gateway's own `agent_chain` [G10]. No documented operator
iterates a set or measures its size [G5]. As with Cedar, the PEP must flatten the ordered chain
into `first_agent` (`chain[1]`) and a Set `hops` of `"prev>cur"` strings, and pass `depth`. A
policy then tests `[<allowed pairs for the action>].containsAll(context.hops)` [G5].

**REQUIRE_APPROVAL.** GAPL's decisions are Permit, Forbid and Not applicable [G8]. The approval
outcome can be encoded the way the Cedar translation does it. A `permit` annotated
`@id("needs-approval:<entitlement>")` holds when the grant's `when` is false. The caller then
treats a Permit whose matched statements are all such permits as REQUIRE_APPROVAL, reading
`context.matchedPolicies[].policyName` [G3]. That mapping happens outside the engine. Gravitee's
Human-in-the-Loop approval [G12] would be the platform's way to hold such a call. It is a separate
rule system with its own tool glob and argument conditions, not a GAPL decision.

## Per-scenario analysis

### approval-bound — workaround

- **No hash.** The approval binds a SHA-256 of the canonical arguments, and GAPL documents no
  hash function [G5, G6]. The caller must pass `attributes_hash`.
- **No search by comparison.**
  - Approvals arrive as a Set of Records [G7], and the set methods test only membership by
    equality [G5].
  - "Is there an item whose `exp >= now`?" is not expressible. Each item's `expired` flag must be
    precomputed so that a whole-record `contains` can match it, with records compared by value
    [G4].
- **Third outcome.** REQUIRE_APPROVAL uses the `@id` convention [G3, G8].
- **Grade.** Workaround: the hash, the `expired` flags and the decision mapping are all outside
  GAPL.

### attenuation-3hop — workaround

- **What must be precomputed.** The middle edge `intake-agent>summary-agent` omits `doc.write`.
  Detecting that needs the consecutive pairs. The chain is only a Set [G4, G7, G10], and no
  operator iterates it [G5].
- **Grade.** Workaround: `first_agent`, `hops` and `depth` are precomputed.

### confused-deputy — native

- **Policy.**

  ```
  permit (principal == AgentIdentity::"export-agent", action == Action::"data.export", resource)
  when { resource.path like "dataset/*" }
  when { context has origin && context.origin.groups.contains("finance") }
  when { context.origin.groups.contains("staff") }
  when { context.agents == ["export-agent"] };
  ```

- **Constructs.** `AgentIdentity` is the entity type the gateway uses for agents [G10]. Also `like`,
  `has` and `contains` [G5], and set equality [G4].
- **Grade.** Native. Nothing is precomputed. A staff-only origin fails `contains("finance")`, which
  is P2.

### deny-overrides — workaround

- **The denies are native.**
  - `forbid … when { resource has path && resource.path like "ledger/frozen-*" }`.
  - `forbid … when { context has agents && context.agents.contains("router-agent") }`, which
    denies a relay without grading it.
  - `forbid … when { context has origin && context.origin has groups && context.origin.groups.contains("contractors") }`.
  - A forbid wins over any permit [G8].
- **What must be precomputed.** The three-link chain's edges (`router-agent` `acts_for`
  `treasury`, then `router-agent>transfer-agent`) need `first_agent` and `hops`.
- **Grade.** Workaround. This matches the Cedar grade. No case's expected decision depends on
  those edges.

### expired-task-grant — native

- **Policy.**
  - `when { context has task_id && context has purpose && context.purpose == "quarterly-report" }`.
    A `null` task id leaves the key out [G7].
  - `when { context has iat && context.iat <= context.now && context.now - context.iat <= 900 }`,
    using Long subtraction and comparison [G5].
- **Grade.** Native.

### forged-purpose — native

- **Policy.** The grant reads `context.purpose`, and the tool argument is
  `context.attributes.purpose`, a different field of a record [G4].
- **Grade.** Native.
- **Deployment caveat.** Properties sent with the action "replace a key with the same name" in
  `context` [G7, G10]. A gateway that maps tool arguments as top-level action properties would let
  an argument named `purpose` overwrite the verified claim. The tool arguments must be mapped
  under a nested key.

### glob-resource — native

- **Policy.** `permit … when { resource.path like "docs/*" }`, where `*` "stands for any sequence of
  characters" [G5], so it also matches `/`, and
  `forbid … when { resource has path && resource.path like "docs/hr/salaries*" }`.
- **Grade.** Native.

### group-and-role — native

- **Policy.**
  - Edge: `context.origin.groups == "sre" || context.origin.groups.contains("sre")`.
  - Grant: `context.origin.roles == "oncall" || context.origin.roles.contains("oncall")`.
  - Both sit in the agent's permit.
- **How a single-string claim is handled.**
  - A single-string claim arrives as a String [G7] and matches by `==`. Comparing a String to a
    Set is false, not an error [G5], and `||` short-circuits [G5].
  - A non-matching String reaches `.contains` on a String, which is an error. That skips the
    permit [G8], giving the correct DENY.
- **Grade.** Native. Normalising the claim to a list in the caller, as the Cedar adapter does,
  would also be construction, not computation.

### orphaned-agent — native

- **Policy.** `when { context has active_owners && context.active_owners.contains(principal.owner) }`.
  `owner` is a principal attribute [G10], and it could equally be the literal `"priya@acme.com"`.
- **Grade.** Native.

### over-deep-delegation — workaround

- **What must be precomputed.**
  - GAPL documents no size of a set [G5], and a Set drops duplicates [G4], so `depth` must be
    passed in.
  - The edges `agent-a>agent-b>agent-c` need `first_agent` and `hops`.
- **The platform's depth limit does not cover this.** Gravitee's Access Management limits the
  nesting of `act` claims at token exchange [G13]. That limit is a per-domain setting enforced
  when tokens are issued. It is not a GAPL policy, and it is not this policy's `max_depth: 2`.
- **Grade.** Workaround.

### prompt-injected-escalation — native

- **Policy.**
  - The agent's permit uses
    `action in [Action::"tickets.read", Action::"tickets.delete", …]`, or a schema action group
    [G3, G9].
  - The edge is `when { action == Action::"tickets.read" && context.origin.groups.contains("support") }`.
  - An injected `tickets.delete` fails only the edge condition.
- **Grade.** Native. The `tickets.*` glob becomes an enumerated list, as in Cedar.

### relay-adds-edge — workaround

- **What must be precomputed.**
  - G5 lists no string concatenation, so `order/${request.order_id}` must arrive precomputed.
  - `direct-chain-has-no-edge` against `relay-supplies-the-edge` needs `first_agent` and `hops`.
  - `otherwise: require_approval` uses the `@id` convention [G3]. Encoded in full, its approved
    path also needs the precomputed `attributes_hash` and `expired` flags, as in `approval-bound`.
- **Grade.** Workaround.

### threshold-approval — workaround

- **Native parts.**
  - The threshold is `context.attributes has amount && context.attributes.amount <= 200` [G5].
  - A missing amount makes neither the permit nor the approval permit match, which gives DENY
    [G8].
- **The third outcome.**
  - REQUIRE_APPROVAL is not a GAPL decision [G8]. It needs the `@id` convention, mapped outside
    the engine [G3].
  - Gravitee's Human-in-the-Loop rules [G12] could hold such a call at the gateway, but they are a
    separate mechanism, not a GAPL decision.
- **The approved path.** Encoded in full, as in the Cedar translation, `payment-small`'s approved
  path needs the precomputed `attributes_hash` and each item's `expired` flag (see
  `approval-bound`) [G5, G6].
- **Grade.** Workaround.

### unknown-principal — workaround

- **Native part.** The known-principal check is native:
  `when { ["known-agent", "known-relay"].containsAll(context.agents) }` [G5].
- **What must be precomputed.** The three- and four-link cases' edges need `first_agent` and
  `hops`.
- **Grade.** Workaround. This matches Cedar.

## Totals

| Grade | Count | Scenarios |
|---|---|---|
| native | 7 | confused-deputy, expired-task-grant, forged-purpose, glob-resource, group-and-role, orphaned-agent, prompt-injected-escalation |
| workaround | 7 | approval-bound, attenuation-3hop, deny-overrides, over-deep-delegation, relay-adds-edge, threshold-approval, unknown-principal |
| not-expressible | 0 | — |
| unknown (not documented) | 0 | — |

The GAPL constructs used here are documented with the same meaning as the Cedar constructs used
in `bench/scenarios/*/cedar`, and the grades come out identical to Cedar's. The official pages do
not say that GAPL derives from Cedar [G1–G9], so this analysis does not claim it.
