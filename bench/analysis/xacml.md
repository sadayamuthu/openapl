# bench/analysis/xacml.md

# XACML 3.0: written expressiveness analysis

This is a written analysis, with nothing run. No XACML PDP was installed or executed. Each grade
says what a conformant XACML 3.0 PDP can express when it uses only the features the standard marks
mandatory (M). The basis is the core specification with Errata 01 [X1] and, where it is relevant,
the Administration and Delegation Profile [X3]. Source IDs (X1, X3, …) refer to
[`sources.md`](sources.md), and § numbers refer to sections of that source.

**Grading rule.** This is the rule used for Cedar and Rego (controller ruling R7). A scenario is
`native` when a PDP can produce its decisions from a request that the PEP or a PIP builds by
placing the given data into attributes, with nothing derived. Placing data means taking the
chain's ends, the claims, the tool arguments, the clock and the directory snapshot as given. If
the PEP or a PIP must compute anything from the request, the scenario is `workaround`, and `why`
names exactly what is computed. Examples are the chain's order flattened into pairs or indexed
positions, a depth or a hash. Grades are relative to the suite's cases. Each scenario is encoded
in full (every edge, deny and condition of its OpenAPL policy), the way the Cedar and Rego
translations were.

## Common encoding

This section gives the request context and policy skeleton that every scenario below reuses. Only
the differences are given per scenario.

**Request context (built by the PEP).**

| OpenAPL request | XACML attribute | Category |
|---|---|---|
| caller, the last chain link | `subject-id` | `access-subject` |
| origin human, `chain[0]` | `subject-id`, `group` (multi-valued), `role` (multi-valued) | custom `urn:openapl:category:origin` (§5.44 allows other categories) |
| ids of all agent links | `agent-id` (multi-valued, so a **bag**) | custom `urn:openapl:category:chain` |
| action | `action-id` | `action` |
| resource path | `resource-id` | `resource` |
| tool arguments (`attributes`) | one attribute per argument (`amount`, `order_id`, …) | custom `urn:openapl:category:arguments` |
| verified `purpose`, `task_id`, `iat`, `now` | one attribute each (integers for `iat`/`now`) | `environment` |
| directory snapshot | `active-owner` (multi-valued) | `environment` (from a PIP) |

The table is built under two constraints from the spec.

- **One `<Attributes>` per category.** "it is a syntax error if there are multiple `<Attributes>`
  elements with the same Category", unless the PDP implements the optional Multiple Decision
  Profile [X1 §5.42, §10.2.1 `MultiRequests` O]. Two links cannot both be `access-subject`. The
  origin and the caller therefore get their own categories, as Cedar used `principal` and
  `context.origin`, which was graded native.
- **Bags are unordered.** "The values in a bag are not ordered, and some of the values may be
  duplicates", and there are no bags of bags [X1 §7.3.2]. The bag of agent ids is the equivalent
  of Cedar's `context.agents` set. It says *which* agents are on the chain, not in which order.

A claim that is a single string arrives as one `<AttributeValue>`, which is a bag of one
[X1 §7.3.3]. This mirrors the Cedar adapter's standard entity construction. An absent attribute
whose designator has `MustBePresent="false"` gives an empty bag [X1 §5.29, §7.3.5].

**Policy skeleton.**
- A top-level `<PolicySet>` with the `first-applicable` policy-combining algorithm (M) [X1 §10.2.3,
  C.8]. Its children, in order:
  1. **Denies.** A `<Policy>` combining with `deny-overrides` (M) [X1 C.2] and one `Effect="Deny"`
     rule per OpenAPL `deny`. A deny that targets a link tests the matching bag. A relay or caller
     uses `string-is-in(<id>, agent-id bag)`, and a group uses
     `string-is-in(<group>, origin group bag)` [X1 A.3.10]. It is NotApplicable when nothing
     matches.
  2. **Grants.** One `Effect="Permit"` rule whose `<Condition>` is an `and` of everything the
     OpenAPL decision needs: the origin's grant (P2), the caller's grant, every delegation edge,
     the depth limit, and every link being a known principal. `and` evaluates left to right and
     stops at the first False [X1 A.3.5]. Each optional attribute is therefore guarded with
     `type-bag-size(...) = 1` before `type-one-and-only`. A missing value then makes the rule
     NotApplicable instead of Indeterminate.
  3. **Approvals** (only scenarios with `otherwise: require_approval`). One `Effect="Deny"` rule per
     approvable grant. Its condition is "all other parts hold and the grant's `when` is false". It
     carries an `<ObligationExpression FulfillOn="Deny">` with id `urn:openapl:require-approval`,
     whose `<AttributeAssignmentExpression>`s carry the approver and the entitlement id
     [X1 §5.39, §5.41].
  4. **Default.** One `Effect="Deny"` rule with no condition.
- Glob matching: `x/*` is `string-starts-with("x/", …)` (M), and general globs use
  `string-regexp-match` (M) [X1 §10.2.8, A.3.9, A.3.13].

**The third decision.** XACML's decisions are Permit, Deny, Indeterminate and NotApplicable
[X1 §5.53]. REQUIRE_APPROVAL is returned as **Deny with the `require-approval` obligation**.
- An obligation is "an operation specified in a rule, policy or policy set that should be
  performed by the PEP in conjunction with the enforcement of an authorization decision"
  [X1 §1.1, glossary].
- A base PEP denies "only if it understands, and it can and will discharge those obligations"
  [X1 §7.2.1].
- Obligations reach the PEP only from rules whose result matches the decision, and never from an
  Indeterminate result [X1 §7.18]. An erroring `when` therefore never offers approval.

The PDP's standard response carries the outcome. The PEP computes nothing to obtain it. It only
recognises an obligation id, as it must for any obligation. This analysis therefore treats it as
native. The same reasoning made Rego's three-valued decision document native (ruling R4). Cedar
differs: it has no obligation or advice element, and its translation gets REQUIRE_APPROVAL from a
policy-id naming convention that the runner maps. See *Concerns* below.

**Chains with relays (the main limit).** OpenAPL checks one edge per consecutive pair of links
(P1). With no ordered value and no iteration, the PEP must flatten the order. It can supply
`first-agent` (`chain[1]`) and a bag `hops` of `"prev>cur"` strings, both computed from the
ordered chain. The grant rule then tests:
- `string-equal(first-agent, "<agent with acts_for>")` with the origin's group, and
- `string-subset(hops, string-bag("a>b", …))` against the literal edge pairs that list the
  action (`type-subset` and `type-bag` are M [X1 §10.2.8, A.3.11]).

This is exactly the precomputation that Cedar's translations read. One alternative is
positional categories (`…:link:1`, `…:link:2`, …), with `string-concatenate` (M) building the
pairs in the policy. That is still a PEP computation: it assigns an index to each link, which is
the same as Cedar's `first_agent`.

**What the delegation profile does not provide.** The Administration and Delegation Profile [X3]
expresses "permissions about the right to issue policies" and checks issued policies against them
through a reduction graph [X3 §3]. Its `MaxDelegationDepth` bounds paths in that graph
[X3 §4.11], not the actors on a request. Acting for someone is left to "different
subject-categories" [X3 §2.1.2]. To model each OpenAPL hop as an issued policy, agents or the PEP
would have to mint and present a policy per request [X3 §2.1.3]. The profile is also a committee
draft, not an OASIS Standard [X3, X4]. It is not used below.

**Optional features not relied on.** `<AttributeSelector>` over `<Content>` (XPath into free-form
XML) could address sibling links in an XML-encoded chain. Both elements, the `xpathExpression`
type and the `xpath-node-*` functions are optional (O) [X1 §10.2.1, §10.2.7, §10.2.8], so a
conformant PDP need not support them. This analysis does not grade on them and has not checked
that such an encoding would work. `access-permitted` (re-evaluating the policy for another
subject) is also O [X1 §10.2.8].

## Per-scenario analysis

### approval-bound — workaround

- **Policy.** The grant rule for `payment-small` holds when `amount <= 200`, or when a presented
  approval matches.
- **Matching an approval.**
  - The approval fields (entitlement id, approver, action, resource, origin, caller, `exp`) arrive
    in a custom `urn:openapl:category:approval` category.
  - The rule compares each with `string-equal` against the request attributes, and compares
    `exp >= now` with `integer-greater-than-or-equal`, all M [X1 §10.2.8].
- **No-approval path.** The approval rule returns Deny with the `require-approval` obligation.
- **What the PEP must compute.**
  - The approval's `attributes_hash` covers the canonical JSON of the tool arguments. XACML has no
    hash or digest function [X1 §10.2.8], so the PEP must compute SHA-256 of the canonical
    arguments and pass it as an attribute.
  - A list of approval records cannot be passed either. A bag cannot hold records or bags
    [X1 §7.3.2], and a second `<Attributes>` element of the approval category is a syntax error
    [X1 §5.42]. The PEP must split the list into one category per item, or preselect the item.
- **Grade.** Workaround. The hash and the approval-list flattening are computed outside the PDP.
  The `exp` comparison and the third outcome are native.

### attenuation-3hop — workaround

- **Policy.**
  - The `intake-agent` `acts_for` edge from `editors` lists read, write and comment.
  - The edges `intake-agent>summary-agent` (read, comment) and `summary-agent>publish-agent`
    (read, write, comment) appear as one literal pair bag per action.
  - The grants are `editors` for the origin and `publish-agent` for the caller (`doc.*` via
    `string-starts-with`).
  - Depth is `string-bag-size(agent-id) <= 3` (M).
- **What the PEP must compute.** The ordered chain flattened into `first-agent` and `hops`.
  `write-middle-edge-omits-action` and `read-skipping-middle-hop` turn on which consecutive pair
  is present, and a bag of agent ids cannot say that [X1 §7.3.2].
- **Grade.** Workaround: `first-agent` and `hops` are computed outside the PDP.

### confused-deputy — native

- **Policy.**
  - Origin grant: `string-is-in("finance", origin group)`.
  - Caller grant: `subject-id = "export-agent"`.
  - Edge: `string-is-in("staff", origin group)` and action `data.export`.
  - The caller must be the only agent: `string-bag-size(agent-id) = 1`.
  - Resource: `string-starts-with("dataset/")`.
- **Request.** Origin and caller are placed in their categories, with groups as given.
- **Grade.** Native. Nothing is computed. P2 is the origin-grant conjunct.

### deny-overrides — workaround

- **Policy.**
  - Three deny rules: `string-starts-with("ledger/frozen-", resource-id)`,
    `string-is-in("router-agent", agent-id)` (a relay is denied without being graded), and
    `string-is-in("contractors", origin group)`.
  - These sit in the denies policy, which comes first and combines with deny-overrides (M)
    [X1 §10.2.3, C.2].
  - Grants as in the common skeleton.
- **What the PEP must compute.** The three-link case `[alice, router-agent, transfer-agent]` also
  has edges `router-agent` `acts_for` `treasury` and `router-agent>transfer-agent`. Encoding them
  needs `first-agent` and `hops`.
- **Grade.** Workaround. This matches Cedar's grade. The denies themselves, including the deny on
  an intermediary, are native. No case's expected decision depends on the edges, since that case
  is DENY by `router-suspended`. Under the superseded case-only rule (R6) this scenario would be
  native.

### expired-task-grant — native

- **Policy.**
  - `agent-run-for-task`:
    - `string-bag-size(task_id) = 1`, with an absent `task_id` giving an empty bag [X1 §7.3.5];
    - `string-is-in("quarterly-report", purpose)`, which is safe on the bag (M) [X1 A.3.10].
  - `agent-export-15m`:
    - `integer-bag-size(iat) = 1`;
    - `integer-less-than-or-equal(iat, now)`;
    - `integer-less-than-or-equal(integer-subtract(now, iat), 900)`.
  - All are M [X1 §10.2.8, A.3.2, A.3.6]. The guards come first in the left-to-right `and`
    [X1 A.3.5].
- **Request.** `now` is passed as an integer attribute, like the suite's `now`. A deployment could
  use the mandatory `current-dateTime` [X1 §10.2.5] with `dateTime-add-dayTimeDuration` (M).
- **Grade.** Native.

### forged-purpose — native

- **Policy.** `refund-agent-refunds` tests the environment attribute `purpose` (the verified
  claim). The tool argument `purpose` is a different attribute in the arguments category, and no
  rule reads it.
- **Grade.** Native. Attributes are identified by Category and AttributeId [X1 §5.29], so the two
  `purpose`s cannot be confused.

### glob-resource — native

- **Policy.** Grants use `string-starts-with("docs/", resource-id)`. The deny rule uses
  `string-starts-with("docs/hr/salaries", resource-id)`, which is OpenAPL's
  `docs/hr/salaries*`. Both functions are M [X1 A.3.9].
- **Grade.** Native. A general glob would use `string-regexp-match` (M) [X1 A.3.13].

### group-and-role — native

- **Policy.**
  - Edge: `string-is-in("sre", origin group)`.
  - Origin grant: `string-is-in("oncall", origin role)`.
  - Caller grant: `subject-id = "ops-agent"`.
- **Request.** A single-string claim becomes one `<AttributeValue>`, a bag of one [X1 §7.3.3].
  Like the Cedar adapter's `_as_list`, this is construction of the request, not computation.
- **Grade.** Native.

### orphaned-agent — native

- **Policy.**
  - `string-is-in("priya@acme.com", active-owner)`, where the owner is the policy's literal for
    `report-agent`, which is the only agent on every chain.
  - The snapshot is a multi-valued environment attribute supplied by a PIP.
- **Grade.** Native. A PIP supplying given data is how XACML gets attributes [X1 §7.3.5]. It
  derives nothing.

### over-deep-delegation — workaround

- **Policy.**
  - Depth `string-bag-size(agent-id) <= 2` is native (M). The agent-id bag counts duplicates
    [X1 §7.3.2], so the count equals `len(chain) - 1` for a chain with a human origin.
  - Edges: `agent-a` `acts_for` `analysts`, then `agent-a>agent-b` and `agent-b>agent-c`.
- **What the PEP must compute.** `first-agent` and `hops` for those edges.
- **Grade.** Workaround: the edges need the order computed outside the PDP. Unlike in Cedar, the
  depth is not the reason.

### prompt-injected-escalation — native

- **Policy.**
  - Edge: `string-is-in("support", origin group)` and `action-id = "tickets.read"`.
  - Grants: `string-starts-with("tickets.", action-id)` for both the origin (support) and the
    caller.
  - An injected `tickets.delete` fails only the edge conjunct.
- **Grade.** Native.

### relay-adds-edge — workaround

- **Policy.**
  - `refund-small-orders`:
    - resource `string-equal(resource-id, string-concatenate("order/", order_id))`
      (string-concatenate is M [X1 A.3.9], unlike Cedar);
    - `amount <= 200`;
    - `string-is-in("support-staff", origin group)`;
    - `purpose`;
    - `task_id` presence;
    - an approval rule with the obligation for `otherwise`.
  - Denies: `account_status = "closed"`, and `string-starts-with("order/bulk-")`.
  - `require_human_origin`: the origin category is present.
- **What the PEP must compute.** `first-agent` and `hops`. `direct-chain-has-no-edge`
  (`[alice, refund-agent]`, DENY) and `relay-supplies-the-edge` (ALLOW) differ only in which agent
  follows the origin.
- **Grade.** Workaround: the order is flattened outside the PDP. Encoded in full, the approved
  path of `otherwise` also needs the PEP-computed `attributes_hash`, as in `approval-bound`.
  Interpolation, denies and the approval outcome are native.

### threshold-approval — workaround

- **Policy.**
  - Grant rule: origin `finance`, the edge, and the guarded `integer-less-than-or-equal(amount, 200)`.
  - Approval rule (Deny with `require-approval`, approver `role:finance-lead`): the same conjuncts
    with `integer-greater-than(amount, 200)`.
  - Approved path: `payment-small`'s `otherwise` also admits a request that presents a matching
    approval item (SPEC.md §7.2, `GRANTED`). The Cedar translation encodes it as well. Encoded in full, it
    is the same as in `approval-bound`.
- **Missing amount.** When `amount` is absent, both guards are False. The default rule gives a
  plain Deny without the obligation, which is the suite's DENY.
- **What the PEP must compute.** For the approved path, the SHA-256 `attributes_hash` of the
  canonical arguments (XACML has no hash function [X1 §10.2.8]), and the approval list split into
  one category per item [X1 §5.42, §7.3.2].
- **Grade.** Workaround, under the full-encoding rule used for every scenario. The threshold, the
  missing-amount DENY and the REQUIRE_APPROVAL outcome (Deny plus obligation, see *The third
  decision*) are native. No case in this scenario presents an approval.

### unknown-principal — workaround

- **Policy.**
  - Every agent link must be a known principal:
    `string-subset(agent-id, string-bag("known-agent", "known-relay"))` (M) [X1 A.3.11].
  - `require_human_origin: false` means the origin category is not required.
  - The grant `*` on `note/*`.
- **What the PEP must compute.** The three- and four-link cases' edges (`known-agent` `acts_for`
  `staff`, `known-agent>known-relay`) need `first-agent` and `hops`.
- **Grade.** Workaround. As with Cedar, the unknown-principal check itself is native.

## Totals

| Grade | Count | Scenarios |
|---|---|---|
| native | 7 | confused-deputy, expired-task-grant, forged-purpose, glob-resource, group-and-role, orphaned-agent, prompt-injected-escalation |
| workaround | 7 | approval-bound, attenuation-3hop, deny-overrides, over-deep-delegation, relay-adds-edge, threshold-approval, unknown-principal |
| not-expressible | 0 | — |

## Concerns

- **The third decision is native in XACML, but no scenario turns on it alone.** This analysis
  treats Deny plus a standard obligation as a native REQUIRE_APPROVAL, because obligations are
  part of the PDP's normative output and the PEP must understand them [X1 §7.2, §7.18]. Cedar has
  no such element. Every scenario with `otherwise: require_approval` (approval-bound,
  relay-adds-edge, threshold-approval) is still workaround. Its approved path needs a PEP-computed
  hash, and relay-adds-edge also needs the chain order.
- **Not run.** No PDP was executed. Each sketch uses only M features, but a reader should treat
  the grades as an analysis of the specification, not a measurement.
