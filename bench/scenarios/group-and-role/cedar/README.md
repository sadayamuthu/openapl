# group-and-role: Cedar translation

Files: `policies.cedar`, `schema.cedarschema`, `entities.json` (the policy's agents and owners). Run by `bench/run_cedar.py` with cedar-policy-cli 4.15.0: `cedar validate` against the schema, then one `cedar authorize -v` per case.

The request is built by `bench/adapters/cedar_input.py`. `principal` is the caller; `context.origin` is the origin human as a `User` entity whose groups and roles claims are `Group`/`Role` parents; `resource` is a `Resource` with its `path`; `context.agents` is the set of agent links; purpose, task_id, iat, now, attributes, approvals and the directory snapshot are passed as given.

Pattern: caller grants are permits; the origin's grant (P2) and the delegation edges are forbid-unless policies; OpenAPL denies are forbids (forbid overrides permit, P3).

## Computed outside Cedar (read by this policy set)

- `context.first_agent`: the link after the human origin (`chain[1]`; in a two-link chain, the principal), for the acts_for edge
- `context.hops`: the chain's consecutive agent->agent pairs as strings `"prev>cur"` (Cedar has no ordered lists or iteration, so the chain's order is flattened into pairs)

## Notes

- A single-string `groups` or `roles` claim becomes one parent (SPEC 5.2); a list becomes one parent per item.
- OpenAPL defaults that no case exercises (unset request time, malformed human links, `max_depth: 3` when the policy does not set it) are not encoded, as in the Rego translation.
