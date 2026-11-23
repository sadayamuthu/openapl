# approval-bound: Cedar translation

Files: `policies.cedar`, `schema.cedarschema`, `entities.json` (the policy's agents and owners). Run by `bench/run_cedar.py` with cedar-policy-cli 4.15.0: `cedar validate` against the schema, then one `cedar authorize -v` per case.

The request is built by `bench/adapters/cedar_input.py`. `principal` is the caller; `context.origin` is the origin human as a `User` entity whose groups and roles claims are `Group`/`Role` parents; `resource` is a `Resource` with its `path`; `context.agents` is the set of agent links; purpose, task_id, iat, now, attributes, approvals and the directory snapshot are passed as given. The adapter always sends its precomputed fields too; only those listed below are read.

Pattern: caller grants are permits; the origin's grant (P2) and the delegation edges are forbid-unless policies; OpenAPL denies are forbids (forbid overrides permit, P3).

## Computed outside Cedar (read by this policy set)

- `attributes_hash`: SHA-256 of the canonical attributes JSON (Cedar has no hash function)
- `expired`: each approval item's `expired = exp < now`, replacing `exp` (Cedar cannot search a set for an item with a comparison, so the policy matches a whole record with `contains`)

## Notes

- Every case is a two-link chain, and this policy has no may_delegate edge. The acts_for edge is therefore checked on the caller (`principal`), and an agent caller must be the chain's only agent (`[principal].containsAll(context.agents)`). A chain naming the same agent twice (`[human, a, a]`) passes that check, while OpenAPL denies it (no `a -> a` edge); no case has one.
- OpenAPL defaults that no case exercises (unset request time, malformed human links, a human after the origin, `max_depth: 3` when the policy does not set it) are not encoded, as in the Rego translation.

REQUIRE_APPROVAL is not a Cedar decision. A permit whose `@id` starts with `needs-approval:` marks the `otherwise` path; `bench/run_cedar.py` reports an ALLOW whose determining policies are all such permits as REQUIRE_APPROVAL. That mapping happens outside Cedar.
