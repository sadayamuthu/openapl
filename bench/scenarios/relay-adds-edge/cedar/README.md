# relay-adds-edge: Cedar translation

Files: `policies.cedar`, `schema.cedarschema`, `entities.json` (the policy's agents and owners), `derived.json`. Run by `bench/run_cedar.py` with cedar-policy-cli 4.15.0: `cedar validate` against the schema, then one `cedar authorize -v` per case.

The request is built by `bench/adapters/cedar_input.py`. `principal` is the caller; `context.origin` is the origin human as a `User` entity whose groups and roles claims are `Group`/`Role` parents; `resource` is a `Resource` with its `path`; `context.agents` is the set of agent links; purpose, task_id, iat, now, attributes, approvals and the directory snapshot are passed as given. The adapter always sends its precomputed fields too; only those listed below are read.

Pattern: caller grants are permits; the origin's grant (P2) and the delegation edges are forbid-unless policies; OpenAPL denies are forbids (forbid overrides permit, P3).

## Computed outside Cedar (read by this policy set)

- `first_agent`: the link after the human origin (`chain[1]`), for the acts_for edge in chains longer than two links
- `hops`: the chain's consecutive agent->agent pairs as strings `"prev>cur"` (Cedar has no ordered lists or iteration, so the chain's order is flattened into pairs)
- `depth`: `len(chain) - 1` (Cedar sets have no size)
- `attributes_hash`: SHA-256 of the canonical attributes JSON (Cedar has no hash function)
- `expired`: each approval item's `expired = exp < now`, replacing `exp` (Cedar cannot search a set for an item with a comparison, so the policy matches a whole record with `contains`)
- `derived`: `order_resource = "order/" + order_id` from `cedar/derived.json` (Cedar has no string concatenation); absent when order_id is absent

## Notes

- Groups as parents cannot tell an absent `groups` claim from an empty one. OpenAPL's `'support-staff' in chain.origin.groups` errors on an absent claim (not eligible for approval), while this translation treats it as false (eligible). No case exercises the difference.
- OpenAPL defaults that no case exercises (unset request time, malformed human links, a human after the origin, `max_depth: 3` when the policy does not set it) are not encoded, as in the Rego translation.

REQUIRE_APPROVAL is not a Cedar decision. A permit whose `@id` starts with `needs-approval:` marks the `otherwise` path; `bench/run_cedar.py` reports an ALLOW whose determining policies are all such permits as REQUIRE_APPROVAL. That mapping happens outside Cedar.
