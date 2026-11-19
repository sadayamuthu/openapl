# deny-overrides: OPA/Rego translation

File: `policy.rego` (package `openapl`). Run by `bench/run_rego.py` with OPA 1.22.4: `opa eval -d policy.rego -i input.json data.openapl.decision`, which returns `"ALLOW"`, `"DENY"` or `"REQUIRE_APPROVAL"`.

The input is built by `bench/adapters/rego_input.py`: the request as given, with `input.chain` the ordered list of `{id, kind, claims}` links, claims verbatim.

## Computed outside Rego

- nothing. Chain order, edges, depth, claim normalisation and the three-valued decision are all computed in the policy.

## Notes

- Globs use `glob.match(pattern, null, value)` so `*` matches any run of characters, including `/` and `.`, as in OpenAPL.
- OpenAPL defaults that no case exercises (unset request time, malformed human links, `max_depth: 3` when the policy does not set it) are not encoded, as in the Cedar translation.
