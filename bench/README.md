# OpenAPL benchmark

`scenarios/<id>/` holds 14 scenarios. Each has a `README.md` (two sentences and the threat it maps to, or none), the OpenAPL policy in `openapl/*.apl.yaml`, and `cases.yaml` with the request and expected decision for every case. Requests use the conformance-suite shape of `spec/conformance/*.yaml`.

Expected decisions come from the specification (`spec/SPEC.md` §6 and §7), not from engine output.

| Result | Command (run from the repository root, in `sidecar/.venv`) |
|---|---|
| `results/env.json` (`tools`) | `sh bench/tools.sh` (builds the Cedar image, pulls OPA; needs Docker) |
| `results/openapl.json` | `python bench/run_openapl.py --out bench/results/openapl.json` |
| `results/cedar.json` | `python bench/run_cedar.py --out bench/results/cedar.json` |
| `results/rego.json` | `python bench/run_rego.py --out bench/results/rego.json` |
| Suite checks | `pytest bench/tests -q` (runs the Cedar and OPA CLIs) |

Each runner exits 1 on any mismatch, and an engine error (CLI failure, schema violation, Rego compile error, Cedar policy evaluation error) counts as a mismatch with the CLI output attached.

## Cedar and OPA/Rego translations

Each scenario has `cedar/` (`policies.cedar`, `schema.cedarschema`, `entities.json`) and `rego/policy.rego`, each with a README listing what was computed outside the engine. The engines run from pinned images through `bench/bin/cedar` (cedar-policy-cli 4.15.0, built by `bench/tools/cedar.Dockerfile`) and `bench/bin/opa` (`openpolicyagent/opa:1.22.4-static`, run by digest). Requests are passed as data by `bench/adapters/`.

`verdict.yaml` grades each engine per scenario, citing translation lines:

- `native`: the committed translation reads no precomputed field (the fields each adapter computes outside the engine, listed in `bench/adapters/*_input.py` `PRECOMPUTED` and in the translation README) in any policy, and needs no decision mapping by the runner. Grades are relative to the suite's cases.
- `workaround`: the translation reads at least one precomputed field, or relies on the runner's decision mapping (Cedar's REQUIRE_APPROVAL, read from `needs-approval:` permits).
- `not-expressible`: the engine cannot decide a case; the case is listed under that engine's `unsupported:` with a reason and is not run.

`test_native_reads_no_precomputed_field` checks the rule against the translation source, and `test_cedar_counterfactual_without_precomputed_fields` reruns Cedar with every precomputed field removed or set to junk and the mapping off: every native scenario still matches, and every workaround scenario flips at least one case. Request shaping shared by every Cedar scenario (caller as principal, origin human as a User with group/role parents, the set of agent links) is not a precomputed field.
