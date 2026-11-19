# OpenAPL benchmark

`scenarios/<id>/` holds 14 scenarios. Each has a `README.md` (two sentences and the threat it maps to, or none), the OpenAPL policy in `openapl/*.apl.yaml`, and `cases.yaml` with the request and expected decision for every case. Requests use the conformance-suite shape of `spec/conformance/*.yaml`.

Expected decisions come from the specification (`spec/SPEC.md` §6 and §7), not from engine output.

| Result | Command (run from the repository root, in `sidecar/.venv`) |
|---|---|
| `results/env.json` (`tools`) | `sh bench/tools.sh` (builds the Cedar image, pulls OPA; needs Docker) |
| `results/openapl.json` | `python bench/run_openapl.py --out bench/results/openapl.json` |
| `results/cedar.json` | `python bench/run_cedar.py --out bench/results/cedar.json` |
| `results/rego.json` | `python bench/run_rego.py --out bench/results/rego.json` |
| `results/latency.json` | `python bench/latency.py --out bench/results/latency.json` |
| `results/gateway.json` | `python bench/gateway_latency.py --out bench/results/gateway.json --batches 10 --per-batch 200` (needs Docker and the demo images) |
| `results/summary.json` | `python bench/analyze.py` (folds every file above; run last) |
| Suite checks | `pytest bench/tests -q` (runs the Cedar and OPA CLIs) |

Each runner exits 1 on any mismatch, and an engine error (CLI failure, schema violation, Rego compile error, Cedar policy evaluation error) counts as a mismatch with the CLI output attached.

## Cedar and OPA/Rego translations

Each scenario has `cedar/` (`policies.cedar`, `schema.cedarschema`, `entities.json`) and `rego/policy.rego`, each with a README listing what was computed outside the engine. The engines run from pinned images through `bench/bin/cedar` (cedar-policy-cli 4.15.0, built by `bench/tools/cedar.Dockerfile`) and `bench/bin/opa` (`openpolicyagent/opa:1.22.4-static`, run by digest). Requests are passed as data by `bench/adapters/`.

`verdict.yaml` grades each engine per scenario, citing translation lines:

- `native`: the committed translation reads no precomputed field (the fields each adapter computes outside the engine, listed in `bench/adapters/*_input.py` `PRECOMPUTED` and in the translation README) in any policy, and needs no decision mapping by the runner. Grades are relative to the suite's cases.
- `workaround`: the translation reads at least one precomputed field, or relies on the runner's decision mapping (Cedar's REQUIRE_APPROVAL, read from `needs-approval:` permits).
- `not-expressible`: the engine cannot decide a case; the case is listed under that engine's `unsupported:` with a reason and is not run.

`test_native_reads_no_precomputed_field` checks the rule against the translation source, and `test_cedar_counterfactual_without_precomputed_fields` reruns Cedar with every precomputed field removed or set to junk and the mapping off: every native scenario still matches, and every workaround scenario flips at least one case. Request shaping shared by every Cedar scenario (caller as principal, origin human as a User with group/role parents, the set of agent links) is not a precomputed field.

## The grading rubric

Each scenario gets one grade per engine in `verdict.yaml`, with the translation lines (or, for XACML and GAPL, source sections) that justify it.

| Grade | Definition |
|---|---|
| `native` | The committed translation reads no precomputed field in any decision-determining policy (controller ruling R7). |
| `workaround` | The translation reads at least one precomputed field, or relies on a runner decision mapping that is not the language's own output. |
| `not-expressible` | The engine cannot decide a case; the case is listed under the engine's `unsupported:` and is not run. |
| `unknown` | Used for GAPL only, as `unknown (not documented)`: the vendor documentation does not say. |

- Grades are relative to the suite's cases, not to the language in general.
- REQUIRE_APPROVAL is a third outcome (R4, R8). It is native when it is the language's own standard output: a Rego string value, or an XACML obligation in the PDP response that the PEP must discharge. It is not native when the runner infers it from determining-policy ids (Cedar's `needs-approval:` permits, GAPL's `@id` convention); that is a workaround.
- XACML and GAPL are written analyses (`bench/analysis/xacml.md`, `bench/analysis/gapl.md`, sources in `sources.md`). Nothing was run. GAPL's public material is vendor documentation.
- R5: Cedar and Rego rows are matched on the decision only, not on reasons.

## What each result means

`results/summary.json` is the only file a paper should cite. Its key paths:

- `suite.{scenarios,cases,allow,deny,require_approval}`: the suite shape from `cases.yaml`.
- `engines.{openapl,cedar,rego}.{matched,mismatched,unsupported}`: case outcomes per engine.
- `grades.<engine>.{native,workaround,not_expressible,unknown}`: scenario counts per grade, for openapl, cedar, rego, xacml and gapl.
- `latency.target.{point,p99_us,met}`: the design target (p99 under 5 ms at 100 principals and 1,000 entitlements). `latency.grid.<PxE>.{p50_us,p99_us,load_ms,n,principals,entitlements}`.
- `gateway.{openapl,baseline}.{p50_us,p99_us,n}`, `gateway.delta.{p50_us,p99_us,batch_median_spread_us,batch_p99_spread_us,paired_batches}`, `gateway.sidecar_decisions.count`.
- `env.*`: tool versions and digests (`tools`), the latency host (`latency_host`) and the gateway stack (`gateway`).

## Latency caveats (`results/latency.json`)

- Only `Authorizer.decide` is timed. Requests are built beforehand and cycled; policy load time is reported separately as `load_ms`.
- Percentiles are nearest-rank over all samples (n per point is recorded). Nothing is dropped.
- One run per grid point, fixed seed, garbage collection enabled, warm-up 1000 decisions discarded.
- The host is a laptop (see `env.json` `latency_host`), not a quiet server.
- The CEL compiled-expression cache (`lru_cache(1024)` in `sdk/src/openapl/conditions.py`) may evict at the 1000x10000 point, so part of that point's cost may be recompilation.
- R9: "principals" means agent and service principals in the policy; "entitlements" is the total, including about 5% denies.
- Each point records its decision mix (ALLOW, DENY, REQUIRE_APPROVAL), so the timed requests exercise real paths.

## Gateway caveats (`results/gateway.json`)

- Two agentgateway v1.7.0 instances (with and without OpenAPL ext_authz) run on one host, with batches in ABBA order so drift cancels.
- One persistent MCP session per batch, but a new TCP connection per request, in both arms.
- Absolute numbers are specific to Docker Desktop on this host. The paired delta is the finding, not either arm's absolute latency.
- `batch_median_spread_us` and `batch_p99_spread_us` are ranges over the `paired_batches` paired batches, not confidence intervals. A per-batch p99 over 200 samples is noisy.
- Every sidecar decision is counted (`sidecar_decisions`) to confirm the OpenAPL arm authorised each call.

## Why latency and gateway runs are not in CI

Shared CI runners have noisy, uneven CPU and no stable Docker networking, so timings there are not comparable to the recorded ones. CI runs only the deterministic parts: the `bench` job installs the SDK and sidecar, builds the Cedar image and pulls OPA (`bench/tools.sh`), runs `pytest bench/tests -q`, then the three engine runners, and fails on any mismatch.
