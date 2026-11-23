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

- `native`: the committed translation reads no precomputed field (the fields each adapter computes outside the engine, listed in `bench/adapters/*_input.py` `PRECOMPUTED` and in the translation README) in any decision-determining policy, and needs no decision mapping by the runner. Each scenario's OpenAPL policy is encoded in full (every edge, deny and condition, including paths no case exercises); a grade is about that encoding. The cases test the encoding; they do not limit it.
- `workaround`: the translation reads at least one precomputed field, or relies on the runner's decision mapping (Cedar's REQUIRE_APPROVAL, read from `needs-approval:` permits).
- `not-expressible`: the engine cannot decide a case; the case is listed under that engine's `unsupported:` with a reason and is not run.

`test_native_reads_no_precomputed_field` checks the rule against the translation source, and `test_cedar_counterfactual_without_precomputed_fields` reruns Cedar with every precomputed field removed or set to junk and the mapping off: every native scenario still matches, and every workaround scenario flips at least one case. This shows a precomputed field is read; it does not show that a given case depends on it. Request shaping shared by every Cedar scenario (caller as principal, origin human as a User with group/role parents, the set of agent links) is not a precomputed field.

## The grading rubric

Each scenario gets one grade per engine in `verdict.yaml`, with the translation lines (or, for XACML and GAPL, source sections) that justify it.

| Grade | Definition |
|---|---|
| `native` | The committed translation reads no precomputed field in any decision-determining policy (controller ruling R7). Chain order carried by position counts as precomputation (see below). |
| `workaround` | The translation reads at least one precomputed field, or relies on a runner decision mapping that is not the language's own output. |
| `not-expressible` | The engine cannot decide a case; the case is listed under the engine's `unsupported:` and is not run. |
| `unknown` | Used for GAPL only, as `unknown (not documented)`: the vendor documentation does not say. |

- Each scenario's OpenAPL policy is encoded in full (every edge, deny and condition, including paths no case exercises); a grade is about that encoding. The cases test the encoding; they do not limit it. Grades are not claims about the language in general.
- **Chain order is precomputation.** Delegation chains are ordered. XACML has unordered bags and positional categories; Cedar has no ordered collection except a record keyed by index. Carrying the order by position (XACML `…:link:1`, `…:link:2`, or a Cedar record keyed by index) means the PEP assigns an index to each link, which is the same computation as supplying `first_agent` and the `hops` pairs. The rule is therefore that carrying chain order by position is precomputation, so the scenario is `workaround`. The reason is that the engine, not the PEP, should derive which link precedes which. Rationale in `analysis/xacml.md` (Chains with relays).
- **OpenAPL's 14/14 native is definitional.** The suite and its expected decisions were written from OpenAPL's SPEC, so OpenAPL's grade is native by construction. Rego ties it on this suite (14 native). The paper must not claim an expressiveness advantage over Rego from this table.
- REQUIRE_APPROVAL is a third outcome (R4, R8). It is native when it is the language's own standard output: a Rego string value, or an XACML obligation in the PDP response that the PEP must discharge. It is not native when the runner infers it from determining-policy ids (Cedar's `needs-approval:` permits, GAPL's `@id` convention); that is a workaround.
- XACML and GAPL are written analyses (`bench/analysis/xacml.md`, `bench/analysis/gapl.md`, sources in `sources.md`). Nothing was run. GAPL's public material is vendor documentation.
- **Chain-order sensitivity** (derived from the recorded reasons in each `verdict.yaml` `why` and the translation READMEs, not re-translated). Under the opposite rule (order by position is not precomputation) these workaround grades would flip to native because chain order is their only precomputation: Cedar: `deny-overrides`, `unknown-principal`. XACML: `attenuation-3hop`, `deny-overrides`, `over-deep-delegation`, `unknown-principal`. GAPL: `deny-overrides`, `unknown-principal`. The other workaround grades rest on something else and would stay workaround: a hash (`approval-bound`, `threshold-approval`, and `relay-adds-edge` for all three), approval-item `expired` flags and the approval-to-decision mapping (Cedar `approval-bound`, `threshold-approval`, `relay-adds-edge`; GAPL the same, with `@id` mapping), depth or size (Cedar and GAPL `attenuation-3hop` and `over-deep-delegation`; XACML has native depth), or string concatenation (Cedar and GAPL `relay-adds-edge`). Rego has no chain-order workaround grades.
- `deny-wrong-group` is a request-intent label in `gen_policies.py` and `latency.json`. It means the origin human's group has no `acts_for` edge to the first agent (a "no acts_for edge" denial); it is not a separate group check. It stays unrenamed so the recorded labels match the committed latency.json.
- R5: Cedar and Rego rows are matched on the decision only, not on reasons.

## What each result means

`results/summary.json` holds the key numbers a paper cites; full statistics are in `results/latency.json` and `results/gateway.json`. Its key paths:

- `suite.{scenarios,cases,allow,deny,require_approval}`: the suite shape from `cases.yaml`.
- `engines.{openapl,cedar,rego}.{matched,mismatched,unsupported}`: case outcomes per engine.
- `grades.<engine>.{native,workaround,not_expressible,unknown}`: scenario counts per grade, for openapl, cedar, rego, xacml and gapl; `grades.openapl_note` records that OpenAPL's grade is native by construction.
- `latency.target.{point,p99_us,met}`: the design target (p99 under 5 ms at 100 principals and 1,000 entitlements). `latency.grid.<PxE>.{p50_us,p99_us,load_ms,n,principals,entitlements}` plus `{met_5ms,p95_us,max_us,mean_us,decision_mix,warmup,seed,request_pool}` per grid point.
- `gateway.{openapl,baseline}.{p50_us,p99_us,n}`, `gateway.delta.{p50_us,p99_us,batch_median_spread_us,batch_p99_spread_us,paired_batches}`, `gateway.sidecar_decisions.count`.
- `env.*`: tool versions and digests (`tools`), the latency host (`latency_host`) and the gateway stack (`gateway`).

## Latency caveats (`results/latency.json`)

- Only `Authorizer.decide` is timed. Requests are built beforehand and cycled; policy load time is reported separately as `load_ms`.
- Percentiles are nearest-rank over all samples (n per point is recorded). Nothing is dropped.
- One run per grid point, fixed seed, garbage collection enabled, warm-up 1000 decisions discarded.
- The host is a laptop (see `env.json` `latency_host`), not a quiet server.
- The CEL compiled-expression cache (`lru_cache(1024)` in `sdk/src/openapl/conditions.py`) may evict at the 1000x10000 point, so part of that point's cost may be recompilation.
- R9: "principals" means agent and service principals in the policy; "entitlements" is the total, including about 5% denies.
- The 5 ms target is met at the 100x1000 target point (p99 2.30 ms) and at 10x100, and missed at the larger points: 300x3000 (p99 6.79 ms) and 1000x10000 (p99 23.4 ms) exceed 5 ms. Cost grows roughly linearly with the number of entitlements.
- Code under test: `latency.py` and `gen_policies.py` were first committed in 436fbc8, and the SDK is unchanged since 90a3156 (the `sdk_git_sha` in the latency env).
- Warm-up (1000 decisions) covers half of the 2000-request pool; the timed 20000 decisions cycle the pool.
- Each point records its decision mix (ALLOW, DENY, REQUIRE_APPROVAL), so the timed requests exercise real paths.

## Gateway caveats (`results/gateway.json`)

- Two agentgateway v1.7.0 instances (with and without OpenAPL ext_authz) run on one host, with batches in ABBA order so drift cancels.
- One persistent MCP session per batch, but a new TCP connection per request, in both arms.
- Absolute numbers are specific to Docker Desktop on this host. The paired delta is the finding, not either arm's absolute latency.
- `batch_median_spread_us` and `batch_p99_spread_us` are ranges over the `paired_batches` paired batches, not confidence intervals. A per-batch p99 over 200 samples is noisy.
- The delta was measured with the demo policy (4 principals, 4 entitlements, 2 denies), not the 100x1000 target policy. It does not predict gateway cost at the target scale.
- Decision logging was ON for the OpenAPL arm: a synchronous append and flush per decision to a Docker Desktop bind mount (off by default in the sidecar). Part of the delta is this logging.
- The baseline has no external authorization, so the delta is the ext_authz hop, the Python sidecar and OpenAPL together. It is not a comparison with another PDP.
- It is one run: 10 batches, N=5 paired batches. The code commit for the run is d1a16e8, with the fixed run at 1bc5e3a. Future runs record `git_sha` and `git_dirty` in the `gateway` env block (not re-run now).
- Every sidecar decision is counted (`sidecar_decisions`) to confirm the OpenAPL arm authorised each call.

## Why latency and gateway runs are not in CI

Shared CI runners have noisy, uneven CPU and no stable Docker networking, so timings there are not comparable to the recorded ones. CI runs only the deterministic parts: the `bench` job installs the SDK and sidecar, builds the Cedar image and pulls OPA (`bench/tools.sh`), runs `pytest bench/tests -q`, then the three engine runners, and fails on any mismatch.
