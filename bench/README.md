# OpenAPL benchmark

`scenarios/<id>/` holds 14 scenarios. Each has a `README.md` (two sentences and the threat it maps to, or none), the OpenAPL policy in `openapl/*.apl.yaml`, and `cases.yaml` with the request and expected decision for every case. Requests use the conformance-suite shape of `spec/conformance/*.yaml`.

Expected decisions come from the specification (`spec/SPEC.md` §6 and §7), not from engine output.

| Result | Command (run from the repository root, in `sidecar/.venv`) |
|---|---|
| `results/openapl.json` | `python bench/run_openapl.py --out bench/results/openapl.json` |
| Suite checks | `pytest bench/tests -q` |

The runner exits 1 on any mismatch, and an engine error counts as a mismatch.
