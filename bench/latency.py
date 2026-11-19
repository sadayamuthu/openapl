# bench/latency.py
"""In-process latency of Authorizer.decide over a synthetic policy grid (design §6).

Usage: python bench/latency.py --out bench/results/latency.json
Only the decide() call is timed (time.perf_counter_ns); Request objects are built beforehand
and cycled. Load time is reported separately. Percentiles are nearest-rank on the sorted
samples. Warm-up decisions are run and discarded; nothing else is dropped."""
import argparse
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_policies  # noqa: E402
from openapl.authorizer import Authorizer  # noqa: E402
from run_openapl import build_request  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
GRID = [(10, 100), (100, 1000), (300, 3000), (1000, 10000)]
TARGET_POINT, TARGET_US = (100, 1000), 5000
SEED = 1


def _pct(sorted_ns: list[int], p: float) -> float:
    return sorted_ns[max(0, math.ceil(p * len(sorted_ns)) - 1)] / 1000


def measure(policy_dir: str, requests: str, *, warmup: int = 1000, n: int = 20000) -> dict:
    raw = [json.loads(l) for l in Path(requests).read_text(encoding="utf-8").splitlines() if l]
    reqs = [build_request(r) for r in raw]
    t0 = time.perf_counter_ns()
    authorizer = Authorizer.from_dir(policy_dir)
    load_ms = (time.perf_counter_ns() - t0) / 1e6
    decide = authorizer.decide
    for i in range(warmup):
        decide(reqs[i % len(reqs)])
    mix = {"ALLOW": 0, "DENY": 0, "REQUIRE_APPROVAL": 0}
    samples = [0] * n
    clock = time.perf_counter_ns
    for i in range(n):
        q = reqs[i % len(reqs)]
        t = clock()
        d = decide(q)
        samples[i] = clock() - t
        mix[d.decision] += 1
    samples.sort()
    return {"n": n, "warmup": warmup, "p50_us": _pct(samples, 0.50), "p95_us": _pct(samples, 0.95),
            "p99_us": _pct(samples, 0.99), "max_us": samples[-1] / 1000,
            "mean_us": sum(samples) / n / 1000, "decision_mix": mix, "load_ms": load_ms,
            "request_pool": len(reqs)}


def _sh(*cmd: str) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def host_env() -> dict:
    ram = _sh("sysctl", "-n", "hw.memsize")
    if ram == "unknown" and Path("/proc/meminfo").exists():
        ram = str(int(Path("/proc/meminfo").read_text().split()[1]) * 1024)
    cpu = _sh("sysctl", "-n", "machdep.cpu.brand_string")
    if cpu == "unknown":
        cpu = platform.processor() or "unknown"
    return {"cpu_model": cpu, "cores": os.cpu_count(),
            "ram_bytes": int(ram) if ram.isdigit() else None,
            "os": f"{platform.system()} {platform.release()} ({platform.platform()})",
            "python": platform.python_version(),
            "sdk_git_sha": _sh("git", "-C", str(REPO), "rev-parse", "HEAD"),
            "sdk_git_dirty": bool(_sh("git", "-C", str(REPO), "status", "--porcelain", "sdk/src"))}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--warmup", type=int, default=1000)
    ap.add_argument("--env", default=str(REPO / "bench" / "results" / "env.json"))
    a = ap.parse_args()
    cmd = "python bench/latency.py " + " ".join(sys.argv[1:])
    env = host_env()
    points = []
    for principals, ents in GRID:
        denies = round(0.05 * ents)
        with tempfile.TemporaryDirectory() as tmp:
            info = gen_policies.generate(tmp, principals=principals, entitlements=ents,
                                         denies=denies, seed=SEED)
            res = measure(tmp, str(Path(tmp) / "requests.jsonl"), warmup=a.warmup, n=a.n)
        res.update({"point": f"{principals}x{ents}", "principals": principals,
                    "entitlements": ents, "denies": denies, "seed": SEED,
                    "when_entitlements": info.when_entitlements,
                    "namespaces": info.namespaces, "request_intents": info.intents})
        points.append(res)
        print(f"{res['point']}: p50={res['p50_us']:.0f}us p99={res['p99_us']:.0f}us "
              f"load={res['load_ms']:.0f}ms mix={res['decision_mix']}", flush=True)
    t = next(p for p in points if p["point"] == f"{TARGET_POINT[0]}x{TARGET_POINT[1]}")
    result = {"command": cmd, "env": env, "seed": SEED, "points": points,
              "target": {"point": t["point"], "p99_us": t["p99_us"], "met": t["p99_us"] < TARGET_US}}
    Path(a.out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    envp = Path(a.env)
    doc = json.loads(envp.read_text(encoding="utf-8")) if envp.exists() else {}
    doc["latency_host"] = env
    envp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
