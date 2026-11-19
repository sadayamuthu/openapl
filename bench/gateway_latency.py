# bench/gateway_latency.py
"""End-to-end latency of MCP tools/call through agentgateway v1.7.0, with and without OpenAPL.

Usage: python bench/gateway_latency.py --out bench/results/gateway.json --batches 10 --per-batch 200

Alternation: both gateways run at once in one compose project (openapl-bench), on the same host,
over the same two MCP backends. `openapl` = demo gateway.yaml (strict jwtAuth + ext_authz to the
sidecar) on 127.0.0.1:3100; `baseline` = bench/gateway/gateway-noauthz.yaml (strict jwtAuth, no
ext_authz) on 127.0.0.1:3101. Batches alternate in ABBA order (O B B O O B B O ...) so a monotonic
drift cancels. Each batch opens a fresh MCP session, discards a warm-up, then times `per-batch`
allowed small-refund tools/call requests (time.perf_counter_ns). Any non-200 or isError result in
EITHER configuration aborts the run; nothing is dropped. The stack is always torn down."""
import argparse
import json
import math
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "demo" / "agentgateway"))

COMPOSE = HERE / "gateway" / "compose.bench.yaml"
OUT_DIR = HERE / "gateway" / "out"
PROJECT = "openapl-bench"
PORTS = {"openapl": 3100, "baseline": 3101}
TOOL = "payments_refund_order"
ARGS = {"order_id": "123", "amount": 150, "account_status": "open"}
ACTORS = ["spiffe://acme.com/agents/support-agent", "refund-agent"]


def _pct(sorted_ns: list[int], p: float) -> float:
    return sorted_ns[max(0, math.ceil(p * len(sorted_ns)) - 1)] / 1000


def summarize(samples_ns: list[int]) -> dict:
    """Nearest-rank percentiles over all samples, in microseconds."""
    if not samples_ns:
        raise ValueError("no samples")
    s = sorted(samples_ns)
    return {"n": len(s), "p50_us": _pct(s, 0.50), "p95_us": _pct(s, 0.95), "p99_us": _pct(s, 0.99),
            "max_us": s[-1] / 1000, "mean_us": sum(s) / len(s) / 1000}


def delta(a: dict, b: dict, a_batch_medians: list[float], b_batch_medians: list[float]) -> dict:
    """a (OpenAPL) minus b (baseline); spread = max-min of the paired per-batch median differences."""
    diffs = [x - y for x, y in zip(a_batch_medians, b_batch_medians)]
    return {"p50_us": a["p50_us"] - b["p50_us"], "p99_us": a["p99_us"] - b["p99_us"],
            "batch_median_spread_us": max(diffs) - min(diffs), "batch_median_deltas_us": diffs}


def batch_order(batches: int) -> list[str]:
    """ABBA alternation, starting with openapl."""
    order: list[str] = []
    while len(order) < batches:
        order += ["openapl", "baseline", "baseline", "openapl"]
    return order[:batches]


def _compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE), *args],
                          capture_output=True, text=True, check=check)


def _sh(*cmd: str) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def prepare_out() -> None:
    import shutil
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir(parents=True)
    OUT_DIR.chmod(0o777)  # the sidecar runs as uid 10001
    subprocess.run([sys.executable, str(REPO / "demo" / "agentgateway" / "issuer.py"), "keys", str(OUT_DIR)],
                   check=True)


def run_batch(config: str, per_batch: int, warmup: int) -> list[int]:
    import issuer
    from mcp_client import McpClient
    token = issuer.mint(str(OUT_DIR), email="alice@acme.com", groups=["support-staff"], actors=ACTORS)
    c = McpClient(f"http://127.0.0.1:{PORTS[config]}/mcp", token)
    st = c.initialize()
    if st != 200:
        raise RuntimeError(f"{config}: initialize returned {st}")
    samples: list[int] = []
    for i in range(warmup + per_batch):
        t0 = time.perf_counter_ns()
        status, result, _ = c.call(TOOL, ARGS)
        dt = time.perf_counter_ns() - t0
        if status != 200 or not isinstance(result, dict) or result.get("isError") or "content" not in result:
            raise RuntimeError(f"{config}: call {i} failed: status={status} result={str(result)[:300]}")
        if i >= warmup:
            samples.append(dt)
    return samples


def gateway_env() -> dict:
    ids = _compose("ps", "-q", "--all").stdout.split()
    images: dict = {}
    for cid in ids:
        info = json.loads(subprocess.run(["docker", "inspect", cid], capture_output=True, text=True,
                                         check=True).stdout)[0]
        svc = info["Config"]["Labels"].get("com.docker.compose.service", cid)
        img = json.loads(subprocess.run(["docker", "image", "inspect", info["Image"]], capture_output=True,
                                        text=True, check=True).stdout)[0]
        images[svc] = {"image": info["Config"]["Image"], "image_id": img["Id"],
                       "repo_digests": img.get("RepoDigests", []), "arch": img.get("Architecture")}
    return {"agentgateway_version": "v1.7.0", "docker_version": _sh("docker", "version", "--format",
            "{{.Server.Version}}"), "docker_context": _sh("docker", "context", "show"),
            "docker_os": _sh("docker", "info", "--format", "{{.OperatingSystem}} {{.Architecture}} "
                             "cpus={{.NCPU}} mem={{.MemTotal}}"), "images": images,
            "ports": PORTS, "compose": "bench/gateway/compose.bench.yaml"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--batches", type=int, default=10)
    ap.add_argument("--per-batch", type=int, default=200)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--env", default=str(HERE / "results" / "env.json"))
    a = ap.parse_args()
    cmd = "python bench/gateway_latency.py " + " ".join(sys.argv[1:])
    order = batch_order(a.batches)
    try:
        _compose("down", "-v", "--remove-orphans", check=False)
        prepare_out()
        up = _compose("up", "-d", "--build", "--wait", "--wait-timeout", "180", check=False)
        if up.returncode:
            sys.stderr.write(up.stdout + up.stderr)
            return 1
        env_gw = gateway_env()
        per: dict[str, list[int]] = {"openapl": [], "baseline": []}
        meds: dict[str, list[float]] = {"openapl": [], "baseline": []}
        for i, cfg in enumerate(order):
            s = run_batch(cfg, a.per_batch, a.warmup)
            per[cfg] += s
            meds[cfg].append(summarize(s)["p50_us"])
            print(f"batch {i} {cfg}: p50={meds[cfg][-1]:.0f}us", flush=True)
        # per-batch medians are listed in chronological order within each configuration
        res = {"command": cmd, "batches": a.batches, "per_batch": a.per_batch,
               "warmup_per_batch": a.warmup, "batch_order": order,
               "operation": f"tools/call {TOOL} {json.dumps(ARGS)} (allowed, 200) over one MCP session per batch",
               "client": "urllib, new TCP connection per request, same host (127.0.0.1)"}
        for cfg in ("openapl", "baseline"):
            res[cfg] = {**summarize(per[cfg]), "batch_medians_us": meds[cfg]}
        res["delta"] = delta(res["openapl"], res["baseline"], meds["openapl"], meds["baseline"])
        res["all_openapl_calls_200_with_result"] = True
        res["gateway_env"] = env_gw
        Path(a.out).write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
        envp = Path(a.env)
        doc = json.loads(envp.read_text(encoding="utf-8")) if envp.exists() else {}
        doc["gateway"] = env_gw
        envp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        for cfg in ("openapl", "baseline"):
            r = res[cfg]
            print(f"{cfg}: n={r['n']} p50={r['p50_us']:.0f} p95={r['p95_us']:.0f} p99={r['p99_us']:.0f} "
                  f"mean={r['mean_us']:.0f} us")
        print("delta:", {k: v for k, v in res["delta"].items() if k != "batch_median_deltas_us"})
        return 0
    except Exception as e:  # any failure aborts; the stack is still torn down below
        sys.stderr.write(f"FAILED: {e}\n")
        try:
            sys.stderr.write(_compose("logs", "--no-color", "--tail", "40", check=False).stdout)
        except Exception:
            pass
        return 1
    finally:
        _compose("down", "-v", "--remove-orphans", check=False)


if __name__ == "__main__":
    sys.exit(main())
