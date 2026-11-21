# bench/tests/test_gen_policies.py
"""Synthetic policy generator: loads, non-constant decision mix, deterministic."""
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCH))

import gen_policies  # noqa: E402
import latency  # noqa: E402


def _gen(tmp_path, name="p", **kw):
    args = dict(principals=100, entitlements=1000, denies=50, seed=7)
    args.update(kw)
    return gen_policies.generate(str(tmp_path / name), **args)


def test_generated_policies_load(tmp_path):
    _gen(tmp_path)
    exe = Path(sys.executable).parent / "openapl"
    r = subprocess.run([str(exe), "validate", str(tmp_path / "p")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_decision_mix_not_constant(tmp_path):
    _gen(tmp_path)
    res = latency.measure(str(tmp_path / "p"), str(tmp_path / "p" / "requests.jsonl"),
                          warmup=10, n=2000)
    mix = res["decision_mix"]
    total = sum(mix.values())
    assert total == 2000
    assert mix["ALLOW"] >= 0.10 * total, mix
    assert mix["DENY"] >= 0.10 * total, mix


def test_counts_and_shapes(tmp_path):
    info = _gen(tmp_path)
    assert info.principals == 100 and info.entitlements == 1000 and info.denies == 50
    reqs = [json.loads(l) for l in (tmp_path / "p" / "requests.jsonl").read_text().splitlines()]
    assert Counter(len(r["chain"]) - 1 for r in reqs).keys() >= {1, 2, 3}


def test_deterministic(tmp_path):
    _gen(tmp_path, "a")
    _gen(tmp_path, "b")
    _gen(tmp_path, "c", seed=8)
    names = sorted(p.name for p in (tmp_path / "a").iterdir())
    assert names == sorted(p.name for p in (tmp_path / "b").iterdir())
    for n in names:
        assert (tmp_path / "a" / n).read_bytes() == (tmp_path / "b" / n).read_bytes()
    assert (tmp_path / "a" / "requests.jsonl").read_bytes() != (tmp_path / "c" / "requests.jsonl").read_bytes()
