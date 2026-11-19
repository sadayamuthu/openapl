# bench/tests/test_gateway_stats.py
"""Pure statistics helpers of bench/gateway_latency.py: fixed inputs, exact outputs."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gateway_latency as gl  # noqa: E402


def test_summarize_nearest_rank_in_us():
    # 1..100 microseconds, shuffled order; nearest-rank percentiles
    samples_ns = [i * 1000 for i in range(100, 0, -1)]
    s = gl.summarize(samples_ns)
    assert s == {"n": 100, "p50_us": 50.0, "p95_us": 95.0, "p99_us": 99.0,
                 "max_us": 100.0, "mean_us": 50.5}


def test_summarize_small_and_empty():
    assert gl.summarize([2000, 4000])["p50_us"] == 2.0
    with pytest.raises(ValueError):
        gl.summarize([])


def test_delta_is_openapl_minus_baseline():
    a = {"p50_us": 1500.0, "p99_us": 3000.0}
    b = {"p50_us": 1000.0, "p99_us": 2200.0}
    d = gl.delta(a, b, [1500.0, 1600.0, 1400.0], [1000.0, 1050.0, 990.0])
    assert d["p50_us"] == 500.0
    assert d["p99_us"] == 800.0
    # spread of the per-batch median differences (a_i - b_i): 500, 550, 410
    assert d["batch_median_spread_us"] == pytest.approx(140.0)


def test_batch_order_abba():
    assert gl.batch_order(4) == ["openapl", "baseline", "baseline", "openapl"]
    o = gl.batch_order(10)
    assert o == ["openapl", "baseline", "baseline", "openapl", "openapl",
                 "baseline", "baseline", "openapl", "openapl", "baseline"]
    assert o.count("openapl") == o.count("baseline") == 5


@pytest.mark.parametrize("n", [3, 7, 0])
def test_batch_order_rejects_odd(n):
    with pytest.raises(ValueError):
        gl.batch_order(n)


def test_delta_paired_p99_range():
    a = {"p50_us": 2.0, "p99_us": 5.0}
    b = {"p50_us": 1.0, "p99_us": 3.0}
    d = gl.delta(a, b, [2.0, 2.0], [1.0, 1.0], [5.0, 9.0], [3.0, 4.0])
    assert d["paired_batches"] == 2
    assert d["batch_p99_deltas_us"] == [2.0, 5.0]
    assert d["batch_p99_spread_us"] == 3.0
