# bench/tests/test_openapl_golden.py
"""Every scenario case decides as expected with the reference Authorizer."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import load_scenarios  # noqa: E402
from run_openapl import decide_case  # noqa: E402

_CASES = [
    pytest.param(s, c, id=f"{s.id}/{c.id}") for s in load_scenarios() for c in s.cases
]


def test_suite_loads_cases():
    assert _CASES, "no scenarios found"


@pytest.mark.parametrize("scenario, case", _CASES)
def test_openapl_golden(tmp_path, scenario, case):
    d = decide_case(scenario, case, tmp_path)
    assert d.decision == case.expect, d.reasons
    for fragment in case.reasons_include:
        assert fragment in d.reasons, d.reasons
    for fragment in case.reasons_exclude:
        assert not any(fragment in r for r in d.reasons), d.reasons
