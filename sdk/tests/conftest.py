# sdk/tests/conftest.py
import shutil
from pathlib import Path

import pytest

from openapl.policyset import load_policy_dir

EXAMPLE = Path(__file__).resolve().parents[2] / "spec" / "examples" / "refund-delegation.apl.yaml"


@pytest.fixture
def refund_dir(tmp_path):
    d = tmp_path / "policies"
    d.mkdir()
    shutil.copy(EXAMPLE, d / "refund-delegation.apl.yaml")
    return d


@pytest.fixture
def ps(refund_dir):
    return load_policy_dir(str(refund_dir))


@pytest.fixture
def authorizer(ps):
    from openapl.authorizer import Authorizer

    return Authorizer(ps)
