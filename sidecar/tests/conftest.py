# sidecar/tests/conftest.py
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "spec" / "examples" / "refund-delegation.apl.yaml"
BINDINGS = ROOT / "sidecar" / "examples" / "refund-bindings.yaml"


@pytest.fixture
def refund_dir(tmp_path):
    d = tmp_path / "policies"
    d.mkdir()
    shutil.copy(EXAMPLE, d / "refund-delegation.apl.yaml")
    return d


@pytest.fixture
def bindings_file():
    return str(BINDINGS)


@pytest.fixture
def alice_claims():
    return {
        "email": "alice@acme.com",
        "groups": ["support-staff"],
        "openapl_purpose": "customer-refund",
        "openapl_task_id": "t1",
        "iat": 900,
        "act": {"sub": "refund-agent", "act": {"sub": "spiffe://acme.com/agents/support-agent"}},
    }
