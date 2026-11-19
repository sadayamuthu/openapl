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


@pytest.fixture
def gate_factory(refund_dir, bindings_file):
    from openapl import Authorizer
    from openapl.decision_log import DecisionLog
    from openapl_sidecar.bindings import load_bindings
    from openapl_sidecar.gate import Gate

    def make(log_path=None, dev_mode=False):
        log = DecisionLog(str(log_path)) if log_path else None
        return Gate(Authorizer.from_dir(str(refund_dir)), load_bindings(bindings_file), log,
                    dev_mode, clock=lambda: 1000)
    return make


@pytest.fixture
def gate(gate_factory):
    return gate_factory()


@pytest.fixture
def dev_gate(gate_factory, tmp_path):
    return gate_factory(tmp_path / "dev.jsonl", dev_mode=True)


@pytest.fixture
def gate_with_log(gate_factory, tmp_path):
    return gate_factory(tmp_path / "log.jsonl")
