# sdk/tests/test_schema.py
import copy
import pathlib

import pytest
import yaml

from openapl.schema import validate

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXAMPLES = sorted((ROOT / "spec" / "examples").glob("*.apl.yaml"))
MINIMAL = {"openapl": "0.1", "policy": "p", "version": "1"}


def _example():
    return yaml.safe_load(EXAMPLES[0].read_text())


def test_example_validates():
    assert EXAMPLES
    for path in EXAMPLES:
        validate(yaml.safe_load(path.read_text()))


def test_rejects_unknown_top_level_key():
    with pytest.raises(ValueError, match="schema"):
        validate({**MINIMAL, "bogus": 1})


def test_rejects_agent_without_owner():
    doc = _example()
    del doc["principals"]["refund-agent"]["owner"]
    with pytest.raises(ValueError, match="schema"):
        validate(doc)


def test_rejects_bad_otherwise():
    doc = _example()
    doc["entitlements"][0]["otherwise"] = "approve(manager)"
    with pytest.raises(ValueError, match="schema"):
        validate(doc)


def test_rejects_acts_for_bare_name():
    doc = copy.deepcopy(_example())
    doc["principals"]["support-agent"]["acts_for"][0]["who"] = "alice"
    with pytest.raises(ValueError, match="schema"):
        validate(doc)


def test_rejects_unknown_framework():
    with pytest.raises(ValueError, match="schema"):
        validate({**MINIMAL, "compliance": ["HIPAA"]})


def test_schema_copies_identical():
    a = (ROOT / "spec" / "schemas" / "openapl-v0.1.json").read_bytes()
    b = (ROOT / "sdk" / "src" / "openapl" / "schemas" / "openapl-v0.1.json").read_bytes()
    assert a == b
