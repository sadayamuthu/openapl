# sdk/tests/test_conditions.py
import pytest

from openapl.conditions import ConditionError, evaluate_conditions


def test_cel_true():
    assert evaluate_conditions(("request.amount <= 200",), {"request": {"amount": 150}})


def test_cel_false():
    assert not evaluate_conditions(("request.amount <= 200",), {"request": {"amount": 250}})


def test_cel_membership():
    assert evaluate_conditions(
        ("'support-staff' in chain.origin.groups",),
        {"chain": {"origin": {"groups": ["support-staff"]}}},
    )


def test_cel_missing_field_raises():
    with pytest.raises(ConditionError):
        evaluate_conditions(("request.amount <= 200",), {"request": {}})


def test_cel_non_bool_raises():
    with pytest.raises(ConditionError):
        evaluate_conditions(("request.amount",), {"request": {"amount": 5}})


def test_cel_syntax_error_raises():
    with pytest.raises(ConditionError):
        evaluate_conditions(("request.amount <=",), {"request": {"amount": 5}})


def test_all_must_be_true():
    act = {"request": {"amount": 150}}
    assert not evaluate_conditions(("request.amount <= 200", "request.amount > 200"), act)


def test_empty_conditions_true():
    assert evaluate_conditions((), {})
