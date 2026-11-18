# sdk/src/openapl/conditions.py
"""CEL condition evaluation. Fail closed: any error raises ConditionError."""
from functools import lru_cache

import celpy
from celpy import celtypes

_ENV = celpy.Environment()


class ConditionError(Exception):
    pass


@lru_cache(maxsize=1024)
def _program(expr: str):
    try:
        return _ENV.program(_ENV.compile(expr))
    except Exception as e:
        raise ConditionError(f"condition does not compile: {expr!r}: {e}") from e


def evaluate_conditions(exprs: tuple[str, ...], activation: dict) -> bool:
    if not exprs:
        return True
    try:
        cel_activation = celpy.json_to_cel(activation)
    except Exception as e:
        raise ConditionError(f"activation not convertible to CEL: {e}") from e
    for expr in exprs:
        program = _program(expr)
        try:
            result = program.evaluate(cel_activation)
        except Exception as e:
            raise ConditionError(f"condition failed to evaluate: {expr!r}: {e}") from e
        if not isinstance(result, celtypes.BoolType):
            raise ConditionError(f"condition is not boolean: {expr!r}")
        if not bool(result):
            return False
    return True
