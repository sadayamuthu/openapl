# sdk/src/openapl/schema.py
"""JSON Schema validation of OpenAPL policy documents."""
import json
from functools import lru_cache
from importlib import resources

import jsonschema


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    text = (
        resources.files("openapl")
        .joinpath("schemas/openapl-v0.1.json")
        .read_text(encoding="utf-8")
    )
    return jsonschema.Draft202012Validator(json.loads(text))


def validate(doc: dict) -> None:
    """Raise ValueError("schema: <path>: <message>") on the first error."""
    errors = sorted(_validator().iter_errors(doc), key=lambda e: list(e.absolute_path))
    if errors:
        e = errors[0]
        path = "/".join(str(p) for p in e.absolute_path) or "<root>"
        raise ValueError(f"schema: {path}: {e.message}")
