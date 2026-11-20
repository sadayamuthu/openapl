#!/usr/bin/env python3
# spec/scripts/validate_examples.py
"""Validate all .apl.yaml example policies against the OpenAPL JSON Schema.

Modelled on opengpl/spec/scripts/validate_examples.py (no code imported).
"""
import json
import pathlib
import sys

import jsonschema
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "openapl-v0.1.json"
EXAMPLES_DIR = REPO_ROOT / "examples"


def main():
    schema = json.loads(SCHEMA_PATH.read_text())
    examples = sorted(EXAMPLES_DIR.glob("*.apl.yaml"))

    if not examples:
        print("No .apl.yaml files found in examples/")
        sys.exit(1)

    errors = []
    for path in examples:
        try:
            doc = yaml.safe_load(path.read_text())
            jsonschema.validate(doc, schema)
            print(f"  ok {path.name}")
        except (yaml.YAMLError, jsonschema.ValidationError) as e:
            errors.append(path.name)
            print(f"  FAIL {path.name}: {e}")

    print(f"\n{len(examples) - len(errors)}/{len(examples)} policies valid")

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
