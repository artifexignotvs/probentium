"""Schema formale ab altero validatore contra exempla probatur."""
import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def main():
    try:
        installed = version("jsonschema")
    except PackageNotFoundError:
        print("Development validation requires jsonschema==4.25.1.", file=sys.stderr)
        return 2
    if installed != "4.25.1":
        print("Development validation requires jsonschema==4.25.1; found " + installed + ".", file=sys.stderr)
        return 2
    from jsonschema import Draft202012Validator, FormatChecker

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    from tests_r1.test_adapters_v2 import invalid_fixtures, runtime_only_invalid_fixtures, valid_fixtures

    schema = json.loads((root / "schemas" / "events-v2.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    valid, invalid = valid_fixtures(), invalid_fixtures()
    failures = []
    for name, value in valid:
        if not validator.is_valid(value):
            failures.append({"fixture": name, "expected": "valid"})
    for name, value in invalid:
        if validator.is_valid(value):
            failures.append({"fixture": name, "expected": "invalid"})
    print(json.dumps({"schema": "probentium.event-schema-check.v1", "validator": "jsonschema " + installed,
                      "valid_fixtures": len(valid), "invalid_fixtures": len(invalid), "failures": failures,
                      "runtime_only_fixtures": len(runtime_only_invalid_fixtures()),
                      "runtime_only_scope": "Separate unit tests cover byte syntax, calendar validity and timestamp interval bounds.",
                      "independent_review": False}, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
