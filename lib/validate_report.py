"""Check a ghscan report against the JSON schema. Used by `ghscan validate`."""
import json
import sys


def main(report_path, schema_path):
    try:
        import jsonschema
    except ImportError:
        print("jsonschema is not installed. Run ./install-deps.sh", file=sys.stderr)
        return 2

    with open(report_path) as fh:
        report = json.load(fh)
    with open(schema_path) as fh:
        schema = json.load(fh)

    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(report),
        key=lambda e: list(e.path),
    )
    for err in errors[:25]:
        where = "/".join(str(p) for p in err.path) or "(root)"
        print("  %s: %s" % (where, err.message[:200]))
    if len(errors) > 25:
        print("  ... and %d more" % (len(errors) - 25))

    if errors:
        print("%d problem(s)" % len(errors))
        return 1
    print("valid")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: validate_report.py <report.json> <schema.json>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
