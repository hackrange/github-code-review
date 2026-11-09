#!/usr/bin/env python3
"""The host names a repository says it serves, or names, for tying sites to code.

    code_hosts.py <checkout>   ->   a JSON list on stdout

The reading itself is app/core/code_hosts.py, loaded by path so the scanner
and the web app read hosts the same way.  It only uses the standard library,
so nothing of the web app has to be importable here.
"""

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_dir():
        print("usage: code_hosts.py <checkout>", file=sys.stderr)
        return 2
    spec = importlib.util.spec_from_file_location(
        "gcr_code_hosts", HERE.parent / "app" / "core" / "code_hosts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    print(json.dumps(module.read(Path(sys.argv[1]))["hosts"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
