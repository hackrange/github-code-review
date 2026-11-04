#!/usr/bin/env python3
"""The routes a repository declares, for matching a dynamic scan to its code.

    routes.py <checkout>   ->   a JSON list of paths on stdout

The reading itself is app/core/dast_whitebox.py, loaded by path so the
scanner and the web app read routes the same way.  It only uses the standard
library, so nothing of the web app has to be importable here.
"""

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_dir():
        print("usage: routes.py <checkout>", file=sys.stderr)
        return 2
    spec = importlib.util.spec_from_file_location(
        "gcr_whitebox", HERE.parent / "app" / "core" / "dast_whitebox.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    got = module.read(Path(sys.argv[1]))
    print(json.dumps(got["routes"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
