#!/usr/bin/env python3
"""A CVSS v3 base score, worked out from the vector an advisory publishes.

osv-scanner hands over the vector and no score.  The vulnerability pass used
to grade from it by one test: high confidentiality, integrity and availability
impact meant critical, and anything else was unknown.  That called a flaw
needing physical access and an administrator's login critical, and left 1,622
Python advisories with a perfectly good vector graded unknown.

The arithmetic is the published FIRST specification for 3.0 and 3.1, base
metrics only.  A vector this cannot read scores nothing, rather than a guess.

Usage: cvss.py --osv-grade < findings.json > findings.json
"""

import json
import math
import re
import sys

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges weigh more when the flaw reaches past its own component.
PRIVILEGES = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
              "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
VECTOR = re.compile(r"^CVSS:3\.[01]/(.+)$")


def _roundup(value: float) -> float:
    """The 3.1 rounding: up to one decimal, without float error."""
    whole = round(value * 100000)
    if whole % 10000 == 0:
        return whole / 100000.0
    return (math.floor(whole / 10000) + 1) / 10.0


def base_score(vector: str):
    """-> the base score, or None when the vector is not a full v3 one."""
    found = VECTOR.match((vector or "").strip())
    if not found:
        return None
    metrics = dict(part.split(":", 1) for part in found.group(1).split("/") if ":" in part)
    try:
        scope = metrics["S"]
        av, ac, ui = (WEIGHTS[k][metrics[k]] for k in ("AV", "AC", "UI"))
        c, i, a = (WEIGHTS[k][metrics[k]] for k in ("C", "I", "A"))
        pr = PRIVILEGES[scope][metrics["PR"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def band(score: float) -> str:
    """The qualitative rating the specification gives a score."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def grade(rows: list) -> list:
    """Score every row whose severity came from no rating of its own.

    That is a row graded unknown, or one the old one-test rule graded from
    the vector (marked _severity_from "vector").  A rating the advisory gives
    itself, such as GitHub's, is left as it is.
    """
    for row in rows:
        guessed = row.pop("_severity_from", None) == "vector"
        if not guessed and row.get("severity") != "unknown":
            continue
        score = base_score(row.get("cvss_vector") or "")
        if score is not None:
            row["cvss_score"] = score
            row["severity"] = band(score)
        elif guessed:
            # Not a vector this can score, so it says unknown.  The old rule's
            # critical claimed more than it knew.
            row["severity"] = "unknown"
    return rows


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--osv-grade":
        raw = sys.stdin.read()
        try:
            rows = json.loads(raw or "[]")
        except ValueError:
            sys.stdout.write(raw)
            return 0
        json.dump(grade(rows), sys.stdout)
        return 0
    for vector in sys.argv[1:]:
        print(vector, base_score(vector))
    return 0


if __name__ == "__main__":
    sys.exit(main())
