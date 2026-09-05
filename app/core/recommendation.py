"""A recommended grade, and why the real one is probably too high.

The scanner already works most of this out and then says nothing about it.  A
finding can carry a triage verdict reading "cast to a number before output,
which cannot carry markup" and go on being displayed as a HIGH, because the
verdict lives in one column and the grade in another and nothing joins them up.

This joins them up.  It reads facts that are already on the finding and turns
them into a sentence and a grade somebody can accept in one click.

Three rules hold it together:

  A recommendation is not a decision.  Nothing here changes a severity.  It
  sits on the page until an administrator accepts it, which is a regrade like
  any other and lands in the audit log with their name on it.

  It is derived, never invented.  Every sentence below is built from the
  triage verdict, the engine's own confidence, the reachability verdict or the
  exploitation data.  There is no second opinion formed at display time.

  Where there is nothing to say, it says nothing.  A recommendation on every
  finding is a recommendation on none, so this returns None far more often
  than not.
"""

from __future__ import annotations

from app.core import risk
from app.core.models import Severity

# Weakest to strongest, so a recommendation can be checked for actually being
# a step down before it is offered.
ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH,
         Severity.CRITICAL]
RANK = {level: index for index, level in enumerate(ORDER)}

# How likely somebody is to be hurt by this, in words.  A number between zero
# and one is a fact about a model, not an answer to the question being asked.
#
# The words themselves live in risk.py now, which is where both halves of the
# question are worked out.  They are re-exported here because this module has
# used these names since before that file existed.
from app.core.risk import (HAPPENING, LIKELY, POSSIBLE,  # noqa: E402,F401
                           UNLIKELY)


def _down(severity, steps: int):
    """A grade this many steps weaker, floored at info."""
    index = RANK.get(severity, RANK[Severity.MEDIUM])
    return ORDER[max(0, index - steps)]


def _enum(value):
    return getattr(value, "value", value)


def likelihood_of(finding) -> tuple:
    """-> (word, why).  What the data already says about exploitation.

    One line, because this used to be worked out here and is now worked out in
    the file that owns both halves of the question.  Kept as a name because
    several places call it.
    """
    return risk.likelihood_of(finding)


def for_finding(finding, context: dict = None):
    """-> {severity, likelihood, likelihood_reason, sentence} or None.

    None means there is nothing worth saying, which is the common case and the
    point.
    """
    current = getattr(finding, "severity", None)
    if current is None:
        return None
    # An administrator has already had this argument and settled it.
    if getattr(finding, "custom_severity", None) is not None:
        return None
    # A malicious package is the attack, not a package with a hole in it, and
    # none of the reasoning below applies to it.  "Nothing imports it" is not a
    # mitigation when the code runs at install time, which is exactly how these
    # execute.  Recommending a downgrade here would be the most dangerous
    # sentence this file could produce.
    if getattr(finding, "malicious", False):
        return None

    # The other direction, and the reason this file is not only a way of
    # calming a report down.
    #
    # A tool that only ever recommends coming down is a tool that talks people
    # into a false sense of security one accepted suggestion at a time.  Where
    # the two halves of the grade say this is worse than it is filed as, it has
    # to say so with the same prominence.
    raised = _raise_it(finding, current, context)
    if raised is not None:
        return raised

    # Nothing to recommend below the floor, in this direction.
    if current == Severity.INFO:
        return None

    triage = (getattr(finding, "triage", "") or "").lower()
    reason = (getattr(finding, "triage_reason", "") or "").strip()
    kind = _enum(getattr(finding, "kind", "")) or ""
    reach = (getattr(finding, "reachability", "") or "").lower()
    reach_reason = (getattr(finding, "reachability_reason", "") or "").strip()

    suggestion = None
    sentence = ""

    if getattr(finding, "base_upgraded", False):
        # Low rather than one step down, and deliberately.
        #
        # These arrive in bulk: one unpatched base produced eighty six of them
        # on a single repository, most of them medium, and a step down leaves
        # eighty six lows sitting exactly where they were in the middle of the
        # queue.  What makes them different from an ordinary medium is not
        # degree, it is that the build already fixed them, so they belong at
        # the bottom together.
        #
        # Not info, and not gone.  The upgrade only reaches as far as the
        # archive had got on the day of the build, so what settles this is not
        # the Dockerfile but how recently anybody ran it.
        suggestion = Severity.LOW
        sentence = ("The Dockerfile upgrades its packages after pulling this "
                    "base image, so what ships is probably not the version "
                    "reported here. The image in the registry really does "
                    "carry this, which is why it is graded down rather than "
                    "set aside. An upgrade is only as current as the day the "
                    "image was built, so the thing that keeps this true is "
                    "rebuilding the image on a routine schedule rather than "
                    "anything in the repository.")
    elif triage == "not_applicable":
        suggestion = Severity.INFO
        sentence = ("The fidelity pass found this is not what its rule was "
                    "looking for" + (f": {reason}" if reason else "."))
    elif triage == "third_party":
        suggestion = _down(current, 2)
        sentence = ("This is in code somebody else wrote rather than code this "
                    "team maintains" + (f": {reason}" if reason else ", so "
                    "fixing it means upgrading or replacing the library, not "
                    "editing the line."))
    elif triage == "advisory":
        suggestion = _down(current, 2)
        sentence = ("The rule that found this reports a pattern rather than a "
                    "problem" + (f": {reason}" if reason else ", which is what "
                    "an audit ruleset is for."))
    elif "cred" not in str(kind) and reach == "unlikely":
        # A vulnerability in a package the application never calls is a real
        # vulnerability in nothing that runs here.
        suggestion = _down(current, 2)
        sentence = ("The vulnerable package is not reached by this application"
                    + (f": {reach_reason}." if reach_reason else "."))
    elif reach == "unknown" and current in (Severity.CRITICAL, Severity.HIGH) \
            and (getattr(finding, "epss_score", None) or 0) < 0.001 \
            and not getattr(finding, "known_exploited", False):
        suggestion = _down(current, 1)
        sentence = ("Nobody is exploiting this and it is not known to be "
                    "reached, so it is worth fixing on the next upgrade rather "
                    "than out of hours.")

    if suggestion is None or RANK.get(suggestion, 0) >= RANK.get(current, 0):
        return None

    assessed = risk.assess(finding, context)
    return {
        "severity": suggestion,
        "direction": "down",
        "likelihood": assessed["likelihood"],
        "likelihood_reason": assessed["likelihood_reason"],
        "impact": assessed["impact"],
        "impact_reason": assessed["impact_reason"],
        "sentence": sentence,
        "from": current,
    }


# What it takes to recommend raising a grade.  Only an observation: somebody
# asked the provider and the credential answered, somebody is exploiting this
# in the wild, or a request was sent and the response showed the thing the rule
# was worried about.
#
# An inference is not enough and must never become enough.  Raising a grade on
# a guess spends the word critical on something nobody proved, which is the
# same failure as lowering one on a probe that did not fire, pointed the other
# way.  The impact side can be inferred, because it is a fact somebody typed in
# about their own system rather than a fact this tool worked out.
OBSERVED = {"happening now"}


def _raise_it(finding, current, context: dict = None):
    """-> a recommendation to grade this higher, or None.

    An observation is the entry requirement and it is not negotiable.  What the
    system holds then decides how far it goes: the same live credential is a
    high in a repository nobody has described and a critical in the one holding
    cardholder data, which is the whole reason both halves are asked.

    A sensitive system on its own raises nothing.  Plenty of sensitive systems
    hold findings nobody has shown to be real, and grading those up on the
    strength of a label would fill the top of the list with the same guesses in
    a different order.
    """
    assessed = risk.assess(finding, context)
    if assessed["likelihood"] not in OBSERVED:
        return None

    suggestion = assessed["severity"]
    if RANK.get(suggestion, 0) <= RANK.get(current, 0):
        return None

    return {
        "severity": suggestion,
        "direction": "up",
        "likelihood": assessed["likelihood"],
        "likelihood_reason": assessed["likelihood_reason"],
        "impact": assessed["impact"],
        "impact_reason": assessed["impact_reason"],
        "sentence": ("This is filed as " + _enum(current) + " and both halves "
                     "of the question say it is worse than that. "
                     + assessed["sentence"]),
        "from": current,
    }
