"""The two questions severity folds into one, asked separately.

A severity is a single number standing in for two different judgements, and
folding them together is why a work list reads as black or white.  "Critical"
is saying both that this would hurt and that somebody could do it, and a rule
that fires on a line of code is only ever entitled to an opinion about the
first one.

So they are asked separately here.

  Impact is what it would cost if somebody did it.  That is a fact about the
  system, not about the code: the same missing escape is an incident in the
  cardholder system and a chore in the brochure site.  Nothing an engine reads
  in a file can tell them apart, and the answer already exists on the
  connection and on the repository, put there by somebody who knows.

  Likelihood is whether anybody can, and how easily.  That is a fact about
  evidence: a credential the provider confirmed still works, an advisory on
  the exploited list, a package nothing imports, a rule that says in the same
  breath that it is guessing.

The separation is the whole point and it has one rule that must not be relaxed:
**nothing counts on both sides.**  A vulnerability being exploited in the wild
is likelihood.  Cardholder data behind it is impact.  Counting the exploited
list on both axes is how a score turns back into the single number this exists
to take apart.

Derived, never invented.  Every value here comes from a column already on the
finding or a label somebody already set, and every value comes back with the
sentence that produced it.  Nothing in this file writes anything down: the
grade on a finding stays where it is until a person changes it, which is what
`recommendation.py` is for.
"""

from __future__ import annotations

from app.core.models import Severity

# --- the vocabularies --------------------------------------------------------
#
# Likelihood keeps the words the recommendation has always shown people, so
# there is one vocabulary in the product rather than two saying the same thing
# in different registers.  Impact is low, medium, high, which is what the
# engines emit and what the column already holds.

UNLIKELY = "unlikely"
POSSIBLE = "possible"
LIKELY = "likely"
HAPPENING = "happening now"

LIKELIHOOD_ORDER = [UNLIKELY, POSSIBLE, LIKELY, HAPPENING]

LOW = "low"
MEDIUM = "medium"
HIGH = "high"

IMPACT_ORDER = [LOW, MEDIUM, HIGH]

# Labels that say the system holds nothing worth taking.  Everything else in
# the vocabulary raises impact; this one lowers it, and only when it is the
# only thing said.  A repository tagged both Public and PCI is a repository
# somebody has told us holds cardholder data.
NOT_SENSITIVE = {"public"}


def _rank(value, order: list) -> int:
    try:
        return order.index(value)
    except ValueError:
        return -1


def _step(value, order: list, by: int):
    """One grade up or down, clamped at both ends."""
    index = _rank(value, order)
    if index < 0:
        return value
    return order[max(0, min(len(order) - 1, index + by))]


def _labels(value) -> list:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _enum(value):
    return getattr(value, "value", value)


# --- what it would cost ------------------------------------------------------

# Where an engine said nothing, the grade it gave the rule is the only opinion
# on the table.  It is a weak one, which is why it is only ever a starting
# point that the facts below move.
FROM_SEVERITY = {
    Severity.CRITICAL: HIGH,
    Severity.HIGH: HIGH,
    Severity.MEDIUM: MEDIUM,
    Severity.LOW: LOW,
    Severity.INFO: LOW,
}


def impact_of(finding, context: dict = None) -> tuple:
    """-> (grade, why).  What it would cost if somebody did this.

    context carries what the repository is, as `repo_context.for_repository`
    returns it, or the two fields this actually reads: `sensitivity` and
    `visibility`.  Without it this falls back to the rule's own opinion, which
    is the answer this whole module exists to improve on, so the caller is
    expected to pass one.
    """
    context = context or {}

    # The engine's view of its own rule, where it has one.  semgrep publishes
    # this per rule and the scanner has always carried it through.
    started_from = "the rule"
    grade = (getattr(finding, "engine_impact", "") or "").strip().lower()
    if grade not in IMPACT_ORDER:
        grade = FROM_SEVERITY.get(getattr(finding, "severity", None), MEDIUM)
        started_from = "the grade"

    reasons = []

    # A CVSS score is a published statement about consequence, and it outranks
    # a guess made from a severity letter.
    score = getattr(finding, "cvss_score", None)
    if score is not None:
        if score >= 9.0 and grade != HIGH:
            grade, started_from = HIGH, "cvss"
            reasons.append(f"CVSS {score} describes it as severe on its own")
        elif score < 4.0 and grade == HIGH:
            grade, started_from = MEDIUM, "cvss"
            reasons.append(f"CVSS {score} does not describe a severe outcome")

    # What the system holds.  The one thing here nothing in a file can see.
    sensitivity = context.get("sensitivity")
    if isinstance(sensitivity, dict):        # repo_context tags the source on
        said_by = sensitivity.get("from", "")
        sensitivity = sensitivity.get("value", "")
    else:
        said_by = "somebody"
    labels = _labels(sensitivity)
    carrying = [one for one in labels if one.lower() not in NOT_SENSITIVE]

    if carrying:
        where = ("set on this repository" if said_by == "repository"
                 else "set on the account" if said_by == "connection"
                 else "recorded against it")
        if grade != HIGH:
            grade = _step(grade, IMPACT_ORDER, 1)
        reasons.append("this system holds " + ", ".join(carrying)
                       + f" ({where})")
    elif labels:
        # Everything said about it says there is nothing behind it.
        if grade != LOW:
            grade = _step(grade, IMPACT_ORDER, -1)
        reasons.append("everything recorded about this system says it holds "
                       "nothing sensitive")

    # A credential in a repository anybody can read is already out, whatever
    # else is true about it.  Only credentials: a missing escape in public
    # source is not worse for being readable.
    kind = str(_enum(getattr(finding, "kind", "")) or "")
    if "cred" in kind and (context.get("visibility") or "").lower() == "public":
        if grade != HIGH:
            grade = _step(grade, IMPACT_ORDER, 1)
        reasons.append("it is a credential in a repository anybody can read")

    if not reasons:
        reasons.append("nobody has said what this system holds, so this is "
                       + ("what the rule claims" if started_from == "the rule"
                          else "read from the grade alone"))

    return grade, "; ".join(reasons)


# --- whether anybody can -----------------------------------------------------

def likelihood_of(finding) -> tuple:
    """-> (word, why).  What the evidence already says about exploitation.

    Strongest evidence first, and it stops at the first thing that is actually
    known.  An observation outranks a score, a score outranks an inference, and
    an inference outranks the engine's opinion of its own rule.
    """
    # An observation.  Nothing below this is in the same class: somebody sent a
    # request and watched the thing happen.
    if (getattr(finding, "dast_verdict", "") or "") == "reproduced":
        return HAPPENING, ("a request was sent in the sandbox and the response "
                           "showed what the rule was worried about")

    if getattr(finding, "known_exploited", False):
        return HAPPENING, ("on the CISA list of vulnerabilities somebody is "
                           "exploiting in the wild")
    if getattr(finding, "verified", False):
        return HAPPENING, ("the provider was asked and said this credential "
                           "still works")

    epss = getattr(finding, "epss_score", None)
    if epss is not None:
        percent = round(epss * 100, 1)
        if epss >= 0.1:
            return LIKELY, f"EPSS puts exploitation in the next 30 days at {percent}%"
        if epss >= 0.01:
            return POSSIBLE, f"EPSS puts exploitation in the next 30 days at {percent}%"
        return UNLIKELY, f"EPSS puts exploitation in the next 30 days at {percent}%"

    # A fact about the tree, established with the checkout on disk.
    if getattr(finding, "reachability", "") == "unlikely":
        return UNLIKELY, (getattr(finding, "reachability_reason", "")
                          or "the application does not appear to reach it")

    # A fact about the file, established by the fidelity pass.
    triage = (getattr(finding, "triage", "") or "").lower()
    reason = (getattr(finding, "triage_reason", "") or "").strip()
    if triage == "not_applicable":
        return UNLIKELY, (reason or "this is not what its rule was looking for")
    if triage == "advisory":
        return UNLIKELY, (reason or "the rule reports a pattern rather than a "
                                    "problem")
    if triage == "third_party":
        return POSSIBLE, (reason or "it is in code somebody else wrote, which "
                                    "is reached by upgrading rather than editing")

    # Two engines matching the same line is the strongest thing either of them
    # says.  It is not an observation, so it does not reach the top of the list.
    if getattr(finding, "corroborated", False):
        return LIKELY, "more than one engine matched the same line"

    if (getattr(finding, "confidence", "") or "").lower() == "low":
        return UNLIKELY, "the engine had low confidence in the rule that found it"

    return POSSIBLE, ""


# --- the two together --------------------------------------------------------
#
# Written out rather than worked out.  Multiplying two ordinals produces a
# number that looks like arithmetic and is not: there is no sense in which
# high impact times unlikely is a quantity.  Twelve cells is small enough to
# read, argue with and change, which a formula is not.
#
# Read down for impact, across for likelihood.
MATRIX = {
    HIGH: {UNLIKELY: Severity.MEDIUM, POSSIBLE: Severity.HIGH,
           LIKELY: Severity.CRITICAL, HAPPENING: Severity.CRITICAL},
    MEDIUM: {UNLIKELY: Severity.LOW, POSSIBLE: Severity.MEDIUM,
             LIKELY: Severity.HIGH, HAPPENING: Severity.HIGH},
    LOW: {UNLIKELY: Severity.INFO, POSSIBLE: Severity.LOW,
          LIKELY: Severity.LOW, HAPPENING: Severity.MEDIUM},
}


# --- one number, and what it is allowed to mean ------------------------------
#
# A score exists for one job: putting four thousand findings in an order
# somebody can work down.  Twelve cells is a set of piles, not a queue, and the
# question "what do I do first" needs a total order.
#
# It is not a verdict and it must never be shown as one.  The rules that keep
# it honest:
#
#   The band is the judgement and the position inside it is arithmetic.  Which
#   band a finding lands in is decided by the two axes above, which are words
#   somebody can argue with.  Where it sits inside that band is decided only by
#   things that are genuinely numeric: how likely exploitation is as a
#   published probability, how severe an advisory says the outcome is, how many
#   people can reach the repository.  So 84 against 82 means "the same
#   judgement, slightly more exposure", which is true, and is all it ever
#   claims.
#
#   Nothing is scored twice.  The band already used the threshold; the position
#   uses the magnitude.  That is resolution, not a second opinion, which is why
#   EPSS may set the word "likely" and then place the finding inside the band
#   the word produced.  A signal that changed one of the axes may not also
#   shift the position on its own account.
#
#   Not knowing does not score low.  A finding with no advisory, no probe and
#   nothing said about the system sits in the middle of its band, never at the
#   bottom of it.  If absence of evidence scored near zero the bottom of the
#   list would fill with things nobody has looked at, sorted underneath things
#   somebody proved harmless, and the whole queue would read as safer than it
#   is.  That is the false sense of security this product exists to refuse,
#   written as a number.
#
#   It never feeds back.  Severity stays the decision a person makes.  This is
#   a view of it.

# Each band is the grade the two axes came to, so the number and the word can
# never contradict each other.  Widest at the top on purpose: the critical band
# is the one somebody actually works down, and it needs room to sort.
BANDS = {
    Severity.CRITICAL: (85, 100),
    Severity.HIGH: (65, 84),
    Severity.MEDIUM: (40, 64),
    Severity.LOW: (15, 39),
    Severity.INFO: (1, 14),
}

# What backs the number.
#
# Observed means somebody proved this finding, not this class of finding: a
# request was sent and the response showed it, or the provider was asked and
# the credential answered.  Everything else is inference, and the exploited
# list is inference too, which is worth being plain about.  CISA saying this
# CVE is being used in the wild is a strong statement about the vulnerability
# and no statement at all about whether this deployment can be reached.
#
# The marker is kept beside the score rather than folded into it.  Two findings
# can deserve the same place in the queue while one is proved and one is
# guessed, and the person working down the list is the one who needs to tell
# them apart.
OBSERVED = "observed"
INFERRED = "inferred"


def evidence_of(finding) -> tuple:
    """-> (observed or inferred, why).  What is actually behind the number."""
    verdict = (getattr(finding, "dast_verdict", "") or "")
    if verdict == "reproduced":
        return OBSERVED, ("a probe reproduced this one in the sandbox and the "
                          "response is on the finding")
    if getattr(finding, "verified", False):
        return OBSERVED, ("the provider was asked and said this credential "
                          "still works")
    if getattr(finding, "known_exploited", False):
        return INFERRED, ("on the CISA exploited list, which says this "
                          "vulnerability is being used somewhere and nothing "
                          "about whether this deployment can be reached")
    return INFERRED, "worked out from the rule and the advisory data"


def _position(finding, context: dict = None) -> tuple:
    """-> (0.0 to 1.0, the factors that produced it).

    Where in its band this sits.  Half way when nothing quantitative is known,
    which is the common case and must stay the common case.
    """
    context = context or {}
    factors = []

    epss = getattr(finding, "epss_score", None)
    if epss is not None:
        factors.append({"name": "EPSS", "weight": 2.0, "value": min(1.0, epss),
                        "detail": f"exploitation in the next 30 days at "
                                  f"{round(epss * 100, 1)}%"})

    score = getattr(finding, "cvss_score", None)
    if score is not None:
        factors.append({"name": "CVSS", "weight": 1.5,
                        "value": max(0.0, min(1.0, score / 10.0)),
                        "detail": f"the advisory scores the outcome {score}"})

    # How many people could reach it.  Not used by either axis, so it is a new
    # fact here rather than the same one counted again.
    people = context.get("people_total")
    if people:
        factors.append({"name": "Reach", "weight": 1.0,
                        "value": min(1.0, people / 50.0),
                        "detail": f"{people} people can reach this repository"})

    # A credential that is in the history as well as the working tree cannot be
    # fixed by editing a file, which is a fact about this finding and about
    # nothing else here.
    if (getattr(finding, "exposure", "") or "") == "current_and_history":
        factors.append({"name": "Exposure", "weight": 1.0, "value": 0.8,
                        "detail": "it is in the history as well as the current "
                                  "tree, so removing the line does not revoke it"})

    if not factors:
        return 0.5, []

    total = sum(f["weight"] for f in factors)
    at = sum(f["weight"] * f["value"] for f in factors) / total
    return at, factors


def score_of(finding, context: dict = None) -> dict:
    """-> the number, the band it sits in, and what is behind it.

    The band comes from the two axes.  The position inside it comes from the
    factors above.  Both halves are returned so a page can show the arithmetic:
    a score nobody can take apart is one people either obey or ignore.
    """
    impact, _ = impact_of(finding, context)
    likelihood, _ = likelihood_of(finding)
    band = MATRIX.get(impact, MATRIX[MEDIUM]).get(likelihood, Severity.MEDIUM)

    low, high = BANDS.get(band, BANDS[Severity.MEDIUM])
    at, factors = _position(finding, context)
    number = int(round(low + (high - low) * at))
    number = max(low, min(high, number))

    evidence, evidence_why = evidence_of(finding)

    # What each factor did to the number, in the number's own units, so the
    # page can show a column of shifts that adds up to what is displayed.
    span = high - low
    for factor in factors:
        factor["shifts"] = int(round((factor["value"] - 0.5) * span
                                     * factor["weight"]
                                     / sum(f["weight"] for f in factors)))

    return {
        "score": number,
        "band": band,
        "band_range": (low, high),
        "midpoint": int(round(low + span * 0.5)),
        "evidence": evidence,
        "evidence_reason": evidence_why,
        "factors": factors,
    }


def assess(finding, context: dict = None) -> dict:
    """Both axes and what they come to, with the reasoning attached.

    The grade this returns is what the two axes say.  It is not applied to
    anything: the finding keeps the severity it has until a person decides
    otherwise, and `recommendation.py` is where that gets offered.
    """
    impact, impact_why = impact_of(finding, context)
    likelihood, likelihood_why = likelihood_of(finding)
    grade = MATRIX.get(impact, MATRIX[MEDIUM]).get(likelihood, Severity.MEDIUM)

    current = getattr(finding, "severity", None)
    if current is None:
        direction = ""
    elif _severity_rank(grade) > _severity_rank(current):
        direction = "higher"
    elif _severity_rank(grade) < _severity_rank(current):
        direction = "lower"
    else:
        direction = "same"

    out = {
        "impact": impact,
        "impact_reason": impact_why,
        "likelihood": likelihood,
        "likelihood_reason": likelihood_why,
        "severity": grade,
        "direction": direction,
        "sentence": _sentence(impact, impact_why, likelihood, likelihood_why),
    }
    # The queue position, in the same answer, because everywhere that shows one
    # of these has to show the other.  A number on its own is the thing this
    # module was written to stop.
    out.update(score_of(finding, context))
    return out


SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH,
                  Severity.CRITICAL]


def _severity_rank(value) -> int:
    try:
        return SEVERITY_ORDER.index(value)
    except ValueError:
        return 2


def _sentence(impact: str, impact_why: str, likelihood: str,
              likelihood_why: str) -> str:
    """One line a person can read without opening anything else."""
    first = f"Impact reads {impact}"
    if impact_why:
        first += f" because {impact_why}"
    second = f"exploitation looks {likelihood}"
    if likelihood_why:
        second += f" because {likelihood_why}"
    return f"{first}, and {second}."


def context_for(session, finding) -> dict:
    """The two fields `impact_of` reads, for one finding's repository.

    A thin wrapper so a caller with a session and a finding does not have to
    know which columns matter.  Ingest builds its own context per repository
    instead, because it is looking at thousands of findings across a few
    hundred repositories and this would be a query for each one.
    """
    from app.core import repo_context

    about = repo_context.for_repository(session, finding.repository,
                                        with_people=False)
    if not about:
        return {}
    return {"sensitivity": about.get("sensitivity"),
            "visibility": about.get("visibility")}
