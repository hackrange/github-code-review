"""What data an application likely holds, and what a breach of it would mean.

The dynamic scan sees a web site from the outside.  The code behind it, and the
tags people already put on those repositories, say what the application handles:
customer records, personal data, payment cards, health data, financial reporting
data under SOX, controlled unclassified information.  That classification is the
other half of risk.  A weakness on an app that holds SOX or card data is a
bigger breach than the same weakness on a brochure site, and the report should
say so, in the real terms a public company cares about: fines, breach
notification, reputational loss.

This module derives that profile from the repositories linked to a DAST asset,
reusing the sensitivity labels, application name and repository name that the
tagging already maintains, and turns it into an impact weight and a plain
consequence.  It is deterministic: a keyword read of tags that already exist, so
the report can state the consequence as fact, not a guess dressed up as one.

Even a mailing address counts: it is personal data, and in a federal context it
can be controlled unclassified information.  So the classes run from the plainly
regulated down to ordinary customer data, and ordinary customer data still
matters.
"""

from __future__ import annotations

import re

# Each class: a label, how much it raises the impact of a breach (0 to 2), and
# the plain consequence a reader should understand.  Ordered most serious first,
# which is the order a dominant class is picked in.
CLASSES = {
    "sox": {
        "label": "SOX financial reporting data",
        "bump": 2,
        "consequence": "For a publicly traded company a breach here can mean "
                       "regulatory fines and a failure of financial reporting "
                       "controls.",
    },
    "pci": {
        "label": "payment card data",
        "bump": 2,
        "consequence": "Exposure can bring payment card brand penalties and the "
                       "loss of the ability to process cards.",
    },
    "phi": {
        "label": "health information",
        "bump": 2,
        "consequence": "Exposure can bring HIPAA penalties and mandatory breach "
                       "notification.",
    },
    "cui": {
        "label": "controlled unclassified information",
        "bump": 2,
        "consequence": "Exposure can breach federal handling rules for controlled "
                       "unclassified information; even a mailing address can be CUI.",
    },
    "spii": {
        "label": "sensitive personal data",
        "bump": 2,
        "consequence": "Exposure of data such as Social Security or financial "
                       "numbers triggers breach notification laws and identity "
                       "theft risk.",
    },
    "pii": {
        "label": "personal data",
        "bump": 1,
        "consequence": "Exposure triggers privacy law obligations and direct harm "
                       "to the people whose data it is.",
    },
    "customer": {
        "label": "customer data",
        "bump": 1,
        "consequence": "A breach exposes customers and brings reputational loss.",
    },
    "credentials": {
        "label": "credentials or secrets",
        "bump": 1,
        "consequence": "Exposed credentials let an attacker reach whatever they "
                       "unlock.",
    },
}

ORDER = ["sox", "pci", "phi", "cui", "spii", "pii", "customer", "credentials"]

# Keywords that place a tag, application name or repository name into a class.
# Read case insensitively over text people already wrote, so it is a floor, not
# a guess: a match means the word is there.
_KEYWORDS = {
    "sox": r"\bsox\b|sarbanes|financial report|general ledger|\bg/?l\b|\berp\b|"
           r"e-?business suite|\bebs\b|revenue recognition|accounts (payable|receivable)|"
           r"\bledger\b|audit trail",
    "pci": r"\bpci\b|cardholder|credit.?card|payment card|\bpan\b|card number|"
           r"card data",
    "phi": r"\bphi\b|hipaa|patient|health record|\behr\b|\bemr\b|medical record",
    "cui": r"\bcui\b|controlled unclassified|\bitar\b|export control|\bfouo\b|dfars|"
           r"\bcmmc\b",
    "spii": r"\bspii\b|social security|\bssn\b|passport|driver.?s?.? ?licen|biometric|"
            r"bank account|routing number|\btax id\b",
    "pii": r"\bpii\b|personal data|personally identifiable|mailing address|"
           r"\baddress(es)?\b|date of birth|\bdob\b|phone number|email address",
    "customer": r"customer|client\b|subscriber|account holder|\bmember\b|consumer|"
                r"\bcrm\b",
    "credentials": r"credential|password|\bsecret(s)?\b|api.?key|private key|token",
}
_COMPILED = {cls: re.compile(pat, re.I) for cls, pat in _KEYWORDS.items()}


def classify(text: str) -> set:
    """The data classes a blob of text points to.  A keyword read, nothing more."""
    t = str(text or "")
    return {cls for cls, pat in _COMPILED.items() if pat.search(t)}


def rank(classes) -> list:
    """The classes present, most serious first."""
    present = set(classes or [])
    return [c for c in ORDER if c in present]


def impact_bump(classes) -> tuple:
    """How much these classes raise the impact of a breach, and why.

    The bump is the single most serious class, not a sum, so a known class lifts
    the impact once; it does not stack an app up to the ceiling on its own."""
    ranked = rank(classes)
    if not ranked:
        return 0, ""
    bump = max(CLASSES[c]["bump"] for c in ranked)
    labels = ", ".join(CLASSES[c]["label"] for c in ranked)
    return bump, f"the application holds {labels}"


def consequence(classes) -> str:
    """One plain statement of what a breach of this data would mean."""
    ranked = rank(classes)
    if not ranked:
        return ""
    out = CLASSES[ranked[0]]["consequence"]
    extra = [CLASSES[c]["label"] for c in ranked[1:]]
    if extra:
        out += " The application also appears to hold " + ", ".join(extra) + "."
    return out


def labels(classes) -> list:
    """Human labels for the classes, most serious first."""
    return [CLASSES[c]["label"] for c in rank(classes)]


def _linked_repos(db, asset):
    from app.core.models import ExternalAssetRepo, Repository

    return (db.query(Repository)
            .join(ExternalAssetRepo, ExternalAssetRepo.repository_id == Repository.id)
            .filter(ExternalAssetRepo.asset_id == asset.id).all())


def profile_for_asset(db, asset) -> dict:
    """Derive the data profile of a DAST asset from the code linked to it.

    -> {classes: [...], labels: [...], consequence: "...", bump: int,
        basis: "...", from_repos: [...]}.  Empty classes when the linked
    repositories carry nothing that places them in a class, so nothing is
    invented: a profile only appears when a tag, an application name or a
    repository name actually says so.
    """
    classes, from_repos = set(), []
    for r in _linked_repos(db, asset):
        text = " ".join([r.sensitivity or "", r.application_name or "", r.name or ""])
        found = classify(text)
        if found:
            classes |= found
            from_repos.append(r.full_name)
    ranked = rank(classes)
    bump, why = impact_bump(ranked)
    basis = ""
    if ranked:
        basis = ("From the code behind this site: " + ", ".join(labels(ranked))
                 + (f" (seen in {', '.join(from_repos[:6])}"
                    + (" and more" if len(from_repos) > 6 else "") + ")"
                    if from_repos else "") + ".")
    return {"classes": ranked, "labels": labels(ranked),
            "consequence": consequence(ranked), "bump": bump,
            "basis": basis, "from_repos": from_repos}
