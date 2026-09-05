"""The sentences on the front of a generated report.

Written for people who do not work in security and will read the first page
and little else.  The house style for these is US English at about a tenth
grade reading level, no em dashes, and two spaces between sentences.  That is
narrower than the style used elsewhere in this codebase and it is deliberate:
the rest is written for engineers, and this is not.

Every number in here comes from the same query the page used.  Nothing is
softened and nothing is dramatized.  A summary that reads better than the data
supports is the fastest way to lose the reader who checks.
"""

from __future__ import annotations

TWO_SPACES = "  "


def _join(sentences: list) -> str:
    """Sentences, two spaces apart, the way this house writes a paragraph."""
    return TWO_SPACES.join(s.strip() for s in sentences if s and s.strip())


def _plural(count: int, one: str, many: str = "") -> str:
    return one if count == 1 else (many or one + "s")


def _mid_sentence(name: str) -> str:
    """A scope name as it should read inside a sentence.

    "All repositories" is a heading and reads as a title on the cover.  Dropped
    into the middle of a sentence with its capital letter still on it, it
    reads as though the sentence was assembled by a machine, which it was, and
    the reader should not be able to tell.

    A real name keeps its capitals, because an organization called Payments is
    not the same word as the middle of a sentence about payments.
    """
    if not name:
        return "this selection"
    if name[:1].isupper() and name.split(" ")[0] in ("All", "Every", "The"):
        return name[0].lower() + name[1:]
    return name


def _sentence_start(name: str) -> str:
    """A name at the start of a sentence, capitalized if it is a plain word.

    A repository is usually lower case and starting a sentence with it looks
    like a typo.  Names with a slash, a dot or an existing capital are left
    exactly as they are: they are identifiers, and changing one makes it wrong.
    """
    if not name:
        return "It"
    if any(ch in name for ch in "/.-_") or not name[:1].isalpha():
        return name
    if name[:1].isupper():
        return name
    return name[0].upper() + name[1:]


def headline(scope_label: str, points: list, basis: str) -> str:
    """One paragraph on what happened over the period."""
    unit = "items of work" if basis == "actions" else "advisories"
    if not points:
        return _join([
            "There is no recorded history for %s yet." % _mid_sentence(scope_label),
            "History is written after each scan, so this fills in once a scan "
            "has run.",
        ])

    first, last = points[0], points[-1]
    start, end = first["total"], last["total"]
    days = len(points)

    opening = ("This report covers %s over the last %d %s."
               % (_mid_sentence(scope_label), days, _plural(days, "day")))

    if start == end:
        movement = ("The number of open %s did not change over the period.  "
                    "It stands at %d." % (unit, end))
    elif end < start:
        movement = ("Open %s fell from %d to %d, a decrease of %d."
                    % (unit, start, end, start - end))
    else:
        movement = ("Open %s rose from %d to %d, an increase of %d."
                    % (unit, start, end, end - start))

    serious = last.get("critical", 0) + last.get("high", 0)
    if serious:
        weight = ("Of the %d open today, %d %s rated critical or high."
                  % (end, serious, _plural(serious, "is", "are")))
    else:
        weight = "Nothing open today is rated critical or high."

    return _join([opening, movement, weight])


def basis_note(basis: str) -> str:
    """What the number in the chart is counting, in plain words."""
    if basis == "actions":
        return _join([
            "The counts in this report are items of work rather than "
            "advisories.",
            "One software update often fixes several published security "
            "advisories at once.",
            "Counting the update once shows the size of the job rather than "
            "the size of the list.",
        ])
    return _join([
        "The counts in this report are individual published advisories.",
        "Several of these are often fixed by a single software update, so "
        "this number is larger than the amount of work involved.",
    ])


def history_note(points: list) -> str:
    """Whether any of this was worked out rather than recorded, and what that means."""
    reconstructed = [p for p in points if p.get("source") == "reconstructed"]
    if not reconstructed:
        return ""
    return _join([
        "Part of this history was calculated from the record of when each "
        "issue was first seen and when it was closed, because it predates the "
        "point where daily history began to be kept.",
        "The counts for those days are accurate.",
        "The split by severity for those days uses today's ratings, so an "
        "issue that was re-rated recently appears at its current rating for "
        "the whole period.",
        "The chart marks where the calculated history ends.",
    ])


def concentration(rows: list, axis: str) -> str:
    """Whether the problem is spread out or sitting in a few places."""
    if not rows:
        return ""
    total = sum(row.get("total", 0) for row in rows)
    if not total:
        return ""
    ranked = sorted(rows, key=lambda r: r.get("total", 0), reverse=True)
    top = ranked[0]
    share = round(100.0 * top.get("total", 0) / total)

    if len(ranked) == 1:
        return ("All of the open work in this report belongs to %s."
                % top["name"])


    if share >= 50:
        return _join([
            "The work is not spread evenly.",
            "%s holds %d percent of it, which is %d of the %d open items."
            % (_sentence_start(top["name"]), share,
               top.get("total", 0), total),
            "Addressing that one %s would remove the largest share of the "
            "total." % axis,
        ])

    top_three = ranked[:3]
    three_total = sum(r.get("total", 0) for r in top_three)
    three_share = round(100.0 * three_total / total)
    return _join([
        "The work is spread across %d %s." % (len(ranked), _plural(len(ranked), axis)),
        "The three largest hold %d percent of it between them: %s."
        % (three_share, ", ".join(r["name"] for r in top_three)),
    ])


def certified_note(counts: dict) -> str:
    """What the review badges say, and what amber means."""
    active = counts.get("active", 0)
    stale = counts.get("stale", 0)
    if not (active or stale):
        return ""
    parts = []
    if active:
        parts.append(
            "%d %s been reviewed by the security team and signed off as safe."
            % (active, _plural(active, "branch has", "branches have")))
    if stale:
        parts.append(
            "%d previously signed off %s changed since that review and %s to "
            "be looked at again."
            % (stale, _plural(stale, "branch has", "branches have"),
               _plural(stale, "needs", "need")))
    return _join(parts)


def what_to_do(rows: list, axis: str, points: list) -> list:
    """A short, ordered list of what would help most.  Never invented.

    Only says things the numbers already show.  A recommendation that does not
    follow from the data in the report is the part a reader checks first and
    the part that costs the rest its credibility.
    """
    out = []
    if not points:
        return out
    last = points[-1]

    serious = last.get("critical", 0) + last.get("high", 0)
    if serious:
        out.append(
            "Start with the %d critical and high rated %s.  These are the "
            "items most likely to matter if someone tries to use them."
            % (serious, _plural(serious, "item", "items")))

    if rows:
        ranked = sorted(rows, key=lambda r: r.get("total", 0), reverse=True)
        top = ranked[0]
        if top.get("total", 0):
            out.append(
                "The largest single %s is %s, with %d open %s.  Work there "
                "removes the most at once."
                % (axis, top["name"], top["total"],
                   _plural(top["total"], "item", "items")))

    if len(points) > 1:
        change = points[-1]["total"] - points[0]["total"]
        if change > 0:
            out.append(
                "The total went up over this period.  It is worth checking "
                "whether new work is arriving faster than it is being closed.")
        elif change < 0:
            out.append(
                "The total came down over this period.  Keeping the same pace "
                "would continue that.")
    return out


# --- the assessment, rather than the chart ----------------------------------

def assessment(data: dict, scope_label: str) -> str:
    """The opening paragraph, built from what was actually found.

    Leads with whatever is provably live, because that is the only part of a
    security report that is not a queue.  Falls back to the shape of the work
    when nothing is proven, and says plainly that nothing was proven rather
    than implying an all clear.
    """
    cover = data["coverage"]
    sev = data["severity"]
    urgent_now = data["urgent"]

    repos = cover["repositories"]
    opening = ("This assessment covers %s: %d %s across %d %s, with %d open "
               "findings."
               % (_mid_sentence(scope_label), repos,
                  _plural(repos, "repository", "repositories"),
                  cover["branches"], _plural(cover["branches"], "branch", "branches"),
                  cover["findings"]))

    serious = sev["critical"] + sev["high"]
    weight = ("%d of them %s rated critical or high."
              % (serious, _plural(serious, "is", "are"))
              if serious else
              "None of them is rated critical or high.")

    live = urgent_now["live_credentials"]["count"]
    bad = urgent_now["malicious_packages"]["count"]
    hot = urgent_now["known_exploited"]["count"]

    if live or bad:
        pieces = []
        if live:
            pieces.append("%d credential%s confirmed to still work"
                          % (live, " was" if live == 1 else "s were"))
        if bad:
            pieces.append("%d package%s identified as malicious rather than "
                          "merely vulnerable"
                          % (bad, " was" if bad == 1 else "s were"))
        alarm = ("Two findings need attention before the rest: "
                 if len(pieces) > 1 else "One finding needs attention before "
                 "the rest: ") + " and ".join(pieces) + "."
        alarm += ("  These are not estimates.  Someone or something confirmed "
                  "each one, and they are listed by name later in this "
                  "report.")
    elif hot:
        alarm = ("%d of these %s a vulnerability that is being exploited "
                 "somewhere in the world today, according to the public "
                 "catalog of known exploited vulnerabilities.  That says "
                 "nothing about whether this system can be reached, and it "
                 "does move them to the front of the queue."
                 % (hot, "is" if hot == 1 else "are"))
    else:
        alarm = ("Nothing in this set has been confirmed as live or as "
                 "actively exploited.  That is a good sign and it is not "
                 "proof of safety: it means no confirmation was found, not "
                 "that none exists.")

    return _join([opening, weight, alarm])


def what_matters(data: dict) -> list:
    """An ordered list of what to do, each item tied to its own number.

    Ordered by what is known rather than by what is rated.  Something proven
    to work comes before something rated critical, because a rating is an
    opinion about a rule and a confirmation is a fact about this system.
    """
    out = []
    urgent_now = data["urgent"]
    sev = data["severity"]

    live = urgent_now["live_credentials"]
    if live["count"]:
        where = sorted({row.repository for row in live["rows"] if row.repository})
        out.append({
            "priority": "Immediately",
            "title": "Rotate the credentials confirmed to still work",
            "detail": ("%d credential%s committed to source control and "
                       "confirmed still valid.  Anyone who can read the "
                       "repository, or its history, has them.  Rotate first "
                       "and remove them from the code second: removing a "
                       "credential from a file does not remove it from the "
                       "history.%s"
                       % (live["count"], " was" if live["count"] == 1 else "s were",
                          ("  Affected: " + ", ".join(where[:6]) + ".") if where else "")),
        })

    bad = urgent_now["malicious_packages"]
    if bad["count"]:
        names = sorted({row.package_name for row in bad["rows"] if row.package_name})
        out.append({
            "priority": "Immediately",
            "title": "Remove the packages identified as malicious",
            "detail": ("%s hostile in itself rather than merely flawed.  "
                       "Upgrading does not help.  Remove the dependency and "
                       "check what ran during installation.%s"
                       % ("One dependency is" if bad["count"] == 1
                          else "%d dependencies are" % bad["count"],
                          ("  Packages: " + ", ".join(names[:6]) + ".") if names else "")),
        })

    hot = urgent_now["known_exploited"]
    if hot["count"]:
        out.append({
            "priority": "This week",
            "title": "Patch the vulnerabilities known to be exploited",
            "detail": ("%d finding%s a vulnerability on the public catalog of "
                       "known exploited vulnerabilities.  Attacks using these "
                       "exist and are in use, so they are worth patching ahead "
                       "of higher rated issues that nobody has been seen "
                       "using."
                       % (hot["count"], " matches" if hot["count"] == 1
                          else "s match")),
        })

    actions = data["actions"]
    if actions:
        biggest = max(actions, key=lambda a: a["advisories"])
        if biggest["advisories"] > 1:
            out.append({
                "priority": "This month",
                "title": "Take the upgrades that clear the most at once",
                "detail": ("Updating %s from %s to %s in %s closes %d "
                           "advisories on its own.  The full list of the "
                           "largest updates is later in this report, and most "
                           "of the dependency work in this assessment is a "
                           "small number of updates repeated across "
                           "repositories."
                           % (biggest["package"], biggest["version"] or "its "
                              "current version", biggest["fixed_in"] or "the "
                              "fixed version", biggest["repository"],
                              biggest["advisories"])),
            })

    creds = next((k for k in data["kinds"] if k["kind"] == "credential"), None)
    if creds and creds["total"] and not live["count"]:
        out.append({
            "priority": "This month",
            "title": "Review the credentials found in source control",
            "detail": ("%d credential%s found in the code or its history.  "
                       "None was confirmed as still working, which is not the "
                       "same as none working: many providers give no way to "
                       "ask.  Treat them as exposed and rotate them."
                       % (creds["total"], " was" if creds["total"] == 1
                          else "s were")),
        })

    if sev["critical"] + sev["high"] and not out:
        out.append({
            "priority": "This month",
            "title": "Work through the critical and high rated findings",
            "detail": ("%d findings are rated critical or high.  Nothing in "
                       "this set has been confirmed as live, so this is "
                       "ordinary remediation work rather than an incident."
                       % (sev["critical"] + sev["high"])),
        })

    return out


def hotspot_note(rows: list, axis: str) -> str:
    """Whether the problem is concentrated, in one sentence with its numbers."""
    if not rows:
        return ""
    total = sum(row["total"] for row in rows)
    if not total:
        return ""
    top = rows[0]
    share = round(100.0 * top["total"] / total)
    serious = top["critical"] + top["high"]
    return _join([
        "%s carries the most, with %d open findings of which %d %s rated "
        "critical or high."
        % (_sentence_start(top["name"]), top["total"], serious,
           _plural(serious, "is", "are")),
        "That is %d percent of everything in this report." % share
        if share >= 20 else
        "No single %s dominates the total." % axis,
    ])
