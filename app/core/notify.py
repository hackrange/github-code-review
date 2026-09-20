"""Telling somebody, without waiting for them to log in.

Scans run overnight and the results sit in a web page.  The most urgent thing
this tool produces is a credential the issuing provider has confirmed still
works, and the response time to it is however long it takes somebody to visit
the site.

Four ways out, which between them cover nearly every installation: a Slack
incoming webhook, a Teams incoming webhook, an SMTP sender, and a plain
outbound webhook for everyone else.

Three rules decide what actually gets sent, and they matter more than the
transports:

  New findings only.  Every finding carries `first_found_at`, so this is
  already answerable.  A nightly message about the standing backlog trains
  people to filter the sender, which is strictly worse than sending nothing.

  Routed by severity, not by volume.  A verified credential and a critical on
  the KEV list go out on their own because somebody should stop what they are
  doing.  Everything else is one digest at the end of the scan.

  Never the secret.  A message leaves this system and lands somewhere with a
  different set of readers than the web page has.  What goes in it is the
  redacted preview and a link, the same as the report files.

Mail carries the whole of what is known about each finding, because mail is
where somebody reads one away from the page: what kind of thing it is, the
branch and the package, whether the application can reach it, where it was
declared, when it was last committed and who by, and three links, to the
finding here, to the file on the host, and to the advisory itself.  Chat stays
one line per finding on purpose, since a webhook posting forty lines into a
channel is read by nobody.

Worth being explicit, because it looks like it cuts across the read only
promise and does not: that promise is about the repositories being scanned.
Every provider call is a GET and nothing here can change a customer's code.
Sending a message outward is not a write to a repository.
"""

from __future__ import annotations

import json
import logging
import re
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from html import escape

from app.core import settings_store as store

log = logging.getLogger("gcr.notify")

# How long any one send gets.  A webhook nobody is listening to must not hold a
# scan open.
TIMEOUT = 15

# What counts as worth interrupting somebody for.
URGENT_REASONS = (
    ("verified", "a credential the provider confirmed still works"),
    ("known_exploited", "on the CISA list of vulnerabilities being exploited"),
    ("malicious", "a package that is itself the attack"),
)

# What each kind is, in words somebody outside security reads the same way.
# The stored value is one word and "code" on its own tells a reader nothing
# about whether they have to rotate something tonight.
KIND_WORDS = {
    "credential": "a credential committed to the code",
    "code": "a weakness in the code",
    "dependency": "a vulnerable package",
    "misconfiguration": "a misconfigured setting",
}

# Said at the top of every message, because the single largest cause of a
# report nobody can work through is repositories nobody works on.  The tool
# cannot archive anything: every call it makes is a GET, so this is the one
# part of the answer that has to be asked for rather than done.
DISCLAIMER = (
    "Repositories no longer in use must be archived or purged.  A repository "
    "nobody maintains is still scanned, still counted and still somebody's to "
    "answer for, and the work in it is work nobody intends to do.  Archiving "
    "it on the host makes it read only and takes its findings out of the "
    "outstanding count, and purging it takes them out altogether.  This tool "
    "only ever reads, so neither can be done from here."
)

# How many findings a message describes in full before it stops and points at
# the page.  A scan that turns up four hundred new findings would otherwise
# send a message no mail client will render and nobody would read.
DETAIL_CAP = 25

# How wide the label column is in a plain text message.
_LABEL = 13

# The spreadsheet, for the scans the message itself cannot hold.
#
# The body describes DETAIL_CAP findings and then points at the page, which
# leaves the rest of a four hundred finding scan unsaid.  The attachment is
# those findings in the same columns as vulnerabilities.csv, which is the one
# format somebody can sort, filter and split across a team in, and it reaches
# the people who have no account here: an application owner, a ticket queue.
#
# It is the scan's new findings and never the standing backlog.  A nightly
# export of everything is exactly the message people learn to filter, which is
# the reason the digest is new findings only in the first place.
ATTACH_ROWS = 5000
# What a mail gateway will carry without quarantining it.  Past this the rows
# are dropped rather than the attachment, so what arrives is still the worst of
# what was found rather than nothing at all.
ATTACH_BYTES = 5 * 1024 * 1024


def _enum(value):
    return getattr(value, "value", value) or ""


def enabled(session) -> bool:
    return bool(store.get(session, "notify.enabled"))


def _targets(session) -> dict:
    return {
        "slack": (store.get(session, "notify.slack_webhook") or "").strip(),
        "teams": (store.get(session, "notify.teams_webhook") or "").strip(),
        "webhook": (store.get(session, "notify.webhook_url") or "").strip(),
        "email": (store.get(session, "notify.email_to") or "").strip(),
    }


def _min_rank(session) -> int:
    order = ["info", "low", "medium", "high", "critical"]
    wanted = (store.get(session, "notify.min_severity") or "high").lower()
    return order.index(wanted) if wanted in order else 3


def _rank(severity) -> int:
    order = ["info", "low", "medium", "high", "critical"]
    value = _enum(severity).lower()
    return order.index(value) if value in order else 0


def is_urgent(finding) -> str:
    """-> why this one should not wait for the digest, or "" if it can."""
    for attribute, why in URGENT_REASONS:
        if getattr(finding, attribute, False):
            return why
    return ""


def base_url(session) -> str:
    return (store.get(session, "notify.base_url") or "").strip().rstrip("/")


def finding_link(session, finding) -> str:
    """This finding on this installation, which is where the work happens."""
    root = base_url(session)
    return f"{root}/findings/{finding.id}" if root else ""


# Kept under the old name as well, because this is what the message builders
# below have always called.
_link = finding_link


def _http(value) -> str:
    """A link a reader will click, or nothing.

    Scheme only.  These come out of advisory data and out of the host rather
    than out of a person, and it is one line to make that structural: a
    javascript: href in a mail client is a different class of problem than a
    link to the wrong page.
    """
    text = str(value or "").strip()
    return text if text.lower().startswith(("https://", "http://")) else ""


# Where each host puts a file in its own URLs, and what it puts in front of a
# line number.  Gitea and Forgejo have no /blob/ route at all, so the GitHub
# shape is a 404 there rather than a redirect to the right page.  A host that
# is not named here gets the GitHub shape, which is what every host got before
# this existed.
_BLOB_PATH = {"gitlab": "-/blob", "bitbucket": "src",
              "gitea": "src/branch", "forgejo": "src/branch"}
_LINE_ANCHOR = {"bitbucket": "#lines-"}


def provider_of(session, finding) -> str:
    """Which host a finding came from, by way of the connection that found it.

    Empty for a finding that predates connections, which is a GitHub one:
    there was nothing else then.
    """
    name = (getattr(finding, "connection", "") or "").strip()
    if not name:
        return ""
    try:
        from app.core import connections as connection_store
        row = connection_store.by_name(session, name)
    except Exception:            # noqa: BLE001
        return ""
    return (getattr(row, "provider", "") or "") if row is not None else ""


def code_link(finding, provider: str = "") -> str:
    """The file on the host, on the branch the scan read.

    A code or credential finding already carries one: the scanner writes the
    permalink it built from the commit it was reading.  A dependency finding's
    url is the advisory instead, so that one is built here out of the
    repository, the branch and whichever file asked for the package.  Without
    this a vulnerable package offered a link to somebody else's security
    tracker and nothing at all to the code it is about.
    """
    kind = _enum(finding.kind)
    direct = _http(finding.url)
    if kind != "dependency" and direct:
        return direct

    # The repository row, for its address and its default branch.  Read
    # defensively: this is a lazy load, and a finding that has been handed here
    # from outside its own session would raise rather than answer.  A message
    # with one link missing beats no message.
    try:
        repo = getattr(finding, "repo", None)
        home = _http(getattr(repo, "html_url", "")).rstrip("/")
    except Exception:            # noqa: BLE001
        return ""
    if not home:
        return ""

    where = ((finding.file_path or "").strip()
             or (finding.manifest_path or "").strip()
             or (finding.dockerfile or "").strip())
    if not where:
        # Nothing to open, so the repository itself.  Most of a link is better
        # than none for a package that came out of a base image.
        return home

    branch = ((finding.branch or "").strip()
              or (getattr(repo, "default_branch", "") or "").strip() or "HEAD")
    blob = _BLOB_PATH.get((provider or "").lower(), "blob")
    mark = _LINE_ANCHOR.get((provider or "").lower(), "#L")
    anchor = f"{mark}{finding.line}" if finding.line else ""
    return (f"{home}/{blob}/{urllib.parse.quote(branch, safe='/')}"
            f"/{urllib.parse.quote(where.lstrip('/'), safe='/')}{anchor}")


def advisory_link(finding) -> str:
    """Where the advisory itself is.

    The engines hand over the source they matched against, which is the
    national database for a CVE and the distribution's own tracker for a
    package a distribution patches, so that is used wherever it came through.
    Otherwise the id says where it lives: CVE at NVD, GHSA at GitHub, and
    everything else at OSV, which aggregates the rest.
    """
    if _enum(finding.kind) == "dependency":
        direct = _http(finding.url)
        if direct:
            return direct

    ident = (finding.vulnerability_id or "").strip()
    if not ident or not re.fullmatch(r"[A-Za-z0-9._:-]{3,64}", ident):
        return ""
    upper = ident.upper()
    if upper.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{upper}"
    if upper.startswith("GHSA-"):
        return f"https://github.com/advisories/{ident}"
    return f"https://osv.dev/vulnerability/{ident}"


def headline(finding) -> str:
    """What this finding is called, in two or three words."""
    named = (finding.rule or finding.vulnerability_id or "").strip()
    if not named:
        named = (finding.title or "a finding").strip().split(". ")[0][:80]
    return named


def kind_word(finding) -> str:
    """credential, code, dependency or misconfiguration, said in words."""
    return KIND_WORDS.get(_enum(finding.kind), "a finding")


def package_of(finding) -> str:
    """The package, its version, and the version that fixes it."""
    name = (finding.package_name or "").strip()
    if not name:
        return ""
    text = name
    if finding.package_version:
        text += f" {finding.package_version}"
    if finding.ecosystem:
        text += f" ({finding.ecosystem})"
    # The source package, where a distribution ships one as many binaries.  One
    # flaw in util-linux arrives eight times and one upgrade answers all eight,
    # which nobody can tell from the binary name alone.
    source = (finding.package_source or "").strip()
    if source and source != name:
        text += f", built from {source}"
    if finding.fixed_in:
        text += f", fixed in {finding.fixed_in}"
    else:
        text += ", no fixed version published yet"
    return text


def found_in(finding) -> str:
    """The clue about where this came from.

    A credential and a code weakness have a file and a line.  A vulnerable
    package has neither, and the first thing anybody asks of one is which file
    asked for it, so the manifest the engine matched is said here.  A package
    that came out of a container image names the image and the Dockerfile that
    pulls it, because that is where the answer is.
    """
    at = (finding.file_path or "").strip()
    if at:
        return f"{at}:{finding.line}" if finding.line else at
    declared = (finding.manifest_path or "").strip()
    if declared:
        return declared
    image = (finding.image_ref or "").strip()
    if image:
        asked = (finding.dockerfile or "").strip()
        text = f"the image {image}"
        if asked:
            text += f", pulled by {asked}"
        if finding.base_upgraded:
            # Not a fix and not a suppression.  The image was read as the
            # registry publishes it, and a build that upgrades packages after
            # pulling it ships something other than what was read.
            text += ", which the build upgrades after pulling"
        return text
    asked = (finding.dockerfile or "").strip()
    return asked or "not recorded"


def reachable(finding) -> str:
    """Whether the application can get to it, and why that was concluded.

    The verdict on its own asks to be trusted.  The reason is what lets
    somebody disagree with it, which is the whole point of recording one.
    """
    verdict = (finding.reachability or "").strip().lower()
    if not verdict:
        return ""
    said = {"reachable": "yes, the code imports it",
            "unlikely": "probably not, nothing imports it",
            "unknown": "could not tell"}.get(verdict, verdict)
    extra = []
    direct = (finding.dependency_direct or "").strip()
    if direct and direct != "unknown":
        extra.append(f"{direct} dependency")
    scope = (finding.dependency_scope or "").strip()
    if scope and scope != "unknown":
        extra.append(scope)
    if extra:
        said += f" ({', '.join(extra)})"
    reason = (finding.reachability_reason or "").strip()
    if reason:
        said += f".  {_upper_first(reason)}"
    return said


def _upper_first(text: str) -> str:
    """A fragment from an engine, started like a sentence.

    The engines write these to sit under a heading on a page, so they begin in
    lower case, and in the middle of a sentence that reads as a typo.  A first
    word that is a path or a file name is left exactly as it is, because
    Services/web/index.js is not a file anybody has.
    """
    first = text.split(" ", 1)[0]
    if any(mark in first for mark in ("/", ".", "@", "_")):
        return text
    return text[0].upper() + text[1:]


def committed(finding) -> str:
    """When the code carrying this was last committed, and who by.

    The blame pass answers this for a credential and for a code weakness.  It
    cannot answer it for a vulnerable package, which has no line: there the
    scanner dates the file that declares it instead, and this says so rather
    than letting it read as blame.  A misconfiguration has nothing to date at
    all, and saying when this tool first saw one beats leaving a reader to
    assume it was written yesterday.
    """
    when = _date(finding.committed_at)
    who = (finding.author_name or finding.author_login
           or finding.author_email or "").strip()
    if when:
        text = when
        if who:
            text += f", by {who}"
            if finding.author_login and finding.author_login != who:
                text += f" ({finding.author_login})"
        if finding.commit_sha:
            text += f", commit {finding.commit_sha[:12]}"
        if _enum(finding.kind) == "dependency":
            # Say what the date is, because it is not the same claim the other
            # kinds make.  A package has no line to blame, so this is the last
            # change to the file that asks for it, which is a ceiling.
            text += (".  That is when the file declaring it last changed, so it "
                     "was being asked for on or before then")
        return text
    if who:
        return f"by {who}, on a date the scan did not record"
    first = _date(finding.first_found_at)
    # An upper bound rather than a date, and said as one.  A number here that
    # looks like a commit date and is actually the day this tool started
    # looking is worse than no number at all.  The blame pass reads a line of
    # code, and a package version has no line, so the most that can honestly be
    # said is that it was already in the code by the time this saw it.
    return (f"not dated for {kind_word(finding)}.  It was already there on "
            f"{first}, when this first saw it" if first else "not recorded")


def describe(finding) -> str:
    """One line, and never the secret itself.

    What chat gets.  A Slack or Teams channel with twelve labeled rows per
    finding in it is a channel people mute, so everything that matters most
    goes on one line and the link carries the rest.
    """
    line = f"{_enum(finding.severity).upper()}  {headline(finding)}"
    line += f"  ({kind_word(finding)})"
    where = (finding.repository or "").strip()
    if where:
        line += f" in {where}"
        if finding.branch:
            line += f" on {finding.branch}"
    package = (finding.package_name or "").strip()
    if package:
        line += f", {package}"
        if finding.package_version:
            line += f" {finding.package_version}"
        if finding.fixed_in:
            line += f", fixed in {finding.fixed_in}"
    at = (finding.file_path or "").strip()
    declared = (finding.manifest_path or "").strip()
    image = (finding.image_ref or "").strip()
    if at:
        line += f" at {at}"
        if finding.line:
            line += f":{finding.line}"
    elif declared:
        line += f", declared in {declared}"
    elif image:
        line += f", from the image {image}"
    verdict = (finding.reachability or "").strip().lower()
    if verdict == "reachable":
        line += ", and the code imports it"
    elif verdict == "unlikely":
        line += ", nothing imports it"
    if finding.secret_preview:
        # The mask, which is what the report files carry.  The value itself
        # never leaves the scan and must not start here.
        line += f"  [{finding.secret_preview}]"
    return line


def _date(value, fmt: str = "%Y-%m-%d") -> str:
    """A stored timestamp in the zone the Settings page names.

    Everything is written as UTC and handed back without a zone attached, so a
    naive value is UTC rather than anything to do with this machine's clock.
    Mail lands in front of a person, and a date four hours out is a date that
    gets argued about.
    """
    if not isinstance(value, datetime):
        return ""
    try:
        from zoneinfo import ZoneInfo

        from app.core import live
        zone = ZoneInfo(live.timezone_name())
    except Exception:            # noqa: BLE001
        zone = timezone.utc
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(zone).strftime(fmt)


def details(session, finding) -> list:
    """Every labeled row a message makes about one finding.

    -> [(label, text, link)], in the order somebody reads them.  A link is
    empty on a row that is not one, so the text and the HTML builders both walk
    the same list and neither decides what a message knows.
    """
    rows = [("Kind", kind_word(finding), "")]

    severity = _enum(finding.severity).upper()
    grade = severity
    if finding.risk_score:
        grade += f", risk {finding.risk_score} of 100"
    if finding.cvss_score:
        grade += f", CVSS {finding.cvss_score}"
    rows.append(("Severity", grade, ""))

    where = (finding.repository or "").strip()
    if finding.organization and not where.startswith(f"{finding.organization}/"):
        where = f"{finding.organization}/{where}" if where else finding.organization
    rows.append(("Repository", where, ""))

    branch = (finding.branch or "").strip()
    spread = _branches(finding)
    if branch or spread:
        text = branch or spread[0]
        if len(spread) > 1:
            # The same finding on several branches is one finding.  Fixing it on
            # the branch named here leaves it on the others.
            text += f", and {len(spread) - 1} other branch(es)"
        rows.append(("Branch", text, ""))

    package = package_of(finding)
    if package:
        rows.append(("Package", package, ""))

    rows.append(("Found in", found_in(finding), ""))

    if finding.vulnerability_id:
        rows.append(("Advisory", finding.vulnerability_id, advisory_link(finding)))
    if finding.known_exploited:
        rows.append(("Exploited", "on the CISA list of vulnerabilities being "
                                  "exploited in the wild", ""))
    if finding.malicious:
        rows.append(("Malicious", (finding.malicious_reason
                                   or "the package is itself the attack"), ""))

    reach = reachable(finding)
    if reach:
        rows.append(("Reachable", reach, ""))

    if finding.secret_preview:
        rows.append(("Value", finding.secret_preview, ""))
    if finding.verified:
        rows.append(("Verified", "the provider confirmed this credential still "
                                 "works", ""))

    rows.append(("Committed", committed(finding), ""))
    first = _date(finding.first_found_at, "%Y-%m-%d %H:%M")
    if first:
        rows.append(("First seen", first, ""))

    link = finding_link(session, finding)
    if link:
        rows.append(("This finding", link, link))
    code = code_link(finding, provider_of(session, finding))
    if code:
        rows.append(("The code", code, code))
    # An advisory with no id to hang it off, which the alert feeds produce.
    advisory = advisory_link(finding)
    if advisory and advisory != code and not finding.vulnerability_id:
        rows.append(("Advisory", advisory, advisory))

    return [(label, text, url) for label, text, url in rows if text]


def _branches(finding) -> list:
    """Every branch this finding sits on, from the list the scan wrote."""
    try:
        loaded = json.loads(finding.branches or "[]")
    except (TypeError, ValueError):
        return []
    return [str(name) for name in loaded if str(name).strip()]


# --- what a message looks like ----------------------------------------------
# The colors a mail client can be relied on to render, which is an inline style
# and nothing else.  A stylesheet in the head is stripped by Outlook and by
# Gmail both, so every rule below travels on the element it applies to.
_SEVERITY_COLOR = {
    "critical": "#8b0000",
    "high": "#b3420a",
    "medium": "#8a6d00",
    "low": "#355e8a",
    "info": "#4a5568",
    "unknown": "#4a5568",
}


def attach_csv(session) -> bool:
    """Whether the digest carries a spreadsheet of what it is about."""
    return bool(store.get(session, "notify.attach_csv"))


def spreadsheet(session, findings: list, label: str = "") -> dict:
    """The attachment, or nothing.

    -> {"name", "text", "rows", "left"}, where left is how many findings did not
    fit.  Built through the same function that writes the file on disk, so the
    columns can never drift apart, and escaped on the way out because a cell
    beginning with an equals sign is a program as soon as somebody double clicks
    it and every value here came out of a repository we do not control.
    """
    from app.core import reports

    rows = list(findings or [])
    if not rows:
        return {}

    kept = rows[:ATTACH_ROWS]
    text = reports.csv_text(session, kept, for_spreadsheet=True)
    # Trim to what a mail gateway will carry.  Worked out from what the rows
    # actually measured rather than guessed at, and the findings are already in
    # severity order, so what goes is the least urgent.
    if len(text.encode("utf-8")) > ATTACH_BYTES and len(kept) > 50:
        share = ATTACH_BYTES / len(text.encode("utf-8"))
        kept = kept[:max(50, int(len(kept) * share) - 1)]
        text = reports.csv_text(session, kept, for_spreadsheet=True)

    stamp = _date(datetime.now(timezone.utc))
    tidy = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-").lower()
    name = f"new-findings-{tidy}-{stamp}.csv" if tidy else f"new-findings-{stamp}.csv"
    return {"name": name, "text": text, "rows": len(kept),
            "left": len(rows) - len(kept)}


def mail_format(session) -> str:
    """text or html, whichever the Notifications page asks for."""
    chosen = (store.get(session, "notify.email_format") or "text").lower()
    return "html" if chosen == "html" else "text"


def attachment_note(sheet: dict) -> str:
    """One line about the spreadsheet, in the body, where a reader looks.

    An attachment nobody is told about is one a reader scrolls past, and the
    count matters: a message describing twenty five findings with four hundred
    in the file beside it reads as a much smaller night than it was.
    """
    if not sheet:
        return ""
    note = (f"Attached: {sheet['name']}, every new finding in this scan "
            f"({sheet['rows']} row(s)), in the same columns as the "
            f"vulnerabilities.csv this installation writes.")
    if sheet.get("left"):
        note += (f"  {sheet['left']} more did not fit and are on the findings "
                 f"page.")
    note += ("  It is a snapshot of this scan rather than the current list, so "
             "anything acted on since is still in it.")
    return note


def text_message(session, title: str, lines: list, findings: list = None,
                 link: str = "", intro: str = "") -> str:
    """The whole of a plain text message.

    Findings are described in full, one labeled block each, because this is
    read away from the page by somebody deciding whether to get up.  Past the
    cap it says how many are left and where they are rather than going on.
    """
    out = [title, "", DISCLAIMER, ""]
    if intro:
        out += [intro, ""]

    shown = list(findings or [])[:DETAIL_CAP]
    for finding in shown:
        out.append(f"{_enum(finding.severity).upper()}  {headline(finding)}")
        for label, text, url in details(session, finding):
            out.append(f"  {label + ':':<{_LABEL}} {text}")
            if url and url != text:
                # Under it rather than beside it.  An advisory id and the page
                # it lives on are two things, and running them together on one
                # line is how a reader ends up pasting both into a browser.
                out.append(f"  {'':<{_LABEL}} {url}")
        out.append("")

    left = len(findings or []) - len(shown)
    if left > 0:
        out.append(f"and {left} more, which are on the findings page rather "
                   f"than in this message.")
        out.append("")

    # Nothing to describe, so whatever the caller wanted said.  The test
    # message and anything else with no findings behind it lands here.
    if not shown:
        out += [str(line) for line in (lines or [])] + [""]

    if link:
        out.append(link)
    return "\n".join(out).rstrip() + "\n"


def html_message(session, title: str, lines: list, findings: list = None,
                 link: str = "", intro: str = "") -> str:
    """The same message as a page.

    Worth having for one reason: the three links per finding are links rather
    than addresses somebody has to copy out of plain text, and a digest of
    twenty findings is a lot of copying.  Deliberately plain otherwise, because
    a mail client is not a browser and anything clever about the layout breaks
    in one of them.
    """
    color = _SEVERITY_COLOR
    parts = [
        '<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,'
        'sans-serif;font-size:14px;color:#1a202c;line-height:1.45">',
        f'<h2 style="font-size:17px;margin:0 0 12px">{escape(title)}</h2>',
        '<p style="margin:0 0 16px;padding:10px 12px;background:#fff8e1;'
        'border-left:4px solid #8a6d00;color:#5c4a00">'
        f'<strong>Housekeeping.</strong> {escape(DISCLAIMER)}</p>',
    ]
    if intro:
        parts.append(f'<p style="margin:0 0 16px">{escape(intro)}</p>')

    shown = list(findings or [])[:DETAIL_CAP]
    for finding in shown:
        grade = _enum(finding.severity).lower()
        edge = color.get(grade, color["unknown"])
        parts.append(
            f'<div style="margin:0 0 18px;border-left:4px solid {edge};'
            'padding:2px 0 2px 12px">')
        parts.append(
            f'<div style="font-weight:600;margin-bottom:6px">'
            f'<span style="color:{edge}">{escape(grade.upper())}</span> '
            f'{escape(headline(finding))}</div>')
        parts.append('<table role="presentation" cellpadding="0" cellspacing="0" '
                     'style="border-collapse:collapse">')
        for label, text, url in details(session, finding):
            if url:
                # The address is the label's value as well as its link, which
                # is what a reader forwarding this to somebody else needs.
                value = (f'<a href="{escape(url, quote=True)}" '
                         f'style="color:#1a4f8a">{escape(text)}</a>')
            else:
                value = escape(text)
            parts.append(
                '<tr>'
                '<th style="text-align:left;vertical-align:top;padding:2px 10px '
                '2px 0;font-weight:500;color:#4a5568;white-space:nowrap">'
                f'{escape(label)}</th>'
                f'<td style="vertical-align:top;padding:2px 0">{value}</td></tr>')
        parts.append('</table></div>')

    left = len(findings or []) - len(shown)
    if left > 0:
        parts.append(f'<p style="margin:0 0 16px;color:#4a5568">and {left} more, '
                     'which are on the findings page rather than in this '
                     'message.</p>')

    if not shown:
        for line in (lines or []):
            parts.append(f'<p style="margin:0 0 8px">{escape(str(line))}</p>')

    if link:
        safe = escape(link, quote=True)
        parts.append(f'<p style="margin:16px 0 0">'
                     f'<a href="{safe}" style="color:#1a4f8a">{escape(link)}</a></p>')
    parts.append('</div>')
    return "\n".join(parts)


# --- the transports ---------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follow nothing.

    The address is checked when it is saved: https, and not the link-local
    range where the cloud metadata service lives.  A redirect would walk
    straight around that check, and there is no legitimate incoming webhook
    that needs one.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _post_json(url: str, payload: dict) -> bool:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "git-code-review"})
    try:
        with _OPENER.open(request, timeout=TIMEOUT) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("could not post to %s: %s", _safe(url), exc)
        return False


def _safe(url: str) -> str:
    """A webhook URL is a credential.  Never log the whole thing."""
    if "://" not in url:
        return "the configured endpoint"
    scheme, rest = url.split("://", 1)
    host = rest.split("/", 1)[0]
    return f"{scheme}://{host}/..."


def send_slack(url: str, title: str, lines: list, link: str = "") -> bool:
    text = f"*{title}*\n" + "\n".join(f"• {line}" for line in lines[:20])
    if len(lines) > 20:
        text += f"\n_and {len(lines) - 20} more_"
    if link:
        text += f"\n{link}"
    return _post_json(url, {"text": text})


def send_teams(url: str, title: str, lines: list, link: str = "") -> bool:
    # The legacy MessageCard, on purpose.  Every Teams incoming webhook
    # accepts it, including the ones created years ago, and an Adaptive Card
    # posted to one of those is rejected with a 400 nobody can read.
    body = "\n\n".join(lines[:20])
    if len(lines) > 20:
        body += f"\n\nand {len(lines) - 20} more"
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": "D93F0B",
        "title": title,
        "text": body,
    }
    if link:
        payload["potentialAction"] = [{
            "@type": "OpenUri", "name": "Open it",
            "targets": [{"os": "default", "uri": link}]}]
    return _post_json(url, payload)


def send_webhook(url: str, title: str, lines: list, extra: dict = None) -> bool:
    payload = {"title": title, "lines": lines,
               "generated_at": datetime.now(timezone.utc).strftime(
                   "%Y-%m-%dT%H:%M:%SZ")}
    payload.update(extra or {})
    return _post_json(url, payload)


# Microsoft's own endpoints, not anything a person types.  That matters: every
# other address this server fetches goes through clean_remote_url, and these
# are constants here precisely so there is nothing to check.
GRAPH_LOGIN = "https://login.microsoftonline.com"
GRAPH_API = "https://graph.microsoft.com/v1.0"


def _graph_token(tenant: str, client_id: str, secret: str) -> str:
    """A token for the app registration.  -> the token, or "" with a reason logged.

    Client credentials, which is the flow for an application acting as itself
    rather than on behalf of a person.  There is no refresh token and no user
    interaction; the secret is the credential.
    """
    import urllib.parse

    body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    request = urllib.request.Request(
        f"{GRAPH_LOGIN}/{urllib.parse.quote(tenant)}/oauth2/v2.0/token",
        data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with _OPENER.open(request, timeout=TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        return payload.get("access_token") or ""
    except urllib.error.HTTPError as exc:
        # The body says which of the three fields is wrong, and that is the
        # whole question when this does not work.  It carries no secret.
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8", "replace")).get(
                "error_description", "")[:300]
        except Exception:            # noqa: BLE001
            pass
        log.warning("Microsoft refused the app registration: %s %s",
                    exc.code, detail)
        return ""
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("could not reach Microsoft to get a token: %s", exc)
        return ""


def send_graph(session, subject: str, body: str, html: str = "",
               to: list = None, sheet: dict = None) -> bool:
    """Send through Microsoft 365, as the mailbox the app registration owns.

    For tenants with basic authentication switched off, which have no SMTP to
    offer at all.  saveToSentItems is false: this is a notification, and
    filling somebody's Sent Items with them helps nobody.
    """
    tenant = (store.get(session, "notify.graph_tenant") or "").strip()
    client = (store.get(session, "notify.graph_client_id") or "").strip()
    secret = store.get(session, "notify.graph_secret") or ""
    sender = (store.get(session, "notify.graph_sender") or "").strip()
    addresses = list(to or []) or _split(store.get(session, "notify.email_to"))

    if not (tenant and client and secret and sender and addresses):
        log.warning("Microsoft 365 mail is selected but not fully configured")
        return False

    token = _graph_token(tenant, client, secret)
    if not token:
        return False

    recipients = [{"emailAddress": {"address": address}}
                  for address in addresses]
    payload = {
        "message": {
            "subject": subject,
            # One or the other, not both: Graph takes a single body, so the
            # HTML is the message when HTML was asked for.
            "body": ({"contentType": "HTML", "content": html} if html
                     else {"contentType": "Text", "content": body}),
            "toRecipients": recipients,
        },
        "saveToSentItems": False,
    }
    if sheet:
        # Base64 in the request body, which is the only way Graph takes a file
        # on a single sendMail call.  Well inside the four megabyte limit that
        # applies before an upload session is needed, because the rows are
        # trimmed to a gateway friendly size before they get here.
        import base64

        payload["message"]["attachments"] = [{
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": sheet["name"],
            "contentType": "text/csv",
            "contentBytes": base64.b64encode(
                sheet["text"].encode("utf-8")).decode("ascii"),
        }]
    request = urllib.request.Request(
        f"{GRAPH_API}/users/{urllib.parse.quote(sender)}/sendMail",
        data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"})
    try:
        with _OPENER.open(request, timeout=TIMEOUT) as response:
            # sendMail answers 202 with no body when it has accepted it.
            return 200 <= response.status < 300
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8", "replace")).get(
                "error", {}).get("message", "")[:300]
        except Exception:            # noqa: BLE001
            pass
        log.warning("Microsoft would not send the message: %s %s", exc.code, detail)
        return False
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("could not reach Microsoft to send: %s", exc)
        return False


def send_email(session, subject: str, body: str, html: str = "",
               to: list = None, sheet: dict = None) -> bool:
    host = (store.get(session, "notify.smtp_host") or "").strip()
    addresses = list(to or []) or _split(store.get(session, "notify.email_to"))
    if not host or not addresses:
        return False

    try:
        port = int(store.get(session, "notify.smtp_port") or 587)
    except (TypeError, ValueError):
        port = 587
    sender = ((store.get(session, "notify.email_from") or "").strip()
              or addresses[0])
    username = (store.get(session, "notify.smtp_user") or "").strip()
    password = store.get(session, "notify.smtp_password") or ""
    mode = (store.get(session, "notify.smtp_security") or "starttls").lower()

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = ", ".join(addresses)
    message.set_content(body)
    if html:
        # Both parts, always.  A reader on a client that will not render HTML,
        # or who has images and markup switched off, still gets the whole
        # message rather than an empty one.
        message.add_alternative(html, subtype="html")
    if sheet:
        # Which promotes the message to multipart/mixed, with the text and HTML
        # parts staying alternatives of each other inside it.  That is the shape
        # every client expects, and getting it wrong is how an attachment ends
        # up shown as the body.
        message.add_attachment(sheet["text"].encode("utf-8"),
                               maintype="text", subtype="csv",
                               filename=sheet["name"])

    try:
        if mode == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(host, port, timeout=TIMEOUT)
        with server:
            server.ehlo()
            if mode == "starttls":
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            if username:
                server.login(username, password)
            server.send_message(message, to_addrs=addresses)
        return True
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        log.warning("could not send mail through %s: %s", host, exc)
        return False


# --- what to send -----------------------------------------------------------
def _split(value) -> list:
    """An address list as typed, as a list, with no duplicates."""
    out = []
    for part in str(value or "").replace(";", ",").split(","):
        address = part.strip()
        if address and address not in out:
            out.append(address)
    return out


def recipients(session, connection=None) -> list:
    """Who this message goes to.

    The Notifications page names the installation wide list, which is usually a
    security mailbox.  A connection can name more: either of its two owners,
    each only if somebody ticked the box beside them, plus anything in its own
    notification field.  Those are added rather than substituted, because the
    mailbox that watches everything still has to see this one.
    """
    out = _split(store.get(session, "notify.email_to"))
    for address in (connection.notify_addresses() if connection is not None
                    else []):
        if address not in out:
            out.append(address)
    return out


def _fan_out(session, title: str, lines: list, link: str = "",
             extra: dict = None, findings: list = None,
             connection=None, sheet_label=None) -> dict:
    """Every configured way out, and which of them worked.

    One failing transport never stops the others: an expired Slack webhook must
    not be the reason nobody got the email.
    """
    targets = _targets(session)
    sent = {}
    if targets["slack"]:
        sent["slack"] = send_slack(targets["slack"], title, lines, link)
    if targets["teams"]:
        sent["teams"] = send_teams(targets["teams"], title, lines, link)
    if targets["webhook"]:
        # Everything the mail says, in a shape something else can read.  A
        # webhook exists so another system can act on this, and a system cannot
        # act on a sentence.
        payload = dict(extra or {})
        payload["disclaimer"] = DISCLAIMER
        if findings:
            payload["findings"] = [
                {label: text for label, text, _url in details(session, one)}
                for one in findings[:DETAIL_CAP]]
        sent["webhook"] = send_webhook(targets["webhook"], title, lines, payload)

    to = recipients(session, connection)
    if to:
        # Only where the caller asked for one, which is the digest and never the
        # three urgent kinds.  A spreadsheet is a worse way to read one finding
        # somebody should stop what they are doing for than four lines of text.
        sheet = {}
        if sheet_label is not None and findings and attach_csv(session):
            sheet = spreadsheet(session, findings, sheet_label)
        note = attachment_note(sheet)
        body = text_message(session, title, lines, findings, link, note)
        html = (html_message(session, title, lines, findings, link, note)
                if mail_format(session) == "html" else "")
        transport = (store.get(session, "notify.mail_transport") or "smtp").lower()
        if transport == "graph":
            sent["microsoft 365"] = send_graph(session, title, body, html, to,
                                               sheet)
        else:
            sent["email"] = send_email(session, title, body, html, to, sheet)
    return sent


def notify_urgent(session, finding, why: str, connection=None) -> dict:
    """One finding somebody should stop what they are doing for."""
    if not enabled(session):
        return {}
    title = f"{_enum(finding.severity).upper()}: {why}"
    return _fan_out(session, title, [describe(finding)],
                    finding_link(session, finding),
                    {"kind": "urgent", "vuln_id": finding.vuln_id or "",
                     "reason": why},
                    findings=[finding], connection=connection)


def notify_digest(session, findings: list, scan_label: str = "",
                  connection=None) -> dict:
    """Everything else this scan found that was not there before."""
    if not enabled(session) or not findings:
        return {}
    counts = {}
    for finding in findings:
        key = _enum(finding.severity)
        counts[key] = counts.get(key, 0) + 1
    summary = ", ".join(f"{count} {name}" for name, count in
                        sorted(counts.items(), key=lambda kv: -_rank(kv[0])))
    title = f"{len(findings)} new finding(s): {summary}"
    if scan_label:
        title += f" ({scan_label})"

    ordered = sorted(findings, key=lambda f: -_rank(f.severity))
    lines = [describe(finding) for finding in ordered]
    root = base_url(session)
    return _fan_out(session, title, lines,
                    f"{root}/findings" if root else "",
                    {"kind": "digest", "counts": counts},
                    findings=ordered, connection=connection,
                    sheet_label=scan_label)


def announce(session, findings: list, scan_label: str = "",
             connection=None) -> dict:
    """What a finished scan sends, in the order it should arrive.

    Urgent items go on their own so they are not buried in a list, and are then
    left out of the digest so nobody reads the same finding twice and assumes
    there were two.

    The connection is the account that was scanned.  It decides who hears about
    it beyond the installation wide list, which is how the team that owns one
    application stops getting another team's findings.
    """
    if not enabled(session):
        return {"sent": False, "reason": "notifications are off"}

    floor = _min_rank(session)
    urgent, rest = [], []
    for finding in findings:
        why = is_urgent(finding)
        if why:
            urgent.append((finding, why))
        elif _rank(finding.severity) >= floor:
            rest.append(finding)

    results = {"urgent": 0, "digest": 0}
    for finding, why in urgent[:25]:
        notify_urgent(session, finding, why, connection=connection)
        results["urgent"] += 1
    if rest:
        notify_digest(session, rest, scan_label, connection=connection)
        results["digest"] = len(rest)
    return results


def test_message(session) -> dict:
    """Prove the wiring, from the page, before anybody relies on it."""
    return _fan_out(
        session, "Git Code Review: a test message",
        ["This confirms the notification settings work.",
         "No findings are attached to it.",
         f"Mail is being sent as {mail_format(session)}."],
        base_url(session))
