"""What the token API offers, written down once.

The API reference tab on the IDE tokens page, the OpenAPI file and the
Postman collection are all built from the list below, so they cannot say
different things.  A test checks this list against the routes that are really
there, so a new endpoint that nobody wrote up here fails the build rather than
going missing from the docs.
"""

from __future__ import annotations

from app.config import VERSION

SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]


def _p(name, description, where="query", kind="string", choices=None,
       default=None, required=False, example=None):
    return {"name": name, "in": where, "type": kind, "enum": choices,
            "default": default, "required": required or where == "path",
            "description": description, "example": example}


PAGING = [
    _p("limit", "How many to return, 1 to 1000.", kind="integer", default=100),
    _p("offset", "How many to skip, for the next page.", kind="integer", default=0),
]


def _finding_filters():
    from app.core.models import FindingKind, FindingState

    return [
        _p("severity", "Only this severity.", choices=SEVERITIES),
        _p("kind", "Only this kind of finding.",
           choices=[k.value for k in FindingKind]),
        _p("state", "Open, waived or fixed.", choices=[s.value for s in FindingState],
           default="open"),
        _p("org", "Only this organization."),
        _p("repo", "Only this repository, by full name.", example="acme/payments"),
        _p("branch", "Only this branch."),
        _p("connection", "Only findings from this connection."),
        _p("q", "Search the id, path, rule, package, CVE and author."),
        _p("exception", "Whether to include findings that have an approved exception.",
           choices=["without", "with", "any"], default="without"),
        _p("triage", "The work list, or what has been set aside.",
           choices=["work", "any", "third_party", "advisory", "not_applicable"],
           default="work"),
        _p("baseline", "New since the organization baseline, the backlog, or both.",
           choices=["new", "backlog", "any"], default="new"),
        _p("since", "New or changed in the last few days.",
           choices=["1", "7", "14", "30"]),
        _p("confidence", "How sure the engine was.",
           choices=["high", "medium", "low", "unrated"]),
        _p("reach", "Package reachability.  By default unlikely ones are left out.",
           choices=["reachable", "unlikely", "unknown", "unrated", "any"]),
        _p("impact", "Impact rating.", choices=["low", "medium", "high"]),
        _p("likelihood", "Likelihood rating.",
           choices=["unlikely", "possible", "likely", "happening now"]),
        _p("malicious", "1 for malicious packages only.", choices=["1"]),
        _p("exploited", "1 for known exploited (KEV) only.", choices=["1"]),
        _p("verified", "1 for credentials that were proven live.", choices=["1"]),
        _p("ai", "reviewed for findings an AI review has read, unreviewed for the "
                 "rest.  A reviewed finding carries ai_review, with the fix.",
           choices=["reviewed", "unreviewed"]),
        _p("archived", "1 for archived repositories only, 0 to leave them out.",
           choices=["0", "1"]),
    ] + PAGING


GROUPS = [
    ("Basics", "Check a token before you build on it."),
    ("Deploy check", "One call for a deploy script: is there anything on "
                     "this repository and branch to fix first."),
    ("Findings", "Your vulnerabilities, credentials and code findings.  "
                 "Only repositories your account can open are included."),
    ("Exceptions", "Ask for an exception, follow it, change it or withdraw it.  "
                   "A request made with a token always waits for an "
                   "administrator to approve it.  You can only read, change or "
                   "withdraw your own, and an id that is not yours answers 404."),
    ("Exclusions", "The rules that keep findings out of the report files, and "
                   "taking one back.  Administrators only.  A token can revoke "
                   "an exclusion but never add one."),
    ("SBOMs", "Software bills of materials for the repositories you can see."),
    ("Trends", "How your numbers have moved over time."),
    ("Report files", "The whole estate report files.  Administrators only."),
    ("Editors", "What the editor plugins use."),
    ("External sites", "The company's domains and subdomains, their dynamic "
                       "scans and the repositories behind them.  Needs the "
                       "external scope on an administrator's token, and External "
                       "sites switched on in Settings."),
]


def endpoints() -> list:
    """Every endpoint, in the order the tab shows them."""
    return [
        {
            "id": "ping", "group": "Basics", "method": "GET", "path": "/ping",
            "scope": None, "permission": None,
            "summary": "Check a token",
            "description": "Says whose token it is, what it may do and when it "
                           "expires.  Any live token works.",
            "params": [],
            "example": {"ok": True, "version": VERSION, "user": "jsmith",
                        "scopes": ["reports"], "expires_at": "2027-01-31T00:00:00+00:00"},
        },
        {
            "id": "check", "group": "Deploy check", "method": "GET", "path": "/check",
            "scope": "reports", "permission": "findings.read",
            "summary": "Check before a deploy",
            "description": "Looks at what the scans found on one repository and "
                           "branch and answers pass, fail or unknown.  It covers "
                           "vulnerable packages, packages in container images, "
                           "and problems in the build: CI workflows, Dockerfiles, "
                           "build scripts, and packages only the build and tests "
                           "use.  Known exploited and malicious packages fail at "
                           "any severity.  Findings with an approved exception do "
                           "not count.  unknown means the branch was never "
                           "scanned, so a script should not read it as a pass.  "
                           "It does not read new code; it answers from the last "
                           "scan, given in last_scanned_at.  The Findings filters "
                           "triage, reach and confidence also work here.",
            "params": [
                _p("repo", "The repository full name.", required=True,
                   example="acme/payments"),
                _p("branch", "The branch being deployed.  The default branch "
                             "when left out.", example="main"),
                _p("fail_on", "The lowest severity that fails the check.",
                   choices=["critical", "high", "medium", "low", "info"],
                   default="high"),
                _p("include", "Which areas to look at, comma separated, or all.",
                   choices=["package,image,build", "package", "image", "build",
                            "config", "credential", "code", "all"],
                   default="package,image,build"),
                _p("block_exploited", "1 to fail on known exploited or malicious "
                                      "packages at any severity, 0 to go by "
                                      "severity alone.", choices=["1", "0"],
                   default="1"),
                _p("reach", "Package reachability.  By default packages that are "
                            "unlikely to be reached are left out.  any counts them.",
                   choices=["any", "reachable", "unlikely", "unknown", "unrated"]),
            ],
            "example": {
                "verdict": "fail",
                "message": "1 finding(s) to fix before this deploys.",
                "repository": "acme/payments", "branch": "main",
                "fail_on": "high", "include": ["build", "image", "package"],
                "block_exploited": True,
                "last_scanned_at": "2026-11-01T04:10:00Z",
                "checked_at": "2026-11-02T15:00:00Z", "truncated": False,
                "summary": {"blocking": 1, "other": 1,
                            "by_area": {"build": 1, "image": 0, "package": 1},
                            "by_severity": {"high": 1, "medium": 1}},
                "blocking": [{
                    "id": 4182, "vuln_id": "GCR-7Q2K9", "area": "package",
                    "kind": "dependency", "severity": "high", "blocking": True,
                    "why": "high is at or above high",
                    "title": "lodash prototype pollution", "branch": "main",
                    "file": "package-lock.json", "line": 0, "rule": "",
                    "known_exploited": False, "malicious": False,
                    "link": "https://gcr.example.com/findings/4182",
                    "package": {"name": "lodash", "version": "4.17.20",
                                "ecosystem": "npm", "fixed_in": "4.17.21",
                                "scope": "runtime", "image": ""},
                    "vulnerability": "CVE-2021-23337",
                    "fix": "Upgrade lodash to 4.17.21 or later."}],
                "other": [{
                    "id": 4190, "area": "build", "kind": "misconfiguration",
                    "severity": "medium", "blocking": False, "why": "",
                    "title": "Workflow uses an action pinned to a tag, not a commit",
                    "file": ".github/workflows/build.yml", "line": 14}],
            },
        },
        {
            "id": "findings", "group": "Findings", "method": "GET", "path": "/findings",
            "scope": "reports", "permission": "findings.read",
            "summary": "List findings",
            "description": "The same filters and order as the Findings page.  "
                           "total is the full count behind the filter, and limit "
                           "and offset page through it.  ai_review is filled in "
                           "only when an AI review still holds for the code as it "
                           "is: its rating, a summary, the fix, what to check and "
                           "what to do in the meantime.  A learned rule gives a "
                           "rating and a reason but no fix.",
            "params": _finding_filters(),
            "example": {"total": 1, "limit": 100, "offset": 0, "count": 1, "findings": [{
                "id": 4182, "vuln_id": "GCR-7Q2K9", "kind": "dependency",
                "severity": "high", "state": "open", "organization": "acme",
                "repository": "acme/payments", "branch": "main",
                "file": "package-lock.json", "title": "lodash prototype pollution",
                "first_found": "2026-09-01T04:12:00Z",
                "last_found": "2026-11-01T04:10:00Z",
                "package": {"name": "lodash", "version": "4.17.20",
                            "ecosystem": "npm", "fixed_in": "4.17.21"},
                "vulnerability": {"id": "CVE-2021-23337", "cvss_score": 7.2,
                                  "known_exploited": False, "epss_score": 0.01},
                "excepted": False, "exception": None,
                "ai_reviewed": False, "ai_review": None}]},
        },
        {
            "id": "finding", "group": "Findings", "method": "GET",
            "path": "/findings/{finding_id}",
            "scope": "reports", "permission": "findings.read",
            "summary": "Get one finding",
            "description": "One finding by its number.  A finding you cannot see "
                           "answers 404, the same as one that does not exist.",
            "params": [_p("finding_id", "The finding number, the id field in a list.",
                          where="path", kind="integer", example=1)],
            "example": {"id": 5120, "vuln_id": "GCR-3M8T1", "kind": "code",
                        "severity": "high", "state": "open",
                        "repository": "acme/payments", "file": "src/report.py",
                        "line": 42, "title": "SQL built from request input",
                        "exception": None, "ai_reviewed": True,
                        "ai_review": {
                            "source": "analysis", "rating": "HIGH",
                            "severity": "high", "confidence": "medium",
                            "model": "example-model",
                            "reviewed_at": "2026-10-30T14:02:00Z",
                            "summary": "The month parameter is put into the SQL text.",
                            "why": "The route needs no sign in.",
                            "fix": "Pass month as a bound parameter to cursor.execute.",
                            "what_to_check": "Whether any proxy limits the value.",
                            "compensating_controls": "Give the report user read access only."}},
        },
        {
            "id": "exceptions", "group": "Exceptions", "method": "GET",
            "path": "/exceptions",
            "scope": "reports", "permission": "findings.read",
            "summary": "List exceptions",
            "description": "Exceptions on findings you can see.  Your own, unless "
                           "your account approves exceptions.",
            "params": [_p("status", "Only this status.",
                          choices=["requested", "approved", "rejected",
                                   "revoked", "expired"]),
                       _p("finding", "Only the exception on this finding number.",
                          kind="integer")] + PAGING,
            "example": {"total": 1, "limit": 100, "offset": 0, "count": 1, "exceptions": [{
                "id": 77, "finding": 4182, "status": "requested", "category": "",
                "reason": "Only reachable from the admin network, fix planned in Q1.",
                "ticket": "SEC-1203", "requested_by": "jsmith",
                "requested_at": "2026-11-02T15:00:00Z",
                "expires_at": "2027-01-31T00:00:00Z", "decided_by": "",
                "decided_at": None, "decision_note": "", "vuln_id": "GCR-7Q2K9",
                "repository": "acme/payments", "title": "lodash prototype pollution"}]},
        },
        {
            "id": "request_exception", "group": "Exceptions", "method": "POST",
            "path": "/findings/{finding_id}/exceptions",
            "scope": "reports", "permission": "waiver.request",
            "summary": "Ask for an exception",
            "description": "Nothing leaves the report files until an administrator "
                           "approves it in the web app.  This is true on an "
                           "administrator's token as well.  Answers 409 if the "
                           "finding already has a pending or approved exception.",
            "params": [_p("finding_id", "The finding number.", where="path",
                          kind="integer", example=1)],
            "body": [
                {"name": "reason", "type": "string", "required": True,
                 "description": "Why this is acceptable.  At least 20 characters."},
                {"name": "expires", "type": "string", "required": True,
                 "description": "When it runs out, as YYYY-MM-DD.  Up to a year away."},
                {"name": "ticket", "type": "string", "required": False,
                 "description": "A ticket number to tie it to."},
                {"name": "category", "type": "string", "required": False,
                 "enum": ["", "not_deployed"],
                 "description": "Empty for an accepted risk, or not_deployed for "
                                "code that never ships.  Not allowed on a credential."},
            ],
            "body_example": {"reason": "Only reachable from the admin network, "
                                       "fix planned in Q1.",
                             "expires": "2027-01-31", "ticket": "SEC-1203",
                             "category": ""},
            "status": 201,
            "example": {"id": 77, "finding": 4182, "status": "requested",
                        "expires_at": "2027-01-31T00:00:00Z"},
        },
        {
            "id": "exception", "group": "Exceptions", "method": "GET",
            "path": "/exceptions/{exception_id}",
            "scope": "reports", "permission": "findings.read",
            "summary": "Read one exception",
            "description": "One of your own, or any on a finding you can see if "
                           "your account approves exceptions.",
            "params": [_p("exception_id", "The exception number.", where="path",
                          kind="integer", example=77)],
            "example": {"id": 77, "finding": 4182, "status": "approved", "category": "",
                "reason": "Only reachable from the admin network, fix planned in Q1.",
                "ticket": "SEC-1203", "requested_by": "jsmith",
                "requested_at": "2026-11-02T15:00:00Z",
                "expires_at": "2027-01-31T00:00:00Z", "decided_by": "admin",
                "decided_at": "2026-11-03T09:12:00Z", "decision_note": "",
                "vuln_id": "GCR-7Q2K9", "repository": "acme/payments",
                "title": "lodash prototype pollution"},
        },
        {
            "id": "edit_exception", "group": "Exceptions", "method": "PATCH",
            "path": "/exceptions/{exception_id}",
            "scope": "reports", "permission": "waiver.request",
            "summary": "Change your own exception",
            "description": "Send only the fields to change.  Only the person "
                           "who asked can change it, whatever their role.  A "
                           "waiting one stays waiting.  An approved one goes "
                           "back to waiting and its finding returns to the "
                           "report files until an administrator approves it "
                           "again.  Answers 409 on one that is rejected or "
                           "revoked: ask again instead.",
            "params": [_p("exception_id", "The exception number.", where="path",
                          kind="integer", example=77)],
            "body": [
                {"name": "reason", "type": "string", "required": False,
                 "description": "Why this is acceptable.  At least 20 characters."},
                {"name": "expires", "type": "string", "required": False,
                 "description": "When it runs out, as YYYY-MM-DD.  Up to a year away."},
                {"name": "ticket", "type": "string", "required": False,
                 "description": "A ticket number to tie it to."},
                {"name": "category", "type": "string", "required": False,
                 "enum": ["", "not_deployed"],
                 "description": "Empty for an accepted risk, or not_deployed."},
            ],
            "body_example": {"expires": "2027-03-31", "ticket": "SEC-1300"},
            "example": {"id": 77, "finding": 4182, "status": "requested",
                        "expires_at": "2027-03-31T00:00:00Z"},
        },
        {
            "id": "withdraw_exception", "group": "Exceptions", "method": "POST",
            "path": "/exceptions/{exception_id}/withdraw",
            "scope": "reports", "permission": "waiver.request",
            "summary": "Withdraw your own exception",
            "description": "Only the person who asked.  Works on a waiting or "
                           "approved one.  It is kept as revoked with a note "
                           "that it was withdrawn, and the finding comes "
                           "straight back.",
            "params": [_p("exception_id", "The exception number.", where="path",
                          kind="integer", example=77)],
            "example": {"id": 77, "finding": 4182, "status": "revoked",
                        "decided_by": "jsmith",
                        "decision_note": "Withdrawn by the person who asked for it."},
        },
        {
            "id": "revoke_exception", "group": "Exceptions", "method": "POST",
            "path": "/exceptions/{exception_id}/revoke",
            "scope": "reports", "permission": "waiver.revoke",
            "summary": "Revoke an approved exception",
            "description": "Administrators only, and only on findings they can "
                           "see.  The finding comes straight back into both "
                           "report files, and the exclusion the approval made "
                           "is switched off.",
            "params": [_p("exception_id", "The exception number.", where="path",
                          kind="integer", example=77)],
            "example": {"id": 77, "finding": 4182, "status": "revoked",
                        "decided_by": "admin"},
        },
        {
            "id": "approve_exception", "group": "Exceptions", "method": "POST",
            "path": "/exceptions/{exception_id}/approve",
            "scope": "approve", "permission": "waiver.approve",
            "summary": "Approve an exception",
            "description": "Needs the approve scope, which only an "
                           "administrator's token can carry.  Only on findings "
                           "you can see.  The finding leaves both report files "
                           "and an exclusion is written so the next scan agrees.  "
                           "Answers 409 if it is not waiting on a decision.",
            "params": [_p("exception_id", "The exception number.", where="path",
                          kind="integer", example=77)],
            "body": [{"name": "note", "type": "string", "required": False,
                      "description": "A note kept with the decision."}],
            "body_example": {"note": "Agreed, revisit after the Q1 upgrade."},
            "example": {"id": 77, "finding": 4182, "status": "approved",
                        "decided_by": "admin",
                        "decision_note": "Agreed, revisit after the Q1 upgrade."},
        },
        {
            "id": "reject_exception", "group": "Exceptions", "method": "POST",
            "path": "/exceptions/{exception_id}/reject",
            "scope": "approve", "permission": "waiver.approve",
            "summary": "Reject an exception",
            "description": "Needs the approve scope.  The finding stays in the "
                           "report files and the person who asked sees why.",
            "params": [_p("exception_id", "The exception number.", where="path",
                          kind="integer", example=77)],
            "body": [{"name": "note", "type": "string", "required": False,
                      "description": "Why, for the person who asked."}],
            "body_example": {"note": "Upgrade instead, the fix is a patch release."},
            "example": {"id": 77, "finding": 4182, "status": "rejected",
                        "decided_by": "admin"},
        },
        {
            "id": "add_exclusion", "group": "Exclusions", "method": "POST",
            "path": "/exclusions",
            "scope": "approve", "permission": "exclusion.write",
            "summary": "Exclude a fingerprint or a finding",
            "description": "Needs the approve scope.  Send fingerprint to "
                           "exclude that value wherever it appears, the same as "
                           "\"Exclude this value\" on a finding, or add "
                           "organization and repository to keep it to one "
                           "place.  Or send finding to exclude one finding, with "
                           "by_value true to cover its value everywhere instead.  "
                           "Answers 409 if a rule already covers it.",
            "params": [],
            "body": [
                {"name": "fingerprint", "type": "string", "required": False,
                 "description": "The hash off the finding, on its own or with "
                                "cred: in front.  This or finding."},
                {"name": "finding", "type": "integer", "required": False,
                 "description": "A finding number.  This or fingerprint."},
                {"name": "by_value", "type": "boolean", "required": False,
                 "description": "With finding: cover its value everywhere."},
                {"name": "reason", "type": "string", "required": True,
                 "description": "Why.  At least 20 characters."},
                {"name": "expires", "type": "string", "required": False,
                 "description": "YYYY-MM-DD, up to a year away.  Empty for no end."},
                {"name": "ticket", "type": "string", "required": False,
                 "description": "A ticket number to tie it to."},
                {"name": "organization", "type": "string", "required": False,
                 "description": "With fingerprint: only in this organization."},
                {"name": "repository", "type": "string", "required": False,
                 "description": "With fingerprint: only in this repository, "
                                "by full name."},
            ],
            "body_example": {"fingerprint": "cred:4f1c9a0b7e2d6c35",
                             "reason": "Test key from the vendor docs, never valid.",
                             "ticket": "SEC-1188"},
            "status": 201,
            "example": {"id": 31, "type": "secret", "fingerprint": "cred:4f1c9a0b7e2d6c35",
                        "organization": "*", "repository": "*", "in_force": True,
                        "revoked": False, "findings_excluded": 3},
        },
        {
            "id": "exclusions", "group": "Exclusions", "method": "GET",
            "path": "/exclusions",
            "scope": "reports", "permission": "exclusion.read",
            "summary": "List exclusions",
            "description": "The rules the Exclusions page shows your account.  "
                           "Use fingerprint to find what \"Exclude this value\" "
                           "wrote, or finding to see what is hiding one finding.",
            "params": [
                _p("fingerprint", "Only rules on this value.  The hash on its "
                   "own or with cred: in front.", example="cred:4f1c9a0b7e2d6c35"),
                _p("finding", "Only the rules in force that cover this finding "
                   "number.", kind="integer"),
                _p("status", "Only these.", choices=["live", "expired", "revoked"]),
            ] + PAGING,
            "example": {"total": 1, "limit": 100, "offset": 0, "count": 1,
                        "exclusions": [{"id": 31, "type": "secret", "vuln_id": "", "organization": "*",
                "repository": "*", "path": "*", "rule": "*",
                "fingerprint": "cred:4f1c9a0b7e2d6c35", "reason": "Test key from the vendor docs.",
                "ticket": "SEC-1188", "reviewed_by": "admin",
                "reviewed_date": "2026-10-20", "expires": "", "in_force": True,
                "revoked": False}]},
        },
        {
            "id": "revoke_exclusion", "group": "Exclusions", "method": "POST",
            "path": "/exclusions/{exclusion_id}/revoke",
            "scope": "reports", "permission": "exclusion.write",
            "summary": "Revoke one exclusion",
            "description": "Switches the rule off.  It stays on the Exclusions "
                           "page marked revoked.  Everything it covered comes "
                           "back into the report files, unless an approved "
                           "exception still holds it.  Answers 409 if it is "
                           "already revoked.",
            "params": [_p("exclusion_id", "The exclusion number.", where="path",
                          kind="integer", example=31)],
            "example": {"id": 31, "type": "secret", "vuln_id": "", "organization": "*",
                "repository": "*", "path": "*", "rule": "*",
                "fingerprint": "cred:4f1c9a0b7e2d6c35", "reason": "Test key from the vendor docs.",
                "ticket": "SEC-1188", "reviewed_by": "admin",
                "reviewed_date": "2026-10-20", "expires": "", "in_force": False,
                "revoked": True},
        },
        {
            "id": "revoke_fingerprint", "group": "Exclusions", "method": "POST",
            "path": "/exclusions/revoke",
            "scope": "reports", "permission": "exclusion.write",
            "summary": "Revoke every exclusion on a fingerprint",
            "description": "Takes back \"Exclude this value\" in one call: every "
                           "rule in force that you can see and that names this "
                           "value is switched off.  Answers 404 when there is none.",
            "params": [],
            "body": [
                {"name": "fingerprint", "type": "string", "required": True,
                 "description": "The hash off the finding, on its own or with "
                                "cred: in front."},
            ],
            "body_example": {"fingerprint": "cred:4f1c9a0b7e2d6c35"},
            "example": {"fingerprint": "cred:4f1c9a0b7e2d6c35", "count": 1,
                        "revoked": [{"id": 31, "type": "secret", "vuln_id": "", "organization": "*",
                "repository": "*", "path": "*", "rule": "*",
                "fingerprint": "cred:4f1c9a0b7e2d6c35", "reason": "Test key from the vendor docs.",
                "ticket": "SEC-1188", "reviewed_by": "admin",
                "reviewed_date": "2026-10-20", "expires": "", "in_force": False,
                "revoked": True}]},
        },
        {
            "id": "repositories", "group": "SBOMs", "method": "GET",
            "path": "/repositories",
            "scope": "reports", "permission": "repo.read",
            "summary": "List your repositories",
            "description": "The repositories you can see, and which SBOM formats "
                           "are on file for each.",
            "params": [_p("org", "Only this organization.")] + PAGING,
            "example": {"total": 1, "limit": 100, "offset": 0, "count": 1, "repositories": [{
                "full_name": "acme/payments", "organization": "acme",
                "default_branch": "main", "archived": False,
                "last_scanned_at": "2026-11-01T04:10:00Z", "sbom": ["cdx", "spdx"]}]},
        },
        {
            "id": "sboms", "group": "SBOMs", "method": "GET", "path": "/sbom",
            "scope": "reports", "permission": "repo.read",
            "summary": "List SBOMs on file",
            "description": "One row per repository and format, for the "
                           "repositories you can see.",
            "params": [],
            "example": {"count": 1, "sboms": [{
                "repository": "acme/payments", "format": "cdx", "bytes": 48211,
                "written_at": "2026-11-01T04:10:00Z"}]},
        },
        {
            "id": "sbom", "group": "SBOMs", "method": "GET",
            "path": "/sbom/{repository}",
            "scope": "reports", "permission": "repo.read",
            "summary": "Download one SBOM",
            "description": "The SBOM file for one repository, by full name.  "
                           "The slash in the name stays as it is.",
            "params": [_p("repository", "The repository full name.", where="path",
                          example="acme/payments"),
                       _p("format", "CycloneDX or SPDX.", choices=["cdx", "spdx"],
                          default="cdx")],
            "example": {"bomFormat": "CycloneDX", "specVersion": "1.5",
                        "components": ["..."]},
        },
        {
            "id": "trends", "group": "Trends", "method": "GET", "path": "/trends",
            "scope": "reports", "permission": "trend.read",
            "summary": "Trend lines",
            "description": "Daily counts by severity, plus a breakdown for the "
                           "latest day.  The breakdown is by organization, by "
                           "repository once org is set, and by branch once repo "
                           "is set.  actions counts things to fix, advisories "
                           "counts every advisory.",
            "params": [
                _p("days", "How far back.", kind="integer",
                   choices=[1, 7, 30, 90, 365], default=30),
                _p("basis", "What a count means.", choices=["actions", "advisories"],
                   default="actions"),
                _p("org", "Only this organization."),
                _p("repo", "Only this repository, by full name."),
                _p("branch", "Only this branch."),
                _p("connection", "Only this connection."),
            ],
            "example": {"basis": "actions", "days": 30,
                        "filters": {"org": "", "repo": "", "branch": "", "connection": ""},
                        "series": [{"day": "2026-11-01", "critical": 2, "high": 14,
                                    "medium": 40, "low": 9, "info": 0, "unknown": 0,
                                    "total": 65, "source": "snapshot"}],
                        "breakdown": {"axis": "organization", "day": "2026-11-01",
                                      "rows": [{"name": "acme", "critical": 2,
                                                "high": 14, "medium": 40, "low": 9,
                                                "info": 0, "total": 65}]}},
        },
        {
            "id": "reports", "group": "Report files", "method": "GET",
            "path": "/reports",
            "scope": "reports", "permission": "report.files",
            "summary": "List report files",
            "description": "The files the last scan wrote for the whole estate.  "
                           "Needs an account allowed the report files.  Everybody "
                           "else uses the endpoints above.",
            "params": [],
            "example": {"reports": [{"name": "vulnerabilities.json", "bytes": 912334,
                                     "written_at": "2026-11-01T04:12:00Z"}]},
        },
        {
            "id": "report", "group": "Report files", "method": "GET",
            "path": "/reports/{name}",
            "scope": "reports", "permission": "report.files",
            "summary": "Download a report file",
            "description": "One file from the list, by name.",
            "params": [_p("name", "A name from the list.", where="path",
                          example="vulnerabilities.json")],
            "example": {"findings": ["..."]},
        },
        {
            "id": "rules", "group": "Editors", "method": "GET", "path": "/rules",
            "scope": "rules", "permission": None,
            "summary": "Triage rules",
            "description": "What this server treats as noise, so a client can "
                           "agree with it.  Sent with an ETag.",
            "params": [],
            "example": {"version": VERSION, "triage": {"value_patterns": [],
                                                       "path_patterns": []},
                        "muted_rules": [], "exclusions": []},
        },
        {
            "id": "review", "group": "Editors", "method": "POST", "path": "/review",
            "scope": "review", "permission": None,
            "summary": "Review some code",
            "description": "Looks at the files sent and says what is wrong.  "
                           "Nothing is stored.  Up to 200 files and 8 MB.",
            "params": [],
            "body": [
                {"name": "files", "type": "array", "required": True,
                 "description": "Objects with a relative path and the content as text."},
                {"name": "only", "type": "string", "required": False,
                 "description": "secrets, code, or secrets,code."},
            ],
            "body_example": {"files": [{"path": "app/settings.py",
                                        "content": "DEBUG = True\n"}],
                             "only": "secrets,code"},
            "example": {"counts": {"credential": 0, "code": 0}, "findings": []},
        },
    ] + _external_endpoints()


def _ext(id_, method, path, summary, description, params=None, body=None,
         body_example=None, example=None):
    e = {"id": id_, "group": "External sites", "method": method, "path": path,
         "scope": "external", "permission": "external.manage",
         "summary": summary, "description": description,
         "params": params or [], "example": example or {}}
    if body is not None:
        e["body"] = body
        e["body_example"] = body_example
    return e


def _f(name, kind, required, description):
    return {"name": name, "type": kind, "required": required, "description": description}


_ASSET = {"id": 12, "host": "shop.example.com", "kind": "subdomain",
          "parent_domain": "example.com", "application": "Storefront",
          "tags": ["ecommerce"], "no_scan": False, "scan_blocked": False,
          "executive_owner": "owner@example.com", "technical_owner": "team@example.com",
          "comments": "", "status": "active", "environment": "prod",
          "external_auth_needed": False, "whitelist_needed": True,
          "change_frequency_days": 14,
          "fields": {"nameservers": {"value": "ns1.example.net, ns2.example.net",
                                     "scan": "ns1.example.net, ns2.example.net",
                                     "manual": False}},
          "telemetry": {"at": "2026-11-03T10:00:00+00:00", "grade": "B",
                        "category": "live", "status_code": 200, "ip": "203.0.113.10",
                        "open_ports": [80, 443], "tls_days_left": 61,
                        "screenshot_url": "https://gcr.example.com/external/12/screenshot.png"},
          "last_dast": {"scanned_at": "2026-11-01T02:00:00+00:00", "severity": "high",
                        "result_url": "https://dast.example.com/assessment/88",
                        "server": "nextgen-dast", "status": "current"},
          "repositories": [{"full_name": "acme/storefront", "score": 95, "linked": True,
                            "reasons": ["host named in its web addresses"],
                            "open_findings": {"high": 2}}],
          "combined_risk": {"level": "critical",
                            "reasons": ["last dynamic scan: high",
                                        "open high findings in the code behind it",
                                        "the site and its code both have problems"]}}
_SCAN = {"id": 40, "asset_id": 12, "server": "nextgen-dast", "source": "recorded",
         "status": "done", "scanned_at": "2026-11-01T02:00:00+00:00",
         "severity": "high", "counts": {"critical": 0, "high": 1, "medium": 3,
                                        "low": 5, "info": 2},
         "result_url": "https://dast.example.com/assessment/88"}
_RECORD_BODY = [
    _f("server", "string", True, "The DAST server that ran it, by name."),
    _f("severity", "string", False, "The worst found: critical, high, medium, low, "
                                    "info or none.  Worked out from counts or "
                                    "findings when left out."),
    _f("result_url", "string", False, "Where the result can be read."),
    _f("scanned_at", "string", False, "When it ran, a date or ISO time.  Now when "
                                      "left out.  Not in the future."),
    _f("counts", "object", False, "Findings per severity."),
    _f("findings", "array", False, "Each with title, severity, url, evidence, cwe "
                                   "and remediation.  Up to 3000."),
    _f("scan_id", "string", False, "The scan's id on the server."),
    _f("note", "string", False, "Anything else."),
]


_DETAILS = [
    _f("executive_owner", "string", False, "Email addresses, comma separated."),
    _f("technical_owner", "string", False, "Email addresses, comma separated."),
    _f("comments", "string", False, "Anything else about the site."),
    _f("status", "string", False, "active or obsolete."),
    _f("environment", "string", False, "One of the environments listed in Settings, "
                                       "which start as Prod, Dev, Stage and Clone."),
    _f("external_auth_needed", "boolean", False, "Signing in goes through something outside the site."),
    _f("whitelist_needed", "boolean", False, "The scanner has to be let through a firewall."),
    _f("change_frequency_days", "integer", False, "How often the site changes, in days."),
    _f("default_profile", "string", False, "The scan profile used when none is given: "
                                           "baseline, quick, standard, thorough or premium."),
    _f("proxy", "string", False, "A web proxy for the site's pages, screenshot, sign in "
                                 "and engines: http://host:port or http://user:password@"
                                 "host:port.  null removes it.  Returned without the password."),
    _f("scan_auth", "object", False, "How a scan signs in: kind header (header_name, "
                                     "header_value), cookie (cookie) or form (login_url, "
                                     "username, password).  null removes it.  Never returned."),
    _f("repositories", "array", False, "Objects with repository (org/name) and an optional "
                                       "branch.  Replaces what was picked before."),
    _f("telemetry_fields", "object", False, "Telemetry filled in by hand, by field name: "
                                            "nameservers, isp, asn, registrar, tls_issuer and "
                                            "the rest.  null clears one."),
]


def _external_endpoints() -> list:
    asset_id = _p("asset_id", "The site's id.", where="path", kind="integer", example=12)
    scan_id = _p("scan_id", "The scan's id.", where="path", kind="integer", example=40)
    return [
        _ext("ext-list", "GET", "/external/assets", "List sites",
             "Every site with its telemetry, last dynamic scan, the repositories "
             "behind it and their open findings, and the combined risk.",
             [_p("q", "Search the host and application."),
              _p("host", "Exactly this host."), _p("application", "Exactly this application."),
              _p("tag", "Only sites with this tag."),
              _p("severity", "Only sites whose last scan was this bad.",
                 choices=["critical", "high", "medium", "low", "info", "none"])] + PAGING,
             example={"total": 1, "limit": 100, "offset": 0, "assets": [_ASSET]}),
        _ext("ext-add", "POST", "/external/assets", "Add a site",
             "Adds a domain or subdomain and reads its telemetry.  Answers 200 with "
             "the existing site when it is already listed.",
             body=[_f("host", "string", True, "The host name.  A whole address is fine."),
                   _f("application", "string", False, "The application it serves."),
                   _f("tags", "array", False, "Application tags."),
                   _f("no_scan", "boolean", False, "True when it must never be scanned, "
                                                   "a SaaS product for example."),
                   _f("no_scan_reason", "string", False, "Why not."),
                   _f("telemetry", "boolean", False, "False to skip the first read.")]
             + _DETAILS,
             body_example={"host": "shop.example.com", "application": "Storefront",
                           "tags": ["ecommerce"]}, example=_ASSET),
        _ext("ext-get", "GET", "/external/assets/{asset_id}", "One site",
             "The same as one row of the list.", [asset_id], example=_ASSET),
        _ext("ext-patch", "PATCH", "/external/assets/{asset_id}", "Change a site",
             "Change the application, tags, notes or no scan.  Fields left out "
             "stay as they are.", [asset_id],
             body=[_f("application", "string", False, "The application."),
                   _f("tags", "array", False, "Replaces the tags."),
                   _f("no_scan", "boolean", False, "Never scan it."),
                   _f("no_scan_reason", "string", False, "Why not.")] + _DETAILS,
             body_example={"no_scan": True, "no_scan_reason": "Vendor hosted"},
             example=_ASSET),
        _ext("ext-bulk", "PATCH", "/external/assets", "Change many sites",
             "The same changes on every site in ids, all or nothing: if any site will not "
             "take a change, nothing is changed and the message names it.  Takes the same "
             "fields as changing one site.  tags_mode is add, remove or replace; "
             "comments_mode is replace or append; repositories_mode is add, replace or clear.",
             body=[_f("ids", "array", True, "The sites to change, up to 500.")] + _DETAILS + [
                 _f("tags", "array", False, "Tags, as tags_mode says."),
                 _f("tags_mode", "string", False, "add, remove or replace."),
                 _f("comments_mode", "string", False, "replace or append."),
                 _f("repositories_mode", "string", False, "add, replace or clear."),
                 _f("no_scan", "boolean", False, "Never scan them."),
                 _f("no_scan_reason", "string", False, "Why not.")],
             body_example={"ids": [12, 14, 15], "environment": "dev",
                           "technical_owner": "team@example.com",
                           "tags": ["ecommerce"], "tags_mode": "add", "whitelist_needed": True},
             example={"changed": 3, "hosts": ["a.example.com", "b.example.com", "c.example.com"]}),
        _ext("ext-delete", "DELETE", "/external/assets/{asset_id}", "Remove a site",
             "Removes the site and its scan history.  409 while a scan runs.",
             [asset_id], example={}),
        _ext("ext-telemetry", "POST", "/external/assets/{asset_id}/telemetry",
             "Read telemetry again",
             "Queues a fresh read: DNS, ports, TLS, headers and a screenshot.  "
             "Passive for a site marked no scan.", [asset_id],
             example={"queued": True}),
        _ext("ext-scans", "GET", "/external/assets/{asset_id}/scans", "A site's scans",
             "Every dynamic scan of the site, newest first.", [asset_id] + PAGING,
             example={"total": 1, "limit": 100, "offset": 0, "scans": [_SCAN]}),
        _ext("ext-scan", "GET", "/external/assets/{asset_id}/scans/{scan_id}",
             "One scan", "One scan with its findings, which engines ran, and "
                         "the AI triage and what it cost.", [asset_id, scan_id],
             example=dict(_SCAN, findings=[{"title": "Git repository metadata is served",
                                            "severity": "high",
                                            "url": "https://shop.example.com/.git/HEAD"}])),
        _ext("ext-report", "GET", "/external/assets/{asset_id}/scans/{scan_id}/report.pdf",
             "Scan report (PDF)",
             "The PDF report on a finished scan this server ran: the grade, the OWASP "
             "Top 10 grades, scope, every finding with how to see it again, and the "
             "code behind the site.  404 for a scan run on a DAST server or recorded.",
             [asset_id, scan_id], example={"content_type": "application/pdf"}),
        _ext("ext-decide", "POST",
             "/external/assets/{asset_id}/scans/{scan_id}/findings/{key}/decision",
             "Decide on a finding",
             "Marks one finding as a false positive, gives it a new severity, or makes an "
             "exception until a date.  A false positive leaves the counts and the PDF; a new "
             "severity is what counts; an exception is not counted until it ends.  With "
             "persist, the default, it holds on every scan of the site that finds the same "
             "thing, new ones too.  With persist false it holds on this scan only, and wins "
             "there over the site's.  Answers with the scan, counted again.",
             [asset_id, scan_id, _p("key", "The finding's key, as the scan lists it.",
                                     where="path", example="9f2c41d0b7a3e5f18c6d2a4b0e7f3c91")],
             body=[_f("kind", "string", True, "false_positive, severity or exception."),
                   _f("reason", "string", True, "Why, in at least 10 characters."),
                   _f("severity", "string", False, "For severity: critical, high, medium, "
                                                    "low or info, not what it was found as."),
                   _f("expires", "string", False, "For exception: the day it ends, "
                                                   "YYYY-MM-DD, at most 365 days out."),
                   _f("persist", "boolean", False, "False for this scan only.  Default true.")],
             body_example={"kind": "severity", "severity": "medium",
                           "reason": "Needs a signed in session first."},
             example=dict(_SCAN, findings=[{"title": "Reflected XSS in q", "severity": "medium",
                                            "severity_found": "high",
                                            "key": "9f2c41d0b7a3e5f18c6d2a4b0e7f3c91",
                                            "decision": {"kind": "severity", "severity": "medium",
                                                         "persist": True}}])),
        _ext("ext-undecide", "DELETE",
             "/external/assets/{asset_id}/scans/{scan_id}/findings/{key}/decision",
             "Revert a finding to original",
             "Takes back the decision that holds on this scan: its own if it has one, which "
             "lets the site's show again, or else the site's.  Answers 204.  404 when there is none.",
             [asset_id, scan_id, _p("key", "The finding's key, as the scan lists it.",
                                     where="path", example="9f2c41d0b7a3e5f18c6d2a4b0e7f3c91")],
             example={}),
        _ext("ext-record", "POST", "/external/assets/{asset_id}/scans", "Record a scan",
             "Records a scan run elsewhere: its severity, result address, when it "
             "ran and which server ran it.  Becomes the site's last scan when it "
             "is the newest.", [asset_id], body=_RECORD_BODY,
             body_example={"server": "nextgen-dast", "severity": "high",
                           "result_url": "https://dast.example.com/assessment/88",
                           "scanned_at": "2026-11-01T02:00:00Z",
                           "counts": {"high": 1, "medium": 3}}, example=_SCAN),
        _ext("ext-record-host", "POST", "/external/scans", "Record a scan by host",
             "The same, by host name, for a server that does not know the ids "
             "here.  404 for a host that is not listed, unless create is true.",
             body=[_f("host", "string", True, "The host that was scanned."),
                   _f("create", "boolean", False, "Add the host when it is not listed.")]
             + _RECORD_BODY,
             body_example={"host": "shop.example.com", "server": "nextgen-dast",
                           "severity": "medium", "create": True}, example=_SCAN),
        _ext("ext-schedules", "GET", "/external/assets/{asset_id}/schedules", "A site's schedules",
             "Every scheduled scan of the site, with its next and last run, and the time "
             "zone the times are read in.", [asset_id],
             example={"time_zone": "America/Chicago", "schedules": [{
                 "id": 3, "frequency": "weekly", "when": "Every Saturday at 02:00",
                 "profile": "quick", "authenticated": False, "ai_triage": True, "enabled": True,
                 "next_run_at": "2026-11-07T08:00:00+00:00", "last_run_at": None,
                 "last_result": ""}]}),
        _ext("ext-schedule-add", "POST", "/external/assets/{asset_id}/schedules", "Schedule a scan",
             "Scan the site once, or every day, week or month.  Times are read in the "
             "time zone set in Settings.  A run that finds the site already being scanned, "
             "or no longer allowed to be, is skipped and says so.", [asset_id],
             body=[_f("frequency", "string", True, "once, daily, weekly or monthly."),
                   _f("time_of_day", "string", True, "HH:MM."),
                   _f("run_on", "string", False, "once: the date, YYYY-MM-DD."),
                   _f("weekday", "integer", False, "weekly: 0 is Monday."),
                   _f("day_of_month", "integer", False, "monthly: 1 to 31; past the end "
                                                        "of a short month it runs on its last day."),
                   _f("profile", "string", False, "The site's default when left out."),
                   _f("authenticated", "boolean", False, "Sign in with the site's scan sign in."),
                   _f("ai", "boolean", False, "Triage each scan with the model."),
                   _f("confirm", "boolean", False, "Needed for standard and up, and for a "
                                                   "signed in scan past baseline.")],
             body_example={"frequency": "weekly", "weekday": 5, "time_of_day": "02:00",
                           "profile": "quick", "ai": True},
             example={"id": 3, "when": "Every Saturday at 02:00",
                      "next_run_at": "2026-11-07T08:00:00+00:00"}),
        _ext("ext-schedule-delete", "DELETE", "/external/assets/{asset_id}/schedules/{schedule_id}",
             "Remove a schedule", "Stops the schedule.  Scans it already ran are kept.",
             [asset_id, _p("schedule_id", "The schedule's id.", where="path", kind="integer",
                           example=3)], example={}),
        _ext("ext-start", "POST", "/external/assets/{asset_id}/dast", "Start a scan",
             "Starts a scan on this server or on a nextgen-dast server.  409 for a "
             "site that may not be scanned or already has one running.  Standard "
             "and up, and any DAST server, send attack payloads and need confirm.",
             [asset_id],
             body=[_f("profile", "string", False, "baseline, quick, standard, "
                                                  "thorough or premium.  The site's default "
                                                  "when left out."),
                   _f("authenticated", "boolean", False, "Sign in with the site's scan "
                                                         "sign in.  On by default when it "
                                                         "has one."),
                   _f("server", "string", False, "builtin, or a nextgen-dast server's name."),
                   _f("confirm", "boolean", False, "True to say you may scan it."),
                   _f("ai", "boolean", False, "True to have the model triage the "
                                              "findings when it ends.  Counted on "
                                              "the AI cost page.")],
             body_example={"profile": "quick", "ai": True},
             example=dict(_SCAN, source="builtin", status="queued", severity="")),
    ]


def grouped() -> list:
    """-> [(group, blurb, [endpoint, ...])] for the page.

    The examples are turned into text here rather than in the template, so the
    page shows exactly what json.dumps writes and nothing escaped twice.
    """
    import json

    every = endpoints()
    for e in every:
        e["example_text"] = json.dumps(e["example"], indent=2)
        if e.get("body_example") is not None:
            e["body_text"] = json.dumps(e["body_example"], indent=2)
    return [(name, blurb, [e for e in every if e["group"] == name])
            for name, blurb in GROUPS]


# --- OpenAPI ----------------------------------------------------------------

def _schema_for(param) -> dict:
    schema = {"type": param["type"]}
    if param.get("enum"):
        schema["enum"] = list(param["enum"])
    if param.get("default") is not None:
        schema["default"] = param["default"]
    return schema


def openapi(server_url: str) -> dict:
    """An OpenAPI 3.0 document, for Swagger UI and code generators."""
    paths = {}
    for e in endpoints():
        operation = {
            "operationId": e["id"],
            "tags": [e["group"]],
            "summary": e["summary"],
            "description": e["description"] + (
                f"  Token scope: {e['scope']}." if e["scope"] else
                "  Any token scope."),
            "parameters": [{
                "name": p["name"], "in": p["in"], "required": bool(p["required"]),
                "description": p["description"], "schema": _schema_for(p),
                **({"example": p["example"]} if p.get("example") is not None else {}),
            } for p in e["params"]],
            "responses": {
                str(e.get("status", 200)): {
                    "description": "OK",
                    "content": {"application/json": {"example": e["example"]}}},
                "401": {"description": "No token, or one that will not do."},
                "403": {"description": "The account behind the token is not allowed this."},
            },
        }
        if any(p["in"] == "path" for p in e["params"]):
            operation["responses"]["404"] = {"description": "Not found, or not yours to see."}
        if e.get("body"):
            properties = {}
            for field in e["body"]:
                prop = {"type": field["type"], "description": field["description"]}
                if field.get("enum"):
                    prop["enum"] = field["enum"]
                if field["type"] == "array":
                    prop["items"] = {"type": "object"}
                properties[field["name"]] = prop
            operation["requestBody"] = {
                "required": True,
                "content": {"application/json": {
                    "schema": {"type": "object", "properties": properties,
                               "required": [f["name"] for f in e["body"]
                                            if f["required"]]},
                    "example": e["body_example"]}},
            }
            operation["responses"]["400"] = {"description": "Something in the body will not do."}
        paths.setdefault(e["path"], {})[e["method"].lower()] = operation

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Git Code Review API",
            "version": VERSION,
            "description": "Send a token made on the IDE tokens page as "
                           "Authorization: Bearer <token>.  Every answer is "
                           "limited to what the token's owner can see.",
        },
        "servers": [{"url": server_url}],
        "components": {"securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"}}},
        "security": [{"bearer": []}],
        "tags": [{"name": name, "description": blurb} for name, blurb in GROUPS],
        "paths": paths,
    }


# --- Postman ----------------------------------------------------------------

def postman(server_url: str) -> dict:
    """A Postman 2.1 collection.  The token goes in the token variable."""
    import json

    folders = []
    for name, blurb, items in grouped():
        requests = []
        for e in items:
            segments = []
            for part in e["path"].strip("/").split("/"):
                if part.startswith("{") and part.endswith("}"):
                    segments.append(":" + part[1:-1])
                else:
                    segments.append(part)
            path_vars = [{"key": p["name"],
                          "value": str(p["example"] if p.get("example") is not None else ""),
                          "description": p["description"]}
                         for p in e["params"] if p["in"] == "path"]
            query = [{"key": p["name"],
                      "value": str(p["default"] if p.get("default") is not None else ""),
                      "description": p["description"],
                      "disabled": p.get("default") is None}
                     for p in e["params"] if p["in"] == "query"]
            raw = "{{baseUrl}}/" + "/".join(segments)
            request = {
                "method": e["method"],
                "header": [{"key": "Accept", "value": "application/json"}],
                "description": e["description"],
                "url": {"raw": raw, "host": ["{{baseUrl}}"], "path": segments,
                        "query": query, "variable": path_vars},
            }
            if e.get("body_example") is not None:
                request["header"].append({"key": "Content-Type",
                                          "value": "application/json"})
                request["body"] = {"mode": "raw",
                                   "raw": json.dumps(e["body_example"], indent=2),
                                   "options": {"raw": {"language": "json"}}}
            requests.append({"name": e["summary"], "request": request})
        folders.append({"name": name, "description": blurb, "item": requests})

    return {
        "info": {
            "name": "Git Code Review API",
            "description": "Set the token variable to a token from the IDE "
                           "tokens page.",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "auth": {"type": "bearer",
                 "bearer": [{"key": "token", "value": "{{token}}", "type": "string"}]},
        "variable": [{"key": "baseUrl", "value": server_url},
                     {"key": "token", "value": ""}],
        "item": folders,
    }
