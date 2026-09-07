"""Settings that live in the database.

An admin changes these from the Settings page and they persist in the volume,
which is where site specific things belong.  The scanner still wants a JSON
file, so we build one from these rows when a scan starts and delete it after.

Secrets are encrypted with the app key rather than sitting in plain text next
to everything else.  Somebody who reads the database file still needs the key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.config import settings as env_settings
from app.core.models import Setting, utcnow

log = logging.getLogger("gcr.settings")

# key, default, is_secret, what it is
DEFAULTS = {
    # ---- how to reach github ----
    "github.api_url":          ("https://api.github.com", False,
                                "Change this for GitHub Enterprise Server."),
    "github.web_url":          ("https://github.com", False,
                                "Where finding links point."),
    "github.auth_method":      ("pat", False, "pat or app."),
    "github.token":            ("", True, "A personal access token. Stored encrypted."),
    "github.app_id":           ("", False, "GitHub App id."),
    "github.app_installation": ("", False, "Installation id. Leave empty to look it up."),
    "github.app_key":          ("", True, "The App private key, PEM. Stored encrypted."),
    "github.parallel_repos":   (4, False, "Repositories scanned at once."),

    # ---- what the generated reports say they are ----
    #
    # These go outside the security team, to people who will read the covering
    # page and not much else, so the document has to name whose assessment it
    # is.  Left empty it says nothing rather than guessing, because a report
    # branded with the wrong name is worse than one branded with none.
    "report.organization_name": ("", False,
                                 "The name on the cover of generated reports."),
    "report.logo":              ("", False,
                                 "A logo for the reports, as a data URI or an https link."),
    "report.footer":            ("", False,
                                 "A line at the foot of every page, for a classification marking or similar."),

    # ---- what to scan ----
    "scan.organizations":      ([], False,
                                "Organizations to scan. Empty means every one the credential can see."),
    "scan.repositories":       ([], False,
                                "Specific repositories, as owner/name. Overrides organizations when set."),
    "scan.exclude_repos":      ([], False, "Repositories to skip."),
    "scan.include_archived":   (False, False, "Scan archived repositories too."),
    "scan.include_forks":      (False, False, "Scan forks too."),
    "scan.max_repos":          (0, False, "Stop after this many repositories. 0 means no limit."),
    "scan.timeout_per_repo":   (3600, False, "Give up on a repository after this many seconds."),
    # The ceiling on the whole run, as opposed to one repository inside it.
    # This existed as an environment variable nobody could reach from here,
    # while the message a scan died with told somebody to raise it on this
    # page.  It is on this page now.
    "scan.max_hours":          (6, False,
                                "Give up on the whole scan after this many hours. "
                                "A run that hits this keeps what finished."),
    # Threads inside one repository, as opposed to repositories at once.
    # Both were fixed numbers chosen for a small machine, and on a large one
    # they leave most of it idle while a scan takes all night.
    "code.jobs":               (2, False,
                                "Processes semgrep may use on one repository."),
    "secrets.concurrency":     (8, False,
                                "Threads trufflehog may use on one repository."),
    "scan.max_concurrent":     (1, False,
                                "How many scans may run at once. One keeps the old "
                                "behavior. Raising it lets a slow organization stop "
                                "holding up the rest of the night; scans on the same "
                                "connection still share one rate limit budget."),
    "clone.max_repo_size_mb":  (4096, False, "Skip repositories bigger than this. 0 means no limit."),
    "secrets.max_file_mb":     (25, False,
                                "Skip files bigger than this when looking for credentials. "
                                "Different from the repository limit above: this one applies "
                                "to each file inside a repository that is being scanned. "
                                "0 means no limit."),

    # How much history one run walks in a repository, in days, newest first.
    #
    # Zero is one pass over everything, which is right until a repository is
    # too large to finish inside the time limit: then that pass is killed, the
    # whole walk is thrown away, and the next run starts from the newest commit
    # and gets no further.  A window is walked, recorded, and continued next
    # time, so the far end of a large history is reached eventually rather than
    # never.
    "secrets.history_window_days": (0, False,
                                    "Days of history to walk per run, newest first. "
                                    "0 walks all of it in one pass."),

    # Using the quiet hours to finish histories nobody has walked to the end.
    #
    # A windowed walk reaches the far end of a large repository one run at a
    # time, and on a nightly schedule that is one window a night.  The machine
    # is idle the rest of the day.  This spends that time on the repositories
    # that are furthest from finished, and gets out of the way the moment real
    # work arrives.
    # On by default, and harmless there: it can do nothing at all until a
    # history window is set, and the window defaults to off.  Somebody who sets
    # one has already said their histories do not fit in a single run, and
    # making them find a second switch to finish the job the first one started
    # is friction that buys no safety.
    "catchup.enabled":         (True, False,
                                "Use idle time to keep walking histories that are "
                                "not finished yet."),
    "catchup.repos_per_run":   (5, False,
                                "How many unfinished repositories one catch up pass takes."),

    # Paths the code pass does not read.
    #
    # Generated output is where precision goes to die.  One repository on a
    # real estate produced 22,048 findings of a single low confidence rule,
    # every one of them the boilerplate of a test report written fresh on each
    # run: 69% of every code finding across that whole estate, none of it
    # anything anybody could act on.  semgrep's own defaults already skip
    # node_modules and vendor; what they cannot skip is generated output,
    # because its directory is named by whatever tool wrote it.
    #
    # Kept conservative, and never silent: the scan says how many findings the
    # list dropped, so a rule that stops reporting is visible rather than
    # mysterious.
    "code.exclude_paths":      (["reports/", "test-results/", "allure-results/",
                                 "coverage/", "screenshots/", "videos/"], False,
                                "Paths the code pass skips. Generated output, "
                                "not source."),

    # The same idea for credentials, and it needed saying separately because
    # the two passes cost very differently.  A generated directory turns one
    # low confidence code rule into thousands of findings, which is annoying.
    # It turns a credential scan into one that does not finish at all: every
    # candidate is fingerprinted, entropy scored and checked against the branch
    # heads one at a time, so a repository of recorded test traffic can spend
    # nine hours and report nothing.
    #
    # Session recordings and archives are here by default and the two other
    # lists do not carry them, because they are the shapes that only hurt on
    # this pass.  A .har is a transcript of requests with every Authorization
    # header and cookie in it, and a .zip is a container whose contents cannot
    # be pointed at by line number even when something is found.
    # A ceiling on how much diff a history walk may hand the engines.
    #
    # The clone size limit asks how big a repository is on disk, which is the
    # wrong question for the pass that reads history.  Two hundred and fourteen
    # megabytes of git, six hundred and ninety commits, and sixteen and a half
    # gigabytes of diff on the way into the engine, because every commit
    # rewrote generated artifacts whole.  It passed the size check and then
    # spent nine hours and twenty eight gigabytes of memory not finishing.
    #
    # Over this and the credential pass reads branch heads instead of history:
    # the current state of every branch, which is where a live credential is,
    # without the walk back through commits that cannot be done at all.
    "secrets.max_history_mb":  (8192, False,
                                "Give up on walking a repository's history "
                                "past this much diff. 0 is no limit."),

    # How long a worker may read and write nothing while still using the
    # processor before it is treated as stuck rather than slow.
    #
    # The per repository limit cannot tell those apart, so both get the whole
    # of it.  An engine that has stopped consuming its input, stopped producing
    # output and settled at a fixed amount of memory is not going to finish,
    # and every one of those is visible from outside the process.
    "scan.stall_minutes":      (30, False,
                                "Stop a repository whose engines have gone "
                                "quiet but are still burning processor. "
                                "0 never does."),

    "secrets.exclude_paths":   (["result*/", "Blueprint/", "AppvanceScripts/",
                                 "reports/", "test-results/", "allure-results/",
                                 "coverage/", "screenshots/", "videos/",
                                 "*.har", "*.zip", "*.log", "*.bak"], False,
                                "Paths the credential pass skips. Generated "
                                "output and recorded traffic, not source."),

    # ---- branches ----
    "branches.mode":           ("all", False, "all, default, or list."),
    "branches.include":        ([], False, "Branch globs to include when the mode is list."),
    "branches.exclude":        (["dependabot/*", "renovate/*", "gh-readonly-queue/*"], False,
                                "Branch globs to skip."),
    "branches.full_history":   (True, False, "Walk every commit, not just the branch heads."),
    # Both off by default, because a limit nobody asked for is a limit that
    # quietly stops finding things.  They are here for estates where a single
    # repository carries thousands of branches, which is slow to scan and
    # writes a very large branch list onto every finding in it.
    "branches.max_per_repo":   (0, False,
                                "Most branches to scan in one repository, newest first.  "
                                "0 is all of them."),
    "branches.stale_days":     (0, False,
                                "Skip branches with no commit in this many days.  "
                                "0 keeps every branch however old."),

    # ---- how hard to look ----
    "secrets.enabled":         (True, False, "Look for credentials."),
    "secrets.verify":          (True, False,
                                "Send candidate credentials to the provider that issued them to see if they are live."),
    "secrets.min_entropy":     (3.0, False,
                                "Bits per character below which a value is treated as a placeholder."),
    "secrets.min_length":      (12, False,
                                "Shorter than this and a value is treated as a placeholder."),
    "secrets.drop_below_entropy": (True, False,
                                "Whether low entropy on its own is enough to call something a "
                                "placeholder, or only counts alongside one of the patterns."),
    "secrets.resolve_authors": (True, False,
                                "Find the account behind each commit that introduced a credential."),
    "code.enabled":            (True, False, "Run static analysis."),
    # security-audit is deliberately not here.  94% of its rules are already
    # in p/default and nothing high fidelity is unique to it, so a new install
    # loses nothing worth having by starting without it.  It is one tick away.
    #
    # Note for anyone tempted to trim further: p/default stays on.  It is
    # where the high fidelity rules live, and the two rules people complain
    # about most, unlink-use and plaintext-http-link, are inside it.  Dropping
    # the pack to be rid of them costs a thousand good rules to lose two bad
    # ones; that is what the mute list and the severity overrides are for.
    "code.rulesets":           (["p/default", "p/owasp-top-ten", "p/secrets",
                                 "p/javascript", "p/typescript", "p/nodejs", "p/python",
                                 "p/java", "p/php", "p/golang", "p/xss", "p/sql-injection",
                                 "p/command-injection"], False, "semgrep rulesets."),
    "sbom.enabled":            (True, False, "Build SBOMs and collect license data."),
    "sbom.enrich":             (["all"], False,
                                "Look declared dependencies up on their registries to get real "
                                "licenses.  all, or any of golang, java, javascript, python, "
                                "vcpkg.  Empty means look nothing up."),
    "sbom.scan_branches":      ("default", False,
                                "default branch only, or all for one SBOM per branch."),
    "sbom.denied_licenses":    (["AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0",
                                 "BUSL-1.1", "Commons-Clause"], False,
                                "Licenses that fail the policy."),
    "sbom.flagged_licenses":   (["GPL-2.0-only", "GPL-3.0-only", "GPL-3.0-or-later",
                                 "LGPL-3.0-only", "CDDL-1.0", "EPL-2.0", "MPL-2.0"], False,
                                "Licenses that get flagged for review."),
    "images.enabled":          (False, False,
                                "Read the base image each Dockerfile names. Finds what the "
                                "operating system layer carries, which is where most of a "
                                "critical count usually lives. Pulls images from their "
                                "registries, so it is off until you want it."),
    "vulns.enabled":           (True, False, "Match packages against vulnerability databases."),
    "vulns.min_severity":      ("all", False, "Report at or above this. all keeps everything."),
    "access.enabled":          (True, False, "Collect who can reach each repository."),
    "pulls.enabled":           (True, False, "Collect pull request history."),
    "exclusions.enabled":      (True, False, "Apply the exclusions from the Exclusions page."),

    # ---- exploitation data ----
    "intel.enabled":           (True, False,
                                "Rank findings with the CISA exploited list and EPSS scores. Both are free."),
    "intel.kev_url":           ("https://www.cisa.gov/sites/default/files/csv/"
                                "known_exploited_vulnerabilities.csv", False,
                                "The CISA known exploited vulnerabilities feed."),
    "intel.epss_url":          ("https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
                                False, "The daily EPSS scores feed."),
    "intel.max_age_hours":     (24, False, "Refetch the feeds when the copy on disk is older than this."),

    # ---- where output goes ----
    "output.dir":              ("/out", False,
                                "Where the report files are written. Mount this as a volume."),
    "output.per_repo_files":   (True, False, "Write a report per repository as well as the combined one."),
    "output.include_clean":    (True, False, "List repositories with nothing wrong in them."),

    # ---- staying under the api limit ----
    "rate.min_remaining":      (100, False, "Stop and wait when the hourly budget gets this low."),
    "rate.adaptive_pacing":    (True, False,
                                "Slow down as the budget runs out instead of stalling at zero."),
    "rate.max_sleep_sec":      (3900, False,
                                "Longest wait for the limit to reset. Has to be over 3600."),
    "rate.retries":            (5, False, "Retries per request."),
    # ---- how people sign in ----
    "auth.mode":               ("", False, "local, oidc, or both. Empty follows GCR_AUTH_MODE."),
    "oidc.issuer":             ("", False, "The provider's base address, the one that serves the discovery document."),
    "oidc.client_id":          ("", False, "The application id your provider issued."),
    "oidc.client_secret":      ("", True, "The client secret. Stored encrypted."),
    "oidc.redirect_url":       ("", False, "Where the provider sends people back to. Has to match the provider exactly."),
    "oidc.scopes":             ("openid profile email groups", False, "Scopes asked for at sign in."),
    "oidc.group_claim":        ("groups", False, "The claim the group names arrive in."),
    "oidc.admin_groups":       ([], False, "Groups that get the admin role."),
    "oidc.developer_groups":   ([], False, "Groups that get the developer role."),
    "oidc.reader_groups":      ([], False, "Groups that get the reader role."),
    "oidc.default_role":       ("", False,
                                "Role for somebody the provider vouched for who is in none of "
                                "the groups above. Empty refuses them, which is the safe way "
                                "round. Only set this when the provider cannot send group "
                                "names and the application is restricted on its side."),

    # ---- sessions and the network in front ----
    "session.hours":           (12, False, "How long a session lasts."),
    "session.idle_minutes":    (60, False, "Sign somebody out after this long doing nothing. 0 never does."),
    "login.attempt_limit":     (5, False, "Wrong passwords before the account locks."),
    "login.lockout_minutes":   (15, False, "How long the lock lasts."),
    "security.force_https":    (True, False, "Mark cookies secure and send HSTS. Leave on behind TLS."),
    "security.trusted_proxies": ([], False,
                                "Addresses the load balancer connects from. X-Forwarded-For is believed from these and nowhere else."),

    # ---- what the systems being scanned hold ----
    "sensitivity.labels":      (["PCI", "HIPAA", "SOX", "Customer Data", "PII",
                                 "CUI", "Login", "Public"], False,
                                "The labels a connection can carry, and the ones an "
                                "exception can be told not to cover. Yours to "
                                "choose: these are a starting point, not a fixed list."),

    # ---- rules that report a pattern rather than a problem ----
    # Written back after every save so the page has something to show, and
    # read by nobody: rule_mutes.effective() is the answer.  A default here
    # would be a second opinion that never reaches the scanner.
    "code.muted_rules":        ([], False,
                                "Rules set aside as advisory. They still run and are still "
                                "recorded with a reason; they just do not sit in the work "
                                "list. Empty this to see everything."),

    # ---- telling somebody, without waiting for them to log in ----
    "notify.enabled":          (False, False,
                                "Send a message when a scan finds something new."),
    "notify.min_severity":     ("high", False,
                                "The floor for the digest. A verified credential, a "
                                "vulnerability on the exploited list and a malicious "
                                "package go out whatever this says."),
    "notify.base_url":         ("", False,
                                "Where this installation is reachable, so a message can "
                                "link to the finding. Without it a message has no link."),
    "notify.slack_webhook":    ("", True, "A Slack incoming webhook. Stored encrypted."),
    "notify.teams_webhook":    ("", True, "A Teams incoming webhook. Stored encrypted."),
    "notify.webhook_url":      ("", True,
                                "Any other endpoint, sent JSON. Stored encrypted."),
    "notify.mail_transport":   ("smtp", False,
                                "smtp, or graph for Microsoft 365 through the Graph API."),
    "notify.email_to":         ("", False, "Where mail goes. Several, separated by commas."),
    # Microsoft 365, through the Graph API rather than SMTP.  Tenants with
    # basic authentication switched off have no SMTP to offer, and an app
    # registration with Mail.Send is the supported way in.
    "notify.graph_tenant":     ("", False, "The directory (tenant) id from the app registration."),
    "notify.graph_client_id":  ("", False, "The application (client) id."),
    "notify.graph_secret":     ("", True, "The client secret value. Stored encrypted."),
    "notify.graph_sender":     ("", False,
                                "The mailbox the message is sent as. The app registration "
                                "needs Mail.Send for it."),
    "notify.email_from":       ("", False, "The sender address."),
    "notify.smtp_host":        ("", False, "The mail server."),
    "notify.smtp_port":        (587, False, "587 for STARTTLS, 465 for SSL, 25 for neither."),
    "notify.smtp_security":    ("starttls", False, "starttls, ssl, or none."),
    "notify.smtp_user":        ("", False, "Leave empty for a server that does not ask."),
    "notify.smtp_password":    ("", True, "Stored encrypted."),

    # ---- how times are shown and when schedules fire ----
    "ui.timezone":             ("GMT", False,
                                "An IANA zone name such as America/New_York. Every time on "
                                "screen is shown in it, and a schedule's cron is read in it. "
                                "GMT leaves everything on UTC."),
}

# The settings the app reads on every request rather than only at scan time.
# live.py caches these.
LIVE_KEYS = [
    "auth.mode", "oidc.issuer", "oidc.client_id", "oidc.client_secret",
    "oidc.redirect_url", "oidc.scopes", "oidc.group_claim",
    "oidc.admin_groups", "oidc.developer_groups", "oidc.reader_groups",
    "oidc.default_role",
    "session.hours", "session.idle_minutes", "login.attempt_limit",
    "login.lockout_minutes", "security.force_https", "security.trusted_proxies",
    "ui.timezone",
]


# What the Settings page shows, in order.  Anything not listed here still
# works, it just does not get a box on the form.
SECTIONS = [
    ("GitHub", ["github.api_url", "github.web_url", "github.auth_method",
                "github.token", "github.app_id", "github.app_installation",
                "github.app_key"]),
    ("What to scan", ["scan.organizations", "scan.repositories",
                      "scan.exclude_repos", "scan.include_archived",
                      "scan.include_forks", "scan.max_repos"]),
    ("Branches", ["branches.mode", "branches.include", "branches.exclude",
                  "branches.full_history", "branches.max_per_repo",
                  "branches.stale_days"]),
    ("Detection", ["secrets.enabled", "secrets.verify", "secrets.min_entropy",
                   "secrets.resolve_authors", "secrets.exclude_paths",
                   "code.enabled", "code.rulesets",
                   "sbom.enabled", "sbom.enrich", "sbom.scan_branches",
                   "sbom.denied_licenses", "sbom.flagged_licenses",
                   "vulns.enabled", "vulns.min_severity", "access.enabled",
                   "pulls.enabled", "exclusions.enabled"]),
    ("Exploitation data", ["intel.enabled", "intel.kev_url", "intel.epss_url",
                           "intel.max_age_hours"]),
    ("Output", ["output.dir", "output.per_repo_files", "output.include_clean"]),
    ("Sign in", ["auth.mode", "oidc.issuer", "oidc.client_id",
                 "oidc.client_secret", "oidc.redirect_url", "oidc.scopes",
                 "oidc.group_claim", "oidc.admin_groups",
                 "oidc.developer_groups", "oidc.reader_groups",
                 "oidc.default_role"]),
    ("Sessions", ["session.hours", "session.idle_minutes",
                  "login.attempt_limit", "login.lockout_minutes",
                  "security.force_https", "security.trusted_proxies"]),
    ("Display", ["ui.timezone"]),
    ("Fidelity", ["code.muted_rules"]),
    ("Sensitivity labels", ["sensitivity.labels"]),
    ("Limits", ["github.parallel_repos", "scan.max_concurrent",
                "secrets.history_window_days",
                "scan.timeout_per_repo", "scan.max_hours", "code.jobs",
                "secrets.concurrency", "clone.max_repo_size_mb",
                "rate.min_remaining", "rate.adaptive_pacing",
                "rate.max_sleep_sec", "rate.retries"]),
]


# The semgrep packs somebody can turn on.  These are registry packs, fetched
# anonymously, no account needed.  A language pack only fires on files of that
# language, so leaving several on costs almost nothing.  A pack that is not
# there any more gets skipped with a warning instead of failing the scan.
# name, label, what it is, and what you are taking on.
#
# The last field is not decoration.  A pack that reports every use of an API is
# a different kind of thing from one that tracks tainted input to a sink, and
# somebody turning the first one on should know that before the first scan
# rather than after eight hundred findings.
RULESETS = [
    ("p/default",            "Default", "The general pack. Leave this on.", ""),
    ("p/security-audit",     "Security audit", "Broad security rules across every language.",
     "94% of this pack is rules Default already runs, so it changes less than "
     "the name suggests. What is unique to it targets C, Go, Ruby and Flask, "
     "and stays quiet on a codebase without them. Nothing high fidelity is "
     "unique to this pack, and if you are drowning in false positives, this "
     "is rarely where they come from."),
    ("p/owasp-top-ten",      "OWASP Top Ten", "The ten categories most reports ask about.", ""),
    ("p/secrets",            "Secrets", "Hardcoded credentials, a second opinion next to the secret engines.", ""),
    ("p/xss",                "Cross site scripting", "Unescaped output reaching a page.", ""),
    ("p/sql-injection",      "SQL injection", "Query strings built from input.", ""),
    ("p/command-injection",  "Command injection", "Shell calls built from input.", ""),
    ("p/jwt",                "JWT", "Token signing and checking mistakes.", ""),
    ("p/insecure-transport", "Insecure transport", "Plain HTTP and disabled certificate checks.", ""),
    ("p/javascript",         "JavaScript", "", ""),
    ("p/typescript",         "TypeScript", "", ""),
    ("p/nodejs",             "Node.js", "", ""),
    ("p/react",              "React", "", ""),
    ("p/python",             "Python", "", ""),
    ("p/django",             "Django", "", ""),
    ("p/flask",              "Flask", "", ""),
    ("p/java",               "Java", "", ""),
    ("p/kotlin",             "Kotlin", "", ""),
    ("p/php",                "PHP", "", ""),
    ("p/golang",             "Go", "", ""),
    ("p/ruby",               "Ruby", "", ""),
    ("p/csharp",             "C#", "", ""),
]

RULESET_NAMES = [entry[0] for entry in RULESETS]

# Rules that report every use of a thing rather than a misuse of it.  Muting is
# not the same as deleting: the finding is still recorded, with the reason, and
# is one filter away.  Anything not listed here is left alone.
# What a system can hold.  A starting vocabulary, not a fixed one: anything an
# organization needs to say can be typed in beside these.
# The default vocabulary, and the notes that explain each one.  What a given
# install actually uses lives in the settings, because an organization's own
# words for its own risk are not ours to fix.
SENSITIVITIES = [
    ("PCI",           "Cardholder data"),
    ("HIPAA",         "Protected health information"),
    ("SOX",           "Financial reporting"),
    ("Customer Data", "Anything belonging to a customer"),
    ("PII",           "Personal information"),
    ("CUI",           "Controlled unclassified information"),
    ("Login",         "Authentication, sessions or credentials"),
    ("Public",        "Nothing sensitive, published on purpose"),
]

SENSITIVITY_NAMES = [name for name, _note in SENSITIVITIES]
SENSITIVITY_NOTES = dict(SENSITIVITIES)


def sensitivity_labels(session) -> list:
    """The labels this install uses, falling back to the starting vocabulary.

    Labels, not levels: PCI does not sit above HIPAA, and a system can carry
    several at once.  Nothing here is ranked.
    """
    levels = [str(x).strip() for x in (get(session, "sensitivity.labels") or [])
              if str(x).strip()]
    return levels or list(SENSITIVITY_NAMES)

# The rules shipped set aside, and why.  Defined once, in the mute engine,
# because that is what decides whether they are in force; this is the same
# dictionary under the name the settings page has always used for it.
from app.core.rule_mutes import SHIPPED as MUTED_RULE_NOTES  # noqa: E402


# Stretching the app key takes real work by design, so do it once.
_key_cache = {}

# Enough rounds to make a short key expensive to guess, few enough that a page
# load does not notice.  Raise it later and old values still open: the key
# below it stays in the chain.
_KDF_ROUNDS = 600_000
_KDF_SALT = b"gcr-settings-encryption-v1"


def _fernet() -> MultiFernet:
    """The key that encrypts secrets in the database.

    GCR_ENCRYPTION_KEY out of .env, falling back to the session key when nobody
    set one.  Whoever reads the database file still needs this to get anything
    out of the token column.

    The key is stretched with PBKDF2 rather than hashed once.  When somebody
    sets a real random key the two are much the same, but people type
    passphrases into .env, and a single sha256 of a short passphrase is cheap
    to guess offline.  Stretching it is not.

    The old single-hash key is kept second in the chain so anything already
    encrypted still opens.  New values are written with the stretched key,
    which is the first one.  Saving a secret again quietly upgrades it.
    """
    raw = env_settings.encryption_key.encode()
    cached = _key_cache.get(raw)
    if cached is not None:
        return cached

    stretched = hashlib.pbkdf2_hmac("sha256", raw, _KDF_SALT, _KDF_ROUNDS)
    legacy = hashlib.sha256(raw).digest()
    chain = MultiFernet([
        Fernet(base64.urlsafe_b64encode(stretched)),
        Fernet(base64.urlsafe_b64encode(legacy)),
    ])
    _key_cache[raw] = chain
    return chain


def _encrypt(value: str) -> str:
    if not value:
        return ""
    return _fernet().encrypt(value.encode()).decode()


def _decrypt(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode()).decode()
    except (InvalidToken, ValueError):
        # Usually means the app key changed.  Better to behave as though it is
        # unset than to hand the scanner something that is not a credential.
        log.warning("could not decrypt a stored secret, treating it as empty")
        return ""


def default_for(key: str):
    entry = DEFAULTS.get(key)
    return entry[0] if entry else None


def is_secret(key: str) -> bool:
    entry = DEFAULTS.get(key)
    return bool(entry and entry[1])


def timezone_choices() -> list:
    """Zone names for the Settings picker, the common ones first.

    A flat alphabetical list of five hundred zones buries the handful anybody
    here actually wants, so the ones in use lead and the rest follow.
    """
    try:
        from zoneinfo import available_timezones
        every = sorted(available_timezones())
    except Exception:
        return ["GMT", "UTC"]

    common = ["GMT", "UTC", "America/New_York", "America/Chicago",
              "America/Denver", "America/Los_Angeles", "America/Phoenix",
              "America/Anchorage", "Pacific/Honolulu", "Europe/London",
              "Europe/Dublin", "Europe/Paris", "Europe/Berlin", "Asia/Kolkata",
              "Asia/Singapore", "Asia/Tokyo", "Australia/Sydney"]
    head = [z for z in common if z in every]
    return head + [z for z in every if z not in head]


def describe(key: str) -> str:
    entry = DEFAULTS.get(key)
    return entry[2] if entry else ""


def get(session, key: str, fallback=None):
    row = session.query(Setting).filter(Setting.key == key).one_or_none()
    if row is None:
        return default_for(key) if fallback is None else fallback

    raw = row.value or ""
    if row.is_secret:
        raw = _decrypt(raw)
        return raw
    try:
        return json.loads(raw) if raw != "" else default_for(key)
    except (ValueError, TypeError):
        return default_for(key)


# Told apart from a stored empty string.
MISSING = object()


def stored(session, key):
    """What is actually in the table, or MISSING if nobody ever set it.

    get() fills in a default, which is right for the scan settings.  It is
    wrong for anything that also has an environment variable behind it: a
    default would quietly beat what somebody put in .env, and they would never
    work out why.
    """
    row = session.query(Setting).filter(Setting.key == key).one_or_none()
    if row is None:
        return MISSING
    raw = row.value or ""
    if row.is_secret:
        return _decrypt(raw)
    if raw == "":
        return MISSING
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return MISSING



def set_value(session, key: str, value, actor: str = "") -> bool:
    """Store it.  -> whether this actually changed anything.

    The answer is worth having.  A settings page posts every field every time,
    so "settings saved" on its own says nothing about what moved, and an audit
    log that cannot say which setting changed is not much of an audit log.
    """
    row = session.query(Setting).filter(Setting.key == key).one_or_none()
    if row is None:
        row = Setting(key=key)
        session.add(row)

    secret = is_secret(key)
    was = row.value
    row.is_secret = secret
    if secret:
        # An empty submission leaves what is already there, so somebody editing
        # the page does not blank the token just by not retyping it.
        if value == "":
            return False
        row.value = _encrypt(str(value))
        # Encryption is not deterministic, so the ciphertext always differs.
        # Somebody typing into a secret field meant to change it.
        row.updated_by = actor or ""
        return True
    row.value = json.dumps(value)
    row.updated_by = actor or ""
    return row.value != was
    row.updated_at = utcnow()


def all_values(session, include_secrets: bool = False) -> dict:
    """Every setting, defaults filled in for anything never set."""
    out = {}
    for key in DEFAULTS:
        if is_secret(key) and not include_secrets:
            stored = get(session, key)
            out[key] = "set" if stored else ""
        else:
            out[key] = get(session, key)
    return out


def readiness(session) -> dict:
    """What is still missing before a scan can run.

    Plain sentences, because "configuration is invalid" tells nobody anything.
    Each one says what to do, not what failed.

    Credentials live on the Connections page now, one per account, so that is
    what this asks about.
    """
    from app.core import connections as connection_store

    rows = connection_store.all_connections(session)
    missing = []

    if not rows:
        missing.append(
            "No accounts yet. Add one on the Connections page: a name, the "
            "organization, and a token that can read it. A fine grained token "
            "reaches one organization, so add one per organization.")
    else:
        unset = [row.name for row in rows
                 if not connection_store.configured(row)]
        if unset:
            missing.append(
                "These accounts have no working credential: "
                + ", ".join(unset[:5])
                + ". Open each on the Connections page and paste a token in.")
        if not any(row.enabled and connection_store.configured(row)
                   for row in rows):
            missing.append(
                "Every account is either switched off or missing a credential, "
                "so a scan would have nothing to do.")

    return {"ready": not missing, "missing": missing}


def configured(session) -> bool:
    """Has anybody set this up yet.

    Somewhere to scan and a way to reach GitHub is the minimum.
    """
    has_scope = bool(get(session, "scan.organizations")
                     or get(session, "scan.repositories"))
    method = get(session, "github.auth_method")
    if method == "app":
        has_auth = bool(get(session, "github.app_id") and get(session, "github.app_key"))
    else:
        has_auth = bool(get(session, "github.token"))
    return has_scope and has_auth
