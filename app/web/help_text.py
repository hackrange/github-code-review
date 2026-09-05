"""What each part of the Settings page is for, in a dialog rather than a wiki.

Settings pages go stale the moment the documentation lives somewhere else.  The
text here sits next to the fields it describes and ships with them, so a change
to a field and a change to its explanation are the same commit.

Each entry is a section of the page:

    title     what the dialog is called
    what      what the setting does, in a sentence or three
    caution   what goes wrong if it is set carelessly, when something does

`caution` is left out when there is nothing honest to put in it.  A warning on
every section is a warning on none of them.

The order here is the order the links across the top of the page appear in, and
it has to match the order of the cards down the page.
"""

from __future__ import annotations

# key -> (nav label, title, what, caution)
SECTIONS = [
    ("accounts", "Accounts", {
        "title": "Accounts and credentials",
        "what": [
            "Every scan runs as some account, and those live on the Connections "
            "page rather than here, one row per credential.",
            "This matters more on GitHub Enterprise than people expect.  A fine "
            "grained token reaches exactly one organization, whatever the scopes "
            "say, so an estate spread across several needs one connection for "
            "each.  Every finding records which connection found it.",
        ],
        "caution": "A token with more reach than the work needs is the most "
                   "common way a scanner becomes the thing worth attacking. "
                   "Read only, and no wider than the organizations you mean "
                   "to scan.",
    }),
    ("scan", "What to scan", {
        "title": "What to scan",
        "what": [
            "Which repositories each account covers is set on the connection "
            "itself.  What is here applies on top of that: repositories to skip, "
            "whether archived ones and forks are included, and a cap on how many "
            "are looked at in one run.",
            "The repository limit is for a first run.  Set it to something small, "
            "see what comes back and how long it takes, then set it to 0.",
        ],
        "caution": "Archived does not mean harmless.  A credential committed to "
                   "a repository nobody maintains is still live, and nobody is "
                   "watching that one.",
    }),
    ("branches", "Branches", {
        "title": "Branches",
        "what": [
            "Which branches are cloned and walked, and how far back through each "
            "one.",
            "Walking the full history is the setting that earns its keep.  A "
            "credential that was committed and then taken out in the next commit "
            "is still in the history, still valid, and invisible to anything that "
            "only looks at what the branch says today.",
            "The two limits are for large estates.  A repository that has "
            "collected thousands of branches takes a long time to walk, and a "
            "finding in an old commit is reachable from all of them, so the "
            "branch list stored against it gets very long.  Skipping branches "
            "nobody has touched in months cuts both, and loses less than "
            "dropping to the default branch does.",
        ],
        "caution": "Turning full history off makes scans faster and makes them "
                   "miss exactly the credentials most worth finding: the ones "
                   "somebody already noticed and thought they had removed.",
    }),
    ("credentials", "Credentials", {
        "title": "Credentials",
        "what": [
            "Finding keys, tokens and passwords in the code and in the history. "
            "Three engines run: gitleaks, trufflehog, and GitHub's own secret "
            "scanning alerts where the plan includes them.",
            "Verification is what separates a live key from an example.  Each "
            "candidate is sent to the provider that issued it to see whether it "
            "still works, and a verified finding is graded on its own.",
            "The placeholder threshold is entropy in bits per character.  Below "
            "it a value is treated as an example.  Finer control over that lives "
            "on the Triage rules page.",
        ],
        "caution": "Verification means this system makes outbound requests to "
                   "AWS, Slack, Stripe and whoever else issued the candidate. "
                   "That is traffic leaving your network, and on a restricted "
                   "one it needs to be allowed for deliberately.",
    }),
    ("code", "Code analysis", {
        "title": "Code analysis",
        "what": [
            "semgrep, with the rule packs ticked below.  They are fetched "
            "anonymously and need no account.",
            "A language pack only fires on files of that language, so leaving "
            "several on costs almost nothing.  Every finding then goes through "
            "this tool's own triage, which reads the surrounding code and says "
            "why it kept or set aside each one.",
        ],
        "caution": "A pack marked advisory reports a pattern rather than a "
                   "problem, and turning several of those on is the quickest "
                   "way to teach people that the list is not worth reading.",
    }),
    ("dependencies", "Dependencies", {
        "title": "Dependencies and licenses",
        "what": [
            "An SBOM per repository, the packages in it matched against "
            "vulnerability databases, and the licenses those packages carry "
            "checked against your policy.",
            "License lookups go to the public registries, because what a package "
            "declares in its manifest and what it is actually licensed under are "
            "often different.",
        ],
        "caution": "License lookups reach out to PyPI, npm, Maven Central and "
                   "the Go proxy.  Turn them off if this system is not allowed "
                   "to make those calls.",
    }),
    ("people", "People and history", {
        "title": "People and history",
        "what": [
            "Who can reach each repository, and the pull request history behind "
            "what is in it.  Both answer questions a finding on its own cannot: "
            "how many people could have seen this, and did anybody review it.",
            "Applying exclusions is here too.  Turning it off shows everything "
            "again without deleting a single rule, which is the safe way to find "
            "out what your exclusions are actually hiding.",
        ],
    }),
    ("intel", "Exploitation data", {
        "title": "Exploitation data",
        "what": [
            "The CISA known exploited vulnerabilities list and the daily EPSS "
            "scores.  Both are free and need no account.",
            "They change what the queue means.  A medium that is being exploited "
            "in the wild this week is more urgent than a critical with no known "
            "exploit, and without this data the list cannot tell you that.",
        ],
        "caution": "Both feeds are fetched over the internet.  On an air gapped "
                   "install turn this off rather than leaving every scan waiting "
                   "on a request that cannot succeed.",
    }),
    ("signin", "Sign in", {
        "title": "How people sign in",
        "what": [
            "Local accounts with two step, an identity provider over OIDC, or "
            "both at once while people move across.",
            "Group claims map to roles.  Somebody in an admin group gets admin on "
            "their next sign in, and a developer still only sees the repositories "
            "they were given on the Users page.",
        ],
        "caution": "Provider settings are checked against the provider when you "
                   "save, so a typed issuer that cannot answer is refused here "
                   "rather than after it has locked everybody out.  Keep one "
                   "local admin account anyway.",
    }),
    ("sessions", "Sessions", {
        "title": "Sessions and the network in front",
        "what": [
            "How long a session lasts, how long doing nothing ends it, and what "
            "happens after a run of wrong passwords.",
            "The load balancer addresses matter more than they look.  Behind a "
            "proxy every request arrives from the proxy, so this is how the app "
            "learns whose request is whose.",
        ],
        "caution": "Leave the load balancer addresses empty behind a proxy and "
                   "every request looks like it came from one address.  One "
                   "person getting their password wrong then locks out "
                   "everybody, and the rate limits count the whole company as "
                   "one visitor.",
    }),
    ("output", "Output", {
        "title": "Output",
        "what": [
            "Where vulnerabilities.json and vulnerabilities.csv are written. "
            "They are rewritten after every scan and after every exception "
            "decision, so the files on disk always agree with the app.",
            "The default is /out, which is a volume, so what lands there "
            "survives the container being replaced.",
        ],
        "caution": "These files carry your repository names, file paths and "
                   "redacted credential previews.  Wherever this directory is "
                   "mounted is as sensitive as the app itself.",
    }),
    ("display", "Display", {
        "title": "Display",
        "what": [
            "The time zone every time on screen is shown in.  A schedule's cron "
            "is read in it too, so 0 2 * * * means two in the morning here.",
            "Times are stored as UTC whatever this says, so changing it never "
            "rewrites anything that already happened.",
        ],
    }),
    ("fidelity", "Fidelity", {
        "title": "Fidelity",
        "what": [
            "Rules that report a pattern rather than a problem.  A finding from "
            "one of these is still run, still recorded and still readable behind "
            "one filter; it just does not sit in the work list.",
            "Setting a rule aside is asked for rather than done.  Somebody else "
            "has to agree, and nobody approves their own request.",
        ],
        "caution": "An exception hides one finding.  Setting a rule aside hides "
                   "every finding that rule will ever produce, in every "
                   "repository, until somebody looks again.  That is why it "
                   "takes two people.",
    }),
    ("sensitivity", "Sensitivity", {
        "title": "Sensitivity labels",
        "what": [
            "What the systems you scan actually hold.  A connection carries "
            "these labels, and an exception can be told not to cover them.",
            "That is what lets an exception be broad without being blind.  A "
            "plain HTTP link is low on a brochure site and is not low on the "
            "system holding cardholder data, and one rule can say both.",
        ],
    }),
    ("limits", "Limits", {
        "title": "Limits",
        "what": [
            "A token gets 5000 requests an hour.  These keep a long scan under "
            "that instead of failing halfway through, and decide how hard the "
            "scan pushes.",
            "Three of them decide how much of the machine a scan is allowed to "
            "use, and they multiply: repositories at once is how many clones "
            "run side by side, and the semgrep and trufflehog numbers are what "
            "each one of those may use inside its own repository.  The defaults "
            "were chosen for a small machine.  On a large one they are what "
            "makes a scan take all night while most of the processor sits idle.",
            "The two timeouts answer different questions.  One gives up on a "
            "repository that is stuck; the other gives up on the run.  An "
            "account with thousands of branches, or one enormous repository, "
            "needs the second one raised, and a run that hits it keeps "
            "everything that had already finished.",
        ],
        "caution": "The longest wait has to stay above an hour.  Set it lower "
                   "and the wait is cut short before the limit has reset, then "
                   "the retries burn out against a budget that has not moved "
                   "and the scan fails anyway.",
    }),
]


def sections() -> list:
    """The sections, in page order, as plain dictionaries for the template."""
    return [{"id": key, "nav": nav, **body} for key, nav, body in SECTIONS]
