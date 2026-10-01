# Git Code Review

Finds secrets, code weaknesses and vulnerable packages across every repository
and branch in a GitHub organization.  Works behind SAML SSO, including Okta.

Version 1.0.1.  MIT licensed.  Tim Rice <tim.j.rice@hackrange.com>

## Install

```bash
curl -fsSL https://git.failoverlb.net/github-code-review/-/raw/master/get-gcr.sh | bash
```

It clones the project, asks a handful of questions, builds the image, starts
it, and prints the username and password to sign in with.

Full guide in [documentation/quick-start.md](documentation/quick-start.md).

## Contents

1. [Auth, and why Okta matters](#1-auth-and-why-okta-matters)
2. [Install](#2-install)
3. [Run](#3-run)
4. [Output files](#4-output-files)
5. [Real secrets vs placeholders](#5-real-secrets-vs-placeholders)
6. [Branches and history](#6-branches-and-history)
7. [SBOM and licensing](#7-sbom-and-licensing)
8. [Vulnerabilities](#8-vulnerabilities)
8a. [Infrastructure as code](#8a-infrastructure-as-code)
8b. [The build pipeline](#8b-the-build-pipeline)
9. [Who has access](#9-who-has-access)
9a. [Pull request history](#9a-pull-request-history)
10. [Configuration](#10-configuration)
11. [Operational notes](#11-operational-notes)
12. [Layout and tests](#12-layout-and-tests)
13. [Known limits](#13-known-limits)

## 1. Auth, and why Okta matters

Okta FastPass is interactive and tied to a device. A scheduled scan has no
browser and no enrolled device, so it cannot do FastPass. What it can do is use
a credential that FastPass already vouched for, or one that bypasses the SSO
check entirely.

### Using a PAT

This is the quickest way to get going.

1. Create a classic PAT with these scopes:

   | Scope | What it gets you |
   |---|---|
   | `repo` | private repositories, full git history |
   | `read:org` | organization list, members, teams |
   | `security_events` | Dependabot, code scanning and secret scanning alerts |
   | `admin:org` (optional) | 2FA status of org members |

2. On the token's page click **Configure SSO** and authorize it for every org
   you want scanned. That step sends you through Okta once, in a browser.

3. Point ghscan at it:

   ```bash
   export GITHUB_TOKEN=ghp_...
   ./bin/ghscan check
   ```

`ghscan check` tells you which scopes the token actually has and warns if
`repo` or `read:org` is missing.

There is one failure mode worth knowing about. If a token is authorized for
some orgs but not others, GitHub does not return an error. It returns `200`
with the unauthorized org's repositories quietly missing, plus an
`X-GitHub-SSO: partial-results` header. ghscan watches for that header, warns
loudly, and sets `scan.sso_results_truncated` in the report. If that flag is
true, the report is incomplete.

### Using a GitHub App instead

Worth doing if this runs on a schedule. Installation tokens are issued to the
App rather than to a person, so GitHub does not put them through the SAML SSO
authorization check at all. They also survive the token owner leaving.

1. Org settings, Developer settings, GitHub Apps, New GitHub App. Uncheck
   **Webhook active**.
2. Repository permissions, all read-only: Contents, Metadata, Secret scanning
   alerts, Dependabot alerts, Code scanning alerts, Administration.
   Organization permissions: Members (read).
3. Create it, note the App ID, generate a private key.
   ```bash
   sudo install -d -m 0700 /etc/ghscan
   sudo install -m 0600 ~/Downloads/app.private-key.pem /etc/ghscan/ghscan-app.private-key.pem
   ```
4. Install the App on the org, all repositories.
5. Set `github.auth.method` to `app` and fill in `app_id` and
   `private_key_path`. ghscan mints and refreshes the hourly token itself.

### Finding everything

Leave `github.scope.orgs` empty and ghscan scans every org the token can see,
via `/user/orgs`. It also pulls `/user/repos` so personal repositories and ones
shared with the token holder directly are included, not just org repositories.

```bash
./bin/ghscan orgs        # what the token can see
./bin/ghscan inventory   # what would be scanned
```

## 2. Install

```bash
curl -fsSL https://git.failoverlb.net/github-code-review/-/raw/master/get-gcr.sh | bash
```

That clones the project, asks a handful of questions, builds the image, starts
it and prints the username and password to sign in with.  Everything the
scanner needs is inside the image.

See [documentation/quick-start.md](documentation/quick-start.md) for what it
asks and [documentation/installation.md](documentation/installation.md) for
where things end up.

### Working on the scanner without a container

`bin/ghscan` runs on its own if you would rather not rebuild an image every
time.  It needs the engines on your PATH:

```bash
sudo ./contrib/install-deps.sh
cp config/config.example.json config/config.json
$EDITOR config/config.json
./bin/ghscan check
```

## 3. Run

`ghscan scan` is the default. Scope comes from the config file, and any CLI
flag overrides it for that one run.

Check scope before a big run. Both of these are cheap and clone nothing:

```bash
./bin/ghscan orgs        # every org, and whether the token can actually read it
./bin/ghscan inventory    # the exact repo list that would be scanned
./bin/ghscan scan --dry-run   # same, plus sizes and an API request estimate
```

### Everything

All organizations the token can see, all repositories, all branches, full git
history. This is the default shape of the config:

```json
"github": {
  "scope": {
    "orgs": [],
    "auto_discover_orgs": true,
    "include_collaborator_repos": true
  },
  "branches": { "mode": "all", "scan_full_history": true }
}
```

```bash
./bin/ghscan scan
```

Empty `orgs` means every org from `/user/orgs`. `include_collaborator_repos`
adds anything reachable through `/user/repos` that is not in one of those orgs,
so personal repositories and ones shared with you directly are included too.

Run `ghscan orgs` first. If it reports fewer orgs than you expect, the token is
not authorized for the rest and the scan will quietly cover less than you think.

### One organization

```bash
./bin/ghscan scan --org acme                 # flag, repeatable
./bin/ghscan scan --org acme --org acme-labs
```

or pin it in the config:

```json
"orgs": ["acme", "acme-labs"],
"auto_discover_orgs": false
```

### One repository, or a few

```bash
./bin/ghscan scan --repo acme/payments
./bin/ghscan scan --repo acme/payments --repo acme/api
```

`--repo` means exactly those repositories. It turns off org enumeration and the
`/user/repos` sweep, so you get what you asked for and nothing else.

The config equivalent:

```json
"include_repos": ["acme/payments", "acme/api"]
```

### Narrowing which repositories

| Setting | Effect |
|---|---|
| `exclude_repos: ["acme/mirror"]` | drop specific repositories |
| `exclude_repo_regex: "^acme/(sandbox\|scratch)-"` | drop by pattern on `owner/name` |
| `include_archived: false` | skip archived repositories (default) |
| `include_forks: false` | skip forks (default) |
| `visibility: "private"` | `all`, `public` or `private` |
| `max_repos: 25` | hard cap, useful for a first run |

### Choosing branches

`github.branches` controls this, and it applies to every repository.

```json
"branches": {
  "mode": "all",
  "include": [],
  "exclude": ["dependabot/*", "renovate/*", "gh-readonly-queue/*"],
  "max_per_repo": 0,
  "stale_days": 0,
  "scan_full_history": true
}
```

| Goal | Setting |
|---|---|
| every branch | `"mode": "all"` |
| default branch only | `"mode": "default"` |
| a named set | `"mode": "list"`, `"include": ["main", "release/*"]` |
| skip bot branches | `"exclude": ["dependabot/*", "renovate/*"]` |
| only recently touched | `"stale_days": 90` |
| cap per repository | `"max_per_repo": 10` |

`include` and `exclude` are shell globs, not regexes. `exclude` wins over
`include`.

The web app has all of these on Settings, under Branches. The two limits are
worth reaching for on a large estate. A repository that has collected thousands
of branches is slow to walk, and a finding sitting in an old commit is reachable
from every one of them, so the branch list recorded against that single finding
gets very long. `stale_days` is the gentler of the two: it drops branches nobody
has touched in months and keeps the ones people work on.

`scan_full_history` is the important one. Left `true`, the secret engines walk
every commit on every ref, so a credential deleted two years ago is still found.
Set it `false` and only the current file contents at each branch head are
scanned: much faster, blind to anything already removed.

### Choosing what to look for

```bash
./bin/ghscan scan --only secrets              # secrets only
./bin/ghscan scan --only sbom,vulns           # dependencies and CVEs
./bin/ghscan scan --only access,pulls         # API only, no cloning at all
```

Components are `secrets`, `sbom`, `vulns`, `access`, `pulls`. Anything not
listed is skipped. `access` and `pulls` need no clone, so they finish in
seconds even across a large estate.

### Worked examples

```bash
# Whole estate, everything, overnight
./bin/ghscan scan -o /var/lib/ghscan/$(date +%F)

# One repo, secrets only, verbose, keep the clone to inspect it
./bin/ghscan scan --repo acme/payments --only secrets -v --keep-clones

# Release branches across one org, no history walk, fast
./bin/ghscan scan --org acme --only secrets \
  -c <(jq '.github.branches = {mode:"list", include:["main","release/*"],
           exclude:[], max_per_repo:0, stale_days:0, scan_full_history:false}' \
       config/config.json)

# Who can reach what, no cloning, whole estate
./bin/ghscan scan --only access -o ./access-review

# First look at an unfamiliar org: cap it, skip verification
./bin/ghscan scan --org acme --no-verify \
  -c <(jq '.github.scope.max_repos = 10' config/config.json)

# CI gate on one repo
./bin/ghscan scan --repo "$GITHUB_REPOSITORY" --fail-on verified-secrets
```

### Other flags

| Flag | Effect |
|---|---|
| `-o DIR` | output directory |
| `-j N` | repositories in parallel (default 4) |
| `--no-verify` | no outbound credential verification |
| `--keep-clones` | leave the working clones on disk |
| `--dry-run` | resolve scope, print the plan and request estimate |
| `--fail-on WHAT` | exit 3 on findings: `secrets`, `verified-secrets`, `critical`, `high`, `license` |
| `-v` / `-vv` / `-q` | debug / trace / quiet |

Exit codes: `0` clean, `1` fatal, `2` bad config or arguments, `3` findings met
`--fail-on`.

### How long a large scan takes

Cloning full history dominates, not the API. A few hundred repositories means
hours and tens of GB of transient disk under `clone.workdir`; clones are deleted
as each repository finishes unless you pass `--keep-clones`.

The API budget is 5000 requests an hour for a PAT. ghscan estimates the cost
before it starts:

```
preflight: about 8509 API requests for 500 repositories (~17 each); 5000 of 5000 left
this scan needs more requests than one hourly window allows.
it will pause and resume across roughly 2 reset window(s). Leave it running; nothing is lost.
```

It paces itself to stay under the limit rather than stalling at zero, so a scan
that needs several hours simply takes several hours. See
[Operational notes](#11-operational-notes) for the details.

## 4. Output files

Everything lands in `output.dir` (default `./out`).

| File | What it is |
|---|---|
| `ghscan-report.json` | the full report: summary, secrets, vulnerabilities, access, per-repo detail |
| `ghscan-report.sarif` | the same findings as SARIF 2.1.0, one run per repository |
| `ghscan-report-secrets.json` | secrets alone: repo, branch, URL, committer, date |
| `ghscan-report-access.json` | access alone: users, teams, invitations, deploy keys |
| `ghscan-report-sbom.json` | SBOM summary with license rollups per repo |
| `ghscan-report-sbom.cdx.json` | one CycloneDX document covering every repo |
| `ghscan-report-sbom.spdx.json` | the same in SPDX 2.3 |
| `sbom/<owner>__<repo>.cdx.json` | per-repo CycloneDX, straight from syft |
| `sbom/<owner>__<repo>.spdx.json` | per-repo SPDX, straight from syft |
| `repos/<owner>__<repo>.json` | one file per repository |
| `ghscan-report-vulnerabilities.csv` | severity, org, repo, branch, CVE, package, fix |
| `ghscan-report-misconfigurations.csv` | severity, org, repo, file, rule, resource, fix |
| `ghscan-report-secrets.csv` | one row per secret per branch |
| `ghscan-report-access.csv` | one row per user per repo per branch |
| `ghscan-report-access-teams-keys.csv` | teams, pending invitations, deploy keys |
| `ghscan-report-pulls.json` | pull request counts by user, repo and branch |
| `ghscan-report-pulls.csv` | the same, one row per user per repo per branch |

`schema/report.schema.json` is the JSON Schema for the report, and
`ghscan validate` checks a file against it.

### SARIF

`ghscan-report.sarif` is the same findings in the format the rest of the world
reads: GitHub's Security tab, GitLab, Azure DevOps, the SARIF viewer in VS
Code, and most vulnerability managers.  Every kind of finding is in it, not
just code.

It is one run per repository.  A path in SARIF is relative to a repository
root, and a scan of an estate carries findings from hundreds of roots, so one
flat run would resolve paths against the wrong tree everywhere except the first
one.  Each run carries the repository it came from and its default branch.

Every result carries a `partialFingerprints` entry, and it is the same
fingerprint the web app uses.  That means a code host deduplicates findings
across nightly runs instead of closing and reopening all of them, and a finding
in a Security tab and the same finding in the web app have one identity between
them rather than two.

Credentials travel as their mask and their fingerprint.  Cleartext never
reaches this file, which matters more here than anywhere else because a SARIF
file gets uploaded and kept as a build artifact.

Set `output.sarif` to `false` to stop writing it.  It needs python in the
scanner venv, which is there in the container.

### Feeding a vulnerability management system

Every vulnerability record carries `severity`, `organization`, `repository`,
`branch`, `id` (CVE or GHSA), `aliases`, `cvss_score`, `cvss_vector`, `cwe`,
`package` with its purl, `fixed_in`, and the advisory URL. Severities are
reported at every level, from critical down to negligible and unknown. Set
`scan.vulnerabilities.min_severity` if you want less.

Secrets are reported as `category: "credential"` with `severity: "critical"`,
because a credential that survives triage is a real credential. Hits under a
test or fixture path drop to `high` and carry `confidence: "low"`. Both
thresholds live in `scan.secrets.severity`.

```bash
# critical and high, ready to import
awk -F, 'NR==1 || $1 ~ /critical|high/' out/ghscan-report-vulnerabilities.csv

# everything proven live, most urgent first
jq -r '.secrets[] | select(.verified)
       | [.severity, .repository, (.branches|join(",")), .author_login, .url]
       | @tsv' out/ghscan-report.json
```

## 4b. The backlog and the work

Point this at a repository with years in it and the first scan comes back with
thousands of findings. Nobody triages thousands. The number never moves, and in
a fortnight the scan gets switched off. So there is a line you can draw.

On the Findings page, pick an organization and press **Draw the line**. Leave
the date blank for today, or set one to put the line where it belongs after the
fact. Everything first seen before it becomes the backlog. Everything after is
the work, and that is what the page shows by default.

Nothing is deleted and nothing is hidden. The backlog keeps its grades, stays
in the report files, and is one click away on the same filter, with a count
beside it so it reads as work to get through rather than work to forget. It is
the finding's own first-seen date that decides, so rescanning never moves
anything across the line, and a finding that was fixed and came back is new
again.

An organization with no line drawn has every finding counted as work, so an
install that never touches this behaves exactly as it did before.

## 5. Real secrets vs placeholders

Three layers.

**Proof.** trufflehog verifies. For something shaped like an AWS key it calls
STS, for a Slack token it calls `auth.test`. If the provider says the
credential works, it is real and nothing can filter it out. Those come back
`verified: true`.

Verification sends the candidate credential to the provider that issued it.
That is what makes it conclusive, and it is also a thing your security team may
want to know about. It is on by default. `--no-verify` turns it off.

**The placeholder filter.** Everything unverified goes through
`scan.secrets.triage`:

1. allowlist match, by fingerprint, path, detector or rule
2. placeholder patterns: `EXAMPLE`, `changeme`, `YOUR_API_KEY`, `${VAR}`,
   `<token>`, `xxxxxxxx`, `AKIAIOSFODNN7EXAMPLE`
3. character diversity: four or fewer distinct characters is filler
4. a JSON web token whose signature could not have been produced by signing
   anything: empty, not base64url, or the wrong length for the algorithm its
   own header names. RS256 signs with 342 characters and HS256 with 43, so a
   token carrying the word SIGNATURE where those go cannot be presented to
   anybody and is not a credential
5. length and entropy floors, 12 characters and 3.0 bits per character
6. path: `test/`, `fixtures/`, `docs/`, `vendor/`, `*.md`, lockfiles. These are
   downgraded, not deleted, because real keys do end up in test fixtures.

Nothing disappears silently. Every dropped candidate is listed under
`placeholders_filtered` with the rule that dropped it.

**Your allowlist.** After the first run, copy the fingerprint of anything you
accept into `config/allowlist.json`. Fingerprints are the first 16 hex of
SHA-256, so they are safe to commit and safe to paste into a ticket.

```json
{
  "fingerprints": ["a3f19c02b7e4d81f"],
  "rules": [{
    "id": "terraform-test-creds",
    "reason": "Synthetic AWS creds for the terraform tests. Reviewed by appsec.",
    "repo": "acme/infra-modules",
    "path_regex": "^test/fixtures/.*\\.tfvars$",
    "detector": "AWS",
    "expires": "2027-01-14"
  }]
}
```

`expires` is enforced, so a temporary exception cannot quietly become permanent.

### Usernames and passwords

Stock rulesets are good at provider tokens and weak at plain credentials.
`config/gitleaks-extra.toml` adds rules for credentials in URLs
(`postgres://svc:Xq7#pL29vBn4@db/billing`), JDBC and ODBC connection strings,
hardcoded `password = "..."` assignments, `Authorization: Basic` headers,
htpasswd hashes, and long opaque bearer tokens. Each has an entropy floor and
its own placeholder allowlist, so `password = "changeme"` never becomes a
candidate.

### Who committed it

Every secret carries `author_name`, `author_email`, `authored_at`,
`committer_name`, `committed_at`, and the commit message. Git metadata can say
anything, so ghscan also resolves the commit through the API and records
`author_login`, the GitHub account that actually pushed it, along with
`commit_verified` for the signature. Grouped findings carry
`first_committed_at` and `last_committed_at`.

## 6. Branches and history

Repos are cloned with `--mirror` and then flipped to a working tree. That gets
`refs/heads/*` for every branch plus a checkout for the SBOM pass, in one fetch.

Secret engines run over `git log --all --full-history`, so a secret committed
to a branch that was later cleaned up is still found. Each finding's commit is
mapped back to branches with `git for-each-ref --contains`, which is why one
finding can name several branches.

### Which branch a finding is really about

Two passes, and they do not cover the same ground.

**Secrets are per branch.**  Every branch is checked out and the history is
walked, so a secret carries the real list of branches it sits on.

**Code, dependencies and infrastructure are not.**  Those run once, on the
default branch checkout.  A release branch is never looked at by them.

That distinction used to be invisible, because a code finding was stamped with
the default branch and nothing said the other branches had gone unexamined.  A
reader seeing nothing against `2.6.2` concludes it was checked and came back
clean, and on a repository whose release branch is the same commit as its
default branch that conclusion is right by luck rather than by evidence.

So a finding from those three passes now carries every branch holding the
identical tree, which git can answer for nothing:

```bash
jq -r '.code_findings[] | [.file, (.branches | join(","))] | @tsv' \
  out/ghscan-report.json | head
```

A branch whose tree differs from the default branch is not in that list, and
that is the honest answer: it was not scanned, so nothing is claimed about it.
If a release branch has genuinely diverged, scan it directly with `--repo` and
a config that names it, or treat the gap as real.

Two exposure states, and they need different fixes:

* `current_and_history`: still at a branch head. Rotate, remove, rewrite history.
* `git_history_only`: gone from every head but still reachable. Rotate anyway,
  because anyone with a clone has it, then rewrite history.

`github.branches.scan_full_history: false` scans branch heads only. Much
faster, and blind to anything already deleted.

### Limiting which branches are walked

Two places set this, and the narrower one wins.

**Settings > Branches** is the estate wide rule: every branch, the default
branch only, or a list, plus a skip list that starts at `dependabot/*`,
`renovate/*` and `gh-readonly-queue/*`. It is `github.branches` in the config
the scanner reads.

**A connection's own branch list** overrides it for that account. One name or
pattern per line, so `master`, `main` and `release/*` all work. Empty, or a
single `*`, means the setting above decides. This exists because one rule is
the wrong shape for an estate: an account holding a handful of release
repositories and an account holding thousands of stale feature branches want
different answers, and the connection is the only place that difference is
known.

The box does not ask anybody to remember the names. Editing a connection shows
what past scans of that account actually found, with the number of repositories
each name appears in, and clicking one adds it. Every scan now records the
branches it walked against each repository, so the list is what was really
there; for scans that ran before that was kept, the names come off the findings
themselves and the panel says so, because branches that carried no finding are
missing from that answer.

A connection's list beats the global skip list too. A skip pattern that would
have swallowed a branch the connection names is dropped for that scan, because
a named branch that silently matched nothing is the worst outcome here: it
reports success and scans no code at all.

Two limits stay global whichever way the branches are chosen:
`branches.max_per_repo` and `branches.stale_days`. Both are off by default.

## 7. SBOM and licensing

syft builds an SBOM per repository from the default branch checkout. Both
formats are written for every repo and merged into one document per format for
the whole estate.

Two settings matter more than they look:

* `catalogers: "+javascript-package-cataloger"`. syft's directory defaults skip
  bare `package.json`, so a repo declaring npm dependencies without a lockfile
  would otherwise report no JavaScript components at all.
* `enrich: ["all"]`. Source repos declare dependencies but rarely vendor them,
  and a declaration carries no license. Enrichment resolves each component
  against PyPI, npm, Maven Central and proxy.golang.org to get the real license.
  It needs network access to those. Set `[]` for an air-gapped run and expect
  most licenses to come back unknown.

Licenses show up as SPDX identifiers (MIT, Apache-2.0, GPL-3.0-only,
AGPL-3.0-or-later) on each component, rolled up per repo and across the estate:

```bash
jq -r '.summary.sbom.license_distribution[] | "\(.count)\t\(.license)"' out/ghscan-report.json
jq -r '.repositories[] | select(.license_policy.status=="fail")
       | .repository.full_name as $r | .license_policy.violations[]
       | "\($r)\t\(.license)\t\(.component)"' out/ghscan-report.json
```

`scan.sbom.license_policy` marks each component denied, flagged or clean by
case-insensitive match on the SPDX id, so `AGPL-3.0-only` also catches
`AGPL-3.0-only WITH exception`. Components with no license metadata are listed
under `sbom.unlicensed_components` rather than counted as clean. The repo's own
license comes from GitHub's license API.

Where syft cannot run, ghscan falls back to GitHub's dependency graph SBOM
endpoint, which needs no clone.

## 8. Vulnerabilities

Three sources, merged and deduplicated on id, package and version:

* **grype**, matched against the SBOM already built, so the tree is not
  rescanned
* **Dependabot alerts**, including transitive dependencies GitHub resolved
* **Code scanning alerts** from CodeQL or whatever else is wired up

Every severity is reported by default. `--fail-on high` gates a pipeline.

## 8a. Infrastructure as code

Everything above reads what the application does.  This reads the files that
decide where it runs: Terraform, CloudFormation, Kubernetes and Helm manifests,
Ansible, and Dockerfiles.  A bucket open to the world, a security group with
`0.0.0.0/0` on it and a container running as root are not code problems, and
nothing else in this tool would have said a word about them.

trivy does the reading, off the same checkout the SBOM pass already makes, so
it costs a scan no extra clone and no extra API call.

```bash
./bin/ghscan scan --only iac
./bin/ghscan review . --only iac        # in a pipeline, on the change
```

Each finding carries what is wrong, the resource it is wrong on, and what to do
about it:

```bash
jq -r '.misconfigurations[] | select(.triage == "review")
       | [.severity, .repository, .file, .rule_id, .title] | @tsv' \
  out/ghscan-report.json
```

An example directory, a test fixture, a downloaded module and a vendored chart
are graded `third_party` rather than reported as though somebody deployed them.
Nothing is deleted, the reason travels with the finding, and the default view is
what is left.

Two settings matter.  `scan.iac.offline` stops trivy fetching its policy bundle,
which an isolated builder needs.  `scan.iac.skip_dirs` drops paths wholesale
where grading them is not enough.

One thing this deliberately does not do.  trivy hands back the source lines that
caused each finding, and a Terraform file is exactly where somebody puts a
password.  Those lines are dropped before anything is written.  The line number
says where to look.

## 8b. The build pipeline

`.github/workflows` was text in a clone and nothing more.  It is also the most
attacked part of a modern repository, and the attacks take the whole
organization rather than one service:

* a `pull_request_target` that checks out an untrusted head
* an issue title interpolated straight into a `run` block
* a third party action pinned to a tag somebody else can move
* secrets handed to a workflow a fork can trigger

zizmor reads them off the same checkout, and the findings are misconfigurations
like the infrastructure ones, so there is one list rather than two.

```bash
./bin/ghscan scan --only workflows
./bin/ghscan review . --only workflows
```

Two things here are worth more than the findings themselves.

**Every branch, not just the default one.**  This clones every branch, so it
sees the workflow on the branch somebody is still writing.  A hosted scanner
looking at the default branch sees it after it merged.

**Who could have stopped it.**  The access inventory is collected in the same
scan, so a workflow finding arrives with the logins of the people who hold admin
on that repository.  "An outsider can trigger this workflow" is a fact.  "And
here are the four people who own it" is something somebody can act on.

```bash
jq -r '.misconfigurations[] | select(.source == "zizmor")
       | [.severity, .repository, .file, .rule_id,
          (.repository_admins // [] | join(" "))] | @tsv' \
  out/ghscan-report.json
```

`scan.workflows.persona` trades false positives for reach: `regular` by
default, then `pedantic` and `auditor`.  `scan.workflows.offline` is `true`,
because the audits that ask GitHub about an action need a token and handing this
tool's credential to another binary should be a decision rather than something
inherited.  Turn it off and the token goes through the environment, never the
command line.

The same rule as everywhere else applies to what comes back: zizmor returns the
offending lines of the workflow, a workflow is a place people put credentials,
and those lines are dropped before anything is written.

## 9. Who has access

For every repo in scope, ghscan records the users who can reach it, their
permission level, and whether it came from being added directly or inherited
from a team or the org default. It also collects teams, pending invitations,
deploy keys and branch protection.

```bash
jq -r '.access.users[] | select(.highest_permission=="admin")
       | "\(.login)\t\(.repository_count) repos"' out/ghscan-report.json

jq -r '.access.users[] | select(.outside_collaborator)
       | "\(.login)\t\(.admin_of | join(","))"' out/ghscan-report.json
```

The CSV has one row per user per repo per branch, with branch protection state,
org role and 2FA status. Set `output.csv.expand_branches` to `false` for one row
per user per repo.

Listing collaborators needs push access to the repository. Where the token does
not have it, that repo is recorded in `access.unreadable_repositories` with the
reason, rather than appearing to have nobody on it.

## 9a. Pull request history

Counts pull requests per user, per repository, per target branch, with first
and last activity.

```json
{
  "username": "alice",
  "user_type": "User",
  "organization": "acme",
  "repository": "acme/payments",
  "branch": "main",
  "count": 34,
  "merged_count": 31,
  "open_count": 1,
  "closed_count": 2,
  "first_pull_at": "2025-11-04T09:12:00Z",
  "last_pull_at": "2026-08-19T16:41:22Z"
}
```

`by_user` rolls the same data up per person across every repo and branch.

A word on the name. GitHub's API cannot tell you who ran `git pull`. Fetches
and clones are only attributed to a user in the Enterprise Cloud audit log,
which is a different API and a different scope. What this counts is pull
requests, which is what the username, branch and date fields describe. The
repo-level `clone_traffic` block carries GitHub's 14 day clone and unique
cloner totals, which have no usernames attached at all. If you need real git
fetch attribution and you are on Enterprise Cloud, that lives in
`/orgs/{org}/audit-log?phrase=action:git.clone` and would be a separate
collector.

Window and volume are controlled by `scan.pull_history.since_days` (365 by
default) and `max_per_repo`.

```bash
jq -r '.by_user[] | [.username, .count, .last_pull_at] | @tsv' out/ghscan-report-pulls.json
```

## 10. Configuration

Everything is in `config/config.json`, and `config/config.example.json` is
annotated throughout.

| Key | Default | What it does |
|---|---|---|
| `github.auth.method` | `pat` | `pat`, `app` or `gh_cli` |
| `github.scope.orgs` | `[]` | empty means every org the token can see |
| `github.scope.affiliation` | owner, collaborator, organization_member | passed to `/user/repos` |
| `github.branches.mode` | `all` | `all`, `default` or `list`; a connection that names its own branches overrides it |
| `github.branches.scan_full_history` | `true` | every commit on every ref |
| `scan.parallel_repos` | `4` | repositories in flight; roughly one per four cores |
| `scan.code_analysis.jobs` | `2` | semgrep processes inside one repository |
| `scan.secrets.trufflehog.concurrency` | `8` | trufflehog threads inside one repository |
| `scan.secrets.trufflehog.verify` | `true` | live credential verification |
| `scan.secrets.severity.credential` | `critical` | severity for a confirmed credential |
| `scan.secrets.triage.min_entropy` | `3.0` | bits per character |
| `scan.sbom.formats` | CycloneDX and SPDX | both are written |
| `scan.sbom.enrich` | `["all"]` | registry lookups for license data |
| `scan.access.enabled` | `true` | the user access inventory |
| `scan.pull_history.enabled` | `true` | pull request counts per user and branch |
| `scan.pull_history.since_days` | `365` | how far back to look |
| `scan.vulnerabilities.min_severity` | `all` | report everything |
| `output.csv.enabled` | `true` | write the CSV views |
| `redaction.prefix_chars` / `suffix_chars` | 4 / 3 | mask shape |

Any string can contain `${ENV_VAR}`. Relative paths resolve against the config
file's own directory. Do not put a token in the config file, use `token_env` or
`token_file`.

### AI validation

Not in `config/config.json`.  It belongs to the web application and lives in
its database, set on the **AI analysis** page: sidebar, **Administration**,
**AI analysis**, or `/ai`, administrators only.  Pick one provider: a hosted
provider's own API, anything that speaks the OpenAI chat API, or your own
inference service described as curl headers and a body with `SAMPLE` where the
question goes.  Keys and the custom secret header are stored encrypted, the
same as every other credential in Settings.

Off until a provider is chosen.  Once one is set up, each finding carries one
**Validate with AI** button, and nothing runs without somebody pressing it.

| Setting | Default | What it does |
|---|---|---|
| Provider | off | which model answers, one at a time |
| Send the code | on | the lines around a finding, or where a package is used; never for a credential |
| Lines either side | `40` | how much code goes with a finding |
| Read the advisory from osv.dev | on | only the public advisory id is sent |
| Longest answer | `16000` tokens | the cap on one answer |
| Time limit | `300` seconds | how long to wait for one |

Turning on a provider with code sending on means source leaves the
installation for that provider.  [documentation/ai-validation.md](documentation/ai-validation.md)
lists the providers, what each needs, and exactly what is and is not sent.

## 11. Operational notes

**Read only.** Every API call is a GET. The single exception in the whole
codebase is the POST that mints a GitHub App installation token, which creates
an ephemeral credential and changes nothing. There is no code path that writes
to a repository, opens an issue, or posts a comment. The tests check this.

**Secret material.** Cleartext lives only in a `0700` temp directory that is
removed on exit, including on Ctrl-C, and the raw findings file is shredded as
soon as triage finishes. Reports carry a mask and a fingerprint, never the
value. The clone URL never contains the token: git gets it through a credential
helper that reads the token file at the moment it is needed, so it stays out of
`ps` output and out of `.git/config`.

**Scale.** Full history for every repo is the expensive part. For 500
repositories expect hours and tens of GB of transient disk under
`clone.workdir`. Clones are deleted as each repo finishes unless you pass
`--keep-clones`.

**History too large for one run is walked a window at a time.**
`secrets.history_window_days` bounds how far back the credential engines go in
a single run, newest first, and each repository records where the walk reached.
The next run continues from there rather than starting at the newest commit
again, until the first commit is reached; after that only new commits are
walked. Zero, the default, keeps the single pass over everything.

The two engines cover this differently, because they have to. gitleaks takes
arbitrary `git log` options, so it walks the window and can eventually cover
the whole history. trufflehog only accepts a commit to start from, so it takes
the newest window each run. Deep history is therefore detected but not
live-verified, and each finding says which it is.

**Idle time finishes what the nightly run could not.** `catchup.enabled` is on
by default and does nothing until a history window is set, which is the switch
that means anything here. A tick every twenty minutes looks for the repositories whose history is
furthest from having been walked to its end and gives them another window. It
refuses itself whenever any scan is running, because the point is to use time
nobody wants rather than to compete for time somebody asked for, and a schedule
that fires stops it and keeps what it had already walked. It needs a history
window set, since without one nothing records where a walk got to.

**A repository that runs out of time keeps what it found.** The passes inside a
repository - credentials, code, SBOM, dependencies - are checkpointed as each
one finishes, written into place in a single step so a worker killed mid-write
cannot leave half a file behind. A repository stopped at its limit is reported
as `partial` rather than vanishing: its findings are in the report, the passes
that finished are listed against it, and the summary counts it under
`incomplete` rather than as scanned or failed.

It is deliberately not counted as scanned. Everything in that set has its
absent findings marked resolved, and a repository that was stopped half way did
not look for them - calling them fixed would be the scanner inventing good
news. So a partial repository can gain findings and never lose them.

**What a repository timeout does.** `scan.timeout_per_repo` stops the work, not
just the bookkeeping. The worker and everything it started - git, gitleaks,
trufflehog, syft - are listed and signalled together, children first, and
anything still alive twenty seconds later is killed outright. This matters
because a worker is a shell whose real work happens in those children: signal
the shell alone and they carry on, reparented to init, holding the run open on
its output pipes and consuming the machine on results nobody is left to
collect. The worker deliberately stays in the scanner's process group, so
stopping a scan from the web app still reaches it.

**Sizing a large machine.** Three numbers multiply, and the defaults were
chosen for a small host:

| What | Default | On 64 cores |
|---|---|---|
| Repositories at once | 4 | 12 to 16 |
| semgrep processes, per repository | 2 | 8 |
| trufflehog threads, per repository | 8 | 16 |
| Give up on the whole scan after | 6 hours | 12 |

The container also has to be allowed to use the machine. `GCR_MEM_LIMIT`
(default `8g`) and `GCR_SHM_SIZE` (default `1g`) cap it whatever the host has;
the second one matters because scan scratch is held in memory to keep
cleartext credentials off disk, and a repository that does not fit falls back
to the disk it was being kept off. On a 128 GB host, `GCR_MEM_LIMIT=96g` and
`GCR_SHM_SIZE=16g` leave room for the database and the operating system.

Past roughly one worker per four cores, repositories queue on disk and on the
API rate limit rather than on the processor, and the engines each hold a
clone open while they work. The Go engines are given `GOMAXPROCS` equal to the
core count divided by the workers, so sixteen workers do not each try to use
all sixty four cores.

**Rate limits.** ghscan reads `x-ratelimit-remaining` and sleeps until reset
when it drops below `rate_limit.min_remaining`, and honors `Retry-After` on
secondary limits. A PAT is capped at 5000 requests an hour no matter what; a
GitHub App's limit scales with how many repositories it is installed on.

**On a schedule.**

```cron
17 2 * * 1 cd /opt/ghscan && ./bin/ghscan scan -q -o /var/lib/ghscan/$(date +\%F) >> /var/log/ghscan.log 2>&1
```

## 12. Layout and tests

```
bin/ghscan                    CLI and orchestration
lib/*.sh                      auth, api, inventory, secrets, triage, sbom,
                              vulns, access, pulls, csv, scan, report
lib/validate_report.py        schema check behind `ghscan validate`
config/config.example.json    annotated config
config/gitleaks-extra.toml    password and connection string rules
config/allowlist.example.json accepted findings
schema/report.schema.json     JSON Schema for the report
requirements.txt              python dependencies
contrib/install-deps.sh       puts the engines on a host, for scanner work
Dockerfile                    unprivileged image
```

To check an installation rather than the code, ask the scanner about itself:

```bash
./bin/ghscan check          # config, credentials and which engines are installed
./bin/ghscan check --probe  # call every endpoint and report what the token reaches
```

That covers the questions somebody running this actually has: whether the
credential works, what it can see, and which engines are on the machine.

## 13. Known limits

* License data depends on what the repo declares. A manifest with no lockfile
  gives you a name and no license. `enrich` resolves most of those, but a
  private registry it cannot reach comes back unknown. Those components are
  listed explicitly rather than counted as clean.
* Verification proves a credential is real, not that it is reachable. And
  `verified: false` means not proven, not "not a secret". An internal service
  the scanner cannot reach has no verifier at all.
* The triage rules are tuned to drop obvious placeholders, not to be perfect.
  Read `placeholders_filtered` on your first real run before trusting them.
* Dependabot, code scanning and secret scanning alerts return 404 when the
  feature is off for a repository. That is logged at debug level and the scan
  continues with whatever else is available.
* detect-secrets runs against the working tree only, so it corroborates
  findings at a branch head but says nothing about history.
