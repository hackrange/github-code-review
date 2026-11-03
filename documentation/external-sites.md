# External sites and dynamic scanning

The rest of Git Code Review reads code.  External sites is the other end of
it: the domains and subdomains the company answers on, as the internet sees
them.  It keeps the list, reads what answers on each one, runs or records
dynamic (DAST) scans against them, and maps each site to the repositories
behind it, so a finding on the live site and a finding in its code can be
read together.

It is for administrators only, and it is off until somebody turns it on.

## Turning it on

Settings, External sites:

| Setting | What it does |
|---|---|
| `external.enabled` | Off by default.  Off hides the menu entry, and every page and API call under it answers 404. |
| `external.screenshots` | Take a screenshot of each site when its telemetry is read. |
| `external.refresh_days` | Read every site's telemetry again after this many days, at 03:30.  0 only reads it when asked. |
| `external.whitebox` | Before an engine scan, read the default branch of the mapped repositories for routes and for the host name. |
| `external.allow_private` | Let telemetry and scans reach private, loopback and link local addresses.  Leave it off unless the sites really are internal. |

The age at which a scan counts as overdue is the same `dast.max_age_days` the
Web Applications tab uses.

## Adding sites

**External sites** in the Administration menu, then **Add sites**.  Paste one
host per line.  After the host a line can carry an application and tags:

    example.com
    shop.example.com, Storefront, ecommerce;public
    https://help.example.com/kb, Help center, saas

A whole address is fine; the host is taken from it.  **Import known hosts**
adds every company domain from Settings and every host in a repository's web
addresses.

Each site also carries:

| Field | What it holds |
|---|---|
| Executive owner, Technical owner | Email addresses only, comma separated |
| Comments | Anything else |
| Status | Active or Obsolete.  An obsolete site keeps its history, gets no Scan button and is left out of the nightly telemetry |
| Environment | Prod, Dev, Stage or Clone |
| External auth needed | Signing in goes through something outside the site |
| Whitelist needed | The scanner's address has to be let through a firewall first |
| Change frequency | How often the site changes, in days |
| Repositories | Organizations, repositories and branches, picked from a searchable list |

The repository picker lists every repository you can see, with the branches
the scans found on it.  Above the list it recommends repositories for the
hosts being added, from the Web Applications tab and the Repositories page:
an application that lists the host recommends every repository in it, and
another environment of a listed host (qaorders for prodorders) counts too.
When an application has owners, **Use these** fills in the application and
both owners.

### No scan

Tick **No scan** for a host the company does not own or may not test, a SaaS
product on the company's name for example.  Marking a domain covers every
host under it.  For those hosts:

- no scan of any kind starts, built in, on a DAST server or through the API
- telemetry tries only ports 443 and 80, offers no old TLS versions, and
  loads the front page once, the same as one browser visit

A scan run somewhere else can still be recorded against one.

## Telemetry

For each host: DNS, the network owner from whois, a TCP check of about eighty
common ports, the TLS certificate and which old versions it still accepts,
the front page's status, redirects, headers and cookies, a firewall block
page check, and a screenshot from a headless Chromium.  The site gets a web
hygiene grade from A to F from its headers and TLS.

Also from DNS and whois, without touching the site: nameservers, the CNAME
chain, IPv6 addresses, mail servers, reverse DNS, the ASN and netblock, and
the domain's registrar, creation and expiry dates.

Every one of those fields can be filled in or corrected by hand, under
**Telemetry by hand** in Edit, or as `telemetry_fields` through the API.  A
value filled in by hand wins over the scan's until it is cleared, and the
page shows what the scan saw beside it.  The site page lays it out like the
standalone site report: the screenshot first, then the summary, the hygiene
score, each telemetry group, the security headers and every response header.

A host that resolves to a private address is not probed unless
`external.allow_private` is on, and every redirect is checked the same way.

## Running a scan

1. Open **External sites** and press **Scan** on a site's row, or open the
   site and press **Run a scan**.
2. Pick where it runs (this server, or a nextgen-dast server) and a profile.
3. For standard and up, tick that you are allowed to scan the site.
4. Press **Start**.  The scan's page refreshes until it ends.

To scan several, tick them in the list and press **Scan the ticked sites**.
They run one after another.  **Delete the ticked sites** removes them and
their scan history.

## Dynamic scans

Three ways a scan gets onto a site.

**Run here.**  The profiles match nextgen-dast's:

| Profile | Engines |
|---|---|
| baseline | Read only checks: headers, cookies, CORS, TRACE, reflection, TLS, exposed files such as `.git` and `.env`, risky open ports, old JavaScript libraries |
| quick | baseline, testssl.sh, nuclei |
| standard | quick, Nikto, Wapiti |
| thorough | standard with ffuf content discovery first and a wider nuclei pass |
| premium | thorough, sqlmap, Dalfox |

From standard up the engines send attack payloads, and the page asks you to
confirm you are allowed to.  One engine scan runs at a time.  An engine that
is not installed is skipped and the scan says so.

Before the engines run, the repositories mapped to the site are checked out
at their default branch and read for routes: Express, Flask, FastAPI, Django,
Spring, JAX-RS, ASP.NET, Go, Rails, Laravel, Mule listeners and OpenAPI files.
The routes become extra starting points for nuclei and the others, which
finds what a crawler cannot reach by following links.  If the site's host
name is written in a repository, that link is kept as confirmed.

**Started on a nextgen-dast server.**  Add the server under **DAST servers**
with its address and API token.  Its own allow list must include this
server's address.  The scan is started by host name, polled every three
minutes, and read back with its findings and a link to the assessment.

**Recorded.**  A scan run anywhere else, by hand on the site's page or
through the API: the server, when it ran, the worst severity, the counts, a
link to the result and, optionally, the findings.

The newest finished scan becomes the site's last scan.  Every finished scan
is also recorded as a DAST test on the Web Applications tab for the web
applications behind the site.

## The PDF report

A finished scan this server ran has a **PDF report** button on its page, and a
PDF link in the site's scan list.  The API serves the same file at
`GET /api/v1/external/assets/{id}/scans/{scan}/report.pdf`.  A scan run on a
nextgen-dast server keeps that server's own report, and a recorded scan has
no report here.

It follows nextgen-dast's penetration test report: a cover with the grade,
document control, an executive summary with the top issues and the OWASP Top
10 grades, scope and method with the screenshot and what did not run, every
finding with its evidence, a command to see it again and how to fix it, the
scan underneath, and a disclaimer.  It is typeset in the same style as the
security assessment, with the logo, organization and footer from Settings.

The grade is nextgen-dast's: each finding costs points by severity (critical
25, high 12, medium 5, low 2), later findings in the same OWASP category cost
less, and no one category takes more than 25 points off the overall score.
When the AI triage ran, a likely false positive costs nothing and a finding
it wants checked costs half.  Without it every finding counts in full, and the
report says they are unconfirmed.

## Repositories behind a site

Worked out on every read, best first:

| Evidence | Score |
|---|---|
| Linked by hand, or the host found in the code by a scan | 100 |
| The host in the repository's web addresses | 95 |
| The host in a diagram's addresses | 80 |
| The site's application or a tag equals the repository's application name | 70 |
| The host's first label, without environment words like dev or stg, equals the repository's name | 60 |
| One contains the other | 40 |

60 and over are linked; below that they are suggestions.  **Not this one**
hides a link for good, and **Unpin** sends a hand made link back to being
worked out.  Only repositories the person can see are offered, so a group
that narrows what someone sees narrows this too.

## Combined risk

The last dynamic scan leads, because it is what an attacker can reach now.
Open code findings behind a live site raise it, one step below their own
level, since the code may not be what is deployed.  Both at medium or worse
raise it one more step.

## AI

Both go through the AI analysis page's model and are off until one is set up.

- **AI triage** of a scan: each finding gets likely real, likely false
  positive or needs review, with the code finding that supports it.  It never
  changes a severity.
- **AI risk read** of a site: the last scan and the worst open code findings
  behind it, read together, with where they agree and what to do first.

Every call is in the AI cost page under `dast-triage` or `external-risk`.  The
scan and the site also keep their own token counts and cost.  Path traversal
and script payloads in engine evidence are left out of what is sent.

## API

Make a token with the `external` scope.  Only an administrator can, and the
call is refused again if they stop being one.  See the API reference tab on
the IDE tokens page for every call, with examples.

    # Record a scan from a DAST server that knows only the host name
    curl -sS -X POST "$GCR/api/v1/external/scans" \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d '{"host": "shop.example.com", "server": "Acme DAST",
           "severity": "high", "result_url": "https://dast.example.com/r/42",
           "scanned_at": "2026-11-03T02:00:00Z", "counts": {"high": 1, "medium": 4}}'

## What it stores

Screenshots are in the data volume under `external/shots`.  DAST server
tokens are encrypted with the same key as the other secrets.  Engine output
is written to the work directory while a scan runs and removed when it ends;
the findings are kept with the scan.  The nuclei templates are fetched into
the cache volume the first time a quick or larger scan runs.
