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
| `external.max_concurrent` | How many engine scans this server runs at once, 1 to 12, default 1.  The rest queue.  Read on every scan, so a change needs no restart.  A site is never scanned twice at once. |
| `external.environments` | The environments a site can be in, comma separated.  The first is the default for a new site.  A site in one that is taken off the list keeps it until somebody picks another. |
| `external.user_agent` | The browser every request says it is.  Empty uses a current desktop Chrome. |
| `external.allow_private` | Let telemetry and scans reach private, loopback and link local addresses.  Leave it off unless the sites really are internal. |
| `external.cert_alert_enabled` | Email when a site's TLS certificate comes within the warning window.  Off by default.  Checked every morning at 08:00. |
| `external.cert_alert_days` | How many days before expiry to warn, 1 to 365, default 29. |
| `external.cert_alert_to` | Who the warnings go to, comma separated.  Empty uses the To list on the Notifications page.  Mail goes through the server set there. |

Certificate warnings name every site, except obsolete ones, whose certificate
ends within the window, soonest first, in one message.  Expired ones are
named too.  Each certificate is named once: a renewed certificate is named
again only if it also comes within the window.  The stored date is as old as
the site's telemetry, so before naming a site its certificate is read again
from the site.  A renewed one is dropped, and when the site does not answer,
the stored date is used and the message says so.  If the mail cannot be sent,
the next morning tries again.

The age at which a scan counts as overdue is the same `dast.max_age_days` the
Web Applications tab uses.

The dynamic scanning settings are on the **DAST Admin** page, reached from
External sites, under **General DAST settings**:

| Setting | What it does |
|---|---|
| `dast.scan_proxy` | Run the engines through a local proxy for each scan.  On by default.  See [The scan proxy](#the-scan-proxy). |
| `dast.oob_url` | The base address the out of band checks use for their callback.  Empty skips those checks. |
| `dast.ai_max_findings` | The most findings one scan sends to the model, default 40. |
| `dast.exposure_check` | Load each site a second time through a proxy no allow list knows.  Off by default.  See [Exposure](#exposure). |
| `dast.unwhitelisted_proxy` | That proxy, such as a Squid address.  Held encrypted. |
| `dast.whitelisted_vantage` | Which side a target's allow list lets in, this server (direct) or the proxy. |
| `dast.whitelisted_ip`, `dast.ip_echo_url` | This server's public address, for reference, and the service that shows what address the proxy leaves from. |

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
| Environment | One of the environments listed in Settings, which start as Prod, Dev, Stage and Clone |
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

Screenshots are taken with Playwright driving full Chromium, which follows
redirects (including after a bot check, a meta refresh or a script) and gets
past most bot checks (Imperva, Cloudflare and others) the way a visitor's
browser does.  The page it ends on is the site's final address, and a page
that loads and is genuinely empty keeps its white screenshot, marked blank.
A bot check in front of the site is named, with whether a browser got past
it; the scanning engines still meet it unless this server is let through, so
mark such sites Whitelist needed.  When almost every port answers, that is the
CDN accepting everything, so open ports are not reported for that site.

A firewall or bot wall that refused the scan is marked as a block page and
its screenshot is left out.  A CDN answering for a site it cannot reach, such
as a Cloudflare 502, is marked as the site being down instead, with its
screenshot.

The list shows 50 sites a page, highest combined risk first, with 100, 200,
500 and 1000 a click away at the top and bottom.  Filters and the chosen size
carry across pages.

The list shows a 256x160 JPEG made from each screenshot rather than the
full 1280x800 picture, so a long list loads quickly.  The thumbnail is made
when the screenshot is taken.  Screenshots from before that get theirs the
first time the list is opened, and show the full picture until then.

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

## Changing many sites at once

Tick sites in the list and press **Edit the ticked sites**.  Every field Edit
has is there with a **Change** box beside it, and only the ticked ones are
changed; typing in a field ticks it.  Tags can be added, removed or replaced,
comments replaced or added to, repositories added, replaced or cleared, and
the proxy and the scan sign in set or removed.  It is all or nothing: the
changes are checked for every ticked site first, and if one will not take
them, nothing is changed and the message names it.  Telemetry filled in by
hand stays per site.  The API does the same with `PATCH
/api/v1/external/assets` and a list of `ids`.

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
| thorough | standard with ffuf content discovery first, a wider nuclei pass and the browser read of client code |
| premium | thorough, sqlmap, Dalfox, and every curated rule that is enabled |

A saved scan profile is a depth plus the rule sets to run.  See
[Curated rules](#curated-rules).

From standard up the engines send attack payloads, and the page asks you to
confirm you are allowed to.  How many engine scans run at once is
`external.max_concurrent`.  An engine that is not installed is skipped and the
scan says so.  Each engine row says how many requests that tool sent.

Thorough and premium give ffuf a list of about 1,150 high signal paths, where
quick uses 140.  Nikto is paced, because a firewall reads its burst of TLS
handshakes as a flood and it then gives up in about a second.  Wapiti skips the
endless spaces an online store generates, such as add to cart, review, login
referer, wishlist and product compare links, which used to take its whole time
limit on one site.

Each engine has a time limit.  A site can set its own, in minutes, for nuclei,
Nikto, ffuf, Wapiti, sqlmap and Dalfox.  A blank one keeps the default.  nuclei
and Dalfox write each finding as they find it, so a stopped engine keeps what it
found.

### The browser read of client code

On thorough and premium, a headless browser loads the pages, runs their scripts
and reads the JavaScript they loaded.  It reports a secret in a distinctive
vendor format, redacted in the finding, and application source exposed through a
source map.  Every request it makes is checked against private addresses, so a
page cannot steer it into this server's network.  With no browser on hand the
stage is skipped.

### The scan proxy

Each scan starts a local mitmproxy that the stock engines run through.  It puts
the site's session on every request, so an engine that signs in badly on its own
still sees what a user sees.  It refuses any host that is not the site or one of
the company's domains from Settings, so an engine that follows a link off the
target cannot reach it.  It counts what it forwards.  testssl reads the site's
own TLS directly, and the baseline checks, the curated rules and the browser
make their own requests, so none of those are in the count.  If mitmproxy will
not start, the engines go direct and the scan says so.

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

**Rapid7 InsightAppSec.**  Turn it on under **Integrations** on the DAST Admin
page, with a region and an API key.  A scan or a schedule can run on a scan
config made in Rapid7.  An hourly job, and **Import results now**, reads every
completed scan, old ones included, splits its findings by host, and gives each
host that is a site here a finished scan dated when Rapid7 finished it.  Only
full scans come in, and Rapid7's false positives and duplicates are left out.  A
site's newest few scans keep their findings, `ias.recent_detail` of them, and
older ones roll back to counts, with **Pull full results** to fetch one again.
A scan with its findings gets the PDF report, which names Rapid7 as the source,
and AI triage.

The newest finished scan becomes the site's last scan, and the list shows its
letter grade, worked out as the page loads with the same rules as the PDF, so a
decision made since then counts.  Every finished scan is also recorded as a DAST
test on the Web Applications tab for the web applications behind the site.

A site's page charts risk over time once it has a finished scan, with one line
per source, such as built in and Rapid7, since they measure different things.
Each point is one scan, its height a weighted risk from that scan's counts and
its color the scan's worst finding.  The bubble on it shows the number and the
point links to the scan.

## Curated rules

The stock engines find what their own templates know.  Curated rules add checks
that each have to prove what they report.  A rule is data rather than code: a
fixed engine reads it, and a small evaluator checks the result, so nothing a rule
says can run as code.  188 ship with the product: 104 misconfiguration and
exposure, 56 access control, 23 injection, and a few each for authentication,
business logic and client side.

**They start off.**  On the DAST Admin page, **Premium Curated Rules**, press
**Load curated rules**.  That adds shipped rules that are not here yet, disabled,
so an upgrade never quietly starts running new checks.  It also refreshes rules
nobody edited, keeping whether each is on, and switches off an untouched rule the
product stopped shipping.  Enable rules one at a time, or tick a whole class.  The
list is grouped by class.

**When they run.**  After the engines, at the premium depth, or under a saved
scan profile that names their rule sets.  A profile called PHP with premium depth
and the php rule set runs just those, and can be a site's default.  The scan's
engine row says how many ran and groups the reasons the rest did not: wanting the
callback, a second account, a mapped repository, or not being in this profile.

**The standard.**  One validator is the gate for a save, for an AI draft and
again before the engine runs a rule.  It requires:

- a safety class.  `read` may send only GET, HEAD or OPTIONS.  `neutral` may send
  a request that changes nothing lasting, and a POST has to say why.  `oob` may
  prove only that a server made contact with the callback
- no PUT, DELETE or PATCH in any class, and nothing in a probe that could change
  data or knock a service over
- a control, a request that cannot succeed so the normal answer is known, and a
  differential, the difference a finding stands on.  A bare 200 is never a finding
- at least one re-test
- how to reproduce it by hand, and how to fix it

The rule's requests are held to the site and the company's domains.  A probe can
try several known paths, can decline to follow a redirect, and can forge a variant
of the signed in session's JSON Web Token to test whether its signature is checked.
The standard is published as a JSON Schema from the same page, so any tool can
write to it.

### Drafting a rule with AI

With a model set up on the AI page, **Draft a rule with AI** takes what you want
to find in a sentence, such as "a detection rule for a PHP-CGI argument injection
flaw".  The model works in the background and the result lands under **Drafted
rules**.

The model is told the standard, and the validator is what enforces it.  A draft
that names a host or an absolute URL, or fails the standard, is not offered as a
rule, and the page says why.  A good one can be reviewed and edited.  It saves
disabled and marked **AI draft**, and a person enables it.  Running a saved rule
sends nothing to the model.

The validator proves a rule is safe in shape and can show evidence.  It cannot
prove a rule finds what you meant, so try it on a site where you know the answer.

### Two accounts

A site can hold a second test account, set under **Second account** in Edit.  With
two accounts, a check finds an object from the second account's own pages, then
reads it as the first account and as a signed out visitor.  It reports only when
the first account gets the second's object and the visitor does not.  It stays
quiet when the object is scoped to its owner or is public, and when no second
account is set.

From outside, nothing can know what your policy meant to allow, so the finding
gives proof to judge: the address, the status each account got, whether the pages
matched, how to repeat it, and a screenshot as each account, on the page and in
the PDF.  Up to six findings get pictures in a scan.  Each account has a field,
**What this login should and should not do**, and it goes into the evidence and
the AI triage, so a read only auditor who may see everything can be told from a
real bug.

These checks run last, and a long scan can outlast a sign in.  So each account
signs in fresh at the start of the stage, a page that says the session expired is
not read as content even when it answers 200, and each may sign in once more part
way.  They only read, so they say who can see an object and not who can change it.

## Scheduled scans

A site's page has **Scheduled scans**: once at a date and time, or every day,
every week on a day, or every month on a day, at a time.  Times are read in
the time zone set in Settings, and move with it.  Day 29, 30 or 31 runs on the
last day of a shorter month.  Each schedule has its own profile (the site's
default unless changed), sign in and AI triage, and one that sends payloads
needs the same confirmation as a scan started by hand.

The scheduler looks every minute.  A run that finds the site already being
scanned, marked no scan or obsolete is skipped, and the schedule says why.  A
once schedule turns itself off after it runs.  Through the API:
`GET` and `POST /api/v1/external/assets/{id}/schedules`, and `DELETE` with the
schedule's id.

**Schedule monthly scans** in the list gives the ticked sites, or every site, a
monthly scan with one profile, standard by default, inside a time window, 22:00
to 04:00 by default.  Each site gets its own slot, across days 1 to 28 and then
half hours, so a night holds a few scans rather than all of them.  A schedule can
also run on InsightAppSec, using a scan config rather than a profile.

## A proxy per site

Some sites only let in certain networks, and turn this server away with a
firewall block page.  A site can have its own web proxy, set under **Proxy**
in Edit or as `proxy` through the API: `http://host:port`, or
`http://user:password@host:port`.  It is saved encrypted and shown without its
password.  The site's page requests, its screenshot, the form login and the
engines (nuclei, ffuf, nikto, wapiti, sqlmap and dalfox) go through it.  DNS,
the port check and the TLS reads, including testssl, go direct: a web proxy
cannot carry them.  A scan sent to a nextgen-dast server runs from that
server, so the proxy does not apply there.

When a site does turn this server away, its screenshot is kept and shown as
the firewall block page this server was given, so it is plain at a glance
that the site is blocking the scanner rather than broken.

## Signing in for a scan

Set under **Scan sign in** in a site's Edit, or as `scan_auth` through the API.
Three ways:

| Kind | What it holds | Good for |
|---|---|---|
| Header | A header name and value, such as Authorization: Bearer and a token | APIs |
| Session cookie | The Cookie a signed in browser sends | Single sign on |
| Form login | The login page, a user name and a password | Ordinary login pages |

The secrets are saved encrypted, are never shown again, and are taken out of
every finding, engine message and error before anything is stored.  A form
login is signed in once before the engines start, keeping hidden fields such
as a CSRF token, and the session it gets is handed to every engine; wapiti is
also given the form so it can sign in again.  The login page has to be on the
site's own domain.

nuclei, ffuf, dalfox, sqlmap, nikto and wapiti sign in.  The baseline checks
and testssl stay signed out.  A scan says whether it signed in, on its page
and in its report, and a signed in scan past baseline needs the confirmation.
Use a test account: a signed in scan can change what that user can change.

**Test sign in** on a site's page signs in now with each saved account, the second
included, and reports the result of each, so a wrong password shows up before a
long scan rather than as a scan with nothing signed in.  A redirect that changes
the host, or drops from https to http, loses every credential the request carried.

A nextgen-dast server's API takes a form login, or HTTP Basic, which is sent
from an Authorization: Basic header.  A bearer token or a cookie has no field
there, so such a scan is refused rather than run signed out.

## The user agent

Every request a scan, a screenshot or a telemetry read makes says it is the
same browser: a current desktop Chrome, or whatever **User agent for scans**
in Settings says.  It has to start Mozilla/5.0 like a real browser's, since a
scanner's own name is what firewalls block first.

## Default scan profile

Each site can have its own default profile, set in Add or Edit.  The scan
dialog starts with it, the API uses it when no profile is sent, and **Scan the
ticked sites** can use each site's own.  Without one it is quick.

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

## Deciding on findings

Each finding on a scan's page has three small buttons:

- **False positive.**  It leaves the scan's counts, its worst severity, the
  site's last scan and the PDF report entirely.
- **Change sev.**  The new severity is what counts and what the report shows.
  The scan page still says what it was found as.
- **Exception.**  Accepted until a date, at most 365 days out.  It is not
  counted until then, and counts again the night after it ends.

Every decision needs a reason of at least 10 characters, and records who made
it.  **Revert to original** or **Remove exception** on the finding's line takes
it back, and **Change** reopens it.

**Keep for new scans** is ticked by default.  The decision then holds on every
scan of the site that finds the same thing, new ones too.  A finding is the
same when its title and its address without the query match.  Untick it and
the decision holds on this scan only.  A scan's own decision wins over the
site's on that scan, and reverting it lets the site's show again.

The API does the same with
`POST /api/v1/external/assets/{id}/scans/{scan}/findings/{key}/decision`, with
kind, reason, severity, expires and persist, and `DELETE` on the same address
to revert.

## Repositories behind a site

Worked out on every read, best first:

| Evidence | Score |
|---|---|
| Linked by hand, or the host found in the code by a scan | 100 |
| The host in the repository's web addresses | 95 |
| A web application the repository is part of lists the host | 90 |
| The host in a diagram's addresses | 80 |
| Another environment of the host is in its web addresses or web application | 75 |
| The host's first label, without environment words like dev or stg, equals the repository's name or its application name | 60 |
| The site's application or a tag equals the repository's application name | 50 |
| One contains the other | 40 |

60 and over are linked; below that they are suggestions.  A shared application
name alone never links a repository: sites with the same application name do not
all run the same code, so it is offered as a suggestion to link by hand.  **Not this one**
hides a link until somebody pins it back, and **Unpin** sends a hand made link
back to being worked out.  Only repositories the person can see are offered, so a group
that narrows what someone sees narrows this too.

## Code behind it, from a scan

A scan run on this server also works out which code answers the site, from
the paths it reached rather than the host name.  That finds the repository
nobody wrote the host down in.

**The routes.**  Every code scan reads the routes the default branch declares
(Express, Flask, FastAPI, Django, Spring, JAX-RS, ASP.NET, Go, Rails, Mule,
Laravel and OpenAPI files) and keeps them on the repository.  A repository
nobody has scanned since this shipped has no routes yet.  Archived
repositories are left out.

**The paths.**  wapiti's crawler keeps every page it fetched in its session,
with the status, and ffuf lists the words that answered.  The other engines
name the addresses of their findings.  Only a 200 is a URI path.  A redirect,
a sign in prompt or a refusal is something in front of a page.  A 200 only
counts as reachable when the site answers an address that cannot exist some
other way.  That answer is asked for at the root and under each prefix, so a
single page app's catch all or a gateway that answers 200 under `/api/v1`
does not count.  A 200 beside a 200 is fetched again, up to 150 of them, and
counts only when its page differs.  What could not be checked is shown as
unchecked and counts for nothing.

**The match.**  A reachable path that a repository declares is evidence for
that repository.  A route parameter matches any one segment.  A route with
two or more fixed segments also matches under a prefix, such as a servlet
context.  Routes every repository has (`/login`, `/health`, and any route
more than 5% of repositories declare) are ignored.  A path several
repositories declare is split between them.  The confidence never reaches
100: **Pin** links the repository to the site, the same as linking it by
hand, and later scans read its routes.  **Match again** re-runs the match
against the routes as they are now and sends nothing to the site.

**A link that looks wrong.**  When a scan reaches none of the routes a linked
repository declares, and the host is not written in its code, the scan's code
section says so and offers **Un-pin**, which hides that repository for this site
and takes it out of the list at once.  It asks you to confirm with the owner,
because a repository can sit behind a site without sharing a route it reached.

**Code that is not a scanned repository.**  Under **Ad-hoc code source** in a site's Edit, give
a public git URL or upload a zip or tar.gz, and the read uses it the way it uses a
mapped repository.  A URL has to be plain https to a public host with no
credential in it.  An archive is unpacked with limits on size and file count, and
every entry is checked so nothing lands outside its own folder.  The read checks
code out in shared memory when there is room, and on disk otherwise.

## Reachable code, and confirmed by both

The read before a scan also looks for dangerous patterns, by type: a query built
by joining strings, a shell or eval call, an unsafe deserialize, a template
rendered from a string, a write into the page, and a file opened from user input.
Each carries the routes its file declares.

After the scan, a pattern is **reachable** when the scan reached one of those
routes, and **context** when it did not.  The report's Code and the scan section
lists the reachable ones as leads and the others as areas to review, which do not
count toward the grade.  This reads routes and patterns.  It is not a call graph,
so a reachable pattern is a strong lead rather than a traced path.

When a reachable pattern of the matching kind sits on the same route as a dynamic
finding, the finding is raised to confirmed, and it names the open code finding of
that type from the repositories behind the site.  Evidence on a confirmed finding
is labeled **Proof** in the report rather than Evidence.  None of this uses a model.

It reads the other way too.  A code finding that a dynamic scan matched says so on
its own page, naming the site and linking the scan, to anybody who can see the
finding.  The exception form then warns that the risk is proven and reachable, and
that "this code does not get deployed" does not apply.

The scan page also says how many URI paths were reachable, how many
addresses answered in all, the status mix, which engine found them, and for
each linked repository how many of its routes the scan reached.  The newest
scan that counted its paths sets `url_paths` and `url_paths_scan` (date and
profile) in the External sites CSV and `url_paths` in the API, so you can
see how big a site's scan is.  Recorded scans count nothing and leave the
last count alone.

## Exposure

With `dast.exposure_check` on and a proxy set, each telemetry refresh also fetches
the site's front page through the proxy.  A firewall or bot page counts as not
reached.

| This server's allowed side | The public side | The site reads |
|---|---|---|
| Reaches the site | Reaches the site | Open to the world |
| Reaches the site | Does not | Whitelisted |
| Does not | Does not | Unreachable |
| Does not | Reaches the site | Anomaly, and worth a look |

**Validate proxy** shows the address each side leaves from.  The list has an
Exposure filter and a badge per row.  The site page shows one picture when it is
open, since both sides saw the same page, and one from each side when they differ.
Each answer says what one outside address saw rather than the whole internet.

## Combined risk

The last dynamic scan leads, because it is what an attacker can reach now.
Open code findings behind a live site raise it, one step below their own
level, since the code may not be what is deployed.  Both at medium or worse
raise it one more step.

## The risk of a finding

Each finding on a scan also goes on a five by five matrix, shown in the PDF with
its reasoning.  It uses no model and no tokens.

**Likelihood** is how sure it is: a curated rule that proved it ranks above a
baseline check, and that ranks above an engine's heuristic.  A known exploited
issue moves it up, and a matching reachable pattern in the code confirms it.

**Impact** is what a successful attack yields, by the class of weakness.  It goes
up on a site open to the world or a sensitive address, and down on a whitelisted
site.  An unconfirmed finding outside the dangerous classes stays capped at its own
severity, so exposure alone cannot make a low into a high.

**The data it holds.**  The product estimates what an application holds from the
linked repositories' sensitivity tags, names, application names and diagrams: SOX,
card data, health data, CUI, sensitive personal data, personal data, customer data
or credentials.  The most serious one raises impact on proven findings, the page
and the report say what it found, and the report names the consequence, such as
fines or breach notification.  When nothing matches, nothing is claimed.  This reads
tags and names, so an untagged repository with a dull name reads as holding nothing
in particular.

**How it is abused, and a real case.**  Findings in a serious class carry how that
class is attacked and a documented public incident from a table kept in the code,
on the page and in the PDF, with AI on or off.  A low or informational finding with
no documented case names none.

A soon to expire certificate is graded by the days it has left: 15 or fewer, or
already expired, is high, 16 to 29 is medium, and 30 to 40 is informational.

## AI

Both go through the AI analysis page's model and are off until one is set up.

- **AI triage** of a scan: each finding gets likely real, likely false
  positive or needs review, with the code finding that supports it, and a short
  account of what can go wrong, how it is attacked and how likely that is here,
  from the exposure, the data held and the computed risk.  It may use only the
  incident and the consequence it was given, and it never changes a severity.
  On a cross account finding it judges the access against what each login is
  meant to do.  A likely false positive is taken out of the scan and
  its counts, unless it is about a secret (a key, password or token, which
  only proof lowers) or a person has decided on it.  The scan page links to
  what was taken out, with the model's reason and a Put back button.
- **AI risk read** of a site: the last scan and the worst open code findings
  behind it, read together, with where they agree and what to do first.

Three limits keep triage cheap.  It reads only what passed the filters above.  A
finding unchanged since the site's last reviewed scan reuses its verdict and sends
nothing.  Of the rest, `dast.ai_max_findings` go to the model, highest risk first,
and the others keep their computed risk and are marked not reviewed.  A person's
decision still wins.

Every call is in the AI cost page under `dast-triage` or `external-risk`.  The
scan and the site also keep their own token counts and cost.  Path traversal
and script payloads in engine evidence are left out of what is sent.

Code findings with an exception, a not deployed scope, or a false positive
grade (info) are never sent, counted or shown.  A saved triage or risk read
was written from the findings as they were at the time, so it is checked
each time it is shown.  When its summary names a code finding that has since
been excepted or marked a false positive, the summary is hidden, on the page
and in the PDF, until it is run again.  Priorities, next steps, matches and
correlations that name one are dropped.  A fixed finding is not hidden.

## Fewer false positives

Every path an engine claims to have found is asked again before the scan is
saved (up to 400 addresses):

- An address that answers 404 or 410 has nothing there, so a claim that a
  file or page was found is dropped.  What the page itself carries stays:
  input it echoes back (XSS, header injection) or a key in it.
- An address that answers with the same page as an address that cannot
  exist is dropped.  Two such addresses are asked: a file under a folder,
  and a name that starts with a dot.  Some sites (Adobe Experience Manager
  among them) give a real 404 for a missing page but their home page for
  `/.anything`, so `/.bash_history` was reported as a shell history file.
- One engine giving the same title on three or more addresses is one
  finding at the site's root that lists them.  When most of the addresses
  that were checked answered not found, it says so: "The site's not found
  page: Google API keys ... The key is: ...".  A title the engine cut short
  joins the rest.

The re-check also drops a path that answers 401 or 403, which is a working access
control or an expired session rather than a served file, and one that redirects to
a sign in page.  ffuf reports a path only on a 200 or 206, and keeps the others as
coverage.  Wapiti's cross site request forgery, Content Security Policy and htaccess
findings are re-checked the same way.  Findings about what a page echoes or holds
stay.  Script injection a Content Security Policy blocks, and cross site request
forgery that SameSite cookies block, are not reported.  Cookies set on a redirect are
kept, so a session cookie set on the way to a login page is seen.  A GraphQL
introspection finding needs a real schema in the answer.

Scans finished before these rules got them once, when the application
started.  Findings with a person's decision were left as they were.

Findings can be ticked on a scan page and given one decision (false
positive, a new severity, or an exception) together.  A decision shows at
once on the page and in the PDF, with no new scan: the PDF is typeset on
each download, and what the saved AI review said about a finding since
called a false positive, excepted, or taken out is left out of it.

Scope matters as much as the filters.  Only the paths of a real page count, as
[Code behind it](#code-behind-it-from-a-scan) explains, and the External sites CSV
adds `http_200_paths`, `unique_endpoints`, `paths_answered` and `scan_blocked`, so a
site that refused most of the scan is plain to see before anybody reads its count
as coverage.

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
