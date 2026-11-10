# Changelog

Newest first.  Written for somebody deciding whether to upgrade, so every entry
says what is different for a person using the product rather than which files
moved.

## 2026-11-10

**New code and web checks from what outside AI pen testers proved.**  Five
vendors tested a PHP application, and the weaknesses they proved were turned
into checks that run on every scan for no model cost:

- Dompdf set to run PHP inside the documents it renders, which turned a
  company name into code execution.
- The request's own path written into a page unescaped, usually
  `$_SERVER['PHP_SELF']` in a form action.
- A spreadsheet formula guard that looks only at the first character, so a
  leading space gets past it.
- An upload accepted on the content type the browser claims.
- An address check that blocks private ranges but lets the 100.64.0.0/10
  shared range through, where some cloud metadata lives (Python `is_private`,
  and PHP's private and reserved range flags, PHP 8.5 included).
- A forwarding header trusted from any address, which lets a caller pick
  their own address past rate limits and lockouts.

Two new web checks: a dependency lock file served from the web root, and extra
path after a PHP script written into the page.  The open redirect check also
tries the path form some servers redirect on, and no longer reports a redirect
to the site's own sign in page that only carries the value along.  Code
reasoning now names the access mistakes those testers found most: a child id
never checked against its parent, a search or export that returns what the
same caller is refused by id, an owner field set to any user, model spend open
to a read only role, and sessions that outlive a deactivated user.  Press
**Load curated rules** on the DAST Admin page after upgrading.

**Site screenshots and ad-hoc clones can no longer be steered to an internal
address.**  The screenshot browser checked each host it loaded, then looked the
name up again on its own, so a name whose DNS changed in between could put a
page onto an internal address.  It now goes through a local proxy that connects
only to public addresses, and only to the address it checked.  Secure pages
pass through it unopened, so sites see the same browser as before.  When a
site has its own proxy set, or allow private addresses is on, nothing changes.
A git URL given for a site's code is no longer followed through a redirect,
since only the address as typed was checked.

**Reasoning findings say what to fix, and every claim is checked before it is
filed.**  The finding page now shows what was found, which it never did: a
finding read as its title and nothing else.  Code reasoning writes each finding
up for the developer: what it is, who can reach it, how it would be exploited,
the impact, how to fix it and what to confirm.  Every claim, not only the high
ones, must now survive a second look that tries to prove it wrong.  That look
sees the access checks the handler calls, and where the permissions and roles
it checks are granted, and a claim it cannot confirm is not filed.  **Check them
again** on the AI page gives the findings filed before this the same look:
confirmed ones get the write-up, and the rest are set aside with the check that
was found, never closed.

**Web checks about what anybody can see now look as anybody.**  In a signed in
scan, 149 checks for exposed files, consoles and admin tools sent the scan's
own session, so a page open only to the signed in account could be reported as
open to the world.  They now send no session.  Press **Load curated rules** on
the DAST Admin page after upgrading so the saved rules pick this up.  Two new
checks: a SCIM user directory that answers without credentials, and an
OpenAPI or Swagger description served to anyone.

**Code reasoning reads each piece of code once.**  It now runs after each scan
on every branch that gets code scanning, not only the default branch.  A branch
still on the commit it was last read at is not fetched at all.  On a branch
that moved, only handlers whose code changed are asked about.  A fork or a copy
of a repository reuses the answers already paid for.  An answer that came back
unreadable is no longer asked for again after every scan.  The per repository
setting is now new questions per scan, and handlers past it are read on the
next scan instead of never.  A cached finding keeps pointing at the right line
after lines are added above it.  Each connection has an **AI code reasoning**
switch, on by default.

**Confirmed reasoning findings turn into reusable rules.**  When code reasoning
confirms a high finding, the model drafts one semgrep rule for that kind of
mistake.  The draft has to match the code it came from, miss the fixed
version, and stay quiet across that repository before it is offered.  It is
listed on the AI page, switched off, for an administrator to turn on.  Then
scans find that mistake for no tokens.

**Sixteen new built in rules** for mistakes a pattern can see without reasoning:
JWT signature checks switched off or the algorithm read from the token, secrets
compared with `==` in Python, JavaScript and PHP, reset codes and tokens made
with a non secure random, whole request bodies poured into models in Python,
JavaScript and Laravel, a Django REST view set open to anybody, request forgery
checks switched off or exempted with no signature check, a model's answer
handed to a shell or a query, and exception text from broad or database errors
sent back to the caller.  Each was run over about 2 GB of real code, and every
false alarm found there is now a test case.

**A scan of this site no longer locks everybody out.**  A web scan aimed at the
site came in through the load balancer, and when the balancer was not listed as
trusted every person shared the balancer's request budget, so the scan used it
up and sign in answered 429 for everyone.  The **Load balancer addresses** box
now refuses anything that is not an address or range, and a new **Scanner
addresses** box on the Sign in tab gives a named scanner its own budget, ten
times the normal one and never unlimited.  The balancer itself cannot be listed
there.  The load balancer guide says how to set both, and that `0.0.0.0` trusts
nothing.

**Sites link to the code that serves them, from the code itself.**  Every scan now
reads each repository's default branch for the hosts it answers on: ingress and
route hosts, Helm values, nginx, Apache, Traefik and Caddy, a `CNAME` file, CDN
aliases and certificates in Terraform, deploy environment urls in CI, OpenAPI
servers, allowed hosts and app url settings.  A site whose host is there links to
the repository, and so does another environment of it.  A host the code only
calls is a suggestion.  A repository that serves more than 20 hosts, such as
shared DNS or CDN code, only suggests.  A repository's page lists **Sites its code
serves**, and an administrator can add the ones that are not External sites yet in
one press.  The lists fill in as each repository is next scanned.

**Unpin or remove several repositories behind a site at once.**  On a site's
page, Code behind it has a tick box per repository and one at the top for all of
them.  **Unpin selected** sends hand picked links back to being worked out, and
**Remove selected** keeps every ticked repository from being linked to the site
again, asking first.

**An application name alone no longer links code to a site.**  A site whose
application, or one of its tags, matched a repository's application name had that
repository linked as code behind it.  Sites that share an application name do not
all run the same code, so that match is now only a suggestion on the site's page,
with a **Link** button.  The host in the repository's web addresses, its web
application, its diagram or its name still links it, and so does anything linked
by hand.

**After upgrading, load the curated rules.**  Several shipped rules were tightened
and six duplicates were retired, and only loading them brings that in.  Rules you
edited yourself are left alone.

**Credentials go only to a certificate this server has seen before.**  A signed in
scan, a sign in test and a signed in screenshot used to send the site's password,
cookie or token over any certificate at all.  A certificate that verifies is used
as before.  One that does not, such as a self signed or internal one, is saved the
first time credentials go to it, and from then on credentials go only to that
certificate.  If it changes, the scan runs signed out and says why.  When the site
really did renew it, press **Clear saved certificates** on the site's page.
Nothing that signs in today stops.

**A scan's session stays with its site.**  The session goes only to the site being
scanned and its subdomains.  Before, the scan proxy also sent it to every other
company domain a link or a redirect reached, and a signed in screenshot sent it to
every host the page loaded anything from.

**Other ways credentials could leak are closed.**
- A login form that submits by GET is refused, because the password would end up
  in the address and in every log that keeps one.
- The single sign on provider has to be https, except on localhost.
- The GitHub token handed to zizmor no longer appears in the process list.
- Code sent to the model is masked more thoroughly: quoted JSON keys, values with
  spaces and YAML blocks are now covered.  Text cannot close the block that marks
  it as data.
- The sample fix plan workflow runs its helper from the base branch, so a pull
  request cannot change the code that holds the token.

**The editor asks before sending code to a workspace's server.**  The token, and
the switch that turns certificate checks off, are now read only from your own
settings.  A repository's settings that name a different server get one question
per workspace before anything is sent there.

**Dynamic rules that said more than they proved.**
- Kubernetes, Portainer, Vault and Solr now report only when a protected list
  answers without credentials, not when a public status page does.
- The Jenkins script console has to be the console itself, not its sign in page.
- Backups have to carry an archive's own signature, and the editor sftp, Docker
  config and actuator beans files have to be real JSON.
- The phpMyAdmin, Adminer, Kibana, WebLogic and ColdFusion sign in pages are now
  low findings that say the page is exposed.  They no longer claim nobody needs a
  password.
- Pairs that reported one exposure twice now report it once.

**Seven more code rules, and code reasoning reads model answers.**  New rules find:
- Chromium told to ignore certificates
- archives read without a size check
- pull request workflows that run their own scripts beside a secret
- git clones that follow redirects
- passwords in a query string
- prompt fences the text can close
- request bodies parsed before any size limit

Code reasoning now also asks about functions that let a model's answer change a
record with no check and no person confirming it.

## 2026-11-09

**After upgrading, load the curated rules.**  Three new dynamic rules arrive
disabled, as always.

**Code reasoning, for the checks that are missing.**  A pattern finds a dangerous
call.  It cannot find a handler that loads a record by the id it was sent without
asking whether the caller may see it, or an admin action whose page hides the button
but whose server never checks the role.  On the AI page, **Code reasoning** has the
model read the request handlers that take an id or do something privileged, each with
the access checks it calls, after every scan.  Nothing else in the repository is
sent.  It is off by default and has its own **monthly token limit**, checked before
every question, with this month's use shown beside it.  An answer is kept against
exactly what was sent, so a handler nobody changed is never asked about again, and
only a high severity claim gets a second question to confirm it.  What it finds is
filed for a person to confirm.  It never lowers, waives or closes anything, and a
scan never closes what it filed.  **Run code reasoning** on a repository's page runs
it on demand.

**Twenty three new code rules.**  They find security checks that return true before
checking anything, CSV exports that do not neutralize formulas, requests that follow
redirects after checking only the first address, a host checked for a private
address and then fetched by name, certificate checking turned off, secrets on a
command line, headers set for a whole browser session, links printed with HTML
escaping only, strip_tags and regular expressions used as HTML sanitizers, archives
read without a size limit, SAML responses not tied to a sign in, privileged
containers, and editor extension settings a workspace can redirect.

**Three new dynamic rules, all read only.**  A sign in form that sends the password
in the address, single sign on discovery that names plain http addresses, and a
session cookie sent on requests from other sites.

**Propose changes and branches not to scan.**  Anybody who can see a repository can
propose changes from its own page, including ticking branches that should not be
scanned, with a reason.  Nothing moves until an administrator approves it on
Proposed Updates.  The default branch is never offered, and a whole repository
cannot be left out this way.  An approved branch is skipped entirely, credentials
included, and findings that live only there stay open.

## 2026-11-08

**After upgrading, load the curated rules.**  Shipped rules do not arrive by
themselves.  On the DAST Admin page, press **Load curated rules** to add new ones,
disabled, and refresh the ones nobody edited.  Stale copies of the cross account
rules are the most important to refresh, because the old ones report on far weaker
evidence.

**A code finding says when a scan confirmed it live.**  A code finding names the
site and links the scan when a dynamic scan reached the same weakness.  When
somebody asks for an exception on one, the form warns that the risk is proven and
reachable, and that "this code does not get deployed" does not apply.  The dynamic
report names the exact code finding, by its id, when a reachable code pattern and
the scan agree.

**A link that looks wrong says so.**  When a scan reaches none of the routes a linked
repository declares and the host is not in its code, the scan page says so and offers
**Un-pin**, which hides the repository for that site and drops it from the page at
once.  The button used to do nothing for a repository linked automatically.

**Code that is not a scanned repository.**  A site can name a public git URL or take
an uploaded zip or tar.gz, and its routes and dangerous patterns are read the same
way.  The URL must be plain https to a public host with no credential in it, and an
archive is unpacked with limits.

**Each weakness explained as a risk.**  AI triage now says what can go wrong, how it
is attacked and how likely that is here, from the exposure and the attack surface.
How a class is abused and a documented public incident come from a table in the code,
on the page and in the PDF with AI on or off.  The model may name no other incident.

**Risk weighs the data an application holds.**  SOX, card data, health data, CUI,
personal and customer data are estimated from the linked repositories' tags, names
and diagrams.  The most serious one raises impact on proven findings, and the report
names the consequence.  A noisy low finding stays low.

**Cross account findings show their proof.**  A finding says what each account saw and
carries a screenshot as each one, on the page and in the PDF.  Each account has a field
for what it should and should not do, which goes into the evidence and the AI triage.
Both accounts sign in fresh for these checks, because a long scan had outlasted the
session and an expired session page that answered 200 was read as the account's
content.  ffuf no longer reports a 401 or 403 as a found file.

**More curated rules.**  Oracle E-Business Suite self registration, file read and
reflected script checks.  Adobe AEM's content, QueryBuilder, developer and OSGi
consoles and a reflected script check.  Magento version.  The MuleSoft APIkit console.
Exposed credential files and Spring Actuator on their known paths.  GraphQL login
amplification through aliases.  Open registration on LibreChat, an open Open WebUI,
and exposed Ollama, Jupyter and vector databases.  CORS with credentials, open redirect
and Host header injection, the first rules for business logic and client side.  A rule
can now try several known paths, and can decline to follow a redirect.

**Risk over time, per source.**  A site page charts risk with one line for each of its
scanners, built in or Rapid7, each point labeled with its number and linked to its scan.

**A time limit per engine, per site.**  A site can set its own minutes for nuclei,
Nikto, ffuf, Wapiti, sqlmap and Dalfox.  Wapiti also keeps out of the endless link
spaces an online store generates, which used to take its whole limit.

**Single sign on and sessions, from a security review.**  An account is now identified
by the provider's issuer and immutable subject rather than a user name that can be
reused, and the flow is bound to the browser that started it.  A scan drops every
credential when a redirect changes host or falls back to http.  The API review no
longer holds up the web worker while it runs, and account recovery codes, which never
verified, now work.

**Rapid7 stops switching itself off.**  Saving the Settings page turned the
InsightAppSec integration off and blanked its key, because that page has none of its
fields.  It now leaves them alone.

## 2026-11-07

**Risk scoring.**  Each dynamic finding goes on a five by five matrix, from how sure it
is and what it would yield.  It uses no model.  The PDF shows the matrix and the
reasoning on each finding.  The same finding reads higher on a site open to the world
than on an allow listed one, and an unconfirmed low stays at its own level.

**Reachable code.**  The code behind a site is read for dangerous patterns.  After the
scan each is marked reachable when the scan reached its route, or context when it did
not.  A live finding on a route with a matching pattern is raised to confirmed, and its
evidence is labeled Proof.

**Open to the world, or whitelisted.**  An optional second look through a proxy on no
allow list sets each site's exposure.  The list filters on it and the site page shows
what each side saw.

**A sign in proxy for every engine.**  Each scan starts a local proxy that puts the
session on every request and refuses hosts out of scope, on by default.  The scan page
shows how many requests each tool sent.

**A browser reads client code.**  Thorough and premium scans load pages in a headless
browser and report a key in a vendor format, redacted, and source exposed through a
source map.

**Close to a hundred more curated rules.**  Served credential and config files,
database dumps, debug panels, registries, consoles and open services, plus JSON Web
Token bypass rules through a new step type.  Each fires on a specific signature against
a control, never a bare 200.  The scan says why any rule skipped, grouped by reason.

**Far fewer false positives.**  Paths answering 401 or 403, redirects to a login,
script injection a Content Security Policy blocks and cross site request forgery that
SameSite cookies block are left out, and Wapiti's findings are re-checked too.  A
refusal that merely names `__schema` is no longer GraphQL introspection.

**AI triage on a budget.**  A finding unchanged since the last reviewed scan reuses its
verdict and sends nothing, and a cap, 40 per scan by default, sends the highest risk
first.

**Rapid7 detail.**  A site's newest InsightAppSec scans keep their full findings, whatever
their size.  An older one has **Pull full results**.  The PDF report, which names Rapid7,
and AI triage work on them.

**Engines that keep what they found.**  nuclei and Dalfox write each finding as they find
it, so a timeout keeps them.  nuclei also covers more in the time.  Nikto is paced so a
firewall does not stop it in a second, and ffuf has about 1,150 paths on the deeper
profiles.

**Test sign in.**  A button on the site page signs in with each account now and reports
the result, the second account included.

**Better screenshots and certificate grades.**  Preloaders and scroll animations are
cleared before the picture, so those pages stop reading as blank.  A certificate within
the window is graded by the days it has left.

## 2026-11-06

**Curated rules, and a page to run them from.**  A new DAST Admin page, reached from
External sites, holds enhanced checks that run after the stock engines.  A rule is data
rather than code, and a validator refuses anything destructive, out of scope or unable
to prove a finding with a control, a re-test, a way to reproduce it and a fix.  Out of
band checks prove server side request forgery with a callback.

**Draft a rule with AI.**  Describe what you want to find and the model drafts a rule in
the background, under **Drafted rules**.  It meets the same validator as a hand written
rule, saves disabled and marked **AI draft**, and runs only once a person enables it.
Running a saved rule sends nothing to the model.

**Scan profiles.**  A saved profile is a depth plus the rule sets to run, per scan or as a
site's default.

**Two accounts.**  A site can hold a second test account, which unlocks read only checks
for one user reaching another's data.

**InsightAppSec moves.**  It is now on the DAST Admin page's Integrations tab, with the
other dynamic scanning settings.

## 2026-11-05

**DAST reports leave out code findings with an exception or a false
positive.**  A scan's AI triage and a site's AI risk read keep what the model
wrote, so a code finding given an exception afterward went on appearing in
the PDF.  Now, when a saved summary names a code finding that has since been
excepted or marked a false positive, the summary is hidden with a note to run
it again, and any priority, next step, match or correlation naming one is
dropped.  The code finding counts beside a site also leave out exceptions.

**Fewer dynamic false positives.**  An address that answers not found is dropped, a name
starting with a dot is tested against a control, and one title on many addresses rolls up
into one finding.  Findings can be ticked and decided together, and a decision shows at
once on the page and in the PDF.

**A grade on the sites list.**  The newest scan's letter grade sits beside its worst
severity, worked out as the page loads with the same rules as the PDF.

**Import web applications.**  The web applications CSV comes back in as a full sync, with a
preview, and a removal has to be ticked.  The External sites CSV fills in change frequency.

**Scan now scans what you can see.**  Somebody who is not an administrator now scans
exactly the repositories they can see.  A group entry of `*` used to send a developer's
click to every account.

**Utilization history survives an upgrade.**  The charts no longer come up empty after a
new container.

## 2026-11-04

**Upgrades wait for running scans, and for a slow start.**  `install.sh
--upgrade` now waits for any scan in progress to finish before it restarts
the app, because a restart stops it.  Use `--upgrade --now` to restart
straight away.  After the restart it keeps waiting while the app is still
starting, which can take several minutes when stopped scans are being read
back, and shows what it is doing.  It used to give up after two minutes and
then print "Upgraded" anyway.  Now it says "Upgraded" only when the app
answers, and otherwise says it is not answering and exits with an error.

**Change, withdraw or resubmit your own exception request.**  The person who
asked can now change the reason, expiry, ticket or kind on the finding page,
and withdraw it while it is still waiting.  A rejected or withdrawn request
shows why, with **Update and resubmit**, which sends it back for approval.
An approved one cannot be changed on the screen; an administrator revokes it.
Nobody else can change or withdraw your request.  The Exceptions page shows
each exception's id (E77), the approver's note, and a **Change** or
**Update and resubmit** button and a **Withdraw** button on your own rows.
The search takes an exception id, as 77, E77 or "exception 77".  In the API,
`PATCH /exceptions/{id}` on a rejected or withdrawn one now resubmits it
instead of answering 409.

**Find exceptions by id in the API.**  `GET /api/v1/exceptions` now takes
`id`, one exception number or several separated by commas, and `vuln_id`, the
GCR id of the finding.  You still see only the exceptions you could see
before.  The Python and bash samples take `--id` and `--vuln-id` (`-g` in
bash) on the exceptions list.

**Code behind it, from a scan.**  A dynamic scan run here now says which
repositories likely serve the site, from the paths it reached rather than the
host name.  Each code scan reads the routes a repository declares, and the
scan page lists the repositories whose routes the site really served, with a
confidence score, the matching paths, and a **Pin** button that links the
repository to the site.  **Match again** re-runs the match against the
routes as they are now without touching the site.

**How many URI paths a scan reached.**  Only a 200 counts, and only when it
is a real page rather than the site's answer for an address that cannot
exist.  The scan page shows that count, every address that answered, the
status mix and which engine found them, and for each linked repository how
many of its routes the scan reached.  The PDF report says it too, and the
External sites CSV has `url_paths` and `url_paths_scan`, so you can see how
big a site's scan is.

**Up to 12 scans at once.**  Settings now allows 1 to 12 engine scans at the
same time, up from 6.  The default is still 1.

**Exceptions and exclusions through the token API.**  A `reports` token now reads, changes
and withdraws its owner's exceptions, and can revoke where its owner's role allows, which
leaves the record in place.  A new `approve` scope, for administrators only, approves,
rejects and writes exclusions, and replaces the rule above that a token could only ever
ask.  A leaked pipeline token still cannot hide anything.  Administrators can change the
scopes of an existing token.

**Rapid7 InsightAppSec.**  Scans can run on it by hand or on a schedule, and every completed
scan comes in on its own, old ones included, matched to your sites by host.

**How big a scan really was.**  The External sites CSV adds `http_200_paths`,
`unique_endpoints`, `paths_answered` and `scan_blocked`.

**Monthly scans for many sites.**  **Schedule monthly scans** spreads them across a night
window.

**Certificate expiry mail and faster lists.**  A morning mail names sites whose certificate
is about to end, after reading the live certificate again.  The list shows 50 sites a page
with small thumbnails.

**Staleness.**  `staleness.csv` and `staleness.json` name repositories and branches nothing
has landed in for 180 days by default, and a weekly or monthly digest can mail them.

**A site stays up during exclusion re-checks.**  They moved off the event loop, after one
froze the web app for about half a minute.

## 2026-11-03

**Decide on external scan findings.**  Each finding on a scan has small
**False positive**, **Change sev** and **Exception** buttons.  A false positive
leaves the counts and the PDF report entirely.  A new severity is what counts
and what the report shows.  An exception is not counted until the date it
ends, at most a year out.  Each needs a reason.  **Revert to original** and
**Remove exception** on the same line take it back.  A decision is kept for
new scans that find the same thing unless **Keep for new scans** is unticked,
and any scan can change it or decide differently for itself.

**Edit many external sites at once.**  Tick sites in the list and change any
of what Edit offers on all of them together: owners, environment, status,
scanning, flags, comments, tags, proxy, sign in and repositories.  Only the
fields ticked to change are touched, and it is all or nothing.

**A proxy per site, and the block page shown.**  A site that only lets in some
networks can be given its own web proxy, so its pages, screenshot, sign in and
engines go out through an address it allows.  A site that blocks this server
now shows the block page it served as its screenshot, instead of a blank card.

**Screenshots through bot checks, and pages that really are blank.**  A site
behind Imperva showed "a flat white page" and seventy open ports.  The
screenshot browser was stopped by Imperva's bot check, and the ports were
Imperva answering on everything.  Screenshots now use Playwright with full
Chromium, which gets past such checks and follows the redirects behind them,
so the site's real final page and address are recorded, and a page that is
genuinely empty keeps its white picture, marked blank.  The CDN and any bot
check are named, and open ports are not reported when nearly all of them answer.

**Scheduled scans, and how many run at once.**  A site can be scanned on a
schedule: once, or every day, week or month at a time, in the time zone set in
Settings.  Settings also says how many scans run at the same time, 1 to 6; a
site is still never scanned twice at once.

**Environments are yours to name.**  The environments an external site can be
in are a list in Settings, under Web and external sites, instead of a fixed
Prod, Dev, Stage and Clone.  The first is the default for a new site, and a
site in one that is taken off the list keeps it until somebody picks another.

**Signed in scans.**  A site can carry a header, a session cookie or a form
login, saved encrypted, and its scans sign in with it: nuclei, ffuf, dalfox,
sqlmap, nikto and wapiti all act as that user, and nothing secret is kept in
the findings.  A form login or HTTP Basic is passed on to nextgen-dast.

**One browser user agent.**  Every scan, screenshot and telemetry read sends
the same current Chrome user agent, which Settings can change.  sqlmap and
testssl no longer pick their own.

**A default scan per site, and quick by default.**  The scan dialog started on
baseline, a seconds long check that runs no engines, which made real scans
look like they finished early.  It now starts on quick, explains each
profile, and uses the site's own default when it has one.

**A site that is down is not a block.**  A Cloudflare 502 was reported as a
firewall block page and its screenshot hidden.  It is now reported as the site
being down behind its CDN, and ordinary pages that mention cookies are no
longer taken for blocks.

**A PDF report on a dynamic scan.**  A scan this server ran downloads as a
report laid out like nextgen-dast's: a graded cover, an executive summary with
OWASP Top 10 grades, scope and method, every finding with a command to see it
again and how to fix it, and the code behind the site.

**External sites: owners, environments, repositories and the full telemetry.**
A site now has executive and technical owners (email only), comments, Active
or Obsolete, Prod, Dev, Stage or Clone, whether external auth or a whitelist
is needed, and how often it changes.  Repositories and branches are picked
from a searchable list that recommends the ones the Web Applications tab ties
to the host, and can fill in the owners from it.  Telemetry adds nameservers,
CNAMEs, IPv6, mail servers, reverse DNS, ASN, netblock and domain registration,
and every field can be filled in by hand.  The site page opens with a large
screenshot, the way the site report did.  The list has a Scan button per site
and scans or deletes the ticked sites.  A scan that found nothing no longer
reports that the model failed when asked to triage it.

**Settings in tabs.**  The Settings page is five tabs instead of one long
scroll.


**External sites and dynamic scanning.**  Off until Settings turns it on, and
for administrators only.  List the company's domains and subdomains, and each
one gets its outside view: DNS, network owner, open ports, TLS, headers, a
hygiene grade and a screenshot.  Run a dynamic scan here with the same
profiles as nextgen-dast, from read only checks up to wapiti, sqlmap and
dalfox, start one on a nextgen-dast server, or record one run anywhere else
by hand or through the API.  Each site is mapped to the repositories behind
it, and a scan first reads their routes out of the code.  A combined risk
reads the live site and its code together, and an AI triage and risk read
are counted on the AI cost page.  A host marked no scan, or under a domain
marked that way, is never scanned.  See
[external-sites.md](external-sites.md).

## 2026-11-02

**Pipeline sample code.**  A new tab on the IDE tokens page downloads a kit
for build pipelines: a step by step guide in Word and PDF, a Python script,
the same features as bash scripts, and three GitHub Actions workflows.  The
server's address is filled in, and no token is ever included.  Its main tool,
the fix plan, lists secrets to rotate, packages to upgrade with the version
to move to, container images to rebuild, problems in build files, and code
fixes from AI reviews.  The scripts keep the token out of files other users
can read and off command lines, refuse plain http, and can read the token
from an encrypted file or a keychain.

**AI reviews over the API.**  A finding an AI review has read now carries the
review in the token API: the rating, the fix, what to check and what to do
meanwhile.  Only a review that still holds for the code as it is counts.
The deploy check passes the fix along, and says whether a secret was
confirmed live.

**Links say https.**  Addresses the server hands out, in the OpenAPI file,
the deploy check and the pull request gate, said http behind a TLS load
balancer.  They now say https when the install is marked as behind TLS.


**More for a reports token, and an API reference.**  A token with the
`reports` scope now reads its owner's findings, SBOMs and trend lines, and
asks for exceptions.  Each answer holds only what that person can open in the
web app, so a developer's token never names another team's repository.  An
exception asked for with a token is always a request, even on an
administrator's token, and still has to be approved in the browser.  The
whole estate report files stay with administrators.

**A check before a deploy.**  `GET /api/v1/check` takes a repository and a
branch and answers pass, fail or unknown.  It covers vulnerable packages,
packages in container images and problems in the build, such as CI
workflows, Dockerfiles and packages only the build uses.  A branch nobody
scanned answers unknown, not pass.  [pipelines.md](pipelines.md#checking-before-a-deploy)
has a script.

**An API reference tab** on the IDE tokens page lists every call, lets you
try each one with your token, and downloads an OpenAPI (Swagger) file and a
Postman collection.

## 2026-10-28

**A credential on a branch head says where.**  A TruffleHog match found on a branch head now
carries its file and line.

## 2026-10-27

**Auto LLM review.**  A switch on the AI page has the model read every new
finding a scan turns up, with no one pressing a button.  It keeps to a
requests per minute setting, shared by every scan, and reads at most a set
number of new findings per scan, worst first.  The findings list now badges
every finding AI has reviewed and has an **AI review** filter for reviewed or
not reviewed.  [ai-validation.md](ai-validation.md#reading-every-new-finding-automatically)
has the details.

## 2026-10-20

**A pull request gate.**  A step in the pipeline asks the server whether a
change may merge, and the server answers pass, warn or fail under one policy,
`config/gate-policy.yaml`.  Only what the change added can block: the files
it touched are reviewed at the merge base and at the head, and lines are
mapped across the diff, so moved or renamed code stays old.  A credential
added and deleted inside the change is still found.  Out of the box it
blocks a credential the provider confirmed is live, code two engines agree
is high or worse, a malicious package, a KEV listing or a reachable
critical, and a handful of named cloud and workflow mistakes.  Waivers and
learned rules apply.  Nothing is written to the code host and no finding is
filed.

Every repository starts in monitor mode, which passes and records that
enforcing would have failed.  The client is `contrib/gcr-gate`, with a
GitHub Actions workflow to start from, and it needs a token with the new
`gate` scope.  If the server is down it still checks the change's commits
for credentials.  [pipelines.md](pipelines.md#holding-a-merge-the-gate) has
the setup.  `ghscan review --base --head --fail-on policy` runs the same
check with no server.

**`--diff` reviews only what changed.**  `ghscan review --diff` recorded the
base and then read every file anyway, so every pipeline recipe in
[pipelines.md](pipelines.md) and its pre-commit hook were reviewing the whole
repository.  It now reads only the files changed against the base, plus
untracked ones.  The editor plugin was never affected, since it picks out
changed lines itself.  A base that is not a commit in that checkout still reviews
everything, with a warning.

**`--fail-on verified-secrets` means verified.**  It counted every
credential, the same as `secrets`.  It now counts only the ones the
provider said still work.  A review also reads a config only when `-c` is
on its command line, so a `GHSCAN_CONFIG` left in the environment for scans
no longer changes what a hook does.

**Mule flows are read.**  Semgrep and CodeQL do not read Mule flows, so a Mule
repository had no code findings at all.  A new engine follows an HTTP listener
with no security filter to mail, a database, an outbound request or a file,
and flags a credential read from the query string and an SMTP login with no
TLS.  An encrypted Mule property is info unless its key is committed beside
it.

**What a security report finds is kept.**  A problem the report finds that no
scanner did becomes a finding at a real file and line, announced the way a
scan finding is, and handed over once a scanner reports the same place.

## 2026-10-19

**Due for a test.**  Each web application can record its dynamic scans and
penetration tests.  It is due when it was never tested, when its code changed
since the last test, or when that test is older than a year by default.  The
due list exports as CSV, a backlog of tests imports from one, and a weekly
mail can name the sites that just became due.

**Addresses found for you.**  A repository's diagram offers the web addresses
its code serves or uses, each with a confidence from 5 to 99 and the reason,
and the likely ones start ticked.  The company's own domains, set on Settings,
count toward an address, and what the build pulls from never does.

**A repository's findings can be removed.**  An administrator can delete every
finding in a repository, with the exceptions on them and the exclusion rules
written for it alone, after typing its name.

## 2026-10-18

**A repository page.**  The name on Repositories opens a page with what the
repository holds, its application, its owners and who is told about it, each
saying whether it was set there or comes from the connection.  Its owners can
get its new findings by mail.

**Part of a web application.**  A repository can be marked as part of a web
application, with the addresses it answers on.  Nothing visits them.  Blast
Radius lists every web application with how long since its code last moved,
newest first.

**Anybody can propose a correction.**  Developers and readers can propose what
a repository holds, who owns it and where it is served.  Nothing changes until
an administrator approves it from Proposed Updates.

**Sign in returns you to the link.**  Following a link while signed out now
lands on that page once you sign in, rather than the dashboard.

## 2026-10-15

**A security report on a branch.**  From a finding, an administrator with AI
set up can ask for a PDF report on its branch: an executive summary, a risk
matrix, a heat map, detailed findings and a roadmap.  Ratings are worked out
in code from the model's likelihood and impact.  A false positive it names can
be lowered across its group with one confirmation.

**Organizations with no connection.**  A fine grained token reaches one
organization, and an organization that is never scanned looks exactly like a
clean one.  A weekly mail, or a button, names every organization the accounts
belong to that no connection covers.

**Why a live check said no.**  A credential now says whether the provider was
asked and could not confirm it, or whether it was never checked at all because
only the history or pattern engine saw it.  Not confirmed no longer reads as
safe.

**Check again leaves credentials open.**  Check again closed a credential once
its line was gone from the branch tip, and the next scan reopened it from the
history.  It no longer closes credentials.

**A JSON key is not a credential.**  A key in a JSON object, after a value
that happened to end in a keyword, was read as an API key.  It no longer is.

**A learned rule stays home.**  A rule learned from a finding with no code to
compare, a workflow for example, applies only in its own repository and to its
own files, and cannot be accepted everywhere.

## 2026-10-14

**A group fences people in.**  A scanning group is now all its members see,
and a login on the host is all anybody else sees.  Access used to be the sum
of everything on an account, so a group meant to fence somebody in widened
back out.

**One repositories table.**  Filter, tick and change scope from one table,
open a repository's branches to tick and scope them together, and export or
import the scope as CSV.  Archived repositories are hidden until asked for.

**Every download checked.**  Each scanner binary in the image is checked
against the sha256 its release publishes, and the build stops at the first one
that does not match.

**Distinct counts on the dashboard.**  Under each kind of problem: unique
secrets, code weaknesses counted once per rule and file, and vulnerable
packages once per version.  Forty repositories on one bad version is many
findings and one upgrade.

**What AI costs.**  The AI page has a cost tab fed by every call, good or
failed, since a failed call is billed too, and a cut off answer says so.

## 2026-10-09

**Credentials only, where nothing ships.**  A repository can be scanned in
full on every branch, in full on a list of branches such as release/*, or for
credentials only.  Credentials are still scanned on every branch of every
repository.

**A token that lost a repository.**  A connection test now names the private
repositories its token can no longer see, which had quietly stopped being
scanned with their findings frozen, and marks the connection partial.

**A pass switched off closes nothing.**  Turning a pass off in Settings used
to tell ingest it had looked and found nothing, and the next scan closed every
finding of that kind as fixed.  It now leaves them as they are.

**Diagrams from a finding.**  A finding offers its repository's diagram, to
draw for an administrator with AI set up, or to open for anybody who can see
the finding.

## 2026-10-01

**Validate a finding with AI.**  A new AI analysis page connects one language
model: a hosted provider's own API, anything that speaks the OpenAI chat API,
or your own inference service described as curl headers and a body with
SAMPLE where the question goes.  [ai-validation.md](ai-validation.md) lists
the providers and what each needs.  Once one is set up, a finding carries one button, Validate with AI.  The
model reads the finding, the reasons behind its grade, what the repository
holds, the decisions already made on findings nearby with their reasons, the
advisory for a vulnerable package, and the code that bears on it, and answers
with a rating, how it would be exploited, what to check, the fix and the
compensating controls.  The answer is kept on the finding with the model's
name on it and changes nothing: the grade still moves only when somebody
regrades it.

Off until an administrator turns it on, and nothing runs by itself: every
question is somebody pressing the button, because every question costs money.
The code around a finding is sent only while sending code is ticked, never for
a credential, and is not stored.  Administrators and developers can press it;
readers see the answers.

## 2026-09-20

**Gitea and Forgejo can be scanned.**  Both are on the Connections page beside
GitHub and GitLab, with a setup guide of their own.  A token from Settings,
Applications reaches everything its account can see, so one connection usually
covers the whole instance rather than one per organization the way a fine
grained GitHub token does.  Type the address of your server and the API address
fills itself in.

Forgejo is a fork of Gitea and speaks the same API, so one implementation
answers for both.  The two names are kept apart everywhere a person reads one,
because somebody running Forgejo should not be told they are running Gitea.

Neither has dependency alerts, code scanning or secret scanning of its own, so
those passes are skipped rather than called and reported as empty.  Members,
teams and pull requests exist there and are not wired up: their member listing
has no role filter, so asking it for the administrators returns everybody, and
a report saying the whole organization owns it is worse than one that does not
say.  Who can reach each repository is still collected, with each person's real
permission asked for one at a time, because the listing itself does not carry
it.

**Finding links now point at pages that exist.**  Every link a scan wrote was
GitHub shaped: `/blob/main/app.py#L12`.  GitLab redirects that one, Bitbucket
does not, and Gitea and Forgejo have no `/blob/` route at all, so those links
were a 404.  Each host now says where it puts a file, a commit and a blame, in
one place, and the eleven writers that used to assume GitHub read it from
there.  Gitea links are `/src/branch/main/app.py#L12`, or `/src/commit/<sha>/`
for a credential found at the commit it was committed in.  A host with no
equivalent page, such as Bitbucket's file history, now gets no link rather than
one that goes nowhere.

**The editor plugin, from your own server.**  A new Editor plugins page hands
out the `.vsix` for Visual Studio Code and Cursor, and the language server for
the JetBrains IDEs, Eclipse and anything else that speaks the protocol.  Not
from a marketplace: this server holds your rules, and plenty of these
installations have no way out to the internet.

Open or save a file and its text goes to `/api/v1/review`, is read by the same
engines a scan uses, graded by the same triage, and deleted.  Nothing is
stored: a review creates no finding, no exception and no scan.  A credential is
shown in red whatever its severity, with the value masked.  By default only the
lines you changed against `HEAD` carry findings, because a plugin that opens
showing two thousand of somebody else's is a plugin nobody keeps.

One language server does the work in every editor, and the Visual Studio Code
extension is a thin front end on the same code.  Neither package has any
dependencies, and building the same release twice gives the same bytes, so the
checksums on the page are worth comparing.  Neither is signed; if your policy
needs a signature, sign it on the way into your own catalog.

## 2026-09-13

**A hash of content is no longer reported as a credential.**  Several detectors
are a length and a nearby keyword and nothing else: thirty two alphanumeric
characters with the word box somewhere in the file is a Box credential as far as
the engine is concerned.  A Cypress run publishes a test report into a
repository, one test name contains the word box, and every test id in that
report is an MD5, so a generated file produced a critical credential finding on
the default branch with nothing in the value's length or entropy to argue with.
The same shape is every ETag, lock file integrity line and coverage report id in
an estate.

Two things now have to hold before one of these is set aside, and neither is
enough on its own.  The value is bare hex at exactly one hash length, which a
real secret of the mixed alphanumeric shape those detectors describe essentially
never is.  And it is one of eight or more strings of that same shape in the same
file, which is what separates a generated artifact from a configuration file
holding a single hex API key that must still be reported.  A thirty two
character hex key on its own in a file is untouched, and a credential the
provider confirmed is never set aside by any of this.

Nothing is deleted.  The finding moves to set aside with a sentence saying it is
a hash of content, one of several of its shape in that file, and that the value
is still in the code.  Existing findings are re-judged on the next scan.  The
threshold is `digest_siblings_min` under the credential triage settings, for an
installation that wants to see more of them or switch the check off.

## 2026-09-12

**The digest says what the finding is.**  A message named the rule, the
repository and the file, and left out most of what somebody reads a finding for.
Every message now describes each finding the way the page does: what kind of
thing it is, the branch it is on and whether there are others, the package with
its version and the version that fixes it, whether the application can reach it
and the reason that was concluded, what was committed and when and by whom, and
three links, to the finding on this installation, to the file on the host, and
to the advisory itself.  Chat stays one line per finding, because a channel that
gets twelve lines per finding is a channel people mute.

**A vulnerable package says which file asked for it.**  Every engine that can
say, says: the manifest or lock file grype read, the manifest osv-scanner
resolved, the path on a provider alert.  None of it was kept, so a report could
say a repository depends on a bad version of something and not whether that came
from package.json or from a lock file six directories down.  It is recorded now,
shown on the finding page as a link to the file, and named in every message.
Existing findings get it on their next scan.

**Mail can be sent as HTML.**  Plain text is still the default, because it is
what every client renders and what a ticket queue can parse.  HTML is worth
choosing for the links: a digest of twenty findings carries sixty of them, and in
plain text those are addresses somebody has to copy.  HTML mail goes with a plain
text copy inside it, so a reader whose client will not render it still gets the
whole message.

**A connection can name who hears about it.**  The addresses on the
Notifications page are one list for the whole installation, which stops being the
right shape as soon as there is more than one application: the team that owns the
payment gateway does not want the brochure site's findings.  Each connection now
has a tick box beside its application owner and its technical owner, and a field
for anybody else, a rota address or a ticket queue.  Those are added to the
installation wide list rather than replacing it, and they only hear about their
own account.  Every box is off on upgrade, because a release that starts mailing
named people who never asked for it is a release that gets the sender blocked.

**The digest can carry a spreadsheet of what it is about.**  The message
describes the first twenty five findings and then points at the page, which left
the rest of a busy night unsaid, and the people a connection now mails often have
no account here to go and look.  Off by default, on the Notifications page: when
it is on, a digest carries that scan's new findings as a CSV in the same columns
as vulnerabilities.csv, so it opens in Excel and can be split across a team.
Never the standing backlog, and never on the three urgent kinds, which read
better as four lines of text.  Cells a spreadsheet would otherwise run as a
formula are escaped, because every value in the file came out of a repository
this tool does not control, and the file on disk is deliberately left alone
because another tool parses it.  The row count is capped and the body says how
many did not fit.

**vulnerabilities.csv gained a column, at the end.**  `declared_in`, which file
asks for a vulnerable package.  Appended rather than inserted, so a tool reading
by position finds every column exactly where it was.  The JSON carries the same
answer inside its package block.

**Every message says to archive or purge what is no longer in use.**  The
largest single reason a report is too long to work through is repositories nobody
works on.  An archived repository is read only, and its findings stop counting as
work somebody is expected to do; a purged one stops appearing at all.  This tool
only ever reads, so it is the one part of the answer that has to be asked for.

## 2026-09-10

**The trends page says why a scope is not certified, and its branch box names
every branch.**  The box was built out of findings, so a branch with nothing
open never appeared in it: a repository of three branches offered one, and "All
branches" read as that one branch.  The seal beside the risk matrix counts every
branch the last scan walked, so it withheld itself over branches the reader
could not see, and the missing seal looked like a fault rather than an answer.
The box now offers every branch that was walked, and where a scope is part way
signed off the space beside the grid says so: one of three, and a seal needs all
of them.  The seal itself is unchanged, because a green mark meaning "mostly" is
worth less than no mark at all.

**A custom severity can name one finding.**  Every condition on a severity
rule described a group: the rule that fired, the engine, the confidence, the
CWE.  Fifteen findings on one rule shared all four, so grading the one somebody
had actually read meant grading the other fourteen with it.  Fingerprint is now
a condition like the rest, written with the kind in front or as the hash on its
own, and it beats every broader rule where both match.  A value that could
never be a fingerprint is refused when the rule is saved rather than accepted
as a rule that never fires.

**A token nobody could present is no longer reported as a credential.**  A JSON
web token pasted into a fixture, a test or a README usually keeps its real
header and its real claims and has a word where the signature goes.  Nothing in
its length or its entropy says so, so it came out critical and developers were
being asked to rotate something that never existed.  The signature is now read
the way the rest of the token already was: RS256 signs with 342 characters and
HS256 with 43, so a signature that is empty, that is not base64url, or that is
the wrong length for the algorithm the header itself names cannot have been
produced by signing anything.  Those are set aside as placeholders, with the
check that dropped them recorded beside them, the same as every other filtered
candidate.  A token signed to the right length is untouched, and an algorithm
whose length this does not know is left alone rather than guessed at.

**What the finding is part of, in both report files.**  Every record in
vulnerabilities.json now carries an asset block: the application, the business
owner, the technical owner, what the repository holds and whether anybody can
read it.  The same five answers are on the end of every row of
vulnerabilities.csv, after last found, so columns a tool already reads keep
their positions.  They are filled the way the finding page fills them, so what
is set on the repository wins and what is empty falls back to the connection,
and the file says which answers were inherited rather than given.  A hardcoded
password is an incident in the payment gateway and a chore in a brochure site,
and until now anything importing these files had to tell those apart with less
than the person reading the screen had.

## 2026-09-09

**A certified seal on the trends page.**  Filter to a branch, a repository or
an organization where every branch has been signed off and a green seal sits in
the space to the right of the risk matrix.  It is faded rather than solid,
because it is a fact about the scope and not a verdict on the risk beside it.
It only appears when the whole scope carries a sign off: eleven branches of
twelve is not a certified repository, and a mark meaning "mostly" is worth less
than no mark, since the reader cannot tell which kind of mostly they have.
Branches marked not applicable come out of the count and the seal says how many.
A sign off a scan wrote says so on the seal itself, the same as everywhere else.

**Archived repositories stop inflating the risk matrix.**  Code that can no
longer be changed is not work anybody can do, and a grid that counts it has
cells that never empty however much gets fixed.  The matrix and the branch
table now set those findings aside, the way the dashboard already did.  Set
aside is not hidden: the count is on the page with a link to the rows, the
findings stay open, and they stay in the findings list, in both report files
and in the export.  The report is built from the same scoped query, so the
document and the screen cannot drift apart.

**The trends chart says when it is out of date.**  The daily rollup only writes
a row where something is open, so a scope that emptied and a scope that stopped
being scanned both just stop having rows.  The chart then drew whatever days it
had across the full width, and three days of a seven day window looked like
seven.  It now names the date of the newest reading and how far back it is,
which is what the PDF report has said all along.  The empty panels say which of
three things happened as well: nothing is open here, findings are open but not
yet assessed on both axes, or everything here is set aside on a retired
repository.  Each offers the rows, because being told a scope is empty by a
page that will not show you what is in it is a dead end.

**A period of one day.**  The rollup is kept per day, so this covers one row
and the chart is a single point rather than a line.  It is offered as Today,
which is what it is.

**Fixed: changing the repository on the trends page kept the branch.**  The
filter boxes cascade, so picking a different repository clears the branch that
was chosen for the last one.  The trends page marks the whole form rather than
each box, and that path was submitting the stale value.  The scope then matched
nothing, and the page came back with an empty matrix and an empty table and no
reason on screen for either.

**Fixed: a heatmap cell could open more rows than it counted.**  The panels set
archived repositories aside and the list the cells linked to did not, so the
number on screen and the number behind it disagreed by whatever was archived.

**The line a code finding is about.**  A code finding used to give you a file
and a line number and nothing else, so the first question anybody asks of one,
whether the string was built from a request or from a constant, meant cloning
the repository and opening the file.  The scanner has always read that line and
masked anything credential shaped in it.  It is now kept, and it sits under the
file name on the finding page.  It arrives with the next scan: findings already
in the database show it once they are seen again.

**Custom severity can read confidence, the engine and the code.**  A grade can
now be written about how sure the engine was, which engine reported it, or text
in the matched line, alone or alongside the conditions that were already there.
"Anything semgrep is unsure about is a low" and "a formatted query built from an
environment variable is informational" are each one rule.  Confidence is one of
low, medium or high and a typo is refused rather than saved as a rule that never
fires.  Code matches anywhere in the line, and a star in it is a star rather than
a wildcard, because "SELECT *" is the sort of thing people paste in.  There is
also a fifth condition row, since five conditions no longer needs a second rule.

**Expiration pickers stop where the rules do.**  The calendar on an exception,
a sign off and an exclusion now opens on tomorrow and stops a year out, which is
what the server was already enforcing.  Picking a date that had already passed
used to be a rejected form and a retyped reason.  The baseline date runs the
other way and stops today, since a line drawn through the future is not a line.

**Approving and rejecting exceptions in bulk.**  The exceptions page already
let an admin take back a batch of approved ones.  It now decides a batch of
requests the same way: tick the rows, approve them or reject them in one go,
and type the reason once.  A ticked row the action does not apply to is left
alone rather than refused, so a mixed selection is fine, and the page says how
many it skipped.  The reason is required, goes on every exception in the batch
next to who decided it and when, and is written to the audit log.  Each
approved finding keeps the expiration date the person who asked for it picked.

**Branches that certify themselves.**  A completed scan now signs off the
branches it found nothing to read on: no findings at all, or nothing above a
low.  Those badges are marked as a machine's work everywhere they appear, and
reports count them apart from the ones a person reviewed.  A scan never writes
over a sign off somebody made, never re-dates one, and never revives one that
was withdrawn.  It only considers a repository whose four passes all reported
themselves finished, because a pass that did not run reports nothing and
nothing is exactly what a clear branch looks like.  See
[certification.md](certification.md).

**The trends page drills down.**  The estate opens into its organizations, an
organization into its repositories, and a repository into its branches, with
the chart and the risk matrix narrowing at each step.  Every row carries a
drill down button and a findings button, so "how much" and "which ones" are two
different clicks.  See [trends.md](trends.md).

**Sortable and paged, over the whole set.**  Every column heading in the grid
sorts on itself, clicking it again turns it around, and the grid pages twenty
five rows at a time with the count of what is behind it.  Both run on the
server across every row at that scope rather than over the rows that fit on
screen.

**Custom severity written as conditions.**  A grade can be written about the
rule, the CWE, the kind, the state, the masked value of a credential, how it
was exposed, or who committed the line, and about several of those at once,
joined with all or with any.  Where two rules both match, the narrower one
wins.  Every rule says how many findings it covers today, before it is saved
and after.  A kind or a state that does not exist is refused on the way in
rather than saved as a rule that silently never fires.

**Fixed: the last point on a trend line could read double.**  On a fresh
install the reconstruction wrote a row for today and the first scan of the day
wrote another, and the chart added them up.  A real record of a day now
replaces a reconstruction of it.

**Fixed: the row count under the grid said "repositorys".**

## 2026-09-08

**Silence stopped being read as remediation.**  A finding is closed only by the
pass that would have found it, and only when the scanner says that pass
finished.  An engine that died, a history walk that covered only a window, a
salvaged run and the credential skip list were four ways a scan produced
silence without reporting it, and each had been read as work somebody had done.

**A credential proved live is never retired quietly.**  One the issuing
provider confirmed still works is closed only by a run that looked and found it
gone, or by a person deciding.

**Coverage of the branches somebody owes a review.**  Counted as a share of
branches scans have actually walked, with archived repositories and branches
nobody is expected to review taken out of the total.

**Archived repositories stopped being outstanding work.**

## 2026-09-07

**A history walked to the end says so.**  The marker recording how far the
credential engines walked is cleared when the engine that walks it dies, so the
catch up pass stops skipping the repository it was written for.

**Two limits for the failure a deadline cannot see.**  A worker that stops
producing anything is caught by a stall watchdog as well as by its deadline.

**Thirty six thousand candidates that were never credentials.**  The triage
rules deciding what counts as an example were widened, with the counts on the
page and a box to test a candidate against.

**A scan of one repository scans one repository.**

## 2026-09-06

**Accounts stopped queueing behind each other.**  Connections scan in parallel
up to a limit that is a setting.

**Told "scanning", and nothing scanned.**  A run that could not start says so
instead of reporting success, and a connection scanned twice at once is refused
rather than raced.

**A stopped run keeps what it had already read** rather than discarding the
night.

## 2026-09-05, version 1.0.1

**Trends and a report to send upstairs.**  A page for how the numbers have
moved, a risk matrix built from impact and likelihood asked separately, and a
PDF written from exactly the filter on screen.

**Deciding about a hundred findings at once**, and the first version of saying
that a branch has been read.

**A fifth of the noise removed.**  Generated output, low confidence low
severity findings and dependencies nothing imports moved out of the default
work list, each with a count and one click back.

**Container images read without building them.**  The base image every
Dockerfile names is resolved from its registry, and advisories the build has
already patched stop being reported as though they were not.
