# What is not built yet

Things that have been asked for and are not in 1.0.1.  Written down so they do
not get lost, and so the shape they should take is decided before somebody
starts.

Two sources.  The earlier items were asked for by somebody using it.  The
later ones come from going through the paid tools in this market and writing
down what they cover and this does not.  Roughly in the order they are worth
doing, and finished items are taken out rather than ticked, so what is here is
what is actually left.

## More than one of this, in front of a cluster

A thousand developers is a different shape of problem from a hundred.  At that
size one container is a single point of failure and a single set of cores, and
the answer is several of them behind a load balancer with a real cluster
underneath.

The database half is already done, and it was not planned.  All twenty tables
are InnoDB and every one has a primary key, which are Galera's two hard
requirements, so the schema would replicate today with nothing changed.

The application half is not, and none of the three reasons are about the
database.

**The scan lock is a lock in one process.**  `scanner.py` holds a
`threading.Lock` and refuses a second scan while it is held.  That is exactly
right for one container and means nothing across three: each one sees an
unlocked gate, and the same organization gets scanned three times at once, into
the same rows, from three different clones.

**The scheduler runs in every copy.**  APScheduler was chosen so there is no
second daemon to babysit, which is the right call for one container and the
wrong one for several.  Three containers means three schedulers, and a cron
that says 02:00 fires three times.

**Schema changes stop the whole cluster.**  Galera runs DDL under total order
isolation, so the boot migration is not a local event any more: it blocks every
node for as long as it takes.  Several containers coming up together each try
the same ALTER on a table with tens of thousands of rows in it.

Two smaller things that only show up under Galera:

- **Certification happens at COMMIT.**  A conflict on another node comes back
  as a deadlock from `commit()` rather than from the statement that caused it,
  and nothing here retries one.  Today that is a lost scan with a traceback.
- **One ingest is one transaction.**  `session_scope` commits once, so a scan
  of a large estate hands the cluster a single writeset holding tens of
  thousands of rows to certify in one go.  It works and it is not what Galera
  is happiest with.

What it should look like:

- **The lock moves into the database.**  A row somebody has to win, with the
  holder and a heartbeat on it, so a container that dies does not leave the
  gate shut forever.  That is the same table the per run stop button in the
  entry above needs, so the two belong together.
- **One scheduler, elected.**  Every container tries to claim a lease, one
  wins, the others idle and watch.  The winner losing power means somebody else
  takes it a minute later rather than nothing running until morning.
- **Migrations stop being a boot side effect.**  A container that comes up
  second should find the schema already right rather than race the first one
  for it.  Either one node is told to migrate, or the migration takes an
  advisory lock first and the rest wait behind it.
- **Retry the certification deadlock.**  It is a normal outcome on a cluster,
  not a fault.  A few retries with a backoff around the ingest commit, and it
  goes back to being invisible.
- **Ingest in batches.**  Smaller writesets certify faster and a conflict costs
  a batch instead of a whole scan.

What it touches:

- `scanner.py` for the lock, `scheduler.py` for the election, `db.py` for the
  migration lock and the retry, `ingest.py` for the batching.
- Nothing in the scanner itself.  It already runs as its own process against a
  work directory, and several of those on several machines is what this is for.

Worth saying plainly: none of this is required to run this well for a hundred
developers, and doing it early would buy complexity nobody needs yet.

## A GitHub App across every organization it is installed on

An App is the right credential for an estate: one identity, and its tokens skip
the SAML authorization step that catches out personal tokens.  What this does
with one today is scan one installation.

`_app_installation_id` in lib/auth.sh takes the first organization in scope,
finds the installation on it, and mints a token for that.  With no organization
named it has nothing to look up and the scan stops.  So an App installed on
twenty six organizations covers them one run at a time, which is not what
anybody expects from it.

What it should do:

- List the installations the App has, and treat each as its own unit of work:
  its own token, its own repository list, its own rate limit budget.  The
  hourly budget belongs to the installation, not to the App, so twenty six
  installations means twenty six budgets rather than one shared one.
- Mint each token as it is needed and let it expire, rather than minting all of
  them at the start of a run that takes half an hour.  Installation tokens last
  an hour, and a scan of a large estate outlives that.
- Report per installation.  A scan that covers twenty of twenty six because six
  installations were suspended has to say so, the way the SSO truncation
  warning does now.

Until then: a classic personal access token, authorized for each organization
under Configure SSO, is the way to cover several organizations in one scan.

## Subversion with its history, rather than one revision

The checkout only mode is built: a subversion connection scans the current
revision, everything that reads files works, and the connection form and the
scan both say plainly that history is not walked.

What is left is the half that was always the valuable one.  The strongest
thing this tool finds is a credential that was committed and later deleted,
and finding those means walking git history, which a Subversion checkout does
not have.

`git svn clone` converts a repository into a real git one and everything
downstream then works unchanged, full history included.  The costs are real:

- The first conversion of an old repository takes hours, sometimes a day.
- It has to be kept.  Every clone today goes into a temp directory and is
  deleted when the scan ends; a mirror has to live in a volume and be brought
  up to date with `git svn fetch` on each run.
- Author names come out as Subversion usernames unless an authors file maps
  them.

So: a mirror directory per connection, kept between runs, and the same
scanning after that.  The same shape would give Perforce its history back
through `git p4`, and for the same reasons.

## Whether risk is going up, and where

The dashboard says what is open now.  It does not say whether that is better or
worse than last month, which is the first thing anybody senior asks and the
only view that tells a team whether the work they did mattered.

**Weighted by severity, not counted.**  A count is the wrong line, and it is
wrong in a way that flatters the tool.  A tuning pass that moved seventy
findings out of high in an afternoon changed nothing about the code, and a
graph counting findings would have drawn that as progress.  Weight the open set
so that criticals dominate, roughly a hundred to ten to three to one, and a
single new critical outranks sixty closed lows.  A pile of low severity
weaknesses must not read as risk going down while a couple of criticals arrive.

**Triage must not move the line.**  This is the same trap from the other side.
When this tool decides a finding is not applicable and drops it to info, risk
has not fallen: the code is what it always was and only our opinion changed.
The trend has to be built from the engine's own grade, or from a flag marking
which transitions came from triage, or every improvement shipped here shows up
as a fake win on somebody's chart.

**Granular, down to the branch.**  Organization, then repository, then branch,
because that is the order somebody narrows a question in.  The branch half is
newly possible: findings carry every branch whose tree matches, so a release
branch can be compared against the default one without scanning it twice.

**Backfilled, not started from empty.**  `first_found_at` and `resolved_at` are
already on every finding, so history can be reconstructed rather than beginning
on the day the feature ships, which is the difference between a graph that is
useful immediately and one that is useful next quarter.  Confirm both are
populated consistently before promising it: a finding that predates the column
would draw a cliff that never happened.

**One thing to decide.**  Whether an accepted risk still counts.  A waived
finding is a decision somebody made, not a weakness that went away, and a chart
where waiving something lowers the line teaches people to waive things.

## A pipeline that blocks on a regression and not on history

The line itself is drawn.  An organization has a baseline, the findings page
defaults to what crossed it, and the backlog is one click away with a count
next to it.  Two places still count everything.

`--fail-on` in the scanner has none, secrets, verified-secrets, the severities
and license.  It has no `new`, which is the one a pipeline on an old repository
actually needs: without it, switching the gate on fails every build until
somebody has worked through ten years of backlog, so nobody switches it on.
The scanner already knows how to exit 3 and the database already knows which
side of the line a finding falls on.  What is missing is the scanner being able
to ask, which on a `review` run means asking the API rather than the database
it has no access to.

`/api/v1` is the other one.  The page defaults to the work; an editor and a
pipeline reading the same estate through the API still see everything, so the
two disagree about what the number is.

What it touches:

- `--fail-on new` in `bin/ghscan`, and a way for a review to find out.
- The v1 API taking the same default the page takes, with the same override.

## A live credential, and the twenty minutes after it

Verification is the strongest thing here.  It does not think the key looks
like a key, it asked the provider and the provider said the key still works.
Then a report gets written and that is the end of it.  The twenty minutes
after that finding are the ones that matter, and nobody is walked through
them.

**This must never revoke anything itself.**  Every provider call being a GET
is a tested property and a real reason a security team is allowed to install
this.  Revoking is a write, into somebody else's account, and getting it wrong
takes a production service down at the worst possible moment.  The person who
has to answer for that outage is the person who should press the button.  This
tells them exactly which button and in what order.  It does not reach for it.

What it should look like:

- Per detector, the real steps.  Which console page retires this kind of key,
  the API call for somebody who would rather, and what stops working when it
  goes.  gitleaks and trufflehog already name the detector, so there is a key
  to hang this off.
- On the finding page, next to the verified badge, where somebody is already
  looking when they need it.
- The order spelled out.  Issue the replacement, deploy it, then retire the
  old one.  Doing those two the other way round is how a scare becomes an
  incident, and it is the step people get wrong under pressure.
- Somewhere to record that it was done, by whom, and when.  That is the answer
  to the only question anybody asks afterwards.
- The finding does not close because the file changed.  It closes when a
  person says the credential is dead.  A key deleted from the tree is still a
  key in the history, and treating the commit as the fix is how this ends up
  reassuring somebody about a key that still works.

What it touches:

- A table of guidance keyed on the detector name, kept with the rules so it
  can be corrected without a release.
- The finding detail page, and a state on the finding for retired, with who
  and when.
- The audit log, which already records everything else of this kind.

## The deep engines for the languages that still have none

A second engine per language is in: gosec on Go, which does real analysis
across a package rather than a file, and bandit on python, which corroborates
rather than adds depth and is not sold as more than that.  Agreement between
engines is kept rather than blended, and a finding says which engines saw it.

What is left is the languages that still have only semgrep, which reads one
file at a time and cannot follow a tainted value across a function boundary:

- **Java**, with find-sec-bugs.  The awkward one, because it reads compiled
  classes rather than source, so it only has something to do where a build
  output is already in the tree.
- **PHP**, with Psalm or PHPStan in taint mode.
- **Ruby on Rails**, with Brakeman.
- **JavaScript**.  njsscan was tried and left out: it pins semgrep back a
  version, and the primary engine does not move for a corroborating one.
  Worth revisiting if that pin catches up.

Only what the tree needs, which is the decision syft already makes from what
is in the checkout, and the triage pass is untouched because it reads findings
rather than whoever produced them.

## A second opinion on the pipeline, and the other CI systems

zizmor reads GitHub Actions and it reads them well.  It does not read anything
else, and this now scans GitLab and Bitbucket as well, so a project whose
pipeline lives in `.gitlab-ci.yml` gets the same silence the Actions ones used
to get.

poutine is the other half.  It covers GitLab CI, Azure Pipelines and Actions,
which makes it both the second opinion on the workflows already being read and
the only opinion on the ones that are not.

What it should look like:

- Another engine next to `run_zizmor` in `lib/workflows.sh`, writing the same
  shape.  The file was built expecting this.
- Findings that both engines produce get corroborated rather than reported
  twice.  The merge key is the rule, the file and the line, which is what the
  secrets pass already does across two engines.
- The provider decides what runs.  Pointing an Actions auditor at a GitLab
  project wastes a minute per repository and finds nothing.

What it touches:

- `lib/workflows.sh`, and nothing else.  The finding kind, the report, the CSV,
  the SARIF and the exclusions already carry these.

## What to change, without changing it for them

Every competitor either opens a fix pull request or writes a patch.  The first
is not going to happen here and that is a feature, not a gap.  Showing somebody
a diff they can apply themselves gives up nothing.

semgrep rules carry autofix metadata and the scanner already keeps it:
`normalize_semgrep` writes `fix` onto every code finding.  It is dropped on the
way into the database and nothing has ever rendered it, so the suggestion is
worked out on every scan and thrown away at the last step.  Carrying it through
and putting it on the finding page is most of this item.

The dependency half is cheaper still, because `fixed_in` is already on every
record.  Rolled up it becomes the sentence people actually want: one bump of
this package to this version clears eleven findings across four repositories.
Ranking upgrades by how much they clear is a query over data already in the
database.

What it touches:

- A `fix` column on findings, and `ingest` keeping what the scanner sends.
- The finding detail template renders it, clearly labeled as a suggestion.
- A remediation view over `findings`, grouping by package and target version.

## The editor API exists and nothing calls it

`/api/v1/review` was built for editors and pipelines.  It has token auth, scope
enforcement, size caps, and it writes nothing down.  There is no editor plugin,
so the hard nine tenths is done and the easy tenth is the part anybody would
actually touch.

An extension that reviews the open file on save and underlines what it finds is
the highest leverage thing left for the people this is written for, because it
catches a credential before the commit exists rather than after it has to be
rotated.

Two bits of packaging alongside it, both hours rather than days:

- **A published action**, so a pipeline says `uses:` instead of copying a
  `docker run` line out of the documentation.
- **A `.pre-commit-hooks.yaml`**, so the hook is three lines in a file
  thousands of repositories already have.

What it touches:

- Nothing in the scanner and nothing in the web app.  Two thin clients over an
  endpoint that is already finished, each in its own repository so the release
  cycles do not have to agree.

## Answering the questionnaire a customer sends

A small team with no security function does not get asked which SAST tool it
uses.  It gets sent a security questionnaire by a customer and has nothing to
put in the box.  Most of the answer is already in the database.

Findings carry `cwe` and `owasp`.  Waivers carry a reason, an approver and an
expiry.  The audit log says who did what.  The SBOM is written in both standard
formats.  What is missing is the view over them.

What it should look like:

- **Framework views** over findings that already carry the mapping: OWASP ASVS,
  PCI DSS 4.0 6.2.4, and the NIST secure software development framework.
- **An evidence pack.**  One dated document saying what was scanned, what was
  found, what was accepted, by whom and until when.  It is a template over the
  audit log, the waiver table and the SBOM.
- **The Cyber Resilience Act** is the one with a date on it.  Its main
  obligations land in 2027 and they require an SBOM and a documented
  vulnerability handling process from anyone selling software into the EU.
  Both of those already exist here and neither is currently presented as
  evidence of anything.

What it touches:

- A mapping table, and an export.  No scanner changes.

## How healthy the repository itself is

Branch protection and member 2FA are collected already.  The rest of the same
question is not: are actions pinned to a digest, is there a SECURITY.md, are
releases signed, is a review required, is Dependabot on, and are there admins
who have not committed anything in a year.

This is securing the repository rather than the code, which makes it the
natural companion to the access inventory, and the access inventory is already
the thing nothing else in this market ships.

What it touches:

- `lib/access.sh`, which makes most of these calls already for other reasons.
- A posture score per repository on the existing repositories page.

## Whether any of this is getting better

`first_found_at` and `last_found_at` are on every finding and scan runs are
kept, so the data for a trend is there and nothing reads it that way.

Introduced against fixed per week.  Mean time to remediate by severity.  Which
repositories are taking on debt fastest.  How much of the backlog was waived
rather than fixed, which is the number that says whether the tool is working or
being managed around.

This is the page a manager opens, and it is the reason a tool keeps its budget
line.  It is a handful of queries and one template, with no scanner changes at
all.

## The risks that come with code a model wrote

Some of this is ordinary and already handled: a model API key is a credential
and the secrets pass finds it like any other.

The rest is not covered by anything here.  Untrusted input reaching a prompt.
Model output reaching `eval` or a shell.  Tool server configuration files
carrying tokens.  A vector store connection string committed next to the code
that uses it.

Rule coverage for this is thin across the whole market, so being early is cheap
here in a way that catching up on the other items is not.

What it touches:

- Rules in a local ruleset directory, the same mechanism
  `config/gitleaks-extra.toml` already uses for passwords in connection
  strings.

## A placeholder somebody base64ed on the way in

Every placeholder pattern reads text.  `VGhpc0lzQW5FeGFtcGxl` is not text, it
is `ThisIsAnExample` with a coat on, and it goes straight through.  Encode any
of the obvious stand-ins and the filter has nothing to say about them, which
is a hole somebody finds by accident rather than on purpose: a fixture written
by a person who base64ed a value because that is what the config format wanted.

What it should look like:

- The check belongs where the value is, which is the point everything else
  derived from a secret is worked out.  Nowhere else in the run still has it.
- If a value is base64 shaped and long enough to be worth the trouble, decode
  it and run the same patterns over what comes out.  A hit on either the raw
  form or the decoded one means placeholder.
- The decoded text gets the same word boundaries as the raw text.  A random
  blob decodes to random bytes, and random bytes spell things: this is the
  same accident that filtered a real private key because its base64 happened
  to contain "mock", and it would be a poor joke to reintroduce it one layer
  down.
- Key armour stays exempt, for the same reason it is exempt now.
- Only decode what decodes.  Anything that comes back as bytes rather than
  readable text is a key, not a sentence, and is left alone.

What it touches:

- The derive step, and nothing else.  The triage already reads a verdict
  rather than working one out.
- Tests for a base64 placeholder that is caught, a base64 real credential that
  is not, and a decode that produces bytes rather than words.

Worth being careful with rather than quick about.  Most high entropy
credentials are base64 shaped already, so this runs against nearly every
secret found, and the cost of getting it wrong is the one failure this tool
cannot afford: dropping something real without saying so.

## The evidence somebody asks for once a year

A security function with no budget is usually also the one that gets handed an
audit, and the work of answering it lands on the person who was already doing
everything else.  The paid tools charge for this report specifically, because
they know it is the thing that has to be produced whether or not anybody has
time.

Every finding already carries a CWE and an OWASP category, so the mapping has
somewhere to start rather than needing a whole new taxonomy.

What it should look like:

- A mapping from what is recorded to the frameworks that reference it, kept as
  a file next to the rules so a control that moves in a new revision is a text
  edit and not a release.
- A report per framework that says, for each control: what is scanned for it,
  what is open, what was accepted, and who accepted it.
- Waivers are the interesting half.  An accepted risk with a name and a date
  and a sentence of reasoning on it is better evidence than a clean report,
  and this already makes people write that sentence.
- Point in time.  An auditor asks what it looked like in March, not what it
  looks like this afternoon, so the report takes a date.
- It shares most of its plumbing with the questionnaire item further up, and
  the two should be built as one thing.

What it touches:

- A mapping file, and a page that renders it.
- Waivers, the audit log and the scan history, which between them already hold
  nearly everything this needs.

This is not certification and should never say that it is.  It produces the
evidence.  Somebody qualified decides whether the evidence is enough.

## The controls the application already has

Six critical findings on one repository said the code calls exec.  The same
repository ships a php-hardening.ini, and reading it looked like the whole
answer: a deployment describes what it will not allow, in files that are in the
repository, and nothing here reads them.

Then the file was read properly, and it is a better argument for the feature
than the one it was supposed to be.

That repository ships two files of that name with different contents.  One
lists exec among the disabled functions and one does not.  The Dockerfile
installs neither: it appends upload limits to a hardening file in the PHP
configuration directory only if that file already exists, and the image is
built from a registry image whose contents are not in the repository at all.
The documented manual install copies one of the two by hand.  Meanwhile three
source comments state as fact that exec is disabled.

So the answer to whether exec runs in that deployment is not in that repository,
and a pass that had picked the first matching file and graded six findings down
would have been confidently wrong on the first file it opened.  Not wrong about
a detail. Wrong in the direction that closes findings.

That is the shape of the whole feature, and the rule it produces is the one the
schema files already taught: **a file in the repository is not a configuration
in the deployment.**

What that means in practice:

- **Find which file reaches the runtime, not which file matches a name.**  A
  configuration is in effect when something installs it: a copy in a build
  file, a line in an entrypoint, a mount in a compose file, a documented
  install step. The reader has to follow that, the same way the credential
  promotion has to check that something loads the schema before it calls a hash
  a default password.
- **Where it cannot be established, say so and change nothing.**  Two files
  disagreeing, or a base image the repository does not contain, is an unknown.
  An unknown is recorded as an unknown. It is never resolved in the direction
  that lowers a grade.
- **Report the disagreement.**  Two hardening files with different disabled
  function lists is worth telling somebody about on its own, whichever one
  turns out to be live, because somebody is going to edit the wrong one.

What is in reach once that is respected:

- **disable_functions**, when the file carrying it can be shown to be installed.
  A finding whose sink is a disabled function is not reachable in that
  deployment.
- **open_basedir.**  A file read that cannot leave a listed directory is a
  smaller thing than one that can, and the tainted filename findings are graded
  today on the assumption that it can.
- **Session and cookie settings, and the headers a vhost sets.**  These are
  facts worth carrying whether or not they downgrade anything.
- **A web application firewall in the stack.**  Evidence, and never a downgrade
  on its own: a rule set blocks the shape of an attack somebody thought of.

What it should look like:

- A pass that reads the deployment description rather than the application code,
  and produces facts rather than findings.
- Every fact carries the file it came from and how that file was shown to be
  installed. A finding graded down on the strength of a php.ini has to name the
  php.ini and say what installs it.
- Grades move down and never up. A control that is present is evidence; a
  control that is absent is evidence of nothing, because the deployment being
  scanned may not be the deployment being run.

This is still worth doing before the dynamic pass and it is still a fraction of
the work. What has changed is that the cheap half is not as cheap as reading a
file, and the difference is the part that keeps it honest.

## Running it, in a box it cannot get out of

The entry above reads what a deployment says about itself.  This runs it and
finds out.  The two are the same idea at different costs, and the cheap one
should be built first, because on the repository this was worked out against
most of the answers were in a config file.

What is left after that is the half a file cannot settle.  A control that is
configured is not necessarily a control that works.  A WAF rule set blocks the
shape of an attack somebody thought of.  open_basedir constrains a path unless
the code resolves it somewhere else first.  The only way to know is to send the
request and see what comes back.

The objection this used to carry was that dynamic testing needs a running
application, somewhere to put it and credentials to get in.  That holds when
somebody points a scanner at a staging environment that has to exist first.  It
stops holding when the deployment comes with the scan: this repository builds
from its own compose file, and the SBOM already says what it is made of.

What it should look like:

- **Aimed, not broad.**  This is not a web scanner looking for what it can
  find.  It takes the findings that are already there and asks one question of
  each: does this reproduce.  A finding is the hypothesis and the request is
  the test.
- **The result rides on the existing finding.**  Reproduced becomes a
  confidence a person can act on first.  Nothing new is created.
- **Not reproduced changes nothing.**  A probe that fails may have been the
  wrong probe.  Downgrading on a failed attempt is how a tool talks somebody
  out of a real problem, and it is the one behavior that would make this worse
  than not having it.
- **Both sides of the boundary.**  Run the same probe with the compensating
  control in place and with it removed.  Blocked by the WAF and blocked by the
  code are different answers: the first is a control doing its job in front of
  a bug that is still there, and only the second means there is nothing to fix.
  Reporting them the same way is how a control gets mistaken for a fix.
**No route off the machine, and the reason is not the one people expect.**  The
usual argument for isolating a sandbox is that the code in it might be hostile.
That is true and it is the smaller half.

The larger half is that the application being tested is not hostile at all and
will do exactly what it was written to do.  A repository carries connection
strings, and the ones in a configuration file are frequently real: a database
host with a username and a password, a message queue, an object store, a
payment endpoint.  Stand that application up with a route to the internet and
it will reach out and log in.  The dynamic pass is then not testing a copy, it
is a second live client of production, holding a real session, running whatever
probe was written for a sink.  A probe that deletes a row deletes it in the
place the row actually lives.

So the container gets no egress at all.  Not filtered egress, not a proxy with
an allow list, none.  The only network it has is the one its own dependencies
sit on, created for the run and destroyed after it, and nothing on that network
can route anywhere else.  A dependency it cannot reach is a boot failure, which
is reported as a declined, and a declined is a perfectly good outcome.

Three things follow from that and each is worth stating so nobody relaxes one
of them to make a scan pass:

- **A failure to resolve a hostname is a success.**  When the application under
  test cannot find its production database, the isolation worked. That is not a
  defect to route around.
- **Whatever it needs, it gets locally or not at all.**  A database from the
  compose file is fine because it comes up beside it. A credential in the
  repository pointing somewhere real is not a reason to open a hole, it is a
  finding in its own right.
- **The probe traffic never leaves either.**  Requests go to the container and
  the record of them comes back through the runner, not through anything the
  application can see.

- **Everything thrown away afterwards.**  No image kept, no volume, no network,
  a hard time and memory budget, nothing mounted from the host.

What it touches:

- Another engine beside the ones already there, and a confidence field on code
  findings.
- The isolation, which is nearly all of the work and all of the risk.

Being honest about that risk.  This runs code out of a repository, and a
repository is where somebody would put code they wanted run.  The container
boundary is not a detail of the feature, it is the feature.  If it cannot be
made convincing enough to describe in a paragraph a security team will sign
off, this should not ship, and saying no a second time is a perfectly good
outcome.

## Wiring the dynamic pass to every repository that can take one

The two entries above say what a dynamic pass is for and how it must behave.
This says how a repository asks for one, what the two halves say to each other,
and which repositories can have it at all.

It has a number now.  On the repository this was worked out against, static
analysis finished at a hundred and sixty nine reports it cannot settle in
either direction.  Ninety of them are an array element off a database row,
written as `$row['id']`.  Nothing in the file says what that column holds.  The
argument for calling them safe is a convention across the whole codebase, which
is a judgment somebody made rather than a fact any line proves, and the
argument for calling them dangerous is that the rule matched.  Neither is
evidence.  One observation of the rendered page settles each of them.

That is the whole case for building this.  Not that a dynamic pass finds more,
but that it answers the ones a static pass has run out of ways to answer.

**Off unless a repository asks.**  A setting per repository, defaulting to off,
because this builds and runs the code in the repository and that is not
something to switch on for an organization by accident.  What the setting has
to carry is small: how to stand the application up, how to know it is up, and
how to log in.  Everything else is inferred.

**A compose file is not the qualifying signal, and assuming it is would be the
worst bug in this feature.**  Four real compose files were read to check that
assumption, from applications written in Node, Python and Go, and not one of
them builds the application from the repository.  Two are not the application
at all: they stand up a database and a cache so somebody can run the code
outside the container, and one is a matrix of six database engines used for
testing.  The rest pull a published image by tag.

That matters more than it first looks.  A dynamic pass that composes up a
published image is testing a release somebody built at some point, not the
commit that was scanned, and it would report evidence about the wrong artifact
in a format that looks authoritative.  Reporting a probe against a different
version of the code as though it settled a finding in this one is the same
mistake as closing a finding a probe never reached.

So the qualifying test is narrow and mechanical.  A service in the compose file
has to build from this repository, and something has to publish an HTTP port.
The application these findings came from passes: its compose builds from its own
Dockerfile, declares a health check and publishes a port.  It is the exception
in the sample rather than the pattern.

**How to stand it up, in the order to try it.**  Compose that builds from the
repository and serves a port, which brings the database and anything else along
with it.  Failing that, a Dockerfile in the repository, built and run alone,
which works for an application whose state lives somewhere it can be told about
and fails for one that needs a database nobody started.  Failing that, no
dynamic pass, and the report says so in as many words.  Silently skipping is
worse than declining, because a missing answer and an answer of no look the same
on a dashboard and only one of them is true.

**Knowing it is up is our problem, not the repository's.**  Only one of the four
files sampled declares a health check at all.  Waiting for a container to report
healthy would wait forever on most of them.  What works is polling the published
port for any HTTP response at all, with a deadline, and treating the deadline as
a declined rather than as a pass.

**Say no clearly.**  Not every repository can take this even with a compose
file.  A library has nothing to serve.  An application that needs a paid third
party to boot will not boot.  The tiers a repository can land in are: dynamic
pass ran, dynamic pass declined and here is why, dynamic pass failed and here
is what it said.  Three different things, and a report that flattens them into
one is lying about coverage.

**What static analysis hands over.**  Not findings.  A probe is a different
object: the sink, the file and line it sits on, the route that reaches it, the
inputs that plausibly influence it, and what the value would have to look like
for the finding to be real.  A finding says a value reached a page.  A probe
says which request to send and what would prove it.

The route is the part that decides whether this works at all, and the estate
this runs against says the obvious approach does not generalize.  Across two
hundred and one repositories with findings, code sits in JavaScript in forty
five of them, YAML in sixty four, HTML in thirty seven, Python in thirty one,
C sharp in twenty seven, and PHP in three.  The application that produced the
hundred and sixty nine is one of the three.

That matters because one file per page is what makes a route free.
`web/grc-assessment.php` answers at `/grc-assessment.php` and ninety of the
hundred and sixty nine are addressable with nothing clever at all.  Building
the whole feature on that would serve three repositories out of two hundred.

What generalizes is not file layout, it is that frameworks declare their routes
somewhere a reader can find them.  Express and the file based routing in the
common React frameworks, the decorators in Flask and the URL configuration in
Django, attribute routing in ASP.NET.  Each is a small reader that turns source
into a table of route to handler, and the order to write them in is the order
above, by how many repositories they reach rather than by which is most
interesting.  PHP first anyway, because it is where the findings that motivated
this are and because it is the cheapest one to prove the rest of the machinery
against.

Sinks whose route cannot be worked out are not guessed at.  They stay exactly
as they are, and the report says how many were out of reach, because a coverage
number that counts what was skipped as though it passed is the same lie as
closing a finding nobody probed.

A second thing the estate says: most of these repositories cannot take a
dynamic pass at all, and the plan has to expect that rather than treat it as an
edge case.  A Splunk add-on, a Lambda, a mobile application and a reporting
extract have no local HTTP surface to stand up, and on a rough count only about
one in six repositories here ships a compose file or a Dockerfile.  That number
is a floor rather than a measurement, because infrastructure scanning is newer
than most of these scans, but the shape of it is not in doubt.  The common
outcome of this feature across an estate is a clear declined, and the value of
the feature is concentrated in the few repositories that are actual web
applications.

**What comes back.**  For each probe: what was sent, what came back, and which
of three things it means.  Reproduced, meaning the payload appeared in the
response where it could execute, which raises the finding and attaches the
request as evidence.  Contradicted, meaning the sink rendered a number when it
was asked for markup, which is the case that closes ninety array elements and
has to name the response that proves it.  Or nothing, meaning the probe did not
settle it, which changes the finding not at all.

That third one is the discipline this stands or falls on, and it is worth
repeating from the entry above because it is the rule everybody breaks.  A
probe that fails is a probe that failed.  It is not evidence the code is safe.
A tool that quietly closes findings on the strength of an attempt that did not
work is worse than no tool, because the report now carries an assurance nobody
earned.

**Confirmed is a different word from high.**  Findings already carry a
confidence, which is the rule's own opinion of its match and is low on four
thousand of them.  A reproduction is not another opinion, it is an observation,
so it gets its own value above the three that are there.  Confirmed means a
request was sent and the response showed the thing the rule was worried about.

The rules around that value are short and none of them may be relaxed.

- Only a reproduction sets it.  Not a heuristic, not a chain of two rules
  agreeing with each other, not a probe that timed out in a way that looked
  suspicious.
- It only ever goes up.  A finding that was high and did not reproduce stays
  high.  There is no value meaning refuted, because a probe that did not fire
  is not a proof of safety and putting that word on a finding would invite
  somebody to close it.
- Severity may follow it up and never down.  The grading already refuses to
  call something critical when the rule says it is unsure, which is what turned
  eight wrong criticals into highs on one repository.  Confirmed is the other
  end of that same argument: an unsure rule has not earned critical, and an
  observed one has.
- The engine's own confidence is kept beside it rather than overwritten, the
  way the engine's severity already is.  Somebody has to be able to see that a
  rule was unsure and reality disagreed.

**What the finding has to say about how it was proved.**  A confidence with
nothing behind it is worse than none, because it asks to be trusted and offers
nothing to check.  So a confirmed finding carries the observation:

- The request.  Method, path, which input carried the payload and what the
  payload was, with the session cookie and anything credential shaped taken
  out.
- The response.  Status, content type, and the span that proved it, meaning the
  payload as it came back and enough either side to show the context it landed
  in.  Bounded to a size a person will read.
- The conditions.  Which control was in place or removed for this attempt,
  because blocked by a firewall and blocked by the code are different results
  and reporting them the same way is how a control gets mistaken for a fix.
- The provenance.  Which commit was built, which image ran, and when.  Without
  those three the observation cannot be repeated and cannot be argued with.

**What it looks like, and the icon that must not be used.**  There is already a
badge for a finding corroborated from outside the rule: a dependency on the
CISA exploited list renders as one, and a validated finding belongs in that
family rather than in a new idiom of its own.

The mark is a biohazard, tinted to the finding's own severity, with the word
validated next to it wherever there is room.  It appears twice: on the row in
the findings list, so a page of two hundred can be read at a glance, and in the
detail header beside the severity badge, where the evidence block sits under it.

The glyph carries the danger and the word carries the proof, and it needs both.
A biohazard on its own says this one is nasty, which the severity badge already
said. What is new about a validated finding is not that it is dangerous, it is
that somebody stopped arguing about whether it is real.

A check mark and a shield are both wrong here and it is worth writing down why,
because they are the obvious choices and somebody will suggest them again.  In
every other interface a check means this one is fine and a shield means
protected. Putting either on a finding that has just been proved exploitable
inverts the meaning at the exact moment the reader is deciding what to do
first. The word validated is right, the conventional glyph for it is not.

Two more things the mark has to do:

- **Say it in text as well as in color.**  Severity tinting is a second
  channel, never the only one. The badge carries the word.
- **Show when it has expired.**  A validation that no longer describes the code
  is drawn hollow and reads stale rather than validated, so it stops claiming
  the grade while keeping the record.

And one thing worth having beside it: a filter on the findings page for
validated only. On a repository with a hundred and sixty nine unresolved
questions, the handful that came back proved is the shortest useful list in the
product.

**Validation expires.**  This is the part that will be got wrong if it is not
written down.  The observation was made against one commit.  When the line
moves, the code around it changes, or the finding is next seen on a different
commit, the confirmation is about code that is no longer there.  It has to be
marked stale rather than carried forward silently, because evidence that
outlives what it describes is the same failure this project already had once,
when an absence of findings was read as a set of fixes.  Stale keeps the record
and stops claiming the grade.

**It leaves in the formats people already read.**  The report and the editor
output both carry findings today, and a confirmed one has to be visibly
different in both, or the work lands somewhere only this application can see.

**Logging in, which is most of the work.**  Nearly every sink worth probing is
behind a session, so a dynamic pass that cannot log in probes the login page and
nothing else.  The application in hand generates an administrator password on
first boot and writes it inside the container, which is the pattern worth
supporting first: stand the container up with an empty volume, read the
credential it made for itself, use it.  Failing that, a login sequence in the
repository setting.  Failing that, the pass runs unauthenticated and the report
says which sinks were out of reach, rather than reporting them as clean.

**A budget, and an order.**  A hundred and sixty nine sinks and several payloads
each is thousands of requests against an application that has to start first.
Highest severity first, a hard ceiling on requests and on wall clock, and a
report that says how far it got.  A pass that ran out of time on the last forty
must say so, for the same reason a static pass that was cut short may not close
anything.

**The same result twice.**  A verdict that changes between runs without the code
changing is the failure this project has already had once, when a static pass
that died part way through closed findings as fixed and they came back on the
next scan.  A flapping probe is that bug wearing different clothes.  A verdict
holds only if it reproduces, and a probe that disagrees with itself reports
nothing rather than reporting last.

**Where it runs.**  In the box described in the entry above, and the boundary is
the feature rather than a detail of it.  No host mount, no network out, nothing
kept afterwards.  The dynamic pass talks to the application it started and to
nothing else, and the only thing that leaves the box is the probe record.

## Moving the scanner off bash, in the order that pays

Not a rewrite.  The engines are already Go and Rust, the orchestration is a
reasonable thing to write in shell, and replacing six thousand working lines to
feel better about them would be the most expensive way to change nothing.

What is worth moving is narrower, and it is the part that has actually gone
wrong.  Three incidents, all the same shape:

- A scan ran with a fraction of its rules and reported success, because a
  failure became `|| true` and then an empty result.  It found 390 fewer things
  than the run before it and nothing said so.
- A finding set reached the triage short and was dropped without a word, three
  times in one afternoon, until the triage was taught to refuse a set it can
  tell is incomplete.
- A review handed its whole document to jq on argv, which runs out on a large
  repository.  A test exists solely to lint for that, because the language
  makes it easy.

Thirty seven places turn a crash into an empty result.  In a scanner that is
the worst available failure: a report that finds nothing looks exactly like a
clean one.

What it should look like, in this order:

- **The normalizers first.**  They are pure JSON in, JSON out, written as jq
  programs up to 390 characters long inside shell strings.  They are the
  highest value and the lowest risk: no subprocess handling, no credentials, no
  control flow, and lib/sarif.py, code_triage.py and code_blame.py already
  prove the shape works.  One engine at a time, with the shell orchestration
  left alone.
- **Then the fingerprint.**  It is written twice, once in lib/sarif.py and once
  in app/core/ingest.py, guarded by a test that notices when the two drift,
  because jq has no sha256 and the two venvs cannot import each other.  One
  module both sides read would end that.
- **Then the silent fallbacks.**  Every `|| echo '[]'` becomes a decision:
  either this genuinely means none, or it means the pass failed and the scan
  should say so.  Most of them are the second thing pretending to be the first.
- **The orchestration stays.**  Cloning, invoking engines, moving files between
  them, pacing against a rate limit: shell is a fair match for that, and it is
  not where the failures have come from.

What it does not buy:

- Speed.  Measured on this project, the wrapper is about one percent of the
  trivy step and nine percent of the zizmor step, against a scan whose own
  documentation says cloning dominates.  Nobody would notice.
- Portability.  The pipeline documentation tells people to run it through
  docker in every example, and the container already carries python.

If a clean sheet were ever on the table the answer would be Go, because every
engine this wraps is a single Go or Rust binary and that is the distribution
story this product already tells.  That is not a reason to start now.

## A secret that is in a vault and also in a repository

Somebody keeps their credentials in Secrets Manager, or Key Vault, or Vault
itself.  Good.  The question none of those can answer is whether the same
value is also sitting in a commit, because a vault knows what it holds and
nothing about anybody's source.

This is the only system holding both halves.  It already fingerprints every
credential it finds and never stores the value, so the comparison can be made
without either side handing over a secret: ask the vault for the digests of
what it holds, and match them against the fingerprints already in the
findings.

What it should look like:

- Read only against the vault, with a credential that can list and hash and
  nothing else.  This never reads a secret value and never stores one.
- The match is on the fingerprint that is already there.  Same hash, same
  secret, and the finding gains a line saying which vault it is supposed to
  live in.
- The interesting direction is the one nobody looks at: not "is this secret in
  the vault" but "this secret is in the vault and somebody committed it
  anyway", which means the rotation everybody thinks happened did not.

What it touches:

- A read only connector per vault, and a lookup beside the exclusion match in
  ingest.  Nothing stores a secret, which is what keeps this on the right side
  of the line drawn below.

## Not planned, and why

Three things other tools sell that this should keep saying no to.  Dynamic
testing used to be a fourth.  It moved up into the list above once there was a
version of it that brings its own deployment, which was the thing that made it
somebody else's product before.

**A secrets store, an IAM or a PAM inside this.**  Asked for, thought about,
and deliberately put somewhere else: it is being built as its own project.
The reason is worth keeping.  This tool clones repositories nobody here
controls and runs nine engines over their contents, which is attacker supplied
input parsed on that host.  Today a compromise costs a read only token and a
list of findings.  A vault in the same process would make the same compromise
cost every production secret an organization owns, and no amount of encryption
in the database changes that, because a process that can decrypt on request is
one an attacker inside it can ask.  Holding secrets and executing other
people's code are two jobs that should not share an address space.  What stays
here is the item above: comparing what a vault holds against what is committed,
which needs no secret to cross the line.

**Runtime protection and cloud posture.**  Both appear on competitor pricing
pages as separate products sharing a login.  Chasing them dilutes something
that is currently very good at one clearly bounded job.

**Write access to a repository.**  Every provider call being a GET is a tested
property and a real reason a security team approves this.  Fix pull requests
and posted review comments both require giving it up.  SARIF gets the pull
request annotations anyway, using the pipeline's own token, and the autofix
item gets the patch on screen without applying it.  There is no version of
those features worth the trade.

**Alerting on the backlog.**  A constraint on the notifications item rather
than a separate decision, and worth writing down next to it.  Alert on what is
new or people stop reading.
