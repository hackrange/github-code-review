# Changelog

Newest first.  Written for somebody deciding whether to upgrade, so every entry
says what is different for a person using the product rather than which files
moved.

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
