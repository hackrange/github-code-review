# Changelog

Newest first.  Written for somebody deciding whether to upgrade, so every entry
says what is different for a person using the product rather than which files
moved.

## 2026-09-09

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
