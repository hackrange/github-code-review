# Certified branches

A record that somebody in security read a branch and found nothing they
considered unsafe, and a way for a completed scan to say the same about the
branches nobody would ever have read.

The badge is the easy part.  What makes it safe to show is the two ways it
stops being true, because a green mark that outlives what it was based on is
worse than no mark at all: it does not merely fail to help, it actively tells
somebody not to look.

## What one covers

One branch of one repository.  The same code on `main` and on a six month old
release branch is different code, and a review of one says nothing about the
other.

A note is required, and twenty characters is the floor.  Somebody is going to
rely on it without being able to ask you, so "what I read, what I checked for,
and why I am satisfied" is the shape of it.

An expiry is required too.  A review with no end date is a claim that nothing
will ever change, which is not a claim anybody means to make.

## The two ways it stops being true

**It expires.**  Past the date it reads as lapsed rather than quietly carrying
on.

**It goes stale the moment anybody pushes.**  The commit that was reviewed is
recorded and compared against where the branch is now, so any new commit at all
turns the badge amber, whether or not it produced a finding.  Waiting for a
finding would be the wrong test: a reviewer read some code, and different code
has not been read.  "Our engines found nothing in it" is not the claim a sign
off makes.

Both are shown rather than enforced.  Nothing here removes a finding, changes a
grade, or keeps anything out of a report.

## The ones a scan writes

Most branches in an estate carry nothing anybody would open.  Asking a person
to sign each of them off produces a queue nobody works through and a coverage
figure nobody believes, so a completed scan signs those off itself.

A branch qualifies when it has no open findings at all, or none above a low.
Low and informational are the grades a reader passes over, and they are the
only ones passed over here.

An automatic certification is marked as automatic and says so everywhere it is
shown.  It claims a great deal less than a person's, and its wording is about
the search rather than about the code:

> This branch is automatically certified because there were no observable
> findings or credentials in our discovery.

Three rules keep that honest.

**It waits for the passes to finish.**  A repository is only considered when
the scanner reports that all four of its passes completed: `code`, `secrets`,
`vulnerabilities` and `misconfigurations`.  A pass that did not run reports
nothing, and nothing is exactly what a clear branch looks like from here, so a
dead engine would otherwise be handed a green badge.  A repository whose worker
died, whose code pass was cut short, or whose credential history walk covered
only a window is not offered at all.

**It never touches a person's.**  A scan may refresh or leave behind a badge it
wrote itself.  It may not overwrite one somebody signed, may not re-date one,
and may not revive one that was withdrawn.  A branch marked as not applicable
is left alone as well.

**It holds to the same grades a reader would.**  Anything above low is a
finding somebody has to look at, and a branch holding one is not signed off by
a machine.

## Where the badges appear

| Page | What it shows |
|---|---|
| A finding | The badge for that branch, with who certified it, when, and what they said.  An automatic one says a scan wrote it. |
| Repositories | Every certification and every exemption, filtered by state, with the note on each. |
| Dashboard | How many branches are current, how many need re-checking, and the coverage share. |
| The PDF report | A sentence counting the two kinds separately.  The seal on the cover is only ever a person's. |

## Coverage

Coverage is a share of branches, not of repositories and not of
certifications.  A count of certifications only ever goes up and tells nobody
how much is left.

The branches counted are the ones scans have actually walked.  A repository
nobody has scanned yet contributes to neither side of the figure, because that
is a scan somebody owes rather than coverage somebody owes.

Archived repositories are left out entirely: a branch on code that can no
longer be changed is not coverage anybody owes, and counting it would make the
figure worse every time a repository is retired.

Branches marked as not applicable come out of the denominator as well.  They
are not counted as done and not counted as outstanding, because a total that
includes branches nobody intends to review measures the wrong thing.

## Who can do what

| | admin | developer | reader |
|---|---|---|---|
| See the badges | yes | yes | yes |
| Certify a branch | yes | no | no |
| Withdraw a certification | yes | no | no |
| Mark a branch not applicable | yes | no | no |

Certifying is done from a finding, because that is where somebody is when they
finish reading one: the repository, the branch and the commit are already in
front of them, and asking them to find those three things again on another page
is how a review ends up recorded against the wrong branch.

## It hides nothing

A certified repository that starts producing criticals shows every one of them,
beside a badge saying the review no longer covers what is there.  The moment a
certification can hide a finding it stops being one person's opinion and
becomes everybody else's blind spot.
