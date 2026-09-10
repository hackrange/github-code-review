# Roles

Three of them, and the gaps between them are on purpose.

| | admin | developer | reader |
|---|---|---|---|
| See findings | everything | assigned orgs and repos only | everything |
| Export reports | yes | yes | yes |
| Ask for an exception | yes | yes | no |
| Approve an exception | yes | no | no |
| Revoke an exception | yes | no | no |
| Certify a branch | yes | no | no |
| Withdraw a certification | yes | no | no |
| Mark a branch not applicable | yes | no | no |
| Write a custom severity rule | yes | no | no |
| See an exclusion | yes | no | no |
| Write an exclusion | yes | no | no |
| Start a scan | yes | yes | no |
| See the scan history | everything | their own runs only | no |
| Stop a scan | any of them | their own runs only | no |
| See the schedules | yes | no | no |
| Edit schedules | yes | no | no |
| See the report files | yes | no | no |
| Manage users | yes | no | no |
| Read the audit log | yes | no | no |

## What a developer sees

Only the organizations and repositories assigned to them. A developer with
nothing assigned sees an empty screen, which is deliberate: a new account
should show nothing until somebody decides what it should show.

A scope is either a whole organization or one repository inside it.

This is enforced in the query, not in the page. Every list starts from the same
scoped query, and every lookup by id goes through the same check. Guessing the
id of a finding in another team's repository returns a 404, not a 403, so the
answer tells you nothing about whether it exists.

## Exceptions need two roles

A developer can ask for an exception on anything they can see. Nothing changes
on disk until an admin approves it, and until then the finding stays in
`vulnerabilities.json` and `vulnerabilities.csv`.

An admin asking for one approves it in the same step, and an admin can approve
an exception they asked for themselves.

A developer sees only the exceptions they asked for.  The list used to be
filtered by repository, so two developers on one team each saw the other's
requests: what they asked to set aside, the reason they gave, and how it was
judged.  An exception is an argument a person made and had decided, which is
nearer to their review than to the finding it sits on.

Every exception has an expiration date, up to a year out. When it passes, the
finding comes back into both files on the next write.

Requests arrive in batches, because one dependency bump is the same finding in
forty repositories. An admin can tick a set of them and approve or reject the
lot in one go, or take back a set already approved. It is the same permission
check as deciding them one at a time, applied per row: an id belonging to a
repository the account cannot see is skipped rather than decided. A reason is
required on a bulk decision, and it is written onto every exception in the
batch as well as into the audit log.

## Somebody else's scans are somebody else's business

A developer can start a scan of a repository they own, so they can see the runs
they started and stop one of those.  They cannot see anybody else's, and they
cannot stop one.

That page had no permission check at all until recently, so every signed in
account could read the scan history for every organization on the install: what
was scanned, when, by whom and how it went.  Stopping a scan asked only whether
the caller could run one, and took the run to stop from the form, so a developer
able to re-read one repository of their own could end a sweep over the whole
estate by posting a number.  A run that is not there and a run belonging to
somebody else now answer the same way, because telling them apart turns an id
into a way to find out what exists.

The history export is narrowed rather than refused.  A developer's own runs are
theirs to take away, and a file is the easiest place to forget a scope, since
nothing on screen shows what came out of it.

## Exclusions and grades are admin only

Writing an exclusion is the same decision as approving an exception: it takes a
finding out of the files another tool reads.  Every route that adds, edits,
imports, purges or deletes an exclusion checks the same permission, and there is
a test that posts to each of them as a developer and as a reader and expects to
be refused.

Reading them is an administrator's too, and it did not used to be.  A developer
held the permission so they could see the rules covering their own
repositories, and the page showed them every rule on every account: what each
team had decided to stop looking at, and why.  An exclusion is a statement about
the whole estate rather than about one person's repositories.  The schedules and
the report files went the same way and for the same reason.

Custom severity is the same argument.  A grade is a statement about what the
whole organization means by a number, so writing one is an administrator's job.
Regrading a single finding is separate and also an administrator's.

Certifying a branch is administrator only for the same reason, and marking a
branch as not applicable is a further permission again, because it removes work
from a list permanently rather than recording that the work was done.  See
[certification.md](certification.md).
