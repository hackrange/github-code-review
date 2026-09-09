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
| Write an exclusion | yes | no | no |
| Start a scan | yes | yes | no |
| Edit schedules | yes | no | no |
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

Every exception has an expiration date, up to a year out. When it passes, the
finding comes back into both files on the next write.

## Exclusions and grades are admin only

Writing an exclusion is the same decision as approving an exception: it takes a
finding out of the files another tool reads.  A developer can see the exclusions
covering their own repositories and cannot write one, and neither can a reader.
Every route that adds, edits, imports, purges or deletes an exclusion checks the
same permission, and there is a test that posts to each of them as a developer
and as a reader and expects to be refused.

Custom severity is the same argument.  A grade is a statement about what the
whole organization means by a number, so writing one is an administrator's job.
Regrading a single finding is separate and also an administrator's.

Certifying a branch is administrator only for the same reason, and marking a
branch as not applicable is a further permission again, because it removes work
from a list permanently rather than recording that the work was done.  See
[certification.md](certification.md).
