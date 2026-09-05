# Roles

Three of them, and the gaps between them are on purpose.

| | admin | developer | reader |
|---|---|---|---|
| See findings | everything | assigned orgs and repos only | everything |
| Export reports | yes | yes | yes |
| Ask for an exception | yes | yes | no |
| Approve an exception | yes | no | no |
| Revoke an exception | yes | no | no |
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
