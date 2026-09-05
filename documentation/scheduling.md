# Scheduling

Two kinds of job, both cron.

| Kind | What it does | Default |
|---|---|---|
| scan | runs the scanner and updates the report files | `17 2 * * *`, nightly |
| feeds | pulls the CISA and EPSS lists again | `0 */12 * * *`, twice a day |

Both get created on first boot. Edit or delete them from the Schedules page.

Times are UTC. Five fields, the usual ones: minute, hour, day of month, month,
day of week. `17 2 * * *` is 02:17 every day.

## Why the feeds job is separate

A finding you already have can turn urgent overnight without anybody touching
the code. A CVE lands on the CISA exploited list, or its EPSS score jumps, and
suddenly something you filed as routine is the thing to work on next.

Refreshing the lists is cheap and takes seconds. A scan clones every repository
and takes hours. Keeping them apart means you can pick up the ranking change
tonight without waiting for the next full scan.

## Scanning only some organizations

Leave the organizations field empty and a scan job covers everything the
credential can see. Fill it in with a comma separated list to narrow it.

Handy when one organization is large enough to want its own slot.

## One at a time

Two scans would fight over the same GitHub rate limit and the same work disk,
and both would finish later than one would have. So a scan that starts while
another is running is turned away rather than queued, and the page says so.

The feeds job is not affected and can run whenever.

## Running one now

The Run now button on the Schedules page fires a job without waiting for its
time to come round. Same as the Scan now button on the scan history page.

## When something is missed

If the container was down when a job was due, it runs once when the container
comes back, as long as it is within the hour. Later than that it waits for the
next scheduled time rather than kicking off a surprise scan hours after the
fact.

## What a scan does, in order

1. Runs the scanner across the repositories in scope.
2. Matches what came back against what is already in the database, so a finding
   that was there yesterday keeps its first found date and gets a new last
   found date.
3. Marks anything that did not come back as fixed, but only in repositories
   that were actually scanned.
4. Rewrites `vulnerabilities.json` and `vulnerabilities.csv`.

Waived findings stay waived. A scan never quietly un-waives something somebody
signed off on.
