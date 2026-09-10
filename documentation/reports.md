# The report files

The findings, in the reports directory, rewritten after every scan and after
every exception decision.

```
/data/docker/github-code-review/reports/vulnerabilities.json
/data/docker/github-code-review/reports/vulnerabilities.csv
```

That path is a contract. Another tool reads these, so the location and the
shape do not change on a whim.

Beside them, the same directory holds the VEX documents and the SBOMs, which
the Report files page also offers as downloads. Everything there is behind the
same gate: an account that does not see the whole estate cannot pull any of
these files, because each one names every organization at once.

## Written atomically

Both are written to a temporary file in the same directory and then renamed
over the top. A reader gets either the old file or the new one, never half of
either, which matters when something is polling them on a timer.

## Every finding has a last found date

```json
{
  "finding_id": "cred:a3f19c02b7e4d81f",
  "kind": "credential",
  "severity": "critical",
  "organization": "example-org",
  "repository": "example-org/api-service",
  "branch": "main",
  "file": "src/config.php",
  "line": 12,
  "rule": "aws-access-token",
  "credential": {
    "preview": "AKIA************J3D",
    "verified": true,
    "exposure": "current_and_history"
  },
  "author": {
    "name": "Some Person",
    "login": "someperson",
    "committed_at": "2023-04-11T16:01:17Z"
  },
  "asset": {
    "application": "Payment gateway",
    "business_owner": "dana@example.com",
    "technical_owner": "sam@example.com",
    "holds": ["PCI", "Customer Data"],
    "visibility": "private",
    "inherited": ["business_owner"]
  },
  "first_found": "2026-06-02T02:17:44Z",
  "last_found": "2026-08-26T02:17:09Z"
}
```

`first_found` is when we saw it the first time. `last_found` is the most recent
scan that still found it. A finding that stops appearing is marked fixed and
drops out of both files.

Findings are matched between scans by `finding_id`, so a credential keeps its
history even if the file it sits in gets renamed.

## What the finding is part of

Every finding carries an `asset` block: the application, its business owner,
its technical owner, what the repository holds, and whether it is public. The
same four answers the finding page shows, resolved the same way, so anything
set on the repository wins and anything left empty falls back to the
connection.

`holds` is a list, so a label can be matched without splitting a string first.
`inherited` names the answers that came from the connection rather than from
this repository, because an answer given about one repository and an answer
given about the account it sits in are not the same claim. An empty value
means nobody has said.

A finding whose repository row has since been deleted carries the block with
everything empty, never a missing key.

## The three kinds

`credential` carries a masked preview, whether it was proven live, and whether
it is only in git history or still at a branch head.

`code` carries the CWE and OWASP categories from static analysis.

`dependency` carries the package, the advisory, the CVSS score, whether it is
on the CISA exploited list and its EPSS score.

Cleartext credentials are never written. Only the mask and a fingerprint.

## The CSV

Same findings, flattened, with a fixed column order so a tool reading it does
not have to guess. Columns it does not need for a given kind are simply empty.

## Exceptions

An approved exception removes the finding from both files. Not hidden, gone.
Hiding it in the web page while leaving it in the file another tool reads would
be dishonest about what was decided.

A requested exception changes nothing until an admin approves it. An expired or
revoked one puts the finding straight back.

## The VEX documents

```
vex.openvex.json
vex.cyclonedx.json
```

The same decisions in the format a customer's procurement team reads: which
advisories this installation says do not affect it, and why. Written every time
the report files are, so they can never describe a set of exceptions that has
since changed.

Only decisions a person made get in. An approved waiver is one. A triage
verdict of not applicable, with the sentence explaining it, is another. A
reachability verdict is not: it answers "does anything in the source import
this package by name", which every transitive dependency fails, so it would
publish a library that runs on every request as one the customer need not
worry about. That verdict stays on the finding, where it helps somebody decide
what to read first.

An accepted risk is reported as affected with the reason attached, not as
unaffected. "We will fix it next quarter" is not a claim that the product is
safe, and saying so in a format built to be trusted is how a supplier ends up
having told a customer something untrue.

Fixed findings and ones somebody excepted are left out, the same as they are
in the files above. Where two repositories reached different conclusions about
the same package, the document carries one statement rather than two, and the
stronger claim is the one that stands.

## The SBOMs

```
sbom.cdx.json          every repository in one CycloneDX document
sbom.spdx.json         the same, in SPDX
sbom-summary.json      the component and license rollup, per repository
sbom/                  one CycloneDX and one SPDX file per repository
```

These come from the scan and only from the scan. A scan writes them into its
own working directory, which goes away when it finishes, so they are copied
here on the way out, including when the scan was stopped or failed part way,
because the repositories that did finish wrote theirs before the stop.

Every CycloneDX file here has a top level `dependencies` array, the per
repository ones and the combined one alike. Without it a document is a list of
components rather than a bill of materials, and the tools it is loaded into
read the graph: Dependency-Track shows a project holding nothing, which looks
exactly like a repository with no dependencies. Whatever graph the scanner
found is kept as it is; a package nothing points at hangs off the document's
own root component, because it is in the document and nothing recorded what
pulled it in; and a package with nothing recorded under it gets an entry with
an empty `dependsOn` rather than being left out of the graph.

In the combined document each repository is an application component holding
its own packages, and every reference is prefixed with the repository it came
from. The same package at the same version in two repositories arrives from
the scanner carrying the same reference in both files, and one document
holding that reference twice is one where half the graph points at the wrong
copy.

Licenses are whatever the scanner stated, carried through untouched by both
the graph pass and the merge. How well they are filled in depends on **License
lookups** under Dependencies and licenses in Settings, which holds `all` by
default and reads PyPI, npm, Maven Central and the Go proxy. It takes `all`,
or any of `golang, java, javascript, python, vcpkg`, and an empty box means
look nothing up. Empty, or run somewhere with no route out to those
registries, a license is only there when the package's own manifest carried
one, which in most ecosystems is a minority of packages. On one real estate
that was three components in every four with no license at all.

Registries answer in their own words, so an enriched license is often free
text rather than an SPDX identifier: "Apache License, Version 2.0" as easily
as "Apache-2.0". The license policy matches by substring, so a denied or
flagged list written only in SPDX identifiers will walk straight past the
spelled out forms. Put both in.

A rescan replaces the set rather than adding to it, so a repository that leaves
the scope does not leave an SBOM behind for ever.

The per repository files download as one zip.

## Rebuilding by hand

The Report files page has a button. It writes the findings and the VEX
documents again from what is in the database right now, without running a scan.

It does not touch the SBOMs, and cannot: the database keeps the packages a
finding was raised against, not every component of every repository. An SBOM
only ever comes from a scan.
