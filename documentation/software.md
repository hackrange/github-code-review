# The software inventory

Under Blast radius, the Software tab. Every package in the estate, which
version, which license, which repositories and branches it sits on, and
whether anything has an advisory against it.

## Why it is not the findings list

A finding exists because somebody published an advisory. A component exists
because it is in the tree. Those are different questions and only one of them
can be answered in a hurry.

A package announced as compromised on a Tuesday morning does not have an
advisory until Thursday. Between those two the only useful question is whether
that exact version is anywhere in the code, and a table built from advisories
cannot answer it, because there is no advisory yet. This one can, because it
never asked whether the package was interesting.

So: type a name into the search box, get every place it is, hand the list to
the teams that own those repositories.

## The branch is part of the answer

A release branch routinely pins a version the default branch has already moved
past. "We upgraded that" is only ever true of a branch somebody checked, so
each branch is a place of its own here.

Branches other than the default only appear when the scan was told to walk
them. Set **SBOM branches** to every branch under Dependencies and licenses in
Settings.

## What is in a row

| Column | What it is |
|---|---|
| Package | The name as the SBOM gives it, with the full purl underneath |
| Version | Exactly what is pinned, not a range |
| Ecosystem | Taken from the purl, so npm, PyPI and Maven each have one spelling rather than the four the engines use |
| License | What the SBOM stated. Empty means it did not say, which is not the same as public domain |
| Repos, Places | How many repositories, and how many repository and branch pairs |
| Advisories | The worst severity against that exact version, whether it is on the CISA exploited list, and whether the package itself is the attack |

## Filtering and exporting

The filter row narrows by ecosystem, organization, repository, branch, license,
whether a license was stated at all, and whether anything has an advisory
against it. Everything the page is showing exports as CSV or JSON, flat, one
row per package per branch per repository, so it can be joined to whatever
list of owners you already keep.

The detail page for one package exports the same way, covering every version
and every place.

**SBOM** gives the same search as a CycloneDX 1.6 document, for the tools that
will only read one. It is a document rather than a table, so it has a shape:
the export holds repositories on branches, and each of those holds its
packages, written out as the top level `dependencies` array. That array is the
part that matters. A CycloneDX file with a component list and no graph is one
plenty of tools accept and then show as empty, because they read the graph
rather than the list.

What it will not do is invent edges between packages. Nothing in the inventory
records which package pulled in which, so a package is a leaf with an empty
`dependsOn`: the reference is there, and the empty array says nothing was
recorded, which is not the same as saying nothing depends on it.

Licenses come with it. A package is one component in the document however many
repositories hold it, and a license any one of those SBOMs stated is kept for
all of them, as an SPDX identifier where there is one and as the name
otherwise. The document also says how many packages nobody could license, so
that number is read rather than assumed to be zero. Advisories ride along in
the `vulnerabilities` array, each graded as this graded it and pointed at the
exact version rather than the package.

## Where the data comes from

The SBOM a scan writes, read into the database at the end of the run. Turn
**Build SBOMs** on under Dependencies and licenses in Settings.

A rescan replaces the inventory for the repositories it covered rather than
adding to it, so a package that has been removed disappears instead of sitting
there looking stale. Repositories the scan did not cover keep what they had.

A scan that was stopped part way still keeps the inventory for the
repositories that finished, the same way it keeps their findings.

The SBOM files themselves are on the [Report files](reports.md) page as
downloads, in CycloneDX and SPDX.

## Who can see it

The same rule as the findings. An account that is scoped to two organizations
sees the software in those two organizations and exports a file holding only
those, because a component list names every repository and what each one is
built from.
