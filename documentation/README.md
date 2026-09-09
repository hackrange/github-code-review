# Git Code Review, documentation

Version 1.0.1.  MIT licensed.  Tim Rice <tim.j.rice@hackrange.com>

| Document | What is in it |
|---|---|
| [quick-start.md](quick-start.md) | One line install, start here |
| [installation.md](installation.md) | The longer version, and what goes where |
| [authentication.md](authentication.md) | Local with TOTP, OIDC, or both |
| [roles.md](roles.md) | Admin, developer and reader, and what each can do |
| [trends.md](trends.md) | How the numbers moved, and drilling down to a branch |
| [certification.md](certification.md) | Signing off a branch, and the ones a scan signs off |
| [reports.md](reports.md) | The findings, VEX and SBOM files on disk |
| [software.md](software.md) | Every package in the estate, and where each one is |
| [scheduling.md](scheduling.md) | Cron for scans and feed refreshes |
| [pipelines.md](pipelines.md) | Running it in CI, and putting findings on a pull request |
| [load-balancer.md](load-balancer.md) | Ports, trusted proxies and health checks |
| [roadmap.md](roadmap.md) | What is not built yet, and the shape each should take |
| [CHANGELOG.md](CHANGELOG.md) | What changed, newest first |

## Things that do not have their own page yet

This table used to list six more.  None of them existed, so every one was a
dead link on the first page anybody opens.  The subjects are all covered, just
in the main [README](../README.md) rather than here, so here is where each one
actually lives until it gets a page of its own.

| Looking for | Where it is |
|---|---|
| Every setting and what it does | [Configuration](../README.md#10-configuration), and the Settings page itself, which explains each field beside it |
| What it looks for and how | [Real secrets vs placeholders](../README.md#5-real-secrets-vs-placeholders), [Branches and history](../README.md#6-branches-and-history), [SBOM and licensing](../README.md#7-sbom-and-licensing), [Vulnerabilities](../README.md#8-vulnerabilities) |
| Tokens, GitHub Apps and SSO | [Auth, and why Okta matters](../README.md#1-auth-and-why-okta-matters) |
| Requesting and approving exceptions | The Waivers page, and [Known limits](../README.md#13-known-limits) |
| The security posture | Every provider call is a GET, which [Layout and tests](../README.md#12-layout-and-tests) covers and the test suite enforces |
| When it does not work | [Operational notes](../README.md#11-operational-notes) |

## What this is

It looks at every repository and every branch in a GitHub organization and
finds three kinds of problem:

- credentials committed to the code, including ones deleted long ago that are
  still sitting in git history
- weaknesses in the code itself, like command injection and SQL injection
- known vulnerabilities in the packages a project depends on

Findings land in a web page you can work through, and in two files on disk that
another tool can read.

## What it is not

It is not a replacement for a security team.  It finds things.  Deciding what
matters is still a person's job, which is why waivers exist and why an admin
has to sign them off.
