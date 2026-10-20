# Running this in a pipeline

Everything else in this tool looks at code that is already merged.  A pipeline
is the one place a credential can still be stopped rather than rotated, so it
is worth the twenty minutes.

The command is the same everywhere:

```bash
ghscan review <path> [--diff <ref>] [--only secrets,code] [--fail-on <what>]
                     [--format json|sarif] [--repo <owner/name>]
```

It needs no token, no configuration file and no account.  It reads a directory
that is already on the machine and writes JSON to stdout.

There is a second way, and for holding a merge it is the better one: the
[pull request gate](#holding-a-merge-the-gate).  A small client in the
pipeline asks your Git Code Review server about the change, and the server
answers with pass, warn or fail under one policy for the whole estate.  The
build agent needs no engines, and the answer takes your waivers into
account.  Most of this page is the first way, and the gate has its own
section further down.

## Exit codes, which are the whole interface

| Code | Meaning |
|---|---|
| 0 | Nothing above the threshold |
| 1 | Something went wrong |
| 2 | The arguments or the path were wrong |
| 3 | It found something that met `--fail-on` |

Only 3 means "there is a finding".  A build that treats any non-zero code as a
finding will call a broken mount a leak, and people stop believing it.

`--fail-on` takes `none`, `secrets`, `verified-secrets`, `critical`, `high`,
`license` or `policy`.  Start at `secrets` and move up when the noise is under
control.  `verified-secrets` counts only credentials the provider said still
work.  Before 2026-10-20 it counted every credential, the same as `secrets`.
`policy` goes with `--base` and `--head` and is covered under the gate.

## The shortest thing that works

```bash
docker run --rm -v "$PWD:/src:ro" \
  --entrypoint /opt/gcr/bin/ghscan \
  github-code-review:1.0.1 \
  review /src --diff origin/main --fail-on secrets
```

Mount read only.  Nothing needs to write to your checkout, and a scanner that
cannot modify what it is looking at is one less thing to think about.

## Getting the scanner onto the build agent

That command assumes `github-code-review:1.0.1` is already on the machine
running the build.  On your own laptop it will be, because that is where you
built it.  On a Jenkins agent it will not, and this is the step every recipe
below quietly skips.

Two things are worth saying plainly before the options.

**The build agent never talks to the Git Code Review server.**  A review reads
a directory on disk and runs the engines against it.  No token, no
configuration, no network call to the server, nothing sent anywhere.  That is
why it works on an agent that has never heard of your install, and it is also
why a finding in a pipeline does not appear on the dashboard: nothing sent it
there.  The dashboard shows what the server's own scans found.  The two are
separate records of the same code, on purpose.

**The agent does not clone this repository.**  It clones the application it is
building, which it already does.  What it needs is the scanner, and that is a
thing you put on the agent once rather than something the build fetches.

### Option one: a registry the agent already pulls from

The one to pick if your agents run Docker and you have a registry.

```bash
# On the machine where you build it
docker tag github-code-review:1.0.1 registry.example.com/security/ghscan:1.0.1
docker push registry.example.com/security/ghscan:1.0.1
```

Then in the pipeline, use that name instead:

```bash
docker run --rm -v "$WORKSPACE:/src:ro" \
  --entrypoint /opt/gcr/bin/ghscan \
  registry.example.com/security/ghscan:1.0.1 \
  review /src --diff origin/main --fail-on secrets
```

The engines, their versions and the rule packs travel together as one pinned
artifact, so every pipeline is running exactly what you tested.  Upgrading the
scanner everywhere is one push and one tag change.

Pin the version.  A pipeline on `:latest` changes what it enforces on a day
nobody chose, and the first anybody knows is a build that fails on code that
did not change.

### Option two: install it on the agent

The one to pick if your agents have no Docker socket, or you would rather not
run containers inside builds.

```bash
# On each agent, once
sudo contrib/install-deps.sh          # gitleaks, trufflehog, semgrep, trivy, syft, grype
sudo mkdir -p /opt/ghscan
sudo cp -r bin lib /opt/ghscan/
```

`ghscan` finds everything relative to its own location, so `bin/` and `lib/`
sitting beside each other under one directory is a complete install.  The
pipeline then calls it directly:

```bash
/opt/ghscan/bin/ghscan review "$WORKSPACE" --diff origin/main --fail-on secrets
```

The cost is that engine versions are now yours to keep level across every
agent.  Two agents on different gitleaks versions will disagree about the same
commit, and that argument is hard to have.

### Option three: build the image during the pipeline

Do not.  It couples every application build to this repository, rebuilds a
scanner that did not change, and adds minutes to a job that should take
seconds.  It is listed only so that ruling it out is a decision rather than an
oversight.

## Three things that catch people out

**A shallow clone breaks `--diff`.**  Jenkins, GitLab and GitHub all clone with
a depth of 1 by default, so the ref you are comparing against is not there and
the review looks at everything, with one warning line in the log.  Fetch the base branch first, or turn
the shallow clone off.  Without that fix a pipeline reports the repository's
whole backlog on every run and gets switched off within a week.

**Code analysis wants the network, credentials do not.**  Secrets detection is
entirely local, tested with the network switched off.  semgrep fetches its rule
packs from the registry on first use, so on an isolated builder either allow
that, cache `$HOME/.semgrep` between runs, or point `rulesets` at a directory
of rules you keep yourself, which works offline.

**Review the change, not the repository.**  Without `--diff` a pipeline reports
everything anybody ever committed, every time.  The first run looks impressive
and the twentieth gets ignored.

## Jenkins

Declarative, on an agent with Docker.  The image name is the one you pushed in
option one above; `github-code-review:1.0.1` only works on a machine that built
it, which a Jenkins agent almost certainly did not.  Substitute your registry
throughout.

```groovy
pipeline {
  agent any
  stages {
    stage('Code review') {
      steps {
        // The base branch has to be here, or --diff has nothing to compare to.
        sh 'git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main'
        script {
          def code = sh(returnStatus: true, script: '''
            docker run --rm -v "$WORKSPACE:/src:ro" \
              --entrypoint /opt/gcr/bin/ghscan \
              github-code-review:1.0.1 \
              review /src --diff origin/main --fail-on secrets \
              > review.json
          ''')
          if (code == 3) {
            error("Credentials found.  See review.json.")
          } else if (code != 0) {
            unstable("The review did not run cleanly, exit ${code}.")
          }
        }
      }
      post {
        always { archiveArtifacts artifacts: 'review.json', allowEmptyArchive: true }
      }
    }
  }
}
```

Note the difference between `error` and `unstable`.  A finding is the build's
problem; a scanner that could not start is the pipeline's, and telling them
apart is what stops people ignoring both.

Scripted, if that is your house style:

```groovy
node {
  checkout scm
  sh 'git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main'
  def code = sh(returnStatus: true, script: "...as above...")
  if (code == 3) { currentBuild.result = 'FAILURE'; error('Credentials found.') }
}
```

For a shallow checkout, add the "Advanced clone behaviors" option and either
set the depth high enough to reach the base, or untick shallow entirely.

## GitLab CI

```yaml
code-review:
  stage: test
  image:
    name: github-code-review:1.0.1
    entrypoint: [""]
  variables:
    GIT_DEPTH: "0"          # without this --diff has nothing to compare to
  script:
    - ghscan review "$CI_PROJECT_DIR"
        --diff "origin/$CI_DEFAULT_BRANCH"
        --fail-on secrets
        > review.json
  artifacts:
    when: always
    paths: [review.json]
    expire_in: 30 days
```

`GIT_DEPTH: "0"` is the whole trick.  GitLab clones 20 commits deep by default
and the base branch will not be among them.

## GitHub Actions

```yaml
name: Code review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # the default of 1 leaves --diff nothing to do

      - name: Review the change
        run: |
          docker run --rm -v "$PWD:/src:ro" \
            --entrypoint /opt/gcr/bin/ghscan \
            ghcr.io/your-org/github-code-review:1.0.1 \
            review /src --diff "origin/${{ github.base_ref }}" \
            --fail-on secrets > review.json

      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: review, path: review.json }
```

## Azure Pipelines

```yaml
steps:
  - checkout: self
    fetchDepth: 0

  - script: |
      docker run --rm -v "$(Build.SourcesDirectory):/src:ro" \
        --entrypoint /opt/gcr/bin/ghscan \
        github-code-review:1.0.1 \
        review /src --diff "origin/$(System.PullRequest.TargetBranch)" \
        --fail-on secrets > review.json
    displayName: Code review

  - publish: review.json
    artifact: review
    condition: always()
```

## Bitbucket Pipelines

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Code review
          clone: { depth: full }
          services: [docker]
          script:
            - docker run --rm -v "$BITBUCKET_CLONE_DIR:/src:ro"
                --entrypoint /opt/gcr/bin/ghscan
                github-code-review:1.0.1
                review /src --diff "origin/$BITBUCKET_PR_DESTINATION_BRANCH"
                --fail-on secrets > review.json
          artifacts: [review.json]
```

## A pre-commit hook

Cheaper than any of the above, because it runs before the commit exists:

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit
docker run --rm -v "$PWD:/src:ro" \
  --entrypoint /opt/gcr/bin/ghscan \
  github-code-review:1.0.1 \
  review /src --diff HEAD --only secrets --fail-on secrets \
  || { echo "A credential is about to be committed.  Look at it."; exit 1; }
```

## Where the output goes

Findings go to stdout, progress goes to stderr.  Redirect stdout to a file and
the JSON is clean; leave stderr alone and the build log says what happened.

If the progress lines are noise in your build output, `-q` turns them down to
warnings only:

```bash
ghscan review /src --diff origin/main --fail-on secrets -q > review.json
```

## Reading the output

```json
{
  "generator": "ghscan 1.0.1",
  "against": "origin/main",
  "counts": { "total": 2, "credential": 2, "code": 0 },
  "findings": [
    {
      "kind": "credential",
      "file": "app/settings.json",
      "line": 12, "start_column": 38, "end_column": 69,
      "rule": "ghscan-hardcoded-password",
      "severity": "critical",
      "preview": "2604************e1d",
      "fingerprint": "1b5be50881d7575f"
    }
  ]
}
```

The value is redacted and the fingerprint is a hash, so the output is safe to
keep as a build artifact.  Cleartext never leaves the review.

That fingerprint is the same one the web app uses, so a credential accepted
there can be excluded here without anybody writing it down twice.

## Putting the findings on the pull request

`--format sarif` writes the same review as SARIF 2.1.0, which is what a code
host reads.  Upload it and the findings appear inline on the diff, on the lines
they are about.

```bash
ghscan review /src --diff origin/main --format sarif --repo acme/payments \
  > review.sarif
```

`--repo` is optional and worth passing.  It names the repository being
reviewed, and it lines the fingerprints up with the ones a scheduled scan of
that same repository produces, so the two do not report the same finding under
two identities.

The whole GitHub Actions job:

```yaml
name: Code review
on: [pull_request]

permissions:
  contents: read
  security-events: write     # for the upload, not for ghscan

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Review the change
        run: |
          docker run --rm -v "$PWD:/src:ro" \
            --entrypoint /opt/gcr/bin/ghscan \
            ghcr.io/your-org/github-code-review:1.0.1 \
            review /src --diff "origin/${{ github.base_ref }}" \
            --format sarif --repo "${{ github.repository }}" \
            > review.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: review.sarif
```

Two things about that job are worth saying out loud.

The `security-events: write` permission belongs to the workflow, not to this
tool.  The upload is done by the job's own token.  ghscan never holds a
credential that can write to a repository, and adding pull request comments has
not changed that.

And `if: always()` on the upload.  Without it a review that fails the build
uploads nothing, which is the run where somebody most wanted to see what it
found.

GitLab reads the same file through `artifacts:reports:sast`, and Azure DevOps
through the SARIF results viewer extension.  Both take it as it is.

## Reporting it centrally instead

A pipeline that only fails builds tells nobody what is happening across the
estate.  If you want the findings somewhere people can see them, post the same
files to the API with a token from the IDE tokens page:

```bash
curl -sS -X POST https://<your server>/api/v1/review \
  -H "Authorization: Bearer $GCR_TOKEN" \
  -H "Content-Type: application/json" \
  -d @files.json
```

The API works out the answer and throws it away; it never writes a finding.
Scheduled scans are what fill the web app, and this is for showing somebody the
answer now.

## Holding a merge: the gate

Everything above runs the engines on the build agent and leaves the verdict
to whoever wrote the pipeline.  The gate moves both to the server.  A step in
the pipeline runs `gcr-gate`, which sends the repository and two commit ids
to your Git Code Review server and waits.  The server fetches those commits
itself, reviews the change, applies one policy, and answers pass, warn or
fail, with a SARIF of what the change added.  Make that step a required
status check and the answer holds the merge.

What it is worth knowing before you switch it on:

- **Only what the change added can block.**  The server reviews the files the
  pull request touched at the merge base and at the head, and maps lines
  across the diff.  Code that moved, a renamed file, or an old line somebody
  edited stays old.  Old findings are the nightly scan's to report, and the
  gate never mentions them.
- **The history of the change counts.**  A credential added in one commit and
  deleted in the next is still found, from the commits in between.  The
  final diff would look clean, and the key would still be in the history.
- **The agent needs no engines and no clone of the server.**  The server
  fetches with the credential its scans already use, into a mirror it keeps
  per repository, so a pull request from a fork works the same way.
- **It writes nothing.**  No finding is filed, no comment is posted, and
  nothing is written to the code host.  The pipeline uploads the SARIF with
  its own token.  Each run is kept on the server and in the audit log.
- **Your decisions apply.**  An approved waiver lets its own finding through
  and nothing else, and an expired one covers nothing.  Learned rules lower a
  new finding the same way they lower an old one.

### Setting it up

1. **The repository has to be one the server already scans.**  The gate
   fetches with that connection's credential, and a repository the server
   does not monitor is refused.
2. **Make a token with the `gate` scope** on the IDE tokens page.  A token is
   a person, and that person has to be able to see the repository.  A
   service account that can see every repository you gate is the usual
   choice.  The token needs no other scope.
3. **Build the client image** from a checkout of this repository, on a
   machine that has the `github-code-review:1.0.1` image, since gitleaks is
   copied out of it: `docker build -f contrib/gcr-gate/Dockerfile -t
   gcr-gate:1.0.1 .`  Push it where your runners pull from.  It has bash, curl, jq, git and
   gitleaks, and nothing that scans.  Or skip the image:
   `contrib/gcr-gate/gcr-gate` is one bash script, and any runner with bash,
   curl and jq can run it.
4. **Add the workflow.**  `contrib/gcr-gate/github-actions.yml` is the one to
   start from.  Set `GCR_URL` as an organization variable and `GCR_TOKEN` as
   an organization secret.
5. **Make `gcr-gate` a required status check** on the protected branches.
   Until it is required, a fail is a red mark and nothing more.

Every repository starts in monitor mode, so steps 1 to 5 block nothing yet.
That is on purpose.  See [Monitor first](#monitor-first-then-enforce).

### The client

```bash
GCR_URL=https://gcr.example.com GCR_TOKEN=gcr_... gcr-gate --sarif gcr.sarif
```

On GitHub Actions, GitLab CI and Azure Pipelines it reads the repository, the
pull request and both commits from the environment.  On Jenkins it reads the
commits but not the repository, so pass `--repo`.  Anywhere else pass
`--repo`, `--base` and `--head` yourself.  `--repo` is the name as Git Code
Review knows it, `owner/name`.

| Code | Meaning |
|---|---|
| 0 | Pass, or warnings only, including a would-be block in monitor mode |
| 1 | Fail: at least one finding the policy blocks on |
| 2 | The server could not answer |

The token goes to curl through a file, never on a command line, so it does
not show up in a process list.  The summary, with what blocked and why, goes
to the job's step summary on GitHub Actions, or to `--summary FILE`.

**When the server cannot answer**, the client does not just give up.  It
checks the commits in the change for credentials itself, with gitleaks, and
fails on any it finds, because a pushed key is the one miss that cannot wait
for the nightly scan.  That needs the full history in the checkout
(`fetch-depth: 0`).  With nothing found it exits 2, and what happens next is
your call: `--fail-open` turns that into a pass with a warning.  A server
that took the request and then could not finish it, a timeout for example,
answers for a repository marked `fail_closed` with a fail, whatever the
pipeline asked for.  When the server cannot be reached at all, the client
has no way to know the repository's policy, so `--fail-open` is the only
thing that decides.

### Monitor first, then enforce

In monitor mode a run that would have failed passes with a warning, and the
run records that enforcing would have blocked it.  Leave a repository there
until the would-be blocks are ones you agree with.  Until there is a page
for them, they are in the audit log: every run is a `gate.run` event with its
verdict and how many findings blocked.

A pipeline can ask for `--mode enforce` to make its own check stricter.  It
cannot ask for monitor under a policy that enforces.  The workflow file lives
in the repository, and anybody who can push can edit it.

### The policy

`config/gate-policy.yaml` decides what blocks.  Out of the box:

| What | Blocks when |
|---|---|
| Credentials | The provider confirmed it still works (`live`).  `any` blocks every new one, `none` never |
| Code | High or above, and two engines agree.  One engine alone is a warning |
| Dependencies | A known malicious package, a typosquat or an install hook, a KEV listing, or a critical that is reachable |
| Infrastructure | Public storage, an admin port open to the world, a privileged container |
| Workflows | Untrusted input in a `run:` step, or secrets handed to a fork |
| Anything else new | Warns |

The wildcard IAM category is in the file and empty.  The trivy release in
the image does not report an Allow of `*` on `*`, and a category with no rule
behind it is better left empty than pretending.

Per repository settings go under `repos:`, merged over the default one key at
a time:

```yaml
repos:
  acme/payments-api:
    mode: enforce
  acme/infra-live:
    mode: enforce
    fail_closed: true
```

Every run records the policy's version and a hash of the file, so a blocked
pull request can always be traced to the rule that blocked it.  Bump
`version:` when you change it.

**Changing it on a server.**  The file in the image is the default, and an
upgrade replaces it.  Put your own copy in the data volume instead, where it
survives upgrades:

```bash
docker compose cp github-code-review:/opt/gcr/config/gate-policy.yaml .
# edit it
chmod 644 gate-policy.yaml
docker compose cp gate-policy.yaml github-code-review:/data/gate-policy.yaml
```

The next run uses it, with no restart.  The `chmod` matters: the copy lands
owned by root, and the app runs as another user, so a file only root can read
turns every run into an error.  A typo in the file does the same, so watch
the next run after an edit.  `GCR_GATE_POLICY` in `.env` points at a file
somewhere else, and wins over both.

### Without the server

The same check runs on a machine that has the engines, with no server and no
token:

```bash
ghscan review . --base origin/main --head HEAD --fail-on policy
```

`--base` and `--head` mark what the head added as new, `--fail-on` then
counts only new findings, and `policy` exits 3 when the policy says fail.
`--policy FILE` uses another policy file.  It has no waivers and no learned
rules to go on, since those live on the server.  A shallow clone is refused
with the fetch depth that fixes it, rather than read as a change to every
file.

### The API underneath

The client is a thin layer over three calls, all with the `gate` token.

```bash
curl -sS -X POST https://<your server>/api/v1/gate \
  -H "Authorization: Bearer $GCR_TOKEN" -H "Content-Type: application/json" \
  -d '{"repo": "acme/payments", "pr": 42, "base_sha": "<sha>", "head_sha": "<sha>"}'
```

That answers at once with 202 and a `status_url`.  `GET` that until `status`
is `done` or `error`.  It carries `verdict`, `mode`, `would_block`,
`blocking`, `warnings`, `exceptions_applied`, `counts` and the policy
version.  `GET /api/v1/gate/runs/{id}/sarif` is the SARIF.  `mode` in the
request takes `monitor` or `enforce`.  A repository the token's owner cannot
see is a 404, the same as one that does not exist.

### Limits worth knowing

- **Five minutes.**  A run past `GCR_GATE_TIMEOUT` (300 seconds) is stopped
  and answered as an error.  A small change took about 20 seconds in
  testing, and a big one takes longer.  A server whose engine caches are
  empty downloads the vulnerability databases on its first run, which took
  close to three minutes in testing and can pass the limit on a slow link.
  A server that has already run a scan has them, and its first run took
  about 30 seconds.
- **Two at a time.**  `GCR_GATE_WORKERS` (2) caps how many run at once beside
  the nightly scan.  A burst of pushes queues rather than starving it.
- **A very large change** gets its verdict but no inline notes if its SARIF
  would be over 8 MiB.  The SARIF call says so.
- **GitHub Actions is the only template so far.**  The client reads GitLab,
  Azure Pipelines and Jenkins too.  You write that job yourself for now.
- **Nothing is uploaded.**  The server always fetches the commits itself.
  Sending the changed files instead is refused rather than ignored.

## What this does not do

`ghscan review` without `--base` reads the working tree, not the history.  A
credential committed last March and removed in April is not here, because it
is not in these files.  That is what the scheduled scan is for, and the two
are not interchangeable.  The gate reads the commits inside the change, and
nothing before them.
