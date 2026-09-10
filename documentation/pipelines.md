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

## Exit codes, which are the whole interface

| Code | Meaning |
|---|---|
| 0 | Nothing above the threshold |
| 1 | Something went wrong |
| 2 | The arguments or the path were wrong |
| 3 | It found something that met `--fail-on` |

Only 3 means "there is a finding".  A build that treats any non-zero code as a
finding will call a broken mount a leak, and people stop believing it.

`--fail-on` takes `none`, `secrets`, `verified-secrets`, `critical`, `high` or
`license`.  Start at `secrets` and move up when the noise is under control.

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
the review silently looks at everything.  Fetch the base branch first, or turn
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

## What this does not do

It reads the working tree, not the history.  A credential committed last March
and removed in April is not here, because it is not in these files.  That is
what the scheduled scan is for, and the two are not interchangeable.
