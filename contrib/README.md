# contrib

Things that are useful but are not part of the running product.

## install-deps.sh

Installs the scanning engines onto a host: gitleaks, trufflehog, syft, grype,
osv-scanner, plus a python venv for semgrep and detect-secrets.

The container already has all of these, so you do not need this to run Github
Code Review. It is here for working on the scanner directly, without building
an image every time.

```bash
sudo ./contrib/install-deps.sh          # everything
./contrib/install-deps.sh --user        # under $HOME, no sudo
./contrib/install-deps.sh --dry-run     # just show what it would do
```

Once those are on your PATH, `bin/ghscan` and `tests/run-all.sh` work straight
from a checkout.

## gcr-gate

The pull request gate client.  A CI step runs it, it asks the server whether
the change may merge, writes the new findings as SARIF for the CI system to
upload, and exits 0 (pass or warnings), 1 (blocked) or 2 (the server could
not answer).  Only findings the change itself added can block.  What blocks
is set by `config/gate-policy.yaml` on the server.

```bash
docker build -f contrib/gcr-gate/Dockerfile -t gcr-gate:1.0.1 .
GCR_URL=https://gcr.example.com GCR_TOKEN=gcr_... gcr-gate --sarif gcr.sarif
```

It needs a token with the `gate` scope, made on the Tokens page.  On GitHub
Actions, GitLab CI, Azure Pipelines and Jenkins it reads the repository and
commits from the environment; anywhere else pass `--repo`, `--base` and
`--head`.  `github-actions.yml` is a workflow to start from.

If the server cannot be reached it still checks the change's commits for
credentials with gitleaks, and fails on any it finds.  Otherwise it exits 2,
or 0 with a warning when given `--fail-open`.  A repository marked
`fail_closed` in the policy fails instead.

The same check runs without a server too, given the engines:

```bash
ghscan review . --base origin/main --head HEAD --fail-on policy
```
