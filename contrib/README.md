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
