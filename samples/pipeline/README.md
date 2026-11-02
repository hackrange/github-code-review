# Git Code Review pipeline samples

Scripts that let a build pipeline ask Git Code Review what needs fixing:
secrets to rotate, packages to upgrade, container images to rebuild, problems
in build files, and code fixes an AI review has suggested.

**Start with the guide:** `docs/Git-Code-Review-Pipeline-Guide.pdf` (or the
Word copy beside it).  It walks through everything step by step, and its FAQ
lists every error message and what to do about it.

## What is in here

| Folder | What it holds |
|---|---|
| `docs/` | The guide, as PDF and Word |
| `python/gcr_api.py` | Every feature in one script.  Needs only Python 3.8 or newer. |
| `bash/` | The same features as small bash scripts.  Needs `curl` and `jq`. |
| `github-actions/` | Ready-to-use GitHub Actions workflows |
| `.env.example` | Settings for running the scripts on your own computer |
| `SHA256SUMS` | Checksums, to confirm the files are the ones the server sent |

## The shortest path, in GitHub Actions

1. Make a token on the **IDE tokens** page with only the **reports** box ticked.
2. In your repository, under **Settings > Secrets and variables > Actions**:
   - add a **secret** named `GCR_TOKEN` holding the token
   - add a **variable** named `GCR_URL` holding the address in `.env.example`
3. Copy the `bash` and `python` folders to `.github/gcr/` in your repository.
4. Copy a workflow from `github-actions/` to `.github/workflows/`.

## On your own computer

```bash
cp .env.example .env
chmod 600 .env
bash bash/gcr-token-store.sh save     # keeps the token encrypted on disk
python3 python/gcr_api.py ping
python3 python/gcr_api.py fix-plan --repo your-org/your-repo
```

## Security notes

- Never commit `.env` or a token.  `.gitignore` already excludes them.
- Give each pipeline its own token with only the **reports** scope, and the
  shortest expiry you can manage.
- The scripts refuse plain `http://`, refuse settings files other users can
  read, never print the token, and never put it on a command line.
