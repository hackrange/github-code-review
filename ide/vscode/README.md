# Git Code Review for Visual Studio Code and Cursor

Reviews the file you are editing against your own Git Code Review server.
Credentials and code analysis, with the same triage the nightly scan uses, so
what you see here is what the report will say.

## Setting it up

1. Open your Git Code Review server and go to **IDE tokens**.  Make a token
   with **review** and **rules** both ticked.  One without both connects and
   then fails on the first save.
2. Install the package: command palette (`Ctrl+Shift+P`, or `Cmd+Shift+P` on a
   Mac), then **Extensions: Install from VSIX**, and pick the file.  The
   `code --install-extension` command does the same thing, when that command is
   on your PATH.  On a Mac it is not until you run **Shell Command: Install
   'code' command in PATH** from the palette.
3. In the editor, run **Git Code Review: Set the token** from the command
   palette and paste it.  It is kept in the editor's secret storage, not in a
   settings file.
4. Set the address in settings:

   ```json
   "gitCodeReview.server": "https://your-server/api/v1"
   ```

5. Run **Git Code Review: Check the connection**.  It says what is wrong, if
   anything is.

## What it does

Open or save a file and it is sent to your server, reviewed, and the findings
come back as ordinary problems in the editor.  A credential is red, because a
live key in a file you are about to commit is the one thing here that cannot
wait.  Everything else is graded the way the server grades it, and anything
the triage set aside is shown struck through rather than hidden, so you can
disagree with it.

Nothing is stored.  A review creates no finding, no exception and no scan; the
file is written to a temporary directory on the server, looked at, and
deleted.  That is why it is safe to run on every save.

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `gitCodeReview.server` | | The address, ending in `/api/v1`. |
| `gitCodeReview.token` | | Better left empty; use the command instead. |
| `gitCodeReview.reviewOn` | `save` | `save`, `type` or `manual`. |
| `gitCodeReview.changedLinesOnly` | `true` | Only findings on lines you changed. |
| `gitCodeReview.only` | `secrets,code` | Which passes to ask for. |
| `gitCodeReview.allowInsecureTls` | `false` | Accept an untrusted certificate. |

Keep `changedLinesOnly` on.  A repository with two thousand findings in it
will otherwise show you two thousand findings, and none of them are yours.

## Before a commit

The editor is not the only place this is useful, and a hook needs no token at
all because it runs where the code already is:

```
ghscan review . --diff HEAD --fail-on secrets
```

Exit code 3 means it found something.  That is the only point where a
credential can still be stopped rather than rotated.
