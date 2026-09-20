# Git Code Review language server

One language server, for every editor that speaks the Language Server
Protocol: Eclipse through LSP4E, the JetBrains IDEs through an LSP client,
Neovim, Helix, Sublime Text.  Visual Studio Code and Cursor have an extension
instead, built from the same code.

It needs Node 18 or newer and nothing else.  There are no dependencies to
install, which is deliberate: this is a security product, and an editor plugin
of ours that pulled a tree of packages off a registry would be arguing against
the thing it is selling.

## Running it

```
node /path/to/git-code-review-lsp/server/main.js
```

It talks the protocol on standard input and output, so it is started by your
editor rather than by you.  Configure it with two environment variables:

```
GCR_SERVER=https://your-server/api/v1
GCR_TOKEN=<a token from the IDE tokens page, with review and rules ticked>
```

or with `initializationOptions.gitCodeReview` if your client sends them.

| Variable | Default | What it does |
| --- | --- | --- |
| `GCR_SERVER` | | The address, ending in `/api/v1`. |
| `GCR_TOKEN` | | Your token. |
| `GCR_REVIEW_ON` | `save` | `save`, `type` or `manual`. |
| `GCR_CHANGED_LINES_ONLY` | `1` | Only findings on lines you changed. |
| `GCR_ONLY` | `secrets,code` | Which passes to ask for. |
| `GCR_ALLOW_INSECURE_TLS` | `0` | Accept an untrusted certificate. |

## JetBrains IDEs

The JetBrains IDEs do not run an arbitrary language server on their own.
Install **LSP4IJ** from the JetBrains Marketplace, then add a user defined
language server:

* **Command**: `node /path/to/git-code-review-lsp/server/main.js`
* **Environment**: `GCR_SERVER` and `GCR_TOKEN` as above
* **File name patterns**: `*` , or the languages you care about

## Eclipse

Install **LSP4E** from the Eclipse Marketplace.  In
*Preferences, Language Servers*, add a server with the same command and
environment, and associate it with the content types you want reviewed.

## What it does, and does not

Open or save a file and its text goes to `/api/v1/review` on your server.  The
findings come back as diagnostics.  Nothing is written anywhere: a review
creates no finding and no exception, and the file the server wrote to a
temporary directory is deleted before the answer is sent.

It does not scan your repository.  That is what the server does nightly, and
showing a repository's whole backlog in an editor is how a plugin gets
uninstalled.  By default only the lines you changed against `HEAD` carry
findings.
