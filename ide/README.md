# The editor side

One core, two front ends, four editors.

```
core/     everything that decides anything, shared
server/   the language server: Eclipse, JetBrains, Neovim, Helix, Sublime
vscode/   the extension: Visual Studio Code, and Cursor, which installs the same file
test/     drives both, against a stub server, with no network
```

One language server rather than a plugin per IDE, because four codebases
against four extension APIs is how these projects die.  A feature lands in one
of them and the other three drift.

## No dependencies

Nothing here has a `node_modules`.  Node's own `http`, `https` and
`child_process` do all of it, and the Language Server Protocol is JSON-RPC
with a `Content-Length` header, which is the ninety lines in `server/lsp.js`.

That is a decision, not an accident.  This product scans other people's
repositories for dependency risk; shipping an editor extension with three
hundred transitive packages in it would be an argument against our own
report.  It also means the packages the server hands out are a zip of the
files in this directory, with nothing fetched and nothing compiled.

## Building the packages

`app/core/editor_plugins.py` builds them on request and the **Editor plugins**
page hands them out.  A `.vsix` is a zip; the language server is a zip.
Neither is committed, because a built copy of files that are already in this
repository goes stale in the way nobody notices.

## Running the tests

`ide/test/ide-test.js` starts a stub that answers `/api/v1`, runs the language
server as a child process, and talks the protocol to it the way an editor
would.  `ide/test/package-test.js` loads the built package with the editor
stubbed out.  Neither needs a network.

```
node ide/test/ide-test.js
```
