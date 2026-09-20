# In the editor

Version 1.0.1.

The nightly scan tells somebody about a credential that has been in the
history for three months and now has to be rotated.  The editor is the only
place where it can still be stopped instead.  That is the whole argument for
this part of the product.

## What a developer installs

Everything comes from the **Editor plugins** page of your own server, at
`/editors`.  Not from a marketplace: this server is the one that holds your
rules and your exclusions, plenty of these installations sit on a network
with no way out, and a developer should not have to fetch a security tool for
your code from somebody else's catalog.

| Editor | What they install |
|---|---|
| Visual Studio Code | The `.vsix` from that page |
| Cursor | The same `.vsix`.  It is a fork of Visual Studio Code and takes the same file |
| IntelliJ, PyCharm, GoLand, WebStorm, Rider | LSP4IJ from the JetBrains Marketplace, pointed at our language server |
| Eclipse | LSP4E from the Eclipse Marketplace, pointed at the same server |
| Neovim, Helix, Sublime Text | The same language server, configured the way that editor configures any other |

One language server does the work in all of them, and the Visual Studio Code
extension is a thin front end around the same code.  There is not a plugin per
IDE to keep in step, which is how this sort of thing usually dies: four
codebases, and a fix that lands in one of them.

Neither package has any dependencies.  The language server needs Node 18 or
newer, which Visual Studio Code and Cursor already carry.

## Visual Studio Code, step by step

Written out for somebody who has not installed an editor extension before.
Cursor is identical and takes the same file.

1. On the server, open **IDE tokens** and make one with **review** and
   **rules** both ticked.  Copy it when it is shown; only its hash is kept.
2. On the same server, open **Editor plugins** and download the `.vsix`.
3. In the editor press `Ctrl+Shift+P`, or `Cmd+Shift+P` on a Mac.  A search
   box drops down from the top of the window.  Anything the editor can do can
   be found by typing its name in there.  The editor calls it the command
   palette; the steps below call it the search box, and every one of them
   starts by opening it.
4. Type `Install from VSIX`, choose **Extensions: Install from VSIX** from the
   list underneath, and pick the file you just downloaded.
5. Search box again.  Type `Git Code Review: Set the token` and paste the
   token in.  It goes into the editor's own secret storage rather than into a
   settings file.
6. Open settings with `Ctrl+,`, search for `gitCodeReview`, and put your
   server's address in **Server**.  It ends in `/api/v1` and the Editor plugins
   page prints it.
7. Search box, then `Git Code Review: Check the connection`.  It answers in a
   message at the bottom right of the window, and names what is wrong when
   something is.
8. Open one of your own files and save it.  Findings appear underlined in the
   file and in the Problems panel, which is `Ctrl+Shift+M`.

If nothing appears, the file may have no findings on the lines you changed,
which is the default.  `Git Code Review: Review this file` checks the whole
file on demand.

Step 4 has a terminal equivalent, `code --install-extension <file>`, for people
who would rather type it.  It only works when that command is on your PATH, and
on a Mac it is not until you run **Shell Command: Install 'code' command in
PATH** from that same search box.  Cursor has the same entry for `cursor`.  The
palette step above needs none of that, which is why it is the one written
out.

## What it needs to be told

Two things, the same everywhere:

* the address, which is printed on the page and ends in `/api/v1`
* a token, made by the developer on the **IDE tokens** page

In Visual Studio Code the token goes in the editor's secret storage, through
the *Git Code Review: Set the token* command, rather than in a settings file.
Everywhere else it goes in the environment of the language server as
`GCR_TOKEN`.

## What happens when a file is saved

The text of that one file goes to `/api/v1/review`.  The server writes it to a
temporary directory, runs the credential and code passes over it, grades the
result with the same triage the nightly scan uses, and deletes it.

Nothing is stored.  A review creates no finding, no exception and no scan, so
there is nothing for anybody to explain afterwards and nothing a stolen token
can change.  That is what makes it safe to run on every save.

## Only what they touched

By default the editor shows findings on lines that differ from `HEAD`, and
says how many older ones are in the file without drawing them.

This matters more than it sounds.  A plugin that opens showing two thousand
findings is uninstalled that afternoon, and none of those two thousand are
the work of the person looking at them.  The setting is
`gitCodeReview.changedLinesOnly`, and `GCR_CHANGED_LINES_ONLY` for the
language server.

## What a developer sees

A credential is red whatever its severity says, because a live key in a file
about to be committed is the one thing here that cannot wait for a review.
The value is shown masked, never whole.

Everything else is graded the way the server grades it, and each finding
carries the triage's own sentence for why it survived the filter.  Anything
the triage set aside is shown struck through rather than hidden, so a
developer can disagree with it rather than wonder what was dropped.

## Before the commit, without a token

A hook runs where the code already is, so it needs nothing from the server:

```
ghscan review . --diff HEAD --fail-on secrets
```

Exit code 3 means it found something.  [pipelines.md](pipelines.md) has the
same command in a build.

## For whoever runs the server

The packages are built from the source in `ide/`, on request, and cached under
the data directory.  Building the same release twice gives the same bytes, so
the checksums printed on the page are worth comparing against what somebody
downloaded.

Neither package is signed.  A marketplace signs what it distributes and this
server is not one; if your policy requires a signature, sign the file on the
way into your own catalog.
