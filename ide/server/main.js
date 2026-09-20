#!/usr/bin/env node
/* The Git Code Review language server.
 *
 * One server, every editor that speaks LSP: Eclipse through LSP4E, the
 * JetBrains IDEs through their LSP client, Neovim, Helix, Sublime.  Visual
 * Studio Code and Cursor get an extension instead, because they can show a
 * status bar item and ask for a token, but it is this same core underneath.
 *
 * What it does is narrow on purpose.  A document is opened or saved, its text
 * goes to /api/v1/review, and what comes back becomes diagnostics.  It creates
 * nothing, waives nothing and stores nothing.
 *
 * Configured by initializationOptions, by workspace/configuration, or by the
 * environment - GCR_SERVER and GCR_TOKEN - because a client that launches a
 * server usually has an easier time with an environment variable than with a
 * settings schema it would have to invent.
 */
"use strict";

const path = require("path");
const url = require("url");

const { Connection } = require("./lsp");
const { Session } = require("../core/session");
const settingsOf = require("../core/settings");

const VERSION = require("./package.json").version;

const connection = new Connection(process.stdin, process.stdout);
const documents = new Map();
let roots = [];
let session = null;
let shuttingDown = false;

function fromUri(uri) {
  try {
    return url.fileURLToPath(uri);
  } catch (err) {
    return "";
  }
}

/* Which workspace a file belongs to, so paths are sent relative to it and the
 * right repository is asked which lines changed.  The longest match wins: a
 * repository checked out inside another one is its own workspace. */
function rootFor(file) {
  let best = "";
  for (const root of roots) {
    if (!root) { continue; }
    if (file === root || file.startsWith(root + path.sep)) {
      if (root.length > best.length) { best = root; }
    }
  }
  return best;
}

function documentFor(uri) {
  const known = documents.get(uri);
  if (!known) { return null; }
  const file = fromUri(uri);
  return { uri: uri, path: file, root: rootFor(file), text: known.text };
}

function makeSession(raw) {
  const resolved = settingsOf.resolve(raw, process.env);
  if (session) { session.apply(resolved); return; }
  session = new Session({
    settings: resolved,
    report: ({ uri, diagnostics }) => {
      connection.notify("textDocument/publishDiagnostics", {
        uri: uri,
        /* The extra field the core carries for the editors that can use it is
         * dropped here: a diagnostic with something the protocol does not know
         * about in it is a diagnostic some clients refuse. */
        diagnostics: diagnostics.map((d) => ({
          range: d.range, severity: d.severity, code: d.code,
          source: d.source, message: d.message
        }))
      });
    },
    notify: (level, message) => {
      connection.notify("window/showMessage", {
        type: level === "error" ? 1 : level === "warning" ? 2 : 3,
        message: message
      });
    },
    log: (line) => connection.notify("window/logMessage", { type: 4, message: line })
  });
}

connection.on("initialize", (params) => {
  roots = [];
  if (Array.isArray(params.workspaceFolders)) {
    for (const folder of params.workspaceFolders) {
      const file = fromUri(folder.uri);
      if (file) { roots.push(file); }
    }
  }
  if (!roots.length && params.rootUri) {
    const file = fromUri(params.rootUri);
    if (file) { roots.push(file); }
  }
  if (!roots.length && params.rootPath) { roots.push(params.rootPath); }

  const given = params.initializationOptions || {};
  makeSession(given.gitCodeReview || given);

  return {
    capabilities: {
      /* Full text on every change.  A file this reviews is one somebody is
       * editing, incremental sync would buy a few kilobytes, and the whole
       * text is what goes to the server anyway. */
      textDocumentSync: { openClose: true, change: 1, save: { includeText: false } }
    },
    serverInfo: { name: "Git Code Review", version: VERSION }
  };
});

connection.on("initialized", () => {
  if (session && !session.api.configured) {
    connection.notify("window/logMessage", {
      type: 2,
      message: "Git Code Review has no server address or no token yet.  Set "
               + "GCR_SERVER and GCR_TOKEN, or send them in "
               + "initializationOptions.gitCodeReview."
    });
  }
});

connection.on("workspace/didChangeConfiguration", (params) => {
  const given = (params.settings || {}).gitCodeReview || params.settings || {};
  makeSession(given);
  /* Everything open is reviewed again against the new settings, because the
   * usual reason somebody changes them is that nothing was working. */
  for (const uri of documents.keys()) {
    const document = documentFor(uri);
    if (document) { session.review(document); }
  }
});

connection.on("textDocument/didOpen", (params) => {
  const item = params.textDocument || {};
  documents.set(item.uri, { text: String(item.text || "") });
  const document = documentFor(item.uri);
  if (document && session) { session.changed(document, "open"); }
});

connection.on("textDocument/didChange", (params) => {
  const item = params.textDocument || {};
  const changes = params.contentChanges || [];
  if (!changes.length) { return; }
  /* Full sync, so the last change carries the whole document. */
  const last = changes[changes.length - 1];
  documents.set(item.uri, { text: String(last.text || "") });
  const document = documentFor(item.uri);
  if (document && session) { session.changed(document, "type"); }
});

connection.on("textDocument/didSave", (params) => {
  const item = params.textDocument || {};
  if (typeof params.text === "string") {
    documents.set(item.uri, { text: params.text });
  }
  const document = documentFor(item.uri);
  if (document && session) { session.changed(document, "save"); }
});

connection.on("textDocument/didClose", (params) => {
  const item = params.textDocument || {};
  documents.delete(item.uri);
  if (session) { session.forget(item.uri); }
});

/* A client with no menu of its own can still ask for these by name. */
connection.on("workspace/executeCommand", async (params) => {
  const command = String(params.command || "");
  if (command === "gitCodeReview.check") {
    const result = await session.check();
    connection.notify("window/showMessage",
                      { type: result.ok ? 3 : 1, message: result.detail });
    return result;
  }
  if (command === "gitCodeReview.reviewFile") {
    const uri = (params.arguments || [])[0];
    const document = documentFor(String(uri || ""));
    if (document) { await session.review(document); }
    return null;
  }
  return null;
});

connection.on("shutdown", () => { shuttingDown = true; return null; });
connection.on("exit", () => { process.exit(shuttingDown ? 0 : 1); });

connection.listen();
