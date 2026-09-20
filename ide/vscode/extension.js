/* Visual Studio Code, and Cursor, which installs the same package.
 *
 * Everything that decides anything lives in ../core and is shared with the
 * language server the other editors drive.  What is here is the part that is
 * genuinely Visual Studio Code: its diagnostic collection, its secret storage
 * for the token, a status bar item, and the commands.
 *
 * It deliberately does not speak LSP to a child process.  The work is a couple
 * of HTTPS calls; spawning a second node process to relay JSON-RPC between two
 * halves of our own code would be a moving part with nothing to do.  The
 * editors that cannot load JavaScript of ours get the language server instead,
 * and both are this same core.
 */
"use strict";

const vscode = require("vscode");
const path = require("path");

/* The shared core sits beside this file in the package and one level up in
 * the repository it is built from.  Both are asked for rather than the build
 * rewriting an import on the way past, because a build step that edits source
 * is a build step somebody debugs at midnight. */
function core(name) {
  try {
    return require("./core/" + name);
  } catch (err) {
    return require("../core/" + name);
  }
}

const { Session } = core("session");
const settingsOf = core("settings");

/* The protocol counts severities from one and Visual Studio Code counts them
 * from zero, in the same order.  This is the only place that matters. */
const SEVERITY = {
  1: vscode.DiagnosticSeverity.Error,
  2: vscode.DiagnosticSeverity.Warning,
  3: vscode.DiagnosticSeverity.Information,
  4: vscode.DiagnosticSeverity.Hint
};

const TOKEN_KEY = "gitCodeReview.token";

function activate(context) {
  const output = vscode.window.createOutputChannel("Git Code Review");
  const collection = vscode.languages.createDiagnosticCollection("gitCodeReview");
  const status = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right, 100);
  status.command = "gitCodeReview.showOutput";
  context.subscriptions.push(output, collection, status);

  let session = null;
  const hidden = new Map();

  async function settings() {
    const config = vscode.workspace.getConfiguration("gitCodeReview");
    /* A token in settings.json wins, because somebody who put it there meant
     * it, but the secret storage is where the command puts it and where it
     * belongs: settings files get committed by accident. */
    const stored = await context.secrets.get(TOKEN_KEY);
    return settingsOf.resolve({
      server: config.get("server"),
      token: config.get("token") || stored || "",
      reviewOn: config.get("reviewOn"),
      changedLinesOnly: config.get("changedLinesOnly"),
      only: config.get("only"),
      allowInsecureTls: config.get("allowInsecureTls")
    }, process.env);
  }

  function show({ uri, diagnostics, summary, hidden: putAway }) {
    const target = vscode.Uri.parse(uri);
    collection.set(target, diagnostics.map((d) => {
      const made = new vscode.Diagnostic(
        new vscode.Range(d.range.start.line, d.range.start.character,
                         d.range.end.line, d.range.end.character),
        d.message,
        SEVERITY[d.severity] || vscode.DiagnosticSeverity.Warning);
      made.source = d.source;
      made.code = d.gcr && d.gcr.help
        ? { value: d.code, target: vscode.Uri.parse(d.gcr.help) }
        : d.code;
      /* Something the triage set aside is real but not this team's problem,
       * and an editor that strikes it through says that without a sentence. */
      if (d.gcr && d.gcr.aside) {
        made.tags = [vscode.DiagnosticTag.Unnecessary];
      }
      return made;
    }));
    hidden.set(uri, putAway || 0);
    paint(summary, putAway || 0, uri);
  }

  function paint(summary, putAway, uri) {
    const editor = vscode.window.activeTextEditor;
    if (!editor || (uri && editor.document.uri.toString() !== uri)) { return; }
    if (!summary) { status.hide(); return; }
    status.text = "$(shield) " + summary;
    status.tooltip = "Git Code Review"
      + (putAway ? "\n" + putAway + " more on lines you did not change" : "");
    status.show();
  }

  function documentOf(document) {
    const file = document.uri.scheme === "file" ? document.uri.fsPath : "";
    const folder = vscode.workspace.getWorkspaceFolder(document.uri);
    return {
      uri: document.uri.toString(),
      path: file || document.uri.toString(),
      root: folder ? folder.uri.fsPath : (file ? path.dirname(file) : ""),
      text: document.getText()
    };
  }

  /* Everything the editor has open that is a real file.  Untitled buffers and
   * the diff views an editor opens are not somebody's working tree.
   *
   * The session is part of the question: activate returns before the first
   * settings read has finished, and an editor firing didOpen in that window
   * would otherwise be a stack trace in somebody's log on every start. */
  function interesting(document) {
    return !!session && !!document && document.uri.scheme === "file";
  }

  async function reload() {
    const resolved = await settings();
    if (session) { session.apply(resolved); return session; }
    session = new Session({
      settings: resolved,
      report: show,
      notify: (level, message) => {
        if (level === "error") { vscode.window.showErrorMessage(message, "Show log")
          .then((choice) => { if (choice) { output.show(true); } }); }
        else { vscode.window.showWarningMessage(message); }
      },
      log: (line) => output.appendLine(stamp() + line)
    });
    return session;
  }

  function stamp() {
    return new Date().toISOString().replace("T", " ").slice(0, 19) + "  ";
  }

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((document) => {
      if (interesting(document)) { session.changed(documentOf(document), "open"); }
    }),
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (interesting(event.document)) {
        session.changed(documentOf(event.document), "type");
      }
    }),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (interesting(document)) { session.changed(documentOf(document), "save"); }
    }),
    vscode.workspace.onDidCloseTextDocument((document) => {
      if (!interesting(document)) { return; }
      const uri = document.uri.toString();
      hidden.delete(uri);
      session.forget(uri);
    }),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (!editor) { status.hide(); return; }
      const uri = editor.document.uri.toString();
      const found = collection.get(editor.document.uri) || [];
      const kept = found.filter(
        (d) => !(d.tags || []).includes(vscode.DiagnosticTag.Unnecessary));
      paint(kept.length ? kept.length + (kept.length === 1 ? " finding" : " findings")
                        : "nothing to fix",
            hidden.get(uri) || 0, uri);
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("gitCodeReview")) { reload(); }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("gitCodeReview.reviewFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) { vscode.window.showInformationMessage("Open a file first."); return; }
      await session.changed(documentOf(editor.document), "manual");
    }),

    vscode.commands.registerCommand("gitCodeReview.setToken", async () => {
      const token = await vscode.window.showInputBox({
        title: "Git Code Review token",
        prompt: "From the IDE tokens page of your Git Code Review server",
        password: true, ignoreFocusOut: true
      });
      if (token === undefined) { return; }
      if (token.trim() === "") { return; }
      await context.secrets.store(TOKEN_KEY, token.trim());
      await reload();
      const result = await session.check();
      vscode.window[result.ok ? "showInformationMessage" : "showErrorMessage"](
        result.detail);
    }),

    vscode.commands.registerCommand("gitCodeReview.forgetToken", async () => {
      await context.secrets.delete(TOKEN_KEY);
      await reload();
      vscode.window.showInformationMessage(
        "The token is gone from this editor.  It is still valid on the server "
        + "until you delete it there.");
    }),

    vscode.commands.registerCommand("gitCodeReview.check", async () => {
      await reload();
      const result = await session.check();
      output.appendLine(stamp() + result.detail);
      vscode.window[result.ok ? "showInformationMessage" : "showErrorMessage"](
        result.detail);
    }),

    vscode.commands.registerCommand("gitCodeReview.showOutput", () => output.show(true))
  );

  reload().then(async () => {
    if (!session.api.configured) {
      /* Said once, on the first start that is not set up, with the two things
       * that fix it rather than a sentence about a settings key. */
      const choice = await vscode.window.showInformationMessage(
        "Git Code Review needs the address of your server and a token.",
        "Set the token", "Open settings");
      if (choice === "Set the token") {
        vscode.commands.executeCommand("gitCodeReview.setToken");
      } else if (choice === "Open settings") {
        vscode.commands.executeCommand("workbench.action.openSettings",
                                       "gitCodeReview");
      }
      return;
    }
    const editor = vscode.window.activeTextEditor;
    if (editor && interesting(editor.document)) {
      session.changed(documentOf(editor.document), "open");
    }
  });
}

function deactivate() {}

module.exports = { activate, deactivate };
