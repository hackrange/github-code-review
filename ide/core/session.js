/* The part that decides when to ask the server, and what to do with the answer.
 *
 * Both front ends - the language server that Eclipse and the JetBrains IDEs
 * drive, and the Visual Studio Code extension - are wrappers around this.  A
 * feature written here appears in every editor at once, which is the whole
 * argument for having a shared core rather than four plugins.
 *
 * Three rules hold it together.
 *
 * One review per document at a time.  A save during a review does not start a
 * second one; it is remembered and run when the first finishes, so a slow
 * server produces a queue of one rather than a queue of forty.
 *
 * The same text is never reviewed twice.  Editors send didSave for files
 * nobody touched, and formatting on save sends a change and a save together.
 *
 * A failure is said once.  A wrong token fails on every keystroke, and an
 * editor that says so every time is an editor somebody turns off.
 */
"use strict";

const path = require("path");

const { Api, ApiError } = require("./api");
const findings = require("./findings");
const { changedLines, onlyChanged } = require("./changed");
const { reviewable } = require("./settings");

function hash(text) {
  /* Not a security decision: this only answers "is this the same text as last
   * time", so the cheapest thing that is stable will do. */
  let h = 5381;
  for (let i = 0; i < text.length; i += 1) {
    h = ((h << 5) + h + text.charCodeAt(i)) | 0;
  }
  return String(h) + ":" + text.length;
}

class Session {
  /* report({uri, diagnostics, summary, hidden}) publishes to the editor.
   * notify(level, message) says something out loud, once per distinct thing.
   * log(line) writes to the editor's output pane. */
  constructor({ settings, report, notify, log }) {
    this.report = report || (() => {});
    this.notify = notify || (() => {});
    this.log = log || (() => {});
    this.state = new Map();
    this.said = new Set();
    this.apply(settings);
  }

  apply(settings) {
    this.settings = settings;
    this.api = new Api({
      server: settings.server,
      token: settings.token,
      timeoutMs: settings.timeoutMs,
      allowInsecureTls: settings.allowInsecureTls
    });
    /* New settings are a new chance for something that was failing to work, so
     * anything already said is said again if it happens again. */
    this.said.clear();
  }

  entry(uri) {
    if (!this.state.has(uri)) {
      this.state.set(uri, { running: false, pending: null, lastHash: "", timer: null });
    }
    return this.state.get(uri);
  }

  forget(uri) {
    const entry = this.state.get(uri);
    if (entry && entry.timer) { clearTimeout(entry.timer); }
    this.state.delete(uri);
    this.report({ uri: uri, diagnostics: [], summary: "", hidden: 0 });
  }

  /* Something happened to a document.  Whether it leads to a review depends on
   * what the person asked for: on save, as they type, or only when asked.
   *
   * Opening a file is the exception and always reviews it, whatever reviewOn
   * says.  reviewOn answers "how often, while I work", and somebody who opens
   * a file and sees nothing reasonably concludes the thing is not running -
   * which is the same conclusion they would reach if it were broken. */
  changed(document, why) {
    const on = this.settings.reviewOn;
    if (why === "manual") { return this.review(document); }
    if (on === "manual") { return Promise.resolve(); }
    if (why === "open") { return this.review(document); }
    if (on === "save" && why !== "save") { return Promise.resolve(); }

    if (why === "type") {
      const entry = this.entry(document.uri);
      if (entry.timer) { clearTimeout(entry.timer); }
      return new Promise((resolve) => {
        entry.timer = setTimeout(() => {
          entry.timer = null;
          this.review(document).then(resolve, resolve);
        }, Math.max(200, this.settings.debounceMs));
      });
    }
    return this.review(document);
  }

  async review(document) {
    const uri = document.uri;
    if (!reviewable(uri)) { return; }
    if (!this.api.configured) {
      this.once("config", "warning",
                "Git Code Review is not set up yet: it needs the server address "
                + "and a token from the IDE tokens page.");
      return;
    }

    const entry = this.entry(uri);
    if (entry.running) { entry.pending = document; return; }

    const text = String(document.text || "");
    const size = Buffer.byteLength(text, "utf8");
    if (size === 0) { this.report({ uri, diagnostics: [], summary: "", hidden: 0 }); return; }
    if (size > this.settings.maxFileBytes) {
      this.log(document.path + " is " + Math.round(size / 1024)
               + " KB, which is past the limit, so it was not sent.");
      this.report({ uri: uri, diagnostics: [], summary: "too large to review",
                    hidden: 0 });
      return;
    }

    const fingerprint = hash(text);
    if (fingerprint === entry.lastHash) { return; }

    entry.running = true;
    const started = Date.now();
    try {
      /* The path is sent relative to the workspace, never the absolute one.
       * A rule can match on a path, and "is this under tests/" is the question
       * the triage asks; /home/someone/work is nobody's business and it goes
       * into the server's log if it is sent. */
      const relative = relativePath(document);
      const result = await this.api.review(
        [{ path: relative, content: text }], this.settings.only);

      entry.lastHash = fingerprint;
      const lines = text.split(/\r?\n/);
      let diagnostics = findings.toDiagnostics(
        (result && result.findings) || [], lines);

      let hidden = 0;
      if (this.settings.changedLinesOnly && document.root) {
        const changed = await changedLines(document.root, document.path);
        const filtered = onlyChanged(diagnostics, changed);
        diagnostics = filtered.kept;
        hidden = filtered.hidden;
      }

      this.log(relative + ": " + findings.summarize(diagnostics)
               + (hidden ? ", " + hidden + " on lines you did not change" : "")
               + " (" + (Date.now() - started) + " ms)");
      this.report({ uri: uri, diagnostics: diagnostics,
                    summary: findings.summarize(diagnostics), hidden: hidden });
      this.said.delete("review");
    } catch (err) {
      /* The last good diagnostics are left where they are.  Clearing them
       * because the network blinked would tell somebody their file is clean. */
      const message = err instanceof ApiError ? err.message : String(err);
      this.log("review failed: " + message);
      this.once(err instanceof ApiError ? err.kind : "review", "error",
                "Git Code Review: " + message);
    } finally {
      entry.running = false;
      const queued = entry.pending;
      entry.pending = null;
      if (queued) { this.review(queued); }
    }
  }

  /* Say a thing once.  The same failure on the next keystroke is the same
   * failure, and the output pane already has every one of them. */
  once(key, level, message) {
    if (this.said.has(key)) { return; }
    this.said.add(key);
    this.notify(level, message);
  }

  /* Does the address answer, and does the token work?  Used by the command
   * people run when it is not working, which is the moment they want the
   * server's own words rather than a guess. */
  async check() {
    if (!this.settings.server) { return { ok: false, detail: "No server address is set." }; }
    if (!this.settings.token) { return { ok: false, detail: "No token is set." }; }
    try {
      const body = await this.api.ping();
      const who = (body && (body.user || body.username)) || "";
      /* A token can answer this and still be unable to do the one thing this
       * is for.  /ping needs the rules permission and a review needs its own,
       * so a token with only one of them connects perfectly and then fails on
       * the first save with something that reads like a broken server. */
      const scopes = (body && body.scopes) || [];
      if (scopes.length && scopes.indexOf("review") === -1) {
        return { ok: false,
                 detail: "Connected as " + (who || "you") + ", but this token "
                         + "cannot ask for a review.  Make one on the IDE "
                         + "tokens page with both review and rules ticked." };
      }
      return { ok: true, detail: "Connected to " + this.api.server
                                 + (who ? " as " + who : "") + "." };
    } catch (err) {
      const message = err instanceof ApiError ? err.message : String(err);
      /* A secure connection that will not start is the one failure worth a
       * second question, because the commonest cause has a one line fix and
       * the message cannot tell on its own. */
      if (err instanceof ApiError && err.kind === "tls") {
        const plain = await this.api.plainHttpAnswers();
        if (plain) {
          return { ok: false,
                   detail: "That server answers on plain http, not https.  "
                           + "Change gitCodeReview.server to "
                           + this.api.server.replace(/^https:/i, "http:")
                           + " and check again.  Anything you edit then "
                           + "travels unencrypted, so it wants a network you "
                           + "trust, or a certificate on the server." };
        }
      }
      return { ok: false, detail: message };
    }
  }
}

function relativePath(document) {
  if (!document.path) { return "file.txt"; }
  if (!document.root) { return path.basename(document.path); }
  const relative = path.relative(document.root, document.path);
  if (!relative || relative.startsWith("..")) { return path.basename(document.path); }
  return relative.split(path.sep).join("/");
}

module.exports = { Session, relativePath };
