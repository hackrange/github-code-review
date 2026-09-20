/* The editor side, driven the way an editor drives it.
 *
 * No network and no server: a stub answers /api/v1 in this process, and the
 * language server is started as a child process and spoken to over its pipes,
 * exactly as Eclipse or a JetBrains IDE would.  What is worth proving is that
 * the wire format is right, that the line and column arithmetic survives the
 * trip, that the token is sent and never printed, and that a file nobody
 * changed is not reviewed twice.
 */
"use strict";

const assert = require("assert");
const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const findings = require(path.join(ROOT, "core/findings"));
const { linesFromHunks, onlyChanged } = require(path.join(ROOT, "core/changed"));
const { normalizeServer } = require(path.join(ROOT, "core/api"));
const settingsOf = require(path.join(ROOT, "core/settings"));

let OK = 0, FAIL = 0;
function check(what, fn) {
  try { fn(); process.stdout.write("  \x1b[32mPASS\x1b[0m " + what + "\n"); OK += 1; }
  catch (err) {
    process.stdout.write("  \x1b[31mFAIL\x1b[0m " + what + ": " + err.message + "\n");
    FAIL += 1;
  }
}

/* ---- the address, however it was pasted ---------------------------------- */
console.log("== whatever they paste, one address comes out ==");
check("the address from the page is left alone", () =>
  assert.strictEqual(normalizeServer("https://gcr.example.com/api/v1"),
                     "https://gcr.example.com/api/v1"));
check("a bare host gets the api path", () =>
  assert.strictEqual(normalizeServer("gcr.example.com"),
                     "https://gcr.example.com/api/v1"));
check("a trailing slash comes off", () =>
  assert.strictEqual(normalizeServer("https://gcr.example.com/api/v1/"),
                     "https://gcr.example.com/api/v1"));
check("and an endpoint somebody tried in a browser is cut back", () =>
  assert.strictEqual(normalizeServer("https://gcr.example.com/api/v1/ping"),
                     "https://gcr.example.com/api/v1"));

/* ---- settings ------------------------------------------------------------ */
console.log("\n== the settings mean the same thing in every editor ==");
check("save is the default, not every keystroke", () =>
  assert.strictEqual(settingsOf.resolve({}, {}).reviewOn, "save"));
check("only what they changed is the default", () =>
  assert.strictEqual(settingsOf.resolve({}, {}).changedLinesOnly, true));
check("the environment configures a server nobody has a settings file for", () => {
  const resolved = settingsOf.resolve({}, { GCR_SERVER: "https://x/api/v1",
                                            GCR_TOKEN: "t" });
  assert.strictEqual(resolved.server, "https://x/api/v1");
  assert.strictEqual(resolved.token, "t");
});
check("and a setting wins over the environment", () =>
  assert.strictEqual(settingsOf.resolve({ server: "https://a" },
                                        { GCR_SERVER: "https://b" }).server,
                     "https://a"));
check("a file inside a jar is not somebody's working tree", () =>
  assert.strictEqual(settingsOf.reviewable("jar:file:///x.jar!/A.java"), false));

/* ---- the arithmetic nobody notices getting wrong -------------------------- */
console.log("\n== lines and columns survive the trip ==");
const credential = {
  kind: "credential", file: "app/config.py", line: 12,
  start_column: 11, end_column: 51, rule: "aws-access-key",
  severity: "critical", title: "AWS access key", message: "a live looking key",
  preview: "AWS1****WXYZ"
};
check("line 12 becomes row 11, because the protocol counts from zero", () =>
  assert.strictEqual(findings.toDiagnostic(credential, "x".repeat(60)).range.start.line, 11));
check("and column 11 becomes character 10", () =>
  assert.strictEqual(findings.toDiagnostic(credential, "x".repeat(60)).range.start.character, 10));
check("the end column is carried, so it underlines the value and not the line", () =>
  assert.strictEqual(findings.toDiagnostic(credential, "x".repeat(60)).range.end.character, 50));
check("a finding with no columns underlines the whole line", () => {
  const range = findings.toDiagnostic(
    { line: 3, severity: "medium", title: "x" }, "abcdefgh").range;
  assert.strictEqual(range.start.character, 0);
  assert.strictEqual(range.end.character, 8);
});
check("a credential is an error whatever its severity says", () =>
  assert.strictEqual(findings.toDiagnostic(
    { kind: "credential", line: 1, severity: "low" }).severity, findings.ERROR));
check("and the redacted value is what is shown, never the value", () => {
  const message = findings.toDiagnostic(credential, "").message;
  assert.ok(message.indexOf("AWS1****WXYZ") !== -1, "the mask is shown");
  assert.ok(message.indexOf("AWS access key") !== -1, "and what it is");
});
check("the triage reason travels with the finding, which is the point of ours", () => {
  const message = findings.toDiagnostic(
    { line: 1, title: "SQL injection", triage_reason: "the value is a literal" }).message;
  assert.ok(message.indexOf("the value is a literal") !== -1);
});
check("something the triage set aside is shown quietly rather than hidden", () => {
  const diagnostic = findings.toDiagnostic(
    { line: 1, severity: "high", title: "x", triage: { verdict: "not_applicable" } });
  assert.strictEqual(diagnostic.severity, findings.HINT);
  assert.strictEqual(diagnostic.gcr.aside, true);
});

/* ---- only what they touched ---------------------------------------------- */
console.log("\n== only the lines this person changed ==");
check("a diff with no context names exactly the changed lines", () => {
  const lines = linesFromHunks("@@ -1,0 +12,3 @@\n@@ -20 +30 @@\n");
  assert.deepStrictEqual([...lines].sort((a, b) => a - b), [12, 13, 14, 30]);
});
check("findings on other lines are put away, and counted", () => {
  const diagnostics = [11, 29, 40].map((row) =>
    ({ range: { start: { line: row } }, gcr: {} }));
  const result = onlyChanged(diagnostics, new Set([12, 30]));
  assert.strictEqual(result.kept.length, 2);
  assert.strictEqual(result.hidden, 1);
});
check("and when git cannot answer, everything is shown rather than nothing", () => {
  const diagnostics = [{ range: { start: { line: 1 } }, gcr: {} }];
  assert.strictEqual(onlyChanged(diagnostics, null).kept.length, 1);
});

/* ---- the server, over a real pipe ---------------------------------------- */
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "gcr-ide-"));
fs.mkdirSync(path.join(workspace, "app"), { recursive: true });
const file = path.join(workspace, "app", "config.py");
fs.writeFileSync(file, "import os\nKEY = \"not-a-real-value-0001\"\n");

const seen = { authorization: "", body: null, reviews: 0,
               scopes: ["review", "rules"] };
const stub = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    seen.authorization = req.headers.authorization || "";
    if (req.url === "/api/v1/ping") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, user: "tester", scopes: seen.scopes }));
      return;
    }
    if (req.url === "/api/v1/review") {
      seen.reviews += 1;
      seen.body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        generator: "ghscan test",
        findings: [{
          kind: "credential", file: seen.body.files[0].path, line: 2,
          start_column: 7, end_column: 29, rule: "aws-access-key",
          severity: "critical", title: "AWS access key",
          message: "committed credential", preview: "not-****-0001"
        }],
        counts: { total: 1, credential: 1, code: 0, misconfiguration: 0 }
      }));
      return;
    }
    res.writeHead(404); res.end("{}");
  });
});

function lsp(child) {
  /* The client half of the framing, so the test reads what a real editor
   * would read rather than what the server meant to send. */
  let buffer = Buffer.alloc(0);
  const waiting = [];
  child.stdout.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const end = buffer.indexOf("\r\n\r\n");
      if (end === -1) { return; }
      const match = buffer.slice(0, end).toString("ascii").match(/Content-Length: (\d+)/i);
      if (!match) { buffer = buffer.slice(end + 4); continue; }
      const length = parseInt(match[1], 10);
      if (buffer.length < end + 4 + length) { return; }
      const body = buffer.slice(end + 4, end + 4 + length).toString("utf8");
      buffer = buffer.slice(end + 4 + length);
      const message = JSON.parse(body);
      for (let i = waiting.length - 1; i >= 0; i -= 1) {
        if (waiting[i].match(message)) { waiting.splice(i, 1)[0].resolve(message); }
      }
    }
  });
  return {
    send(message) {
      const body = Buffer.from(JSON.stringify(
        Object.assign({ jsonrpc: "2.0" }, message)), "utf8");
      child.stdin.write("Content-Length: " + body.length + "\r\n\r\n");
      child.stdin.write(body);
    },
    wait(match, what) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("nothing matched " + what + " in time")), 15000);
        waiting.push({ match: match,
                       resolve: (m) => { clearTimeout(timer); resolve(m); } });
      });
    }
  };
}

async function main() {
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
  const port = stub.address().port;

  const child = spawn(process.execPath, [path.join(ROOT, "server/main.js")], {
    env: Object.assign({}, process.env, {
      GCR_SERVER: "http://127.0.0.1:" + port + "/api/v1",
      GCR_TOKEN: "test-token-value",
      GCR_CHANGED_LINES_ONLY: "0"
    }),
    stdio: ["pipe", "pipe", "pipe"]
  });
  const errors = [];
  child.stderr.on("data", (chunk) => errors.push(String(chunk)));

  const client = lsp(child);
  console.log("\n== the language server, over its own pipe ==");

  client.send({ id: 1, method: "initialize",
                params: { processId: process.pid,
                          rootUri: "file://" + workspace,
                          capabilities: {} } });
  const initialized = await client.wait((m) => m.id === 1, "the initialize answer");
  check("it answers initialize with what it can do", () => {
    assert.ok(initialized.result.capabilities.textDocumentSync.openClose);
    assert.strictEqual(initialized.result.serverInfo.name, "Git Code Review");
  });

  client.send({ method: "initialized", params: {} });
  const uri = "file://" + file;
  client.send({ method: "textDocument/didOpen", params: { textDocument: {
    uri: uri, languageId: "python", version: 1,
    text: fs.readFileSync(file, "utf8") } } });

  const published = await client.wait(
    (m) => m.method === "textDocument/publishDiagnostics"
           && m.params.diagnostics.length > 0, "diagnostics");

  check("a credential in an opened file comes back as a diagnostic", () => {
    assert.strictEqual(published.params.uri, uri);
    assert.strictEqual(published.params.diagnostics.length, 1);
  });
  check("on the right line, counted the way the protocol counts", () =>
    assert.strictEqual(published.params.diagnostics[0].range.start.line, 1));
  check("underlining the value rather than the whole line", () => {
    assert.strictEqual(published.params.diagnostics[0].range.start.character, 6);
    assert.strictEqual(published.params.diagnostics[0].range.end.character, 28);
  });
  check("in red, because a live key is not a suggestion", () =>
    assert.strictEqual(published.params.diagnostics[0].severity, 1));
  check("and nothing the protocol does not know about is sent", () =>
    assert.deepStrictEqual(
      Object.keys(published.params.diagnostics[0]).sort(),
      ["code", "message", "range", "severity", "source"]));

  check("the token went in the header", () =>
    assert.strictEqual(seen.authorization, "Bearer test-token-value"));
  check("the path was sent relative to the workspace, not from the home directory", () =>
    assert.strictEqual(seen.body.files[0].path, "app/config.py"));
  check("and the file went as it is on the disk", () =>
    assert.ok(seen.body.files[0].content.indexOf("not-a-real-value-0001") !== -1));

  /* Saving a file nobody edited is the commonest event an editor sends, and
   * reviewing it again is a semgrep run somebody pays for. */
  const before = seen.reviews;
  client.send({ method: "textDocument/didSave", params: { textDocument: { uri: uri } } });
  await new Promise((resolve) => setTimeout(resolve, 600));
  check("saving unchanged text does not review it again", () =>
    assert.strictEqual(seen.reviews, before));

  client.send({ method: "textDocument/didChange", params: {
    textDocument: { uri: uri, version: 2 },
    contentChanges: [{ text: "import os\nKEY = os.environ['KEY']\n" }] } });
  client.send({ method: "textDocument/didSave", params: { textDocument: { uri: uri } } });
  await client.wait((m) => m.method === "textDocument/publishDiagnostics", "the second answer");
  check("but changed text is", () => assert.ok(seen.reviews > before));

  client.send({ method: "textDocument/didClose", params: { textDocument: { uri: uri } } });
  const cleared = await client.wait(
    (m) => m.method === "textDocument/publishDiagnostics"
           && m.params.diagnostics.length === 0, "the diagnostics being cleared");
  check("closing a file clears what it was showing", () =>
    assert.strictEqual(cleared.params.diagnostics.length, 0));

  check("and the token was never written to stderr", () =>
    assert.strictEqual(errors.join("").indexOf("test-token-value"), -1));

  /* A token made with only one of the two permissions answers /ping and then
   * fails on the first save, which reads like a broken server rather than a
   * token made in a hurry. */
  console.log("\n== a token that cannot do the job says so ==");
  const { Session } = require(path.join(ROOT, "core/session"));
  const settings = settingsOf.resolve(
    { server: "http://127.0.0.1:" + port + "/api/v1", token: "t" }, {});
  const session = new Session({ settings: settings });

  seen.scopes = ["review", "rules"];
  let result = await session.check();
  check("a token with both permissions checks out", () =>
    assert.ok(result.ok, result.detail));

  seen.scopes = ["rules"];
  result = await session.check();
  check("one with only rules is refused, and told which to tick", () => {
    assert.strictEqual(result.ok, false);
    assert.ok(/review and rules/.test(result.detail), result.detail);
  });
  seen.scopes = ["review", "rules"];

  client.send({ id: 99, method: "shutdown", params: {} });
  await client.wait((m) => m.id === 99, "shutdown");
  client.send({ method: "exit", params: {} });
  child.kill();
  stub.close();
  fs.rmSync(workspace, { recursive: true, force: true });

  console.log("\n  \x1b[1m" + OK + " passed, " + FAIL + " failed\x1b[0m\n");
  process.exit(FAIL === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("the test itself fell over: " + (err && err.stack || err));
  process.exit(1);
});
