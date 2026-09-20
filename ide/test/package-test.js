/* The package as a developer receives it, not as it sits in the repository.
 *
 * The .vsix is unpacked by the shell script that runs this, and the extension
 * is loaded out of that directory with a stub in place of the editor's own
 * API.  What this catches is everything that only goes wrong once the files
 * have moved: the shared core sitting somewhere else in the package than in
 * the source tree, a file left out of the zip, a manifest naming an entry
 * point that is not there.
 */
"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const unpacked = process.argv[2];
if (!unpacked) {
  console.error("usage: node package-test.js <unpacked extension directory>");
  process.exit(2);
}

let OK = 0, FAIL = 0;
function check(what, fn) {
  try { fn(); process.stdout.write("  \x1b[32mPASS\x1b[0m " + what + "\n"); OK += 1; }
  catch (err) {
    process.stdout.write("  \x1b[31mFAIL\x1b[0m " + what + ": " + err.message + "\n");
    FAIL += 1;
  }
}

console.log("== the package has what it says it has ==");
const manifest = JSON.parse(
  fs.readFileSync(path.join(unpacked, "package.json"), "utf8"));

check("the entry point named in the manifest is in the package", () =>
  assert.ok(fs.existsSync(path.join(unpacked, manifest.main))));
check("and the shared core came with it", () =>
  assert.ok(fs.existsSync(path.join(unpacked, "core", "session.js"))));
check("and the license", () =>
  assert.ok(fs.existsSync(path.join(unpacked, "LICENSE"))));
check("nothing needs installing", () =>
  assert.deepStrictEqual(manifest.dependencies || {}, {}));
check("the settings are the ones the server's own page tells people to set", () => {
  const properties = manifest.contributes.configuration.properties;
  for (const key of ["gitCodeReview.server", "gitCodeReview.token",
                     "gitCodeReview.reviewOn", "gitCodeReview.changedLinesOnly"]) {
    assert.ok(properties[key], key + " is missing from the manifest");
  }
});
check("and an untrusted workspace is refused, because the file is sent away", () =>
  assert.strictEqual(manifest.capabilities.untrustedWorkspaces.supported, false));

console.log("\n== it loads, with the editor stubbed out ==");
const said = [];
const registered = [];
const stub = {
  StatusBarAlignment: { Right: 2 },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  DiagnosticTag: { Unnecessary: 1 },
  Range: class { constructor(a, b, c, d) { Object.assign(this, { a, b, c, d }); } },
  Diagnostic: class { constructor(range, message, severity) {
    Object.assign(this, { range, message, severity }); } },
  Uri: { parse: (value) => ({ toString: () => value, fsPath: value }) },
  window: {
    createOutputChannel: () => ({ appendLine() {}, show() {} }),
    createStatusBarItem: () => ({ show() {}, hide() {}, dispose() {} }),
    showInformationMessage: (message) => { said.push(message); return Promise.resolve(); },
    showWarningMessage: (message) => { said.push(message); return Promise.resolve(); },
    showErrorMessage: (message) => { said.push(message); return Promise.resolve(); },
    showInputBox: () => Promise.resolve(undefined),
    onDidChangeActiveTextEditor: () => ({ dispose() {} }),
    activeTextEditor: null
  },
  languages: { createDiagnosticCollection: () => ({ set() {}, get: () => [], dispose() {} }) },
  workspace: {
    getConfiguration: () => ({ get: () => "" }),
    getWorkspaceFolder: () => null,
    onDidOpenTextDocument: () => ({ dispose() {} }),
    onDidChangeTextDocument: () => ({ dispose() {} }),
    onDidSaveTextDocument: () => ({ dispose() {} }),
    onDidCloseTextDocument: () => ({ dispose() {} }),
    onDidChangeConfiguration: () => ({ dispose() {} })
  },
  commands: {
    registerCommand: (name) => { registered.push(name); return { dispose() {} }; },
    executeCommand: () => Promise.resolve()
  }
};

/* Put the stub where require("vscode") will find it, beside the package. */
const stubDir = path.join(unpacked, "..", "node_modules", "vscode");
fs.mkdirSync(stubDir, { recursive: true });
fs.writeFileSync(path.join(stubDir, "package.json"),
                 JSON.stringify({ name: "vscode", main: "index.js" }));
fs.writeFileSync(path.join(stubDir, "index.js"),
                 "module.exports = global.__vscodeStub;");
global.__vscodeStub = stub;

const extension = require(path.join(unpacked, manifest.main));

check("it exports what the editor calls", () => {
  assert.strictEqual(typeof extension.activate, "function");
  assert.strictEqual(typeof extension.deactivate, "function");
});

const subscriptions = [];
extension.activate({
  subscriptions: subscriptions,
  secrets: { get: () => Promise.resolve(""), store: () => Promise.resolve(),
             delete: () => Promise.resolve() }
});

check("every command the manifest promises is actually registered", () => {
  for (const entry of manifest.contributes.commands) {
    assert.ok(registered.indexOf(entry.command) !== -1,
              entry.command + " is in the manifest and not in the code");
  }
});
check("and it cleans up after itself", () =>
  assert.ok(subscriptions.length > 0));

setTimeout(() => {
  check("with nothing configured it says so, rather than failing quietly", () =>
    assert.ok(said.some((line) => /server and a token/i.test(line)),
              "said: " + JSON.stringify(said)));
  console.log("\n  \x1b[1m" + OK + " passed, " + FAIL + " failed\x1b[0m\n");
  process.exit(FAIL === 0 ? 0 : 1);
}, 200);
