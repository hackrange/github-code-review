/* What the editor was told, made into something the rest of this can use.
 *
 * Three settings do the work everywhere - the address, the token, and whether
 * to look at the whole file or only what changed - and they are spelled the
 * same in every editor, because the page in the product that tells people how
 * to set this up spells them one way.
 *
 * The environment is read as well as the settings, because a language server
 * launched by Eclipse or by a JetBrains LSP client is usually configured by
 * environment variable rather than by a settings file it would have to invent.
 */
"use strict";

const REVIEW_ON = { save: true, type: true, manual: true };

function pick(...values) {
  for (const value of values) {
    if (value === undefined || value === null) { continue; }
    const text = String(value).trim();
    if (text !== "") { return text; }
  }
  return "";
}

function bool(value, fallback) {
  if (value === undefined || value === null || value === "") { return fallback; }
  if (typeof value === "boolean") { return value; }
  const text = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].indexOf(text) !== -1) { return true; }
  if (["0", "false", "no", "off"].indexOf(text) !== -1) { return false; }
  return fallback;
}

function resolve(raw, env) {
  const given = raw || {};
  const environment = env || {};
  const reviewOn = pick(given.reviewOn, environment.GCR_REVIEW_ON, "save");

  return {
    server: pick(given.server, environment.GCR_SERVER, environment.GCR_URL),
    token: pick(given.token, environment.GCR_TOKEN),
    /* save is the default rather than type.  A review runs semgrep on the
     * server, which is seconds rather than milliseconds, and one per keystroke
     * would be a denial of service somebody paid for. */
    reviewOn: REVIEW_ON[reviewOn] ? reviewOn : "save",
    changedLinesOnly: bool(given.changedLinesOnly,
                           bool(environment.GCR_CHANGED_LINES_ONLY, true)),
    only: pick(given.only, environment.GCR_ONLY, "secrets,code"),
    /* Long enough for semgrep on a large file, and short enough that a hung
     * server does not leave an editor waiting for ever. */
    timeoutMs: Number(pick(given.timeoutMs, environment.GCR_TIMEOUT_MS, "130000")),
    allowInsecureTls: bool(given.allowInsecureTls,
                           bool(environment.GCR_ALLOW_INSECURE_TLS, false)),
    /* A file bigger than this is not what somebody is editing; it is a build
     * artifact or a dump, and the server refuses it anyway. */
    maxFileBytes: Number(pick(given.maxFileBytes, environment.GCR_MAX_FILE_BYTES,
                              String(1024 * 1024))),
    debounceMs: Number(pick(given.debounceMs, environment.GCR_DEBOUNCE_MS, "1500"))
  };
}

/* What a workspace may decide, and what only the person may.
 *
 * A repository can carry editor settings, and opening it applies them.  So the
 * token and the switch that turns certificate checks off are read from the
 * person's own settings (or secret storage) only.  A workspace naming a server
 * other than the person's own is asked about once: send this workspace's code,
 * with the token, to that address?  The answer is remembered per workspace, as
 * "allow:<address>" or "deny:<address>", so the question comes back only if the
 * address changes.
 *
 * inspected is VS Code's inspect() for server, token and allowInsecureTls.
 * -> {server, token, allowInsecureTls, ask}, ask being the address to ask
 *    about, or "" when there is nothing to ask. */
function trusted(inspected, stored, decision) {
  const look = inspected || {};
  const user = (key) => (look[key] || {}).globalValue;
  const shared = (key) => pick((look[key] || {}).workspaceFolderValue,
                               (look[key] || {}).workspaceValue);
  const own = pick(user("server"));
  const asked = shared("server");
  let server = own;
  let ask = "";
  if (asked && asked !== own) {
    if (decision === "allow:" + asked) { server = asked; }
    else if (decision !== "deny:" + asked) { ask = asked; }
  }
  return {
    server,
    token: pick(user("token"), stored),
    allowInsecureTls: bool(user("allowInsecureTls"), false),
    ask
  };
}

/* Only these are sent anywhere.  A file the editor opened out of a jar, a
 * settings file, a git object - none of that is somebody's working tree. */
function reviewable(uriOrPath) {
  const text = String(uriOrPath || "");
  if (!text) { return false; }
  if (/^[a-z][a-z0-9+.-]*:/i.test(text) && !/^file:/i.test(text)) { return false; }
  return true;
}

module.exports = { resolve, reviewable, trusted };
