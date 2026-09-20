/* The client for /api/v1, and nothing else.
 *
 * No dependencies, on purpose.  This is a security product: an editor
 * extension of ours that pulls three hundred packages off a registry to make
 * an HTTP request would be arguing against the thing it is selling.  Node's
 * own http and https modules do all of it.
 *
 * Three calls matter.  ping says whether the address and the token are any
 * good, rules says what this installation treats as noise, and review sends a
 * file and gets findings back.  Nothing here writes anything: the API has no
 * endpoint that changes the estate, so the worst a stolen token does is read
 * the rules and spend some of the server's CPU.
 */
"use strict";

const http = require("http");
const https = require("https");
const { URL } = require("url");

const USER_AGENT = "git-code-review-editor";

class ApiError extends Error {
  constructor(message, { status = 0, kind = "" } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    /* What sort of wrong it is, so a caller can decide whether to say it out
     * loud again.  A bad token is worth one message and not one per keystroke. */
    this.kind = kind || (status === 401 ? "auth" : status ? "http" : "network");
  }
}

/* Whatever somebody pasted, turned into the address the calls go to.
 *
 * The page they copied it from shows https://host/api/v1, but people paste the
 * address of the site they were just looking at, with or without a trailing
 * slash, and sometimes with the path of the page they were on.  All of that is
 * the same intent. */
function normalizeServer(raw) {
  let text = String(raw || "").trim();
  if (!text) { return ""; }
  if (!/^https?:\/\//i.test(text)) { text = "https://" + text.replace(/^\/+/, ""); }
  text = text.replace(/\/+$/, "");
  const match = text.match(/^(.*?\/api\/v\d+)(\/.*)?$/);
  if (match) { return match[1]; }
  return text + "/api/v1";
}

class Api {
  constructor({ server, token, timeoutMs = 130000, allowInsecureTls = false } = {}) {
    this.server = normalizeServer(server);
    this.token = String(token || "").trim();
    this.timeoutMs = timeoutMs;
    this.allowInsecureTls = !!allowInsecureTls;
    /* The rules change about once a month and are asked for on every start, so
     * the answer is kept with its ETag and re-asked rather than re-sent. */
    this._rulesEtag = "";
    this._rules = null;
  }

  get configured() { return !!(this.server && this.token); }

  request(path, { method = "GET", body = null, headers = {} } = {}) {
    return new Promise((resolve, reject) => {
      if (!this.server) {
        reject(new ApiError("No server address is set.", { kind: "config" }));
        return;
      }
      if (!this.token) {
        reject(new ApiError("No token is set.", { kind: "config" }));
        return;
      }

      let target;
      try {
        target = new URL(this.server + path);
      } catch (err) {
        reject(new ApiError("That server address is not a URL.", { kind: "config" }));
        return;
      }

      const payload = body === null ? null : Buffer.from(JSON.stringify(body), "utf8");
      const secure = target.protocol === "https:";
      const options = {
        method: method,
        hostname: target.hostname,
        port: target.port || (secure ? 443 : 80),
        path: target.pathname + target.search,
        headers: Object.assign({
          /* The token goes in a header and is never written to a log, an error
           * message or a URL.  A URL ends up in proxy logs and in somebody's
           * shell history. */
          "Authorization": "Bearer " + this.token,
          "Accept": "application/json",
          "User-Agent": USER_AGENT
        }, headers)
      };
      if (payload) {
        options.headers["Content-Type"] = "application/json";
        options.headers["Content-Length"] = payload.length;
      }
      if (secure && this.allowInsecureTls) { options.rejectUnauthorized = false; }

      const call = (secure ? https : http).request(options, (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          resolve({ status: response.statusCode || 0,
                    headers: response.headers, text: text });
        });
      });

      call.setTimeout(this.timeoutMs, () => {
        call.destroy(new ApiError("The server did not answer in time.",
                                  { kind: "timeout" }));
      });
      call.on("error", (err) => reject(explain(err, target)));
      if (payload) { call.write(payload); }
      call.end();
    });
  }

  async json(path, options) {
    const response = await this.request(path, options);
    if (response.status === 304) { return null; }
    if (response.status < 200 || response.status >= 300) {
      throw new ApiError(detail(response), { status: response.status });
    }
    try {
      return JSON.parse(response.text);
    } catch (err) {
      throw new ApiError("The server sent something that is not JSON.",
                         { status: response.status, kind: "protocol" });
    }
  }

  ping() { return this.json("/ping"); }

  /* Does this same address answer over plain http?
   *
   * Asked only after a secure connection has already failed, to tell "your
   * server is not using TLS" apart from "your server's certificate is wrong".
   * Deliberately sends no token: an answer here means the connection is
   * cleartext, and a credential must never be the thing that finds that out.
   * A 401 is the answer being looked for, because it is this API saying no
   * rather than something else saying anything.
   */
  plainHttpAnswers() {
    return new Promise((resolve) => {
      let target;
      try {
        target = new URL(this.server.replace(/^https:/i, "http:") + "/ping");
      } catch (err) {
        resolve(false);
        return;
      }
      if (target.protocol !== "http:") { resolve(false); return; }
      const call = http.request({
        method: "GET",
        hostname: target.hostname,
        port: target.port || 80,
        path: target.pathname + target.search,
        headers: { "Accept": "application/json", "User-Agent": USER_AGENT }
      }, (response) => {
        response.resume();
        resolve(response.statusCode === 401 || response.statusCode === 200);
      });
      call.setTimeout(5000, () => { call.destroy(); resolve(false); });
      call.on("error", () => resolve(false));
      call.end();
    });
  }

  /* The triage rules, exclusions and muted rules this installation uses.
   *
   * Kept so the editor can agree with the server about what is noise even
   * between reviews, and asked for with the ETag so the usual answer is 304
   * and nothing on the wire. */
  async rules() {
    const headers = this._rulesEtag ? { "If-None-Match": this._rulesEtag } : {};
    const response = await this.request("/rules", { headers: headers });
    if (response.status === 304 && this._rules) { return this._rules; }
    if (response.status < 200 || response.status >= 300) {
      throw new ApiError(detail(response), { status: response.status });
    }
    this._rulesEtag = String(response.headers.etag || "");
    this._rules = JSON.parse(response.text);
    return this._rules;
  }

  /* Send files, get findings.  The server writes them to a temporary directory,
   * looks at them and deletes them; nothing is stored and no finding is
   * created, which is why this is safe to call on every save. */
  review(files, only) {
    return this.json("/review", {
      method: "POST",
      body: { files: files, only: only || "secrets,code" }
    });
  }
}

/* The body of a refusal, as one sentence somebody can act on. */
function detail(response) {
  let said = "";
  try {
    const body = JSON.parse(response.text);
    said = String(body.detail || body.message || "").trim();
  } catch (err) { said = ""; }
  switch (response.status) {
    case 401:
      /* Four different things arrive as one 401, on purpose: the server will
       * not say which, because telling a caller apart helps somebody working
       * through a list of guesses.  So the message names all four. */
      return "The token was refused.  It has expired, been revoked, was typed "
             + "wrong, or was made without both the review and rules "
             + "permissions.";
    case 403:
      return said || "That token is not allowed to do this.";
    case 404:
      return "No API at that address.  Check the server setting: it ends in /api/v1.";
    case 413:
      return said || "That file is larger than the server will look at.";
    case 429:
      return said || "Too many requests.  Wait a moment.";
    case 504:
      return said || "The review took too long and the server stopped it.";
    default:
      return said || ("The server answered " + response.status + ".");
  }
}

/* A transport failure, said in terms of what to do about it rather than in
 * terms of the error code Node happens to use. */
function explain(err, target) {
  if (err instanceof ApiError) { return err; }
  const code = String(err && err.code || "");
  const where = target ? target.host : "the server";
  if (code === "ECONNREFUSED") {
    return new ApiError("Nothing is listening at " + where + ".", { kind: "network" });
  }
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return new ApiError("Cannot find " + where + ".  Check the address, and "
                        + "whether this machine is on that network.",
                        { kind: "network" });
  }
  if (code === "ETIMEDOUT" || code === "ECONNRESET") {
    return new ApiError("The connection to " + where + " did not hold.",
                        { kind: "network" });
  }
  /* The handshake itself failed, before any certificate was judged.
   *
   * The editor runs on BoringSSL and prints a line of C++ file names and an
   * alert number, which tells somebody who already knows TLS what happened and
   * tells everybody else nothing at all.  There are only three causes worth
   * naming and they are told apart by asking, which the connection check
   * does. */
  const text = String(err && err.message || "");
  if (code === "EPROTO" || code === "ERR_SSL_WRONG_VERSION_NUMBER"
      || /wrong version number|handshake fail|alert number 40|SSLV3_ALERT/i.test(text)) {
    return new ApiError(
      "The secure connection to " + where + " could not be set up.  Either the "
      + "address begins with https:// and that server speaks plain http, or "
      + "the server has no certificate for the name you used, which is what "
      + "happens when an address is an IP rather than a hostname, or something "
      + "between the two is inspecting the traffic.  Run Git Code Review: "
      + "Check the connection, which asks the server and says which of those "
      + "it is.",
      { kind: "tls" });
  }
  if (code.indexOf("CERT") !== -1 || code === "SELF_SIGNED_CERT_IN_CHAIN"
      || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE") {
    return new ApiError(
      "The certificate at " + where + " was not trusted (" + code + ").  "
      + "Install the certificate authority on this machine, or turn on "
      + "gitCodeReview.allowInsecureTls if you accept that risk.",
      { kind: "tls" });
  }
  return new ApiError(String(err && err.message || err), { kind: "network" });
}

module.exports = { Api, ApiError, normalizeServer };
