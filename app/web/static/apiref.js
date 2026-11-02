/* The API reference tab on the IDE tokens page.
 *
 * Each endpoint has a Send button that makes the real call with the token
 * typed at the top of the page, and shows what came back.  The token lives in
 * a variable for as long as the tab is open and goes nowhere else: not into
 * storage, not into the address, not into the curl line shown below a call.
 */
(function () {
  "use strict";

  var root = document.getElementById("api-ref");
  if (!root) { return; }
  var api = root.getAttribute("data-api") || "";
  var tokenBox = document.getElementById("api-token");
  var MAX_SHOWN = 200000;

  function token() { return (tokenBox && tokenBox.value || "").trim(); }

  // A repository full name keeps its slash, so each segment is encoded on its
  // own rather than the whole value at once.
  function encodePath(value) {
    return String(value).split("/").map(encodeURIComponent).join("/");
  }

  function build(op) {
    var path = op.getAttribute("data-path");
    var query = [];
    var missing = [];
    op.querySelectorAll("[data-param]").forEach(function (field) {
      var name = field.getAttribute("data-param");
      var where = field.getAttribute("data-in");
      var value = (field.value || "").trim();
      if (where === "path") {
        if (!value) { missing.push(name); }
        path = path.replace("{" + name + "}", encodePath(value));
      } else if (value) {
        query.push(encodeURIComponent(name) + "=" + encodeURIComponent(value));
      }
    });
    var url = api + path + (query.length ? "?" + query.join("&") : "");
    var bodyBox = op.querySelector(".api-body");
    return { url: url, missing: missing,
             method: op.getAttribute("data-method"),
             body: bodyBox ? bodyBox.value : null };
  }

  function shellQuote(text) {
    return "'" + String(text).replace(/'/g, "'\\''") + "'";
  }

  function curlFor(call) {
    var lines = ["curl -sS" + (call.method !== "GET" ? " -X " + call.method : "") +
                 " " + shellQuote(call.url) + " \\",
                 "  -H 'Authorization: Bearer $GCR_TOKEN'"];
    if (call.body !== null) {
      lines[lines.length - 1] += " \\";
      lines.push("  -H 'Content-Type: application/json' \\");
      lines.push("  --data " + shellQuote(call.body.replace(/\s*\n\s*/g, " ")));
    }
    return lines.join("\n");
  }

  function refresh(op) {
    var out = op.querySelector(".api-curl");
    if (out) { out.textContent = curlFor(build(op)); }
  }

  function show(op, status, text, kind) {
    var line = op.querySelector(".api-status");
    var result = op.querySelector(".api-result");
    line.textContent = status;
    line.className = "api-status " + (kind || "faint");
    result.hidden = text === null;
    if (text !== null) { result.textContent = text; }
  }

  function send(op) {
    var call = build(op);
    if (!token()) {
      show(op, "Paste a token at the top of the page first.", null, "api-bad");
      tokenBox && tokenBox.focus();
      return;
    }
    if (call.missing.length) {
      show(op, "Fill in " + call.missing.join(", ") + " first.", null, "api-bad");
      return;
    }
    var options = { method: call.method, credentials: "omit",
                    headers: { "Authorization": "Bearer " + token(),
                               "Accept": "application/json" } };
    if (call.body !== null) {
      try { JSON.parse(call.body); } catch (err) {
        show(op, "The body is not valid JSON: " + err.message, null, "api-bad");
        return;
      }
      options.headers["Content-Type"] = "application/json";
      options.body = call.body;
    }
    var started = Date.now();
    show(op, "Sending...", null);
    fetch(call.url, options).then(function (response) {
      return response.text().then(function (text) {
        var took = Date.now() - started;
        var pretty = text;
        try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch (err) { /* not JSON */ }
        if (pretty.length > MAX_SHOWN) {
          pretty = pretty.slice(0, MAX_SHOWN) + "\n... cut off here, " +
                   text.length + " bytes in all.  Download it with the curl line above.";
        }
        show(op, response.status + " " + (response.statusText || "") + " in " + took + " ms",
             pretty || "(empty)", response.ok ? "api-good" : "api-bad");
      });
    }).catch(function (err) {
      show(op, "The call did not go through: " + err.message, null, "api-bad");
    });
  }

  root.querySelectorAll(".api-op").forEach(function (op) {
    refresh(op);
    op.addEventListener("input", function () { refresh(op); });
    op.addEventListener("change", function () { refresh(op); });
    var button = op.querySelector(".api-send");
    if (button) { button.addEventListener("click", function () { send(op); }); }
  });

  // Opening a link to one endpoint opens that endpoint.
  if (location.hash && location.hash.indexOf("#op-") === 0) {
    var target = document.getElementById(location.hash.slice(1));
    if (target) { target.open = true; }
  }
})();
