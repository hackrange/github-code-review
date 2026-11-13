/* Ask AI: the chat panel in the top bar.  Administrators only.
 *
 * Its own file because the content security policy has no unsafe-inline.
 * Everything the server sends back is put on the page as text, never as
 * HTML, because the answer is written from data anyone can commit. */
(function () {
  "use strict";

  var base = (document.querySelector('meta[name="gcr-base"]') || {}).content || "";
  var csrf = (document.querySelector('meta[name="gcr-csrf"]') || {}).content || "";
  var toggle = document.getElementById("ask-toggle");
  var panel = document.getElementById("ask-panel");
  if (!toggle || !panel) { return; }

  var log = document.getElementById("ask-log");
  var form = document.getElementById("ask-form");
  var input = document.getElementById("ask-input");
  var send = document.getElementById("ask-send");
  var greeting = log.innerHTML;
  var history = [];
  var busy = false;

  function open(show) {
    panel.hidden = !show;
    toggle.setAttribute("aria-expanded", show ? "true" : "false");
    if (show) { input.focus(); }
  }
  toggle.addEventListener("click", function () { open(panel.hidden); });
  document.getElementById("ask-close").addEventListener("click", function () { open(false); });
  document.getElementById("ask-clear").addEventListener("click", function () {
    history = [];
    log.innerHTML = greeting;
    input.focus();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !panel.hidden) { open(false); }
  });

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined) { node.textContent = text; }
    return node;
  }

  /* Only links to this site's own pages, which is all the server sends. */
  function safeHref(href) {
    return typeof href === "string" && href.indexOf(base + "/") === 0 &&
           href.indexOf("//") !== 0 ? href : "";
  }

  function scrollDown() { log.scrollTop = log.scrollHeight; }

  function add(role, text) {
    var msg = el("div", "ask-msg " + role, text);
    log.appendChild(msg);
    scrollDown();
    return msg;
  }

  function table(view) {
    var wrap = el("details", "ask-table");
    var label = view.title + " (" + view.total + (view.truncated ? "+" : "") + " rows)";
    wrap.appendChild(el("summary", "", label));
    var scroller = el("div", "ask-table-scroll");
    var t = el("table", "table");
    var head = el("tr");
    view.columns.forEach(function (c) { head.appendChild(el("th", "", c)); });
    var thead = el("thead"); thead.appendChild(head); t.appendChild(thead);
    var body = el("tbody");
    view.rows.forEach(function (row) {
      var tr = el("tr");
      row.forEach(function (v) { tr.appendChild(el("td", "", v)); });
      body.appendChild(tr);
    });
    t.appendChild(body);
    scroller.appendChild(t);
    wrap.appendChild(scroller);
    return wrap;
  }

  function figures(report) {
    var box = el("div", "ask-figures");
    var sev = report.severity || {};
    [["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]]
      .forEach(function (pair) {
        var f = el("div", "ask-figure sev-" + pair[0]);
        f.appendChild(el("strong", "", String(sev[pair[0]] || 0)));
        f.appendChild(el("span", "", pair[1]));
        box.appendChild(f);
      });
    var urgent = report.urgent || {};
    var notes = [];
    if (urgent.live_credentials) { notes.push(urgent.live_credentials + " credential(s) confirmed working"); }
    if (urgent.malicious_packages) { notes.push(urgent.malicious_packages + " malicious package(s)"); }
    if (urgent.known_exploited) { notes.push(urgent.known_exploited + " known exploited"); }
    var wrap = el("div", "");
    wrap.appendChild(box);
    wrap.appendChild(el("div", "small faint", (report.findings || 0) + " findings in " +
      (report.repositories || 0) + " repositories" + (notes.length ? ".  Urgent: " + notes.join(", ") : "")));
    return wrap;
  }

  function diffPre(text) {
    var pre = el("pre", "ask-diff-body");
    text.split("\n").forEach(function (line) {
      var cls = "";
      if (line.indexOf("@@") === 0) { cls = "hunk"; }
      else if (line.indexOf("diff --git") === 0) { cls = "file"; }
      else if (line.indexOf("+") === 0 && line.indexOf("+++") !== 0) { cls = "add"; }
      else if (line.indexOf("-") === 0 && line.indexOf("---") !== 0) { cls = "del"; }
      pre.appendChild(el("span", cls, line + "\n"));
    });
    return pre;
  }

  function activityBlock(a) {
    var box = el("div", "ask-activity");
    box.appendChild(el("div", "small faint",
      "Commits " + (a.authors && a.authors.length ? "by " + a.authors.join(" or ") : "by anyone") +
      " since " + a.since + ", read from the repositories."));
    if (a.concerns && a.concerns.length) {
      var notes = el("div", "ask-concerns");
      notes.appendChild(el("strong", "", "Security notes (AI review)"));
      a.concerns.forEach(function (c) { notes.appendChild(el("div", "", "- " + c)); });
      box.appendChild(notes);
    }
    (a.repositories || []).forEach(function (repo) {
      var r = el("div", "ask-repo");
      r.appendChild(el("div", "ask-diff-head", repo.repository + " (" + repo.commits.length + " commit" +
        (repo.commits.length === 1 ? "" : "s") + (repo.more ? ", more not shown" : "") + ")"));
      if (repo.error) { r.appendChild(el("div", "small faint", repo.error)); }
      if (repo.note) { r.appendChild(el("div", "small faint", repo.note)); }
      repo.commits.forEach(function (c) {
        var d = el("details", "ask-commit");
        d.appendChild(el("summary", "", c.sha + "  " + c.date + "  " + c.author + ": " + c.subject));
        if (c.summary) { d.appendChild(el("div", "small", "AI summary: " + c.summary)); }
        if (c.files && c.files.length) { d.appendChild(el("div", "small faint", c.files.join(";  "))); }
        if (c.diff) { d.appendChild(diffPre(c.diff)); }
        r.appendChild(d);
      });
      box.appendChild(r);
    });
    return box;
  }

  function diffBlock(d) {
    var box = el("div", "ask-diff");
    box.appendChild(el("div", "ask-diff-head", (d.vuln_id || "") + "  " + (d.repository || "") +
      " on " + (d.branch || "") + ", " + (d.file || "") + (d.line ? ":" + d.line : "")));
    if (d.error) {
      box.appendChild(el("div", "small faint", d.error));
      return box;
    }
    box.appendChild(el("div", "small faint",
      (d.mode === "fixed" ? "The fix: " : "Changes since it was found: ") +
      (d.before_commit || "") + " (" + (d.before_at || "") + ") to " + (d.after_commit || "") +
      (d.after_at ? " (" + d.after_at + ")" : " (now)")));
    if (d.commits && d.commits.length) {
      box.appendChild(el("div", "small faint", "Commits: " + d.commits.join("; ")));
    }
    if (d.note) { box.appendChild(el("div", "small", d.note)); }
    if (d.diff) {
      box.appendChild(diffPre(d.diff));
      if (d.truncated) { box.appendChild(el("div", "small faint", "Cut at 400 lines.")); }
    }
    return box;
  }

  function answer(data) {
    var msg = add("bot", data.answer || "");
    if (data.report) { msg.appendChild(figures(data.report)); }
    (data.diffs || []).forEach(function (d) { msg.appendChild(diffBlock(d)); });
    if (data.activity) { msg.appendChild(activityBlock(data.activity)); }
    if (data.files && data.files.length) {
      var files = el("div", "ask-files");
      data.files.forEach(function (f) {
        var href = safeHref(f.href);
        if (!href) { return; }
        var a = el("a", "btn sm", "Download " + f.label);
        a.href = href;
        a.setAttribute("download", f.name || "");
        files.appendChild(a);
      });
      msg.appendChild(files);
    }
    if (data.links && data.links.length) {
      var links = el("div", "ask-links");
      data.links.forEach(function (l) {
        var href = safeHref(l.href);
        if (!href) { return; }
        var a = el("a", "", l.label);
        a.href = href;
        links.appendChild(a);
      });
      msg.appendChild(links);
    }
    (data.tables || []).forEach(function (v) { msg.appendChild(table(v)); });
    if (data.queries && data.queries.length) {
      var q = el("details", "ask-sql");
      q.appendChild(el("summary", "", "How this was looked up"));
      data.queries.forEach(function (item) {
        q.appendChild(el("div", "small", item.title + (item.error ? " (" + item.error + ")" : "")));
        q.appendChild(el("pre", "mono", item.sql || ""));
      });
      msg.appendChild(q);
    }
    scrollDown();
  }

  function ask(question) {
    busy = true;
    send.disabled = true;
    add("user", question);
    var waiting = add("bot pending", "Looking that up.  A report or a diff can take a minute...");
    fetch(base + "/ai/ask", {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
      body: JSON.stringify({question: question, history: history})
    }).then(function (r) {
      return r.json().catch(function () { return {error: "The server sent something unexpected."}; })
        .then(function (data) { return {ok: r.ok, data: data}; });
    }).then(function (res) {
      waiting.remove();
      var data = res.data || {};
      if (!res.ok || data.error || data.detail) {
        add("bot error", data.error || data.detail || "That did not work.");
        return;
      }
      answer(data);
      history.push({role: "user", text: question});
      history.push({role: "assistant", text: data.answer || ""});
      history = history.slice(-6);
    }).catch(function () {
      waiting.remove();
      add("bot error", "Could not reach the server.");
    }).then(function () {
      busy = false;
      send.disabled = false;
      input.focus();
    });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var q = input.value.trim();
    if (!q || busy) { return; }
    input.value = "";
    ask(q);
  });
  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event("submit"));
    }
  });
})();
