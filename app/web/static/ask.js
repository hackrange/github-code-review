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

  function answer(data) {
    var msg = add("bot", data.answer || "");
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
    var waiting = add("bot pending", "Looking that up...");
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
