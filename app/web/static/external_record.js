// Record a session: drive the browser on the server from a picture of it.
// The picture refreshes on its own; a click is sent as a point on the page,
// and typing goes to whatever field the page has focused.
(function () {
  "use strict";
  var root = document.getElementById("recorder");
  if (!root) return;
  var inputUrl = root.getAttribute("data-input");
  var frameUrl = root.getAttribute("data-frame");
  var csrf = root.getAttribute("data-csrf");
  var img = root.querySelector("[data-rec-img]");
  var screen = root.querySelector("[data-rec-screen]");
  var status = root.querySelector("[data-rec-status]");
  var urlBox = root.querySelector("[data-rec-url]");
  var stepsOut = root.querySelector("[data-rec-steps]");
  var humanOut = root.querySelector("[data-rec-human-count]");
  var W = 1280, H = 800;
  var ended = false, loading = false, busy = Promise.resolve(), typed = "", typeTimer = null;

  function say(text) { status.textContent = text || ""; }

  function refresh() {
    if (ended || loading) return;
    loading = true;
    var next = new Image();
    next.onload = function () { img.src = next.src; loading = false; };
    next.onerror = function () { loading = false; };
    next.src = frameUrl + "?t=" + Date.now();
  }

  function send(cmd) {
    // One command at a time, in order: a click must land before the typing.
    busy = busy.then(function () {
      if (ended) return null;
      return fetch(inputUrl, {
        method: "POST", credentials: "same-origin",
        headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
        body: JSON.stringify(cmd)
      }).then(function (res) {
        return res.json().catch(function () { return {ok: false, error: "HTTP " + res.status}; })
          .then(function (data) {
            if (res.status === 410) { ended = true; }
            if (data.url && document.activeElement !== urlBox) urlBox.value = data.url;
            say(data.ok ? (data.title || data.url || "") : (data.error || "That did not work."));
            if (typeof data.steps === "number") stepsOut.textContent = data.steps;
            humanOut.textContent = data.human_steps ? ", " + data.human_steps + " needing a person" : "";
            refresh();
            return data;
          });
      }).catch(function () { say("The server did not answer."); });
    });
    return busy;
  }

  function flushTyping() {
    if (typeTimer) { clearTimeout(typeTimer); typeTimer = null; }
    if (typed) { var t = typed; typed = ""; send({op: "type", text: t}); }
  }

  img.addEventListener("click", function (e) {
    var box = img.getBoundingClientRect();
    flushTyping();
    send({op: "click",
          x: Math.round((e.clientX - box.left) * W / box.width),
          y: Math.round((e.clientY - box.top) * H / box.height)});
    screen.focus();
  });

  var KEYS = {Enter: 1, Tab: 1, Backspace: 1, Escape: 1, ArrowDown: 1, ArrowUp: 1, Delete: 1};
  screen.addEventListener("keydown", function (e) {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (KEYS[e.key]) {
      e.preventDefault();
      flushTyping();
      send({op: "key", key: e.key});
    } else if (e.key && e.key.length === 1) {
      e.preventDefault();
      typed += e.key;
      if (typeTimer) clearTimeout(typeTimer);
      typeTimer = setTimeout(flushTyping, 350);
    }
  });

  screen.addEventListener("wheel", function (e) {
    e.preventDefault();
    send({op: "scroll", dy: Math.max(-2000, Math.min(2000, Math.round(e.deltaY)))});
  }, {passive: false});

  root.querySelectorAll("[data-rec-op]").forEach(function (b) {
    b.addEventListener("click", function () { flushTyping(); send({op: b.getAttribute("data-rec-op")}); });
  });
  root.querySelectorAll("[data-rec-key]").forEach(function (b) {
    b.addEventListener("click", function () { flushTyping(); send({op: "key", key: b.getAttribute("data-rec-key")}); });
  });
  root.querySelectorAll("[data-rec-scroll]").forEach(function (b) {
    b.addEventListener("click", function () { send({op: "scroll", dy: parseInt(b.getAttribute("data-rec-scroll"), 10)}); });
  });

  var text = root.querySelector("[data-rec-text]");
  function sendText() {
    if (!text.value) return;
    flushTyping();
    send({op: "type", text: text.value});
    text.value = "";
  }
  root.querySelector("[data-rec-send]").addEventListener("click", sendText);
  text.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); sendText(); } });

  root.querySelector("[data-rec-go]").addEventListener("click", function () {
    flushTyping();
    send({op: "goto", url: urlBox.value});
  });
  urlBox.addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); flushTyping(); send({op: "goto", url: urlBox.value}); }
  });

  var totp = root.querySelector("[data-rec-totp]");
  root.querySelector("[data-rec-totp-send]").addEventListener("click", function () {
    if (!totp.value) return;
    flushTyping();
    send({op: "totp", secret: totp.value});
    totp.value = "";
  });
  root.querySelector("[data-rec-human]").addEventListener("click", function () {
    send({op: "human"});
  });

  refresh();
  setInterval(refresh, 800);
})();
