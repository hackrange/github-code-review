/* The audit log, answering as somebody types.
 *
 * The filtering is done by the server, not here.  Hiding rows in the browser
 * would only ever search the page already on screen, and then a search that
 * found nothing would mean "not in the last three hundred events" while
 * looking exactly like "never happened".  On an append only log that is the
 * one answer that must not be wrong.
 *
 * The form works on its own with this file absent: it is a GET form with a
 * submit button, and everything below is an improvement on top of that.
 */
(function () {
  "use strict";

  var form = document.getElementById("audit-filters");
  var body = document.getElementById("audit-rows");
  var count = document.getElementById("audit-count");
  if (!form || !body) { return; }

  var box = form.querySelector('input[name="q"]');
  var outcome = form.querySelector('select[name="outcome"]');
  var endpoint = form.getAttribute("data-rows");
  var timer = null;
  var inflight = null;
  var latest = 0;

  function query() {
    var parts = [];
    if (box && box.value) { parts.push("q=" + encodeURIComponent(box.value)); }
    if (outcome && outcome.value) {
      parts.push("outcome=" + encodeURIComponent(outcome.value));
    }
    return parts.join("&");
  }

  function run() {
    var q = query();
    /* Answers can come back out of order when somebody types quickly, and a
       slow early one landing last would show results for a search they have
       already moved on from.  Number them and ignore anything stale. */
    var mine = ++latest;

    if (inflight) { inflight.abort(); }
    var request = new XMLHttpRequest();
    inflight = request;
    request.open("GET", endpoint + (q ? "?" + q : ""), true);
    request.setRequestHeader("X-Requested-With", "XMLHttpRequest");
    request.onload = function () {
      if (mine !== latest) { return; }
      inflight = null;
      if (request.status !== 200) { return; }
      body.innerHTML = request.responseText;
      var said = request.getResponseHeader("X-Audit-Summary");
      if (said && count) { count.textContent = said; }
      /* Keep the address bar honest, so a reload or a shared link shows the
         same thing that is on screen. */
      if (window.history && window.history.replaceState) {
        var here = form.getAttribute("action") + (q ? "?" + q : "");
        window.history.replaceState(null, "", here);
      }
    };
    request.onerror = function () { inflight = null; };
    request.send();
  }

  /* Clicking an event opens the panel under it.  Delegated from the table
     body rather than bound per row, because the rows are replaced wholesale
     every time somebody types and per row handlers would go with them. */
  function toggle(row) {
    var panel = document.getElementById(row.getAttribute("aria-controls"));
    if (!panel) { return; }
    var open = panel.hidden;
    panel.hidden = !open;
    row.setAttribute("aria-expanded", open ? "true" : "false");
  }

  body.addEventListener("click", function (event) {
    /* A link inside the panel is a link, not a toggle. */
    if (event.target.closest("a")) { return; }
    var row = event.target.closest("tr.audit-row");
    if (row) { toggle(row); }
  });

  body.addEventListener("keydown", function (event) {
    if (event.key !== "Enter" && event.key !== " ") { return; }
    var row = event.target.closest("tr.audit-row");
    if (!row) { return; }
    event.preventDefault();          /* space would scroll the page */
    toggle(row);
  });

  function schedule() {
    window.clearTimeout(timer);
    /* Long enough that a word is one request rather than five, short enough
       that it still feels like it is keeping up. */
    timer = window.setTimeout(run, 180);
  }

  if (box) {
    box.addEventListener("input", schedule);
    /* No "search" event listener: that only fires on input[type=search], and
       this is a text input so it matches the height of everything beside it. */
  }
  if (outcome) { outcome.addEventListener("change", run); }

  /* The button has nothing left to do, and leaving it would reload the page
     for a result that is already on screen. */
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    window.clearTimeout(timer);
    run();
  });
})();
