/* DAST admin page: tabs, the rule and profile modals, select all, and the
   refresh while a draft is working.  In a static file because the content
   security policy does not allow inline scripts. */
(function () {
  "use strict";

  // A header checkbox ticks or clears every rule in its class.
  document.addEventListener("change", function (e) {
    var head = e.target;
    if (!head.matches || !head.matches("[data-check-all]")) { return; }
    var form = head.closest("form");
    if (!form) { return; }
    Array.prototype.forEach.call(
      form.querySelectorAll('input[name="rule_id"]'),
      function (cb) { cb.checked = head.checked; });
  });

  // Tabs: show one pane at a time, remember it in the address.
  var nav = document.querySelector(".section-nav");
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".section-nav [data-tab]"));
  var panes = Array.prototype.slice.call(document.querySelectorAll("[data-pane]"));
  function show(name) {
    tabs.forEach(function (t) { t.classList.toggle("active", t.getAttribute("data-tab") === name); });
    panes.forEach(function (p) { p.hidden = p.getAttribute("data-pane") !== name; });
  }
  tabs.forEach(function (t) {
    t.addEventListener("click", function (e) {
      e.preventDefault();
      var name = t.getAttribute("data-tab");
      show(name);
      window.history.replaceState(null, "", "#tab-" + name);
    });
  });
  var hash = (window.location.hash || "").replace("#tab-", "");
  show(tabs.some(function (t) { return t.getAttribute("data-tab") === hash; }) ? hash : "rules");

  // The rule modal fills its textarea from the button that opened it, and
  // pretty prints the stored spec so it is easy to edit.
  var spec = document.getElementById("rule-spec");
  var editing = document.getElementById("rule-editing");
  var origin = document.getElementById("rule-origin");
  function fill(text) {
    if (!spec) { return; }
    try { spec.value = JSON.stringify(JSON.parse(text), null, 2); }
    catch (e) { spec.value = text || ""; }
  }
  var fromDraft = document.getElementById("rule-from-draft");
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest('[data-modal="rule-modal"]') : null;
    if (!b) { return; }
    if (editing) { editing.value = b.getAttribute("data-editing") || ""; }
    if (origin) { origin.value = b.getAttribute("data-origin") || "custom"; }
    if (fromDraft) { fromDraft.value = b.getAttribute("data-from-draft") || ""; }
    fill(b.getAttribute("data-spec") || "");
  });

  // The scan profile modal fills from the button that opened it, and ticks
  // the rulesets the profile already runs.
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest('[data-modal="profile-modal"]') : null;
    if (!b) { return; }
    var set = function (id, v) { var el = document.getElementById(id); if (el) { el.value = v; } };
    set("profile-editing", b.getAttribute("data-editing") || "");
    set("profile-name", b.getAttribute("data-name") || "");
    set("profile-depth", b.getAttribute("data-depth") || "premium");
    set("profile-notes", b.getAttribute("data-notes") || "");
    var chosen = [];
    try { chosen = JSON.parse(b.getAttribute("data-rulesets") || "[]"); } catch (x) { chosen = []; }
    Array.prototype.forEach.call(
      document.querySelectorAll('#profile-modal [name="rulesets"]'),
      function (cb) { cb.checked = chosen.indexOf(cb.value) !== -1; });
  });

  // Expand or collapse every curated-rule class section at once.  The sections
  // are <details> and start collapsed, so a long list is quiet until opened.
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest("[data-rules-toggle]") : null;
    if (!b) { return; }
    var open = b.getAttribute("data-rules-toggle") === "expand";
    Array.prototype.forEach.call(
      document.querySelectorAll("details.rule-group"),
      function (d) { d.open = open; });
  });

  // While a rule is being drafted in the background, refresh so it appears
  // under Drafted rules when it is ready, without losing the current tab.
  if (nav && nav.getAttribute("data-drafting") === "1") {
    window.setTimeout(function () { window.location.reload(); }, 5000);
  }
})();
