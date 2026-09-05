/* Small helpers.  No framework, no build step, nothing fetched.
 *
 * Every POST carries the CSRF token from the meta tag, so the server can tell
 * a form we drew apart from one somebody else did.
 */
(function () {
  "use strict";

  var base = (document.querySelector('meta[name="gcr-base"]') || {}).content || "";
  var csrf = (document.querySelector('meta[name="gcr-csrf"]') || {}).content || "";

  /* Sidebar groups fold up, and remember it. */
  document.querySelectorAll(".group-label").forEach(function (button) {
    button.addEventListener("click", function () {
      var open = button.getAttribute("aria-expanded") === "true";
      button.setAttribute("aria-expanded", String(!open));
      try {
        var key = "gcr.nav." + (button.textContent || "").trim();
        window.localStorage.setItem(key, String(!open));
      } catch (e) { /* private window, not worth caring about */ }
    });
    try {
      var key = "gcr.nav." + (button.textContent || "").trim();
      if (window.localStorage.getItem(key) === "false") {
        button.setAttribute("aria-expanded", "false");
      }
    } catch (e) { /* same */ }
  });

  /* Sidebar on a phone. */
  var toggle = document.querySelector(".menu-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var nav = document.querySelector(".sidebar");
      if (nav) { nav.classList.toggle("open"); }
    });
  }

  /* A closed panel must not be able to block a submit.
   *
   * Several panels put their fields in somebody else's form with the form
   * attribute, deliberately, so that one list of ticked rows is shared rather
   * than kept twice in two lists that would eventually disagree.  The cost is
   * that a field in a closed panel is still part of that form, and a required
   * one that nobody has filled in still fails validation when the form is
   * submitted from a different panel.
   *
   * The browser then refuses to submit and says nothing, because the control
   * it wants to complain about is inside a hidden element and cannot be shown
   * or focused.  The button appears dead.  There is no error, in the page or
   * in the console for most of them, and nothing reaches the server, which is
   * about the worst way for a form to fail.
   *
   * A disabled control is skipped by validation and is not submitted, so
   * closed panels have their fields disabled and opening one gives them back.
   * That also settles a second problem underneath this one: two panels on the
   * same form both had a field called reason, and whichever way the browser
   * broke the tie, one of the two would have been sending the other panel's
   * text.  Only the open panel submits anything now.
   *
   * Marked so that a field the template disabled on purpose stays that way.
   */
  var PARKED = "data-parked";
  function park(panel) {
    panel.querySelectorAll("input, textarea, select, button").forEach(function (f) {
      if (f.disabled) { return; }
      f.disabled = true;
      f.setAttribute(PARKED, "");
    });
  }
  function unpark(panel) {
    panel.querySelectorAll("[" + PARKED + "]").forEach(function (f) {
      f.disabled = false;
      f.removeAttribute(PARKED);
    });
  }

  /* Watched rather than done at the point of opening, because panels are
   * opened from several places: the generic trigger below, and the page
   * scripts that open one directly after filling it in. */
  document.querySelectorAll(".modal-backdrop").forEach(function (node) {
    if (node.hidden) { park(node); }
    new MutationObserver(function () {
      if (node.hidden) { park(node); } else { unpark(node); }
    }).observe(node, {attributes: true, attributeFilter: ["hidden"]});
  });

  /* Modals.  Anything with data-modal opens the panel with that id. */
  function closeModals() {
    document.querySelectorAll(".modal-backdrop").forEach(function (node) {
      node.hidden = true;
    });
  }
  document.querySelectorAll("[data-modal]").forEach(function (trigger) {
    trigger.addEventListener("click", function (event) {
      event.preventDefault();
      var panel = document.getElementById(trigger.getAttribute("data-modal"));
      if (!panel) { return; }
      panel.hidden = false;
      /* Synchronously as well as through the observer above, which does not
       * run until the current task finishes: the prefill and the focus below
       * both happen before that, and neither works on a disabled field. */
      unpark(panel);
      /* Carry the row this came from into the form. */
      Object.keys(trigger.dataset).forEach(function (name) {
        if (name === "modal" || name === "post" || name === "confirm" ||
            name === "busy" || name === "body") { return; }
        var field = panel.querySelector('[name="' + name + '"]');
        /* A tick box carries its own value and the tick is what says yes.
         * Writing the row's value onto one replaces the thing it submits,
         * so a set of them named for the attribute that fills them in, like
         * the scanning groups, quietly stops saving.  Whoever opens the
         * panel ticks those; this only fills in fields that hold text. */
        if (field && field.type !== "checkbox" && field.type !== "radio") {
          field.value = trigger.dataset[name];
        }
        var slot = panel.querySelector('[data-slot="' + name + '"]');
        if (slot) { slot.textContent = trigger.dataset[name]; }
      });
      var first = panel.querySelector("input:not([type=hidden]), textarea, select");
      if (first) { first.focus(); }
    });
  });
  document.querySelectorAll("[data-close-modal]").forEach(function (button) {
    button.addEventListener("click", closeModals);
  });
  /* Has somebody typed anything into this panel yet. */
  function hasInput(panel) {
    var fields = panel.querySelectorAll("input, textarea, select");
    for (var i = 0; i < fields.length; i++) {
      var field = fields[i];
      if (field.type === "hidden" || field.disabled) { continue; }
      if (field.type === "checkbox" || field.type === "radio") {
        if (field.checked !== field.defaultChecked) { return true; }
      } else if ((field.value || "") !== (field.defaultValue || "")) {
        return true;
      }
    }
    return false;
  }

  function tryClose(panel) {
    if (panel && hasInput(panel) &&
        !window.confirm("Close this and lose what you have typed?")) {
      return;
    }
    closeModals();
  }

  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") { return; }
    var open = document.querySelector(".modal-backdrop:not([hidden])");
    tryClose(open);
  });

  /* Closing by clicking away.
   *
   * The click has to both start and finish on the backdrop.  Otherwise a drag
   * that begins on the text you are selecting and ends a pixel outside the
   * panel counts as a click on the backdrop, and the dialog disappears along
   * with everything you had typed into it. */
  document.querySelectorAll(".modal-backdrop").forEach(function (node) {
    /* Some panels are there to be read rather than filled in, and closing one
       because the click to scroll landed an inch too far left is its own small
       insult.  Those say so, and only the button and Escape close them. */
    if (node.hasAttribute("data-sticky")) { return; }
    var startedOutside = false;
    node.addEventListener("mousedown", function (event) {
      startedOutside = event.target === node;
    });
    node.addEventListener("click", function (event) {
      if (event.target === node && startedOutside) { tryClose(node); }
      startedOutside = false;
    });
  });

  /* Filters submit as you change them, no Apply button to forget. */
  document.querySelectorAll("[data-autosubmit]").forEach(function (field) {
    field.addEventListener("change", function () {
      var form = field.closest("form");
      if (form) { form.submit(); }
    });
  });

  /* Anything that kicks off work and then needs the page back. */
  document.querySelectorAll("[data-post]").forEach(function (button) {
    button.addEventListener("click", function (event) {
      event.preventDefault();
      if (button.dataset.confirm && !window.confirm(button.dataset.confirm)) {
        return;
      }
      button.disabled = true;
      var original = button.textContent;
      button.textContent = button.dataset.busy || "Working";
      fetch(base + button.getAttribute("data-post"), {
        method: "POST",
        headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json" },
        body: button.dataset.body || "{}",
        credentials: "same-origin"
      }).then(function (response) {
        if (response.redirected) { window.location = response.url; return; }
        window.location.reload();
      }).catch(function () {
        button.disabled = false;
        button.textContent = original;
      });
    });
  });
})();
