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

  /* What a data attribute has to say for a tick box to be ticked.  A row
   * writes 1 or 0 from a template, and true or yes are what somebody writing
   * one by hand reaches for. */
  var TRUTHY = ["1", "true", "on", "yes"];

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
      /* Back to what the panel ships with, before this row is put into it.
       *
       * One panel serves every row's Edit button and the Add button as well,
       * so whatever was in it last time is still there: the name of a row
       * somebody looked at and cancelled, a tick box turned off two rows ago,
       * and the id of the row that was being edited, which would make Add
       * save over it.  A field this row says nothing about has to be the
       * panel's own default rather than somebody else's answer. */
      panel.querySelectorAll("input, textarea, select").forEach(function (field) {
        if (field.type === "checkbox" || field.type === "radio") {
          field.checked = field.defaultChecked;
        } else if (field.tagName === "SELECT") {
          var preset = field.querySelector("option[selected]");
          field.value = preset ? preset.value
                               : (field.options.length ? field.options[0].value : "");
        } else {
          field.value = field.defaultValue;
        }
      });
      /* Carry the row this came from into the form. */
      Object.keys(trigger.dataset).forEach(function (name) {
        if (name === "modal" || name === "post" || name === "confirm" ||
            name === "busy" || name === "body") { return; }
        var field = panel.querySelector('[name="' + name + '"]');
        /* A tick box carries its own value and the tick is what says yes, so
         * the row decides whether it is ticked rather than what it sends.
         * Writing the row's value onto one replaces the thing it submits and
         * it quietly stops saving, which is why this used to skip them
         * entirely.  Skipping them meant a panel that always showed the
         * template's answer instead of the row's: a schedule that was off
         * opened with Turned on ticked, and turning it on meant clicking the
         * box, which turned it off. */
        if (field && field.type === "checkbox") {
          field.checked = TRUTHY.indexOf(
            String(trigger.dataset[name]).toLowerCase()) !== -1;
        } else if (field && field.type === "radio") {
          /* A group shares one name, so the value picks which of them. */
          panel.querySelectorAll('[name="' + name + '"]').forEach(function (one) {
            one.checked = (one.value === String(trigger.dataset[name]));
          });
        } else if (field) {
          field.value = trigger.dataset[name];
        }
        /* Every slot, not the first one.  A dialog that names the thing it
         * is about twice, once in the heading and once in the sentence you
         * have to type it into, filled only the heading. */
        panel.querySelectorAll('[data-slot="' + name + '"]').forEach(
          function (slot) { slot.textContent = trigger.dataset[name]; });
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
  /* A drill down clears what it has just made meaningless.
   *
   * The where filters narrow each other: an account narrows organizations, an
   * organization narrows repositories, a repository narrows branches.  Change
   * one near the top and the choices below it are answers to a question nobody
   * is asking any more.  Left alone they stay in the query string, so the page
   * comes back filtered to a repository that is not in the organization on
   * screen, showing nothing, with no visible reason why.
   *
   * So each of these clears the ones downstream of it before submitting.
   * Order matters and is the order of the boxes on the page.
   */
  var CASCADE = ["connection", "org", "repo", "branch"];

  function clearDownstream(form, name) {
    var at = CASCADE.indexOf(name);
    if (at === -1) { return; }
    CASCADE.slice(at + 1).forEach(function (downstream) {
      var box = form.querySelector("[name=" + downstream + "]");
      if (box) { box.value = ""; }
    });
  }

  document.querySelectorAll("[data-autosubmit]").forEach(function (field) {
    field.addEventListener("change", function () {
      var form = field.closest("form");
      if (!form) { return; }
      clearDownstream(form, field.name);
      form.submit();
    });
  });

  /* Forms that ask before they do something.
   *
   * These used to be an onsubmit attribute on the form, and every one of them
   * was dead.  The content security policy has no unsafe-inline for scripts,
   * which is the whole point of it, and an event handler written as an
   * attribute is inline script: the browser refuses to run it and says so
   * only in the console.  So six destructive actions across three pages were
   * going straight through without asking, and the confirmation each one
   * appeared to have was markup that never executed.
   *
   * Nothing here is new behavior.  It is the behavior those pages were
   * written to have. */
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.dataset.confirm)) {
        event.preventDefault();
      }
    });
  });

  /* A form whose answer takes a while.  The button says so and cannot be
   * pressed twice, because a second press is a second paid request and the
   * page gives no other sign that the first one is still going.  Registered
   * after the confirmation above, so a cancelled confirmation never gets
   * here. */
  document.querySelectorAll("form[data-busy]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (event.defaultPrevented) { return; }
      form.querySelectorAll("button[type=submit]").forEach(function (button) {
        button.disabled = true;
        button.textContent = form.dataset.busy;
      });
    });
  });

  /* Filter bars that apply as soon as something is picked.
   *
   * Same reason as above: this was an onchange attribute and the policy
   * refuses to run it, so the boxes moved and the page never reloaded.  A
   * submit button is kept in the markup for anybody without javascript, and
   * hidden here once this is running, so the form works either way. */
  document.querySelectorAll("form[data-autosubmit]").forEach(function (form) {
    form.addEventListener("change", function (event) {
      if (event.target.matches("select, input[type=date], input[type=radio]")) {
        /* The same cascade the individual boxes get.
         *
         * A form that carries the whole set of filters gets this handler
         * rather than one per box, and it was submitting whatever the boxes
         * to the right still held.  So picking a different repository kept
         * the branch chosen for the last one, the scope matched nothing, and
         * the page came back with an empty matrix and an empty table and no
         * reason on screen for either.  Clearing downstream first is what the
         * boxes elsewhere already do. */
        clearDownstream(form, event.target.name);
        form.submit();
      }
    });
    form.querySelectorAll("[data-manual-apply]").forEach(function (button) {
      button.hidden = true;
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
