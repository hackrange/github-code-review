/* The exclusion panel adds one and edits one.
 *
 * The generic modal code copies the row into the form.  What is left is
 * pointing the form at the right place and hiding the paste-an-id shortcut
 * when the rule already exists, since changing which finding a rule is
 * attached to is not an edit, it is a different rule. */
(function () {
  "use strict";

  var form = document.getElementById("exclusion-form");
  if (!form) { return; }

  var base = form.getAttribute("action").replace(/\/exclusions\/add$/, "");
  var head = form.querySelector(".modal-head");

  /* Arrived from a finding with a value to exclude.  The generic modal code
     lives in app.js, which the page loads after this one, so wait for the
     document rather than clicking at something that is not listening yet. */
  document.addEventListener("DOMContentLoaded", function () {
    var opener = document.querySelector(
      '[data-modal="exclusion-modal"][data-autoopen]');
    if (opener) { opener.click(); }
  });

  document.querySelectorAll('[data-modal="exclusion-modal"]').forEach(function (trigger) {
    trigger.addEventListener("click", function () {
      var id = trigger.getAttribute("data-exclusion_id");
      var editing = !!id;

      form.setAttribute("action", editing ? base + "/exclusions/" + id + "/save"
                                          : base + "/exclusions/add");
      form.querySelectorAll("[data-new-only]").forEach(function (node) {
        node.hidden = editing;
      });
      if (head) {
        head.childNodes[0].nodeValue = editing ? "Edit exclusion " : "Add an exclusion ";
      }
    });
  });
})();
