/* Point the waive form at whichever finding the button came from. */
(function () {
  "use strict";
  var base = (document.querySelector('meta[name="gcr-base"]') || {}).content || "";
  var form = document.getElementById("waive-form");
  if (!form) { return; }

  document.querySelectorAll('[data-modal="waive-modal"]').forEach(function (button) {
    button.addEventListener("click", function () {
      var id = button.getAttribute("data-finding");
      if (id) { form.action = base + "/findings/" + encodeURIComponent(id) + "/waive"; }
    });
  });
})();

/* Ticking rows, and waiving the lot in one go.
 *
 * The checkboxes belong to a form elsewhere on the page through form=, so the
 * table markup stays a table and the selection survives the modal opening. */
(function () {
  "use strict";

  var bar = document.getElementById("bulk-bar");
  if (!bar) { return; }

  var picks = Array.prototype.slice.call(document.querySelectorAll(".pick"));
  var page = document.getElementById("select-page");
  var count = document.getElementById("bulk-count");
  var scope = document.getElementById("bulk-scope");
  var allMatching = document.getElementById("all-matching");
  var allButton = document.getElementById("select-all-matching");
  var clear = document.getElementById("bulk-clear");
  var slots = document.querySelectorAll('[data-slot="bulk-count"]');

  function ticked() {
    return picks.filter(function (box) { return box.checked && !box.disabled; });
  }

  function refresh() {
    var n = allMatching.value ? (scope.getAttribute("data-total") || ticked().length)
                              : ticked().length;
    var shown = allMatching.value
      ? (allButton ? allButton.textContent.replace(/\D+/g, "") : n)
      : n;
    count.textContent = shown;
    slots.forEach(function (slot) { slot.textContent = shown; });
    bar.hidden = ticked().length === 0 && !allMatching.value;
  }

  picks.forEach(function (box) {
    box.addEventListener("change", function () {
      /* Ticking anything by hand means this is no longer everything. */
      allMatching.value = "";
      scope.hidden = true;
      refresh();
    });
  });

  if (page) {
    page.addEventListener("change", function () {
      picks.forEach(function (box) {
        if (!box.disabled) { box.checked = page.checked; }
      });
      allMatching.value = "";
      scope.hidden = true;
      refresh();
    });
  }

  if (allButton) {
    allButton.addEventListener("click", function () {
      picks.forEach(function (box) { if (!box.disabled) { box.checked = true; } });
      /* Send the filters instead of ten thousand ids. */
      allMatching.value = "1";
      scope.hidden = false;
      if (page) { page.checked = true; }
      refresh();
    });
  }

  if (clear) {
    clear.addEventListener("click", function () {
      picks.forEach(function (box) { box.checked = false; });
      if (page) { page.checked = false; }
      allMatching.value = "";
      scope.hidden = true;
      refresh();
    });
  }

  refresh();
})();

/* Deleting what is ticked.
 *
 * The row checkboxes belong to bulk-form, so the delete form cannot see them.
 * Rather than duplicating every box, the ids get copied across as one comma
 * separated value when the dialog opens, which the route already knows how to
 * read. */
(function () {
  "use strict";

  var form = document.getElementById("delete-form");
  if (!form) { return; }

  var ids = document.getElementById("delete-ids");
  var matching = document.getElementById("delete-all-matching");
  var shown = document.getElementById("delete-count");
  var source = document.getElementById("all-matching");

  document.querySelectorAll('[data-modal="delete-modal"]').forEach(function (button) {
    button.addEventListener("click", function () {
      var picked = Array.prototype.slice
        .call(document.querySelectorAll(".pick"))
        .filter(function (box) { return box.checked && !box.disabled; });

      /* A select-all sends the filters instead of the ids, the same way the
         waive path does, so the count comes off the page rather than the
         boxes on this screen. */
      var everything = source && source.value ? "1" : "";
      matching.value = everything;
      ids.value = everything ? "" : picked.map(function (box) {
        return box.value;
      }).join(",");

      if (shown) {
        var all = document.getElementById("select-all-matching");
        shown.textContent = everything && all
          ? all.textContent.replace(/\D+/g, "")
          : picked.length;
      }
    });
  });
})();

/* The whole estate.  A dialog alone is one stray click, so the button stays
   dead until the word is typed. */
(function () {
  "use strict";

  var field = document.getElementById("delete-confirm");
  var go = document.getElementById("delete-all-go");
  if (!field || !go) { return; }

  function check() {
    go.disabled = field.value.trim().toUpperCase() !== "DELETE";
  }
  field.addEventListener("input", check);
  field.addEventListener("change", check);
  check();
})();
