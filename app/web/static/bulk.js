/* Ticking rows and acting on the lot, on the pages that only need one such
 * action.
 *
 * The findings page has its own, because it carries two competing actions and
 * a select-all-matching-the-filters that sends filters instead of ids.  This
 * is the simple case: what is ticked on this page, and nothing cleverer.
 *
 * The checkboxes stay out of the acting form and their ids are copied across
 * as one comma separated value when the dialog opens, so the table markup
 * stays a table. */
(function () {
  "use strict";

  var bar = document.getElementById("bulk-bar");
  var field = document.getElementById("bulk-ids");
  if (!bar || !field) { return; }

  var picks = Array.prototype.slice.call(document.querySelectorAll(".bulk-pick"));
  var page = document.getElementById("bulk-select-page");
  var counts = document.querySelectorAll('[data-slot="bulk-n"]');
  var clear = document.getElementById("bulk-clear");

  function ticked() {
    return picks.filter(function (box) { return box.checked && !box.disabled; });
  }

  function refresh() {
    var picked = ticked();
    field.value = picked.map(function (box) { return box.value; }).join(",");
    counts.forEach(function (slot) { slot.textContent = picked.length; });
    bar.hidden = picked.length === 0;
    if (page) {
      page.checked = picked.length > 0 && picked.length === picks.filter(
        function (box) { return !box.disabled; }).length;
    }
  }

  picks.forEach(function (box) { box.addEventListener("change", refresh); });

  if (page) {
    page.addEventListener("change", function () {
      picks.forEach(function (box) {
        if (!box.disabled) { box.checked = page.checked; }
      });
      refresh();
    });
  }

  if (clear) {
    clear.addEventListener("click", function () {
      picks.forEach(function (box) { box.checked = false; });
      refresh();
    });
  }

  refresh();
})();
