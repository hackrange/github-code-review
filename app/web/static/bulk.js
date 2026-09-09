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
  var fields = Array.prototype.slice.call(
    document.querySelectorAll("#bulk-ids, .bulk-ids"));
  if (!bar || !fields.length) { return; }

  var picks = Array.prototype.slice.call(document.querySelectorAll(".bulk-pick"));
  var page = document.getElementById("bulk-select-page");
  var counts = document.querySelectorAll('[data-slot="bulk-n"]');
  var clear = document.getElementById("bulk-clear");

  /* One list, more than one thing you can do to it.
   *
   * On the exceptions page a row waiting on a decision can be approved or
   * rejected, and an approved one can be taken back, and both kinds sit in
   * the same table.  So the tally is kept per state as well as in total: a
   * slot named bulk-n-approved shows how many approved ones are ticked, and a
   * button that says data-needs="approved" is dead until there is one.
   *
   * A page with a single action puts no data-state on anything, both lists
   * below come back empty, and none of this does a thing. */
  var stateSlots = Array.prototype.slice.call(
    document.querySelectorAll('[data-slot^="bulk-n-"]'));
  var gated = Array.prototype.slice.call(
    document.querySelectorAll("[data-needs]"));

  function ticked() {
    return picks.filter(function (box) { return box.checked && !box.disabled; });
  }

  function refresh() {
    var picked = ticked();
    var ids = picked.map(function (box) { return box.value; }).join(",");
    fields.forEach(function (field) { field.value = ids; });
    counts.forEach(function (slot) { slot.textContent = picked.length; });

    var perState = {};
    picked.forEach(function (box) {
      var state = box.getAttribute("data-state") || "";
      perState[state] = (perState[state] || 0) + 1;
    });
    stateSlots.forEach(function (slot) {
      var state = slot.getAttribute("data-slot").slice("bulk-n-".length);
      slot.textContent = perState[state] || 0;
    });
    gated.forEach(function (button) {
      button.disabled = !perState[button.getAttribute("data-needs")];
    });

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
