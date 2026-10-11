/* Select all, on the scan scope page of a connection.
 *
 * Shown means what the search left visible, so a search for "feature/", or
 * branch!=main branch!=master, and a select all ticks those and nothing else.  A box hidden by the search is
 * unticked rather than left as it was, because a change to a branch nobody
 * could see on the screen is a change nobody checked.
 */
(function () {
  "use strict";

  var form = document.getElementById("conn-scope");
  if (!form) { return; }

  /* A branch the branch search left out of its list counts as hidden too,
   * even though its row is showing. */
  function shown(box) {
    var row = box.closest("tr");
    var label = box.closest("[data-branch-name]");
    return row && !row.hidden && !(label && label.hidden);
  }

  function all(selector) {
    return Array.prototype.slice.call(form.querySelectorAll(selector));
  }

  function tickAll(selector, on) {
    all(selector).forEach(function (box) { box.checked = shown(box) ? on : false; });
    count();
  }

  function count() {
    var repos = all('input[name="repo"]').filter(function (b) { return b.checked; }).length;
    var branches = all('input[name="pair"]').filter(function (b) { return b.checked; }).length;
    var note = form.querySelector("[data-scope-count]");
    var button = form.querySelector("[data-scope-submit]");
    if (note) {
      note.textContent = repos + " repositor" + (repos === 1 ? "y" : "ies") +
        " and " + branches + " branch" + (branches === 1 ? "" : "es") + " ticked";
    }
    if (button) { button.disabled = repos + branches === 0; }
  }

  var repoBox = document.getElementById("tick-all-repos");
  if (repoBox) {
    repoBox.addEventListener("change", function () {
      tickAll('input[name="repo"]', repoBox.checked);
    });
  }
  var branchBox = document.getElementById("tick-all-branches");
  if (branchBox) {
    branchBox.addEventListener("change", function () {
      tickAll('input[name="pair"]', branchBox.checked);
    });
  }

  // Every branch of one repository, from the box at the top of its list.
  all("[data-tick-repo-branches]").forEach(function (box) {
    box.addEventListener("change", function () {
      var list = box.closest("details");
      Array.prototype.slice.call(list.querySelectorAll('input[name="pair"]'))
        .forEach(function (b) { b.checked = shown(b) ? box.checked : false; });
      count();
    });
  });

  form.addEventListener("change", function (event) {
    if (event.target && (event.target.name === "repo" || event.target.name === "pair")) {
      count();
    }
  });
  count();
})();
