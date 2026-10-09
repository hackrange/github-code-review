/* Tick every repository shown, for the scan scope form under the table.
 *
 * Shown means what the search left visible, the same rule the certification
 * list uses: a change to a repository nobody could see on the screen is a
 * change nobody checked.  The confirmation page lists them all again anyway.
 */
(function () {
  "use strict";

  var all = document.getElementById("select-repos");
  var form = document.getElementById("scope-bulk");
  if (!all || !form) { return; }

  var button = form.querySelector('button[type="submit"]');

  function boxes() {
    return Array.prototype.slice.call(
      document.querySelectorAll('#repo-table input[name="repo"]'));
  }

  function visible(box) {
    var row = box.closest("tr");
    return row && row.offsetParent !== null;
  }

  function refresh() {
    var n = boxes().filter(function (b) { return b.checked && visible(b); }).length;
    if (button) { button.disabled = n === 0; }
  }

  all.addEventListener("change", function () {
    boxes().forEach(function (box) {
      box.checked = visible(box) ? all.checked : false;
    });
    refresh();
  });

  document.addEventListener("change", function (event) {
    if (event.target && event.target.name === "repo") { refresh(); }
  });

  refresh();
})();
