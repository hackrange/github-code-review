/* Tick every certification shown, and keep the button honest about how many.
 *
 * The rows can be filtered by state and searched by text at the same time, so
 * "everything shown" has to mean the rows a person can actually see rather
 * than every row in the table.  Ticking a hidden row is how somebody withdraws
 * a sign off they never looked at, and a withdrawn one looks exactly like one
 * that was never given.
 */
(function () {
  "use strict";

  var all = document.getElementById("select-certs");
  var form = document.getElementById("cert-bulk");
  if (!all || !form) { return; }

  var button = form.querySelector('button[type="submit"]');
  var label = button ? button.textContent : "";

  function boxes() {
    return Array.prototype.slice.call(
      document.querySelectorAll('#cert-table input[name="pair"]'));
  }

  function visible(box) {
    var row = box.closest("tr");
    return row && row.offsetParent !== null && !box.disabled;
  }

  function refresh() {
    var n = boxes().filter(function (b) { return b.checked && visible(b); }).length;
    if (!button) { return; }
    button.textContent = n ? label.replace("the ticked", n + (n === 1 ? " ticked" : " ticked")) : label;
    button.disabled = n === 0;
  }

  all.addEventListener("change", function () {
    boxes().forEach(function (box) {
      if (visible(box)) { box.checked = all.checked; }
    });
    refresh();
  });

  document.addEventListener("change", function (event) {
    if (event.target && event.target.name === "pair") { refresh(); }
  });

  refresh();
})();
