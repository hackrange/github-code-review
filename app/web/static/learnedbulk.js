/* Tick learned rules and act on the lot.
 *
 * Each button asks its own question before it goes, since stopping a rule
 * applying everywhere and deleting it for good are not the same size of
 * thing.  The buttons stay off until something is ticked.
 */
(function () {
  "use strict";

  var form = document.getElementById("rule-bulk");
  if (!form) { return; }

  var all = document.getElementById("select-rules");
  var count = form.querySelector("[data-ticked]");
  var buttons = Array.prototype.slice.call(
    form.querySelectorAll('button[type="submit"]'));

  function boxes() {
    return Array.prototype.slice.call(
      document.querySelectorAll('#rule-table input[name="rule"]'));
  }

  function refresh() {
    var n = boxes().filter(function (b) { return b.checked; }).length;
    count.textContent = n ? n + " ticked" : "Nothing ticked";
    buttons.forEach(function (button) { button.disabled = n === 0; });
    if (all) {
      all.checked = n > 0 && n === boxes().length;
      all.indeterminate = n > 0 && n < boxes().length;
    }
  }

  if (all) {
    all.addEventListener("change", function () {
      boxes().forEach(function (box) { box.checked = all.checked; });
      refresh();
    });
  }

  document.addEventListener("change", function (event) {
    if (event.target && event.target.name === "rule") { refresh(); }
  });

  form.addEventListener("submit", function (event) {
    var button = event.submitter;
    if (button && button.dataset.confirm && !window.confirm(button.dataset.confirm)) {
      event.preventDefault();
    }
  });

  refresh();
})();
