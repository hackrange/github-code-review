/* Ticking repositories to tag several at once.
 *
 * Tagging an estate one repository at a time is not something anybody
 * finishes, so the form carries whatever is ticked and says how many. */
(function () {
  "use strict";

  var ids = document.getElementById("tag-ids");
  var count = document.getElementById("tag-count");
  if (!ids) { return; }

  function picks() {
    return Array.prototype.slice.call(document.querySelectorAll(".tag-pick"));
  }

  function refresh() {
    var chosen = picks().filter(function (box) { return box.checked; })
                        .map(function (box) { return box.value; });
    ids.value = chosen.join(",");
    if (count) { count.textContent = String(chosen.length); }
  }

  picks().forEach(function (box) { box.addEventListener("change", refresh); });

  var all = document.getElementById("tag-all");
  if (all) {
    all.addEventListener("change", function () {
      picks().forEach(function (box) { box.checked = all.checked; });
      refresh();
    });
  }

  document.getElementById("tag-form").addEventListener("submit", function (event) {
    if (!ids.value) {
      event.preventDefault();
      window.alert("Tick the repositories to tag first.");
    }
  });

  refresh();
})();
