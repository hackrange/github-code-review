/* Code behind it, on a site's page: tick several repositories, or all of
   them, and unpin or remove them together.  In a static file because the
   content security policy does not allow inline scripts. */
(function () {
  "use strict";

  var form = document.getElementById("repos-bulk");
  if (!form) { return; }
  var all = document.querySelector("[data-repos-check-all]");
  var count = form.querySelector("[data-repos-count]");
  var buttons = form.querySelectorAll("[data-repos-needs-tick]");

  function ticks() {
    return Array.prototype.slice.call(document.querySelectorAll("[data-repos-tick]"));
  }

  function refresh() {
    var boxes = ticks();
    var n = boxes.filter(function (b) { return b.checked; }).length;
    if (count) { count.textContent = n ? n + " ticked" : "None ticked"; }
    Array.prototype.forEach.call(buttons, function (b) { b.disabled = !n; });
    if (all) {
      all.checked = n > 0 && n === boxes.length;
      all.indeterminate = n > 0 && n < boxes.length;
    }
  }

  if (all) {
    all.addEventListener("change", function () {
      ticks().forEach(function (b) { b.checked = all.checked; });
      refresh();
    });
  }
  document.addEventListener("change", function (e) {
    if (e.target.matches && e.target.matches("[data-repos-tick]")) { refresh(); }
  });
  form.addEventListener("submit", function (e) {
    var n = ticks().filter(function (b) { return b.checked; }).length;
    var hide = e.submitter && e.submitter.value === "hide";
    if (hide && !window.confirm("Remove " + n + " repositor" + (n === 1 ? "y" : "ies") +
                                " from this site?  They will not be linked again " +
                                "unless someone links them by hand.")) {
      e.preventDefault();
    }
  });
  refresh();
})();
