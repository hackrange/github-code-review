/* Open a repository to see what it is.
 *
 * Delegated from the table body rather than bound per row, and the same
 * behavior the audit log uses, so the two read the same way. */
(function () {
  "use strict";

  var table = document.getElementById("repo-reach-table");
  if (!table) { return; }
  var body = table.querySelector("tbody");
  if (!body) { return; }

  body.addEventListener("click", function (event) {
    /* A link or a form inside the panel is itself, not a toggle. */
    if (event.target.closest("a, form, textarea, button, input")) { return; }
    var row = event.target.closest("tr[data-repo-row]");
    if (!row) { return; }
    var panel = document.getElementById(row.getAttribute("aria-controls"));
    if (!panel) { return; }
    var open = panel.hidden;
    panel.hidden = !open;
    row.setAttribute("aria-expanded", open ? "true" : "false");
  });

  body.addEventListener("keydown", function (event) {
    if (event.key !== "Enter" && event.key !== " ") { return; }
    var row = event.target.closest("tr[data-repo-row]");
    if (!row) { return; }
    event.preventDefault();
    row.click();
  });
})();
