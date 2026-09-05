/* Narrowing a table as somebody types.
 *
 * These pages already send the whole list to the browser: two hundred and
 * fifty nine repositories, nineteen organizations, and everybody with access
 * to one of them. Asking the server again on every keystroke would be slower
 * than looking at what is already here, and it would need a spinner to cover
 * a round trip that has nothing to do.
 *
 * Any table can opt in without touching this file:
 *
 *   <input data-filter="repo-table" ...>
 *   <span data-filter-count="repo-table"></span>
 *   <table id="repo-table"> ... rows in a tbody ...
 */
(function () {
  "use strict";

  function rowsOf(table) {
    var body = table.tBodies && table.tBodies[0];
    return body ? Array.prototype.slice.call(body.rows) : [];
  }

  /* Every word has to appear somewhere in the row, in any order and any
   * column, so "acme web" finds the web repository in the acme organization
   * without anybody having to know which column is which. */
  function matches(haystack, terms) {
    for (var i = 0; i < terms.length; i++) {
      if (haystack.indexOf(terms[i]) === -1) { return false; }
    }
    return true;
  }

  function wire(input) {
    var id = input.getAttribute("data-filter");
    var table = document.getElementById(id);
    if (!table) { return; }

    var counter = document.querySelector('[data-filter-count="' + id + '"]');
    var rows = rowsOf(table);
    if (!rows.length) { return; }

    /* Read each row once. Doing this per keystroke is what makes a filter
     * feel heavy on a long page. */
    var text = rows.map(function (row) {
      return (row.textContent || "").toLowerCase().replace(/\s+/g, " ");
    });
    var total = rows.length;

    function apply() {
      var terms = input.value.toLowerCase().split(/\s+/).filter(Boolean);
      var shown = 0;
      for (var i = 0; i < rows.length; i++) {
        var keep = !terms.length || matches(text[i], terms);
        rows[i].hidden = !keep;
        if (keep) { shown++; }
      }
      if (counter) {
        counter.textContent = terms.length
          ? shown + " of " + total
          : total + (total === 1 ? " row" : " rows");
      }
      var empty = document.querySelector('[data-filter-empty="' + id + '"]');
      if (empty) { empty.hidden = shown !== 0; }
    }

    input.addEventListener("input", apply);
    /* A back button can restore a typed value without firing input. */
    apply();
  }

  document.querySelectorAll("[data-filter]").forEach(wire);
})();
