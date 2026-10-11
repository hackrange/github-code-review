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
 *
 * Drop downs narrow it too.  The value has to be one of the words in that
 * attribute on the row, and an empty value means any:
 *
 *   <select data-filter-by="repo-table" data-filter-key="org">
 *   <tr data-org="acme">
 *
 * Rows that carry data-branches also take branch=name and branch!=name in
 * the search box, and any [data-branch-name] inside the row that the search
 * did not name is hidden.  A row is shown when one of its branches is named by an =
 * term, if there are any, and is not named by any != term.  So
 * "branch!=master branch!=main" means some branch other than those two, which
 * is what somebody writing it means, rather than the always true thing the
 * same words say as logic.  OR and AND are allowed and change nothing.
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

  /* release/* and the like.  Whole name, any case. */
  function glob(text) {
    var body = text.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
    return new RegExp("^" + body + "$", "i");
  }

  function parse(value, branchy) {
    var out = { words: [], want: [], skip: [] };
    var text = value.replace(/\s*(!=|=)\s*/g, "$1");
    text.split(/\s+/).forEach(function (word) {
      if (!word) { return; }
      if (/^(or|and|\||&|&&|\|\|)$/i.test(word)) { return; }
      var m = branchy && /^branch(!=|=|:)(.+)$/i.exec(word);
      if (m) {
        (m[1] === "!=" ? out.skip : out.want).push(glob(m[2]));
      } else {
        out.words.push(word.toLowerCase());
      }
    });
    return out;
  }

  function branchHits(names, query) {
    return names.filter(function (name) {
      var wanted = !query.want.length || query.want.some(function (re) { return re.test(name); });
      return wanted && !query.skip.some(function (re) { return re.test(name); });
    });
  }

  function wire(id) {
    var table = document.getElementById(id);
    if (!table) { return; }

    var input = document.querySelector('input[data-filter="' + id + '"]');
    var selects = Array.prototype.slice.call(
      document.querySelectorAll('[data-filter-by="' + id + '"]'));
    var counter = document.querySelector('[data-filter-count="' + id + '"]');
    var rows = rowsOf(table);
    if (!rows.length) { return; }

    /* Read each row once. Doing this per keystroke is what makes a filter
     * feel heavy on a long page. */
    var text = rows.map(function (row) {
      return (row.textContent || "").toLowerCase().replace(/\s+/g, " ");
    });
    var branches = rows.map(function (row) {
      var raw = row.getAttribute("data-branches");
      return raw === null ? null : raw.split(/\s+/).filter(Boolean);
    });
    var branchy = branches.some(function (b) { return b !== null; });
    var total = rows.length;

    function apply() {
      var query = parse(input ? input.value : "", branchy);
      var picks = selects.filter(function (s) { return s.value; }).map(function (s) {
        return { key: "data-" + s.getAttribute("data-filter-key"), value: s.value };
      });
      var byBranch = query.want.length || query.skip.length;
      var narrowed = query.words.length || byBranch || picks.length;
      var shown = 0;
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var keep = !query.words.length || matches(text[i], query.words);
        for (var p = 0; keep && p < picks.length; p++) {
          var have = (row.getAttribute(picks[p].key) || "").split(/\s+/);
          keep = have.indexOf(picks[p].value) !== -1;
        }
        var hits = null;
        if (keep && byBranch && branches[i] !== null) {
          hits = branchHits(branches[i], query);
          keep = hits.length > 0;
        }
        row.hidden = !keep;
        if (keep) { shown++; }

        /* A row that lists its branches one by one shows only the ones the
         * search named, opened up so they can be seen and ticked. */
        var labels = row.querySelectorAll("[data-branch-name]");
        for (var l = 0; l < labels.length; l++) {
          labels[l].hidden = !!(hits && keep) &&
            hits.indexOf(labels[l].getAttribute("data-branch-name")) === -1;
        }
        if (labels.length && hits && keep) {
          row.querySelectorAll("details").forEach(function (d) { d.open = true; });
        }

        /* Which branches matched, on the row, so the reason it is shown can
         * be read without opening anything. */
        var cell = row.querySelector("[data-branch-hits]");
        if (cell) {
          if (hits && keep) {
            var list = hits.slice(0, 4).join(", ");
            if (hits.length > 4) { list += " and " + (hits.length - 4) + " more"; }
            cell.textContent = hits.length + " match: " + list;
            cell.hidden = false;
          } else {
            cell.hidden = true;
          }
        }
      }
      if (counter) {
        counter.textContent = narrowed
          ? shown + " of " + total
          : total + (total === 1 ? " row" : " rows");
      }
      var empty = document.querySelector('[data-filter-empty="' + id + '"]');
      if (empty) { empty.hidden = shown !== 0; }
      table.dispatchEvent(new CustomEvent("tablefilter", { bubbles: true }));
    }

    if (input) { input.addEventListener("input", apply); }
    selects.forEach(function (s) { s.addEventListener("change", apply); });
    /* A back button can restore a typed value without firing input. */
    apply();
  }

  var ids = {};
  document.querySelectorAll("[data-filter], [data-filter-by]").forEach(function (el) {
    ids[el.getAttribute("data-filter") || el.getAttribute("data-filter-by")] = true;
  });
  Object.keys(ids).forEach(wire);
})();
