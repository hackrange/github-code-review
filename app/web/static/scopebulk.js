/* The scan scope bar over the repository table.
 *
 * Ticks stay put when the filters change, so somebody can tick one
 * organization, switch to another and tick some more, and send the lot as
 * one change.  The bar says how many of the ticked ones the filters are
 * hiding, because a change to a repository nobody can see on the screen is a
 * change nobody checked.  The confirmation page lists every one of them again
 * before anything happens.
 *
 * The box in the header ticks what is shown and nothing else, and a shift
 * click ticks the run of shown rows between two boxes.
 */
(function () {
  "use strict";

  var form = document.getElementById("scope-bulk");
  if (!form) { return; }

  var all = document.getElementById("select-repos");
  var submit = form.querySelector('button[type="submit"]');
  var clear = form.querySelector("[data-clear]");
  var count = form.querySelector("[data-ticked]");
  var hiddenNote = form.querySelector("[data-ticked-hidden]");
  var patterns = document.getElementById("scope-bulk-patterns");
  var search = document.getElementById("repo-search");
  var last = null;

  function boxes() {
    return Array.prototype.slice.call(
      document.querySelectorAll('#repo-table input[name="repo"]'));
  }

  function visible(box) {
    var row = box.closest("tr");
    return row && !row.hidden;
  }

  function mode() {
    var picked = form.querySelector('input[name="mode"]:checked');
    return picked ? picked.value : "";
  }

  /* branch=main OR branch=master in the search box is very likely the list
   * somebody wants a full scan on, so it is offered as a start. */
  function branchesFromSearch() {
    if (!search) { return ""; }
    var found = [];
    search.value.replace(/\s*=\s*/g, "=").split(/\s+/).forEach(function (word) {
      var m = /^branch[=:](.+)$/i.exec(word);
      if (m) { found.push(m[1]); }
    });
    return found.join(", ");
  }

  function refresh() {
    var ticked = boxes().filter(function (b) { return b.checked; });
    var shown = ticked.filter(visible).length;
    var n = ticked.length;
    count.textContent = n ? n + " ticked" : "Nothing ticked";
    hiddenNote.textContent = n > shown
      ? "(" + (n - shown) + " hidden by the filters)" : "";
    if (clear) { clear.hidden = n === 0; }

    var chosen = mode() === "chosen";
    patterns.hidden = !chosen;
    patterns.required = chosen;
    patterns.disabled = !chosen;
    submit.disabled = !n || !mode() || (chosen && !patterns.value.trim());

    if (all) {
      var onScreen = boxes().filter(visible);
      var on = onScreen.filter(function (b) { return b.checked; }).length;
      all.checked = onScreen.length > 0 && on === onScreen.length;
      all.indeterminate = on > 0 && on < onScreen.length;
    }
  }

  if (all) {
    all.addEventListener("change", function () {
      boxes().filter(visible).forEach(function (box) { box.checked = all.checked; });
      refresh();
    });
  }

  document.addEventListener("click", function (event) {
    var box = event.target;
    if (!box || box.name !== "repo" || !box.closest("#repo-table")) { return; }
    if (event.shiftKey && last && last !== box) {
      var shown = boxes().filter(visible);
      var a = shown.indexOf(last), b = shown.indexOf(box);
      if (a !== -1 && b !== -1) {
        shown.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(function (x) {
          x.checked = box.checked;
        });
      }
    }
    last = box;
    refresh();
  });

  form.addEventListener("change", function (event) {
    if (event.target.name === "mode" && mode() === "chosen" && !patterns.value.trim()) {
      patterns.value = branchesFromSearch();
      patterns.focus();
    }
    refresh();
  });
  patterns.addEventListener("input", refresh);

  if (clear) {
    clear.addEventListener("click", function () {
      boxes().forEach(function (box) { box.checked = false; });
      refresh();
    });
  }

  /* Keep the bar on screen while the table scrolls past.  CSS sticky cannot
   * do it here: .content is a scroll container that never scrolls, so a
   * sticky child sticks to that rather than to the window.  A spacer holds
   * the bar's place so the table does not jump when it lifts out. */
  var card = form.closest(".card");
  var spacer = document.createElement("div");
  form.parentNode.insertBefore(spacer, form);
  function place() {
    var spot = spacer.getBoundingClientRect();
    var end = card ? card.getBoundingClientRect().bottom : Infinity;
    var lift = spot.top < 0 && end > form.offsetHeight + 40;
    if (lift && !form.classList.contains("floating")) {
      var gap = getComputedStyle(form);
      spacer.style.height = (form.offsetHeight + parseFloat(gap.marginTop) +
                             parseFloat(gap.marginBottom)) + "px";
      form.classList.add("floating");
    } else if (!lift && form.classList.contains("floating")) {
      spacer.style.height = "";
      form.classList.remove("floating");
    }
    if (lift) {
      form.style.left = spot.left + "px";
      form.style.width = spot.width + "px";
    } else {
      form.style.left = form.style.width = "";
    }
  }
  window.addEventListener("scroll", place, { passive: true });
  window.addEventListener("resize", place);

  document.addEventListener("tablefilter", refresh);
  refresh();
  place();
})();
