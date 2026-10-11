/* Ticking branches on one repository's scope page.
 *
 * The same rules as the repository list: ticks survive a change of search,
 * the bar says how many are out of sight, the box in the header ticks what is
 * shown and nothing else, and a shift click ticks the run between two boxes.
 * Every ticked branch is listed again on the confirmation page.
 */
(function () {
  "use strict";

  var form = document.getElementById("branch-bulk");
  if (!form) { return; }

  var all = document.getElementById("select-branches");
  var actions = Array.prototype.slice.call(
    form.querySelectorAll('button[type="submit"]'));
  var clear = form.querySelector("[data-clear]");
  var count = form.querySelector("[data-ticked]");
  var hiddenNote = form.querySelector("[data-ticked-hidden]");
  var last = null;

  function boxes() {
    return Array.prototype.slice.call(
      document.querySelectorAll('#branch-table input[name="branch"]'));
  }

  function visible(box) {
    var row = box.closest("tr");
    return row && !row.hidden;
  }

  function refresh() {
    var ticked = boxes().filter(function (b) { return b.checked; });
    var n = ticked.length;
    var out = n - ticked.filter(visible).length;
    count.textContent = n ? n + " ticked" : "Nothing ticked";
    hiddenNote.textContent = out ? "(" + out + " hidden by the search)" : "";
    actions.forEach(function (b) { b.disabled = n === 0; });
    if (clear) { clear.hidden = n === 0; }
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
    if (!box || box.name !== "branch" || !box.closest("#branch-table")) { return; }
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

  if (clear) {
    clear.addEventListener("click", function () {
      boxes().forEach(function (box) { box.checked = false; });
      refresh();
    });
  }

  /* On screen while the list scrolls past.  See scopebulk.js for why this
   * is not CSS sticky. */
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
    form.style.left = lift ? spot.left + "px" : "";
    form.style.width = lift ? spot.width + "px" : "";
  }
  window.addEventListener("scroll", place, { passive: true });
  window.addEventListener("resize", place);

  document.addEventListener("tablefilter", refresh);
  refresh();
  place();
})();
