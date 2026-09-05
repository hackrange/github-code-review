/* Show the fields that go with the sign in method, and hide the rest.
 *
 * Three empty boxes for a GitHub App on a page where somebody is pasting a
 * token is how you end up wondering whether you were supposed to fill them
 * in. */
(function () {
  "use strict";

  var picker = document.getElementById("auth-method");
  if (!picker) { return; }

  function apply() {
    var app = picker.value === "app";
    document.querySelectorAll("[data-app-only]").forEach(function (node) {
      node.hidden = !app;
    });
    document.querySelectorAll("[data-pat-only]").forEach(function (node) {
      node.hidden = app;
    });
  }

  picker.addEventListener("change", apply);
  apply();
})();
