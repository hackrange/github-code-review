/* Show the fields for the way mail is actually being sent.
 *
 * Offering SMTP and Microsoft 365 at once means most of the section is wrong
 * whichever one is in use, and a half filled set of the other one is a support
 * question waiting to happen. */
(function () {
  "use strict";

  var select = document.getElementById("mail-transport");
  if (!select) { return; }

  function apply() {
    var chosen = select.value === "graph" ? "graph" : "smtp";
    document.querySelectorAll("[data-mail]").forEach(function (block) {
      block.hidden = block.getAttribute("data-mail") !== chosen;
    });
  }

  select.addEventListener("change", apply);
  apply();
})();
