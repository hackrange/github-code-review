/* The account panel does double duty: it adds one and it edits one.
 *
 * The generic modal code copies the row into the form for us.  What is left is
 * pointing the form at the right place, and not offering to change a username
 * or a sign in method on an account that already exists.  Both of those are
 * decisions somebody would have to unpick later. */
(function () {
  "use strict";

  var form = document.getElementById("user-form");
  if (!form) { return; }

  var base = form.getAttribute("action").replace(/\/users\/add$/, "");
  var username = form.querySelector('[name="username"]');
  var head = form.querySelector(".modal-head");

  document.querySelectorAll('[data-modal="user-modal"]').forEach(function (trigger) {
    trigger.addEventListener("click", function () {
      var id = trigger.getAttribute("data-user_id");
      var editing = !!id;

      form.setAttribute("action", editing ? base + "/users/" + id + "/save"
                                          : base + "/users/add");
      if (username) {
        username.readOnly = editing;
        username.required = !editing;
      }
      form.querySelectorAll("[data-new-only]").forEach(function (node) {
        node.hidden = editing;
      });

      /* Tick the groups this person is already in, and the pin.
       *
       * After the generic modal code, not before it.  That code runs second
       * on the same click: it puts every tick box back to the template's
       * default, then reads data-groups="3,5" as a yes or no for the first
       * box named groups.  Ticking them here first meant all of it was
       * undone, and a person's scanning groups opened unticked, so saving
       * the account quietly took them out of every group.  An External
       * sites group only looked kept when its id happened to be 1. */
      setTimeout(function () {
        var mine = (trigger.getAttribute("data-groups") || "")
          .split(",").filter(function (x) { return x; });
        form.querySelectorAll("[data-group-pick]").forEach(function (box) {
          box.checked = mine.indexOf(box.getAttribute("data-group-pick")) !== -1;
        });
        var sites = (trigger.getAttribute("data-site_groups") || "")
          .split(",").filter(function (x) { return x; });
        form.querySelectorAll("[data-site-group-pick]").forEach(function (box) {
          box.checked = sites.indexOf(box.getAttribute("data-site-group-pick")) !== -1;
        });
        var pin = form.querySelector("[data-role-pin]");
        if (pin) {
          pin.checked = !!trigger.getAttribute("data-role_pinned");
        }
      }, 0);
      if (head) {
        head.childNodes[0].nodeValue = editing ? "Edit account " : "Add an account ";
      }
    });
  });
})();

/* The group panel adds one and edits one. */
(function () {
  "use strict";
  var form = document.getElementById("group-form");
  if (!form) { return; }
  var base = form.getAttribute("action").replace(/\/groups\/save$/, "");
  var head = form.querySelector(".modal-head");

  document.querySelectorAll('[data-modal="group-modal"]').forEach(function (trigger) {
    trigger.addEventListener("click", function () {
      var id = trigger.getAttribute("data-group_id");
      form.setAttribute("action", base + "/groups/save");
      if (head) {
        head.childNodes[0].nodeValue = id ? "Edit group " : "Add a group ";
      }
    });
  });
})();

/* The External sites group panel adds one and edits one. */
(function () {
  "use strict";
  var form = document.getElementById("site-group-form");
  if (!form) { return; }
  var head = form.querySelector(".modal-head");
  document.querySelectorAll('[data-modal="site-group-modal"]').forEach(function (trigger) {
    trigger.addEventListener("click", function () {
      if (head) {
        head.childNodes[0].nodeValue = trigger.getAttribute("data-group_id")
          ? "Edit External sites group " : "Add an External sites group ";
      }
    });
  });
})();
