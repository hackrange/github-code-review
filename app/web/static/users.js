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

      /* Tick the groups this person is already in.  The generic modal code
       * copies values into fields by name, and a set of checkboxes is not a
       * field with a value. */
      var mine = (trigger.getAttribute("data-groups") || "")
        .split(",").filter(function (x) { return x; });
      form.querySelectorAll("[data-group-pick]").forEach(function (box) {
        box.checked = mine.indexOf(box.getAttribute("data-group-pick")) !== -1;
      });
      /* Same reason as the groups above: the generic code copies values into
       * fields, and a checkbox is a state rather than a value. */
      var pin = form.querySelector("[data-role-pin]");
      if (pin) {
        pin.checked = !!trigger.getAttribute("data-role_pinned");
      }
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
