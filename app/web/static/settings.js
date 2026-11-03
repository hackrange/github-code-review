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

/* Tabs.  The page is one long form, and nobody wants to scroll past sign in
 * to reach the reports.  Only the cards on the chosen tab show; the rest are
 * hidden, not removed, so the form still sends every field when it is saved.
 *
 * The tab comes from the address (#tab-reports, or a section such as
 * #external), then from the last one used, then the first.  A field the
 * browser refuses on a tab that is not showing would stop the save without
 * saying why, so its tab is opened first. */
(function () {
  "use strict";

  var links = Array.prototype.slice.call(
    document.querySelectorAll(".settings-tabs [data-tab]"));
  if (!links.length) { return; }
  var owner = {};
  links.forEach(function (link) {
    link.getAttribute("data-sections").split(" ").forEach(function (id) {
      owner[id] = link.getAttribute("data-tab");
    });
  });

  function remember(tab) {
    try { window.sessionStorage.setItem("gcr-settings-tab", tab); } catch (e) { /* private mode */ }
  }

  function recalled() {
    try { return window.sessionStorage.getItem("gcr-settings-tab"); } catch (e) { return null; }
  }

  function show(tab) {
    links.forEach(function (link) {
      var on = link.getAttribute("data-tab") === tab;
      link.classList.toggle("active", on);
      link.setAttribute("aria-selected", on ? "true" : "false");
    });
    Object.keys(owner).forEach(function (id) {
      var card = document.getElementById(id);
      if (card) { card.hidden = owner[id] !== tab; }
    });
    document.querySelectorAll("[data-on-tab]").forEach(function (node) {
      node.hidden = node.getAttribute("data-on-tab") !== tab;
    });
    remember(tab);
  }

  function fromHash() {
    var hash = (window.location.hash || "").replace(/^#/, "");
    if (hash.indexOf("tab-") === 0 && links.some(function (l) {
      return l.getAttribute("data-tab") === hash.slice(4); })) {
      return hash.slice(4);
    }
    return owner[hash] || null;
  }

  links.forEach(function (link) {
    link.addEventListener("click", function (event) {
      event.preventDefault();
      var tab = link.getAttribute("data-tab");
      show(tab);
      if (window.history && window.history.replaceState) {
        window.history.replaceState(null, "", "#tab-" + tab);
      }
    });
  });

  window.addEventListener("hashchange", function () {
    var tab = fromHash();
    if (tab) {
      show(tab);
      var target = document.getElementById(window.location.hash.slice(1));
      if (target && owner[target.id]) { target.scrollIntoView(); }
    }
  });

  var form = document.getElementById("settings-form");
  if (form) {
    form.addEventListener("invalid", function (event) {
      var card = event.target.closest(".card[id]");
      if (card && owner[card.id] && card.hidden) { show(owner[card.id]); }
    }, true);
  }

  var start = fromHash();
  var last = recalled();
  if (!start && last && links.some(function (l) { return l.getAttribute("data-tab") === last; })) {
    start = last;
  }
  show(start || links[0].getAttribute("data-tab"));
  var direct = document.getElementById((window.location.hash || "").slice(1));
  if (direct && owner[direct.id]) { direct.scrollIntoView(); }
})();
