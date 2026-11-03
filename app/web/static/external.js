/* The repository picker on External sites.
 *
 * Every repository the person may see, with the branches the scans found on
 * it, as tick boxes, searchable.  What is ticked goes into the form as
 * hidden "pick" fields, "<repository id>|<branch>", an empty branch meaning
 * the default one.  The list is fetched once and filtered here, so typing in
 * the search box does not go back to the server.
 *
 * The modal resets every field to its starting value each time it opens,
 * so each box's starting value is kept in step with what is picked.
 */
(function () {
  "use strict";

  var pickers = document.querySelectorAll("[data-picker]");
  if (!pickers.length) { return; }
  var base = (document.querySelector('meta[name="gcr-base"]') || {}).content || "";
  var SHOW = 150;
  var loading = null;

  function choices() {
    if (!loading) {
      loading = fetch(base + "/external/repo-choices", {credentials: "same-origin"})
        .then(function (r) { if (!r.ok) { throw new Error(r.status); } return r.json(); });
    }
    return loading;
  }

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    if (text) { node.textContent = text; }
    return node;
  }

  function setup(root) {
    var picked = {};
    try {
      JSON.parse(root.getAttribute("data-picked") || "[]").forEach(function (v) { picked[v] = true; });
    } catch (e) { /* nothing picked */ }
    var search = root.querySelector("[data-picker-search]");
    var list = root.querySelector("[data-picker-list]");
    var summary = root.querySelector("[data-picker-summary]");
    var hidden = root.querySelector("[data-picker-hidden]");
    var suggest = root.querySelector("[data-picker-suggest]");
    var repos = [];
    var form = root.closest("form");
    var asset = root.getAttribute("data-asset") || "";

    function writeHidden() {
      hidden.textContent = "";
      var keys = Object.keys(picked);
      keys.forEach(function (key) {
        hidden.appendChild(el("input", {type: "hidden", name: "pick", value: key}));
      });
      var names = {};
      keys.forEach(function (key) {
        var id = key.split("|")[0];
        var repo = repos.filter(function (r) { return String(r.id) === id; })[0];
        if (repo) { names[repo.full_name] = true; }
      });
      var count = Object.keys(names).length;
      summary.textContent = count
        ? count + " repositor" + (count === 1 ? "y" : "ies") + " picked: " +
          Object.keys(names).slice(0, 6).join(", ") + (count > 6 ? ", and more" : "")
        : "None picked.  Repositories are still worked out from web addresses and names.";
    }

    function box(key, label, cls) {
      var wrap = el("label", {"class": "check " + (cls || "")});
      var input = el("input", {type: "checkbox", value: key});
      input.checked = input.defaultChecked = !!picked[key];
      input.addEventListener("change", function () {
        if (input.checked) { picked[key] = true; } else { delete picked[key]; }
        input.defaultChecked = input.checked;
        writeHidden();
      });
      wrap.appendChild(input);
      wrap.appendChild(el("span", {}, label));
      return wrap;
    }

    function render() {
      var q = (search.value || "").trim().toLowerCase();
      list.textContent = "";
      var shown = 0, matched = 0;
      repos.forEach(function (repo) {
        var name = repo.full_name.toLowerCase();
        var branchHits = q ? repo.branches.filter(function (b) {
          return b.toLowerCase().indexOf(q) !== -1; }) : [];
        var hit = !q || name.indexOf(q) !== -1 || branchHits.length;
        var anyPicked = Object.keys(picked).some(function (k) {
          return k.split("|")[0] === String(repo.id); });
        if (!hit && !anyPicked) { return; }
        matched += 1;
        if (shown >= SHOW && !anyPicked) { return; }
        shown += 1;
        var row = el("div", {"class": "picker-repo"});
        row.appendChild(box(repo.id + "|", repo.full_name +
          (repo["default"] ? "  (default: " + repo["default"] + ")" : "") +
          (repo.archived ? "  archived" : ""), "picker-head"));
        var others = repo.branches.filter(function (b) { return b !== repo["default"]; });
        if (others.length || repo["default"]) {
          var more = el("details", {"class": "picker-branches"});
          var open = branchHits.length || repo.branches.some(function (b) {
            return picked[repo.id + "|" + b]; });
          if (open) { more.open = true; }
          more.appendChild(el("summary", {"class": "small faint"},
            repo.branches.length + " branch" + (repo.branches.length === 1 ? "" : "es")));
          (q && branchHits.length ? branchHits : repo.branches).forEach(function (b) {
            more.appendChild(box(repo.id + "|" + b, b, "picker-branch"));
          });
          row.appendChild(more);
        }
        list.appendChild(row);
      });
      if (!matched) {
        list.appendChild(el("div", {"class": "faint small"}, "Nothing matches that."));
      } else if (matched > shown) {
        list.appendChild(el("div", {"class": "faint small"},
          "Showing " + shown + " of " + matched + ".  Search to narrow it down."));
      }
    }

    /* Recommended: the repositories the Repositories page ties to these
     * hosts, by web address, another environment of one, or by name.  For a
     * new site the hosts come from the box above as they are typed. */
    function field(name) {
      var node = form && form.querySelector('[name="' + name + '"]');
      return node ? node.value : "";
    }

    function recommend() {
      if (!suggest) { return; }
      var hosts = field("hosts");
      var params = new URLSearchParams();
      if (asset) { params.set("asset", asset); }
      if (hosts) { params.set("hosts", hosts.split(/\n/).map(function (l) {
        return l.split(",")[0].trim(); }).filter(Boolean).slice(0, 50).join(",")); }
      params.set("application", field("application"));
      params.set("tags", field("tags"));
      if (!asset && !hosts.trim()) {
        suggest.textContent = "";
        suggest.appendChild(el("div", {"class": "faint small"},
          "Type the hosts above to see the repositories that go with them."));
        return;
      }
      fetch(base + "/external/repo-recommendations?" + params.toString(),
            {credentials: "same-origin"})
        .then(function (r) { if (!r.ok) { throw new Error(r.status); } return r.json(); })
        .then(function (answer) {
          var found = answer.repositories || [];
          suggest.textContent = "";
          (answer.applications || []).slice(0, 3).forEach(function (app) {
            var card = el("div", {"class": "picker-app small"});
            card.appendChild(el("div", {}, "Web Applications tab: " + (app.name || "an unnamed application") +
              (app.exact ? "" : " (another environment of one of its addresses)")));
            if (app.owners.length) { card.appendChild(el("div", {"class": "faint"}, "Business owners: " + app.owners.join(", "))); }
            if (app.technical.length) { card.appendChild(el("div", {"class": "faint"}, "Technical owners: " + app.technical.join(", "))); }
            var use = el("button", {type: "button", "class": "btn sm"}, "Use these");
            use.addEventListener("click", function () {
              var set = function (name, value) {
                var node = form && form.querySelector('[name="' + name + '"]');
                if (node && value) { node.value = value; node.defaultValue = value; }
              };
              set("application", app.name);
              set("executive_owner", app.owners.join(", "));
              set("technical_owner", app.technical.join(", "));
              use.textContent = "Filled in";
            });
            if (app.name || app.owners.length || app.technical.length) { card.appendChild(use); }
            suggest.appendChild(card);
          });
          if (!found.length) {
            suggest.appendChild(el("div", {"class": "faint small"},
              "Nothing on the Repositories page points at these hosts."));
            return;
          }
          suggest.appendChild(el("div", {"class": "small"}, "Recommended"));
          found.forEach(function (rec) {
            var row = box(rec.id + "|", rec.full_name, "picker-head");
            var why = el("div", {"class": "faint small picker-why"},
              rec.score + ": " + rec.reasons.join("; ") +
              (rec.links_itself ? ".  Links on its own; tick it to pick branches or keep it." : "."));
            row.appendChild(why);
            suggest.appendChild(row);
          });
        })
        .catch(function () {
          suggest.textContent = "";
          suggest.appendChild(el("div", {"class": "faint small"}, "Recommendations could not be loaded."));
        });
    }

    var waiting = null;
    ["hosts", "application", "tags"].forEach(function (name) {
      var node = form && form.querySelector('[name="' + name + '"]');
      if (node) {
        node.addEventListener("input", function () {
          clearTimeout(waiting);
          waiting = setTimeout(recommend, 500);
        });
      }
    });

    var timer = null;
    search.addEventListener("input", function () {
      clearTimeout(timer);
      timer = setTimeout(render, 120);
    });
    /* Enter in the search box would submit the whole form. */
    search.addEventListener("keydown", function (event) {
      if (event.key === "Enter") { event.preventDefault(); }
    });

    choices().then(function (data) {
      repos = data;
      writeHidden();
      render();
      recommend();
    }).catch(function () {
      summary.textContent = "The repositories could not be loaded.  Reload the page to try again.";
    });
  }

  Array.prototype.forEach.call(pickers, setup);
})();

/* Pages that are waiting on something reload themselves, but never while a
 * dialog is open: that would throw away whatever somebody was typing. */
(function () {
  "use strict";
  var meta = document.querySelector('meta[name="gcr-refresh"]');
  if (!meta) { return; }
  var seconds = Math.max(5, parseInt(meta.content, 10) || 15);
  setInterval(function () {
    var open = Array.prototype.some.call(
      document.querySelectorAll(".modal-backdrop"), function (n) { return !n.hidden; });
    if (!open && !document.hidden) { window.location.reload(); }
  }, seconds * 1000);
})();

/* The list: tick all, a count of what is ticked, actions that need a tick,
 * and a confirmation before removing anything.  A site page opened with
 * #scan opens its scan dialog, which is where the list's Scan button goes. */
(function () {
  "use strict";
  var boxes = function () { return document.querySelectorAll('input[name="id"][form="pick"]'); };
  var all = document.querySelector("[data-tick-all]");
  var count = document.querySelector("[data-tick-count]");
  function update() {
    var n = Array.prototype.filter.call(boxes(), function (b) { return b.checked; }).length;
    if (count) { count.textContent = n ? n + " ticked" : "Tick sites in the list to act on them."; }
    document.querySelectorAll("[data-needs-tick]").forEach(function (b) { b.disabled = !n; });
  }
  if (all) {
    all.addEventListener("change", function () {
      boxes().forEach(function (b) { b.checked = all.checked; });
      update();
    });
  }
  Array.prototype.forEach.call(boxes(), function (b) { b.addEventListener("change", update); });
  if (count) { update(); }
  document.querySelectorAll("[data-ext-confirm]").forEach(function (button) {
    button.addEventListener("click", function (event) {
      if (!window.confirm(button.getAttribute("data-ext-confirm"))) { event.preventDefault(); }
    });
  });
  /* After the page has loaded, when the dialog code is listening. */
  window.addEventListener("load", function () {
    if (window.location.hash === "#scan") {
      var open = document.querySelector('[data-modal="scan-modal"]');
      if (open) { open.click(); }
    }
  });
})();

/* The sign in fields: only the ones for the kind picked. */
(function () {
  "use strict";
  document.querySelectorAll("[data-auth-kind]").forEach(function (picker) {
    var scope = picker.closest("details") || document;
    function apply() {
      scope.querySelectorAll("[data-auth-for]").forEach(function (block) {
        block.hidden = block.getAttribute("data-auth-for") !== picker.value;
      });
    }
    picker.addEventListener("change", apply);
    /* The dialog puts every field back when it opens, without saying so. */
    document.addEventListener("click", function (event) {
      if (event.target.closest && event.target.closest("[data-modal]")) { setTimeout(apply, 0); }
    });
    apply();
  });
})();

/* The schedule dialog: only the fields for how often it runs. */
(function () {
  "use strict";
  document.querySelectorAll("[data-sched-frequency]").forEach(function (picker) {
    var form = picker.closest("form");
    function apply() {
      form.querySelectorAll("[data-sched-for]").forEach(function (field) {
        field.hidden = field.getAttribute("data-sched-for") !== picker.value;
      });
    }
    picker.addEventListener("change", apply);
    document.addEventListener("click", function (event) {
      if (event.target.closest && event.target.closest("[data-modal]")) { setTimeout(apply, 0); }
    });
    apply();
  });
})();
