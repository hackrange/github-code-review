/* The connection panel adds one and edits one.  Same trick as the others:
 * point the form at the right place, and do not offer to rename an account
 * that findings are already labeled with. */
(function () {
  "use strict";
  var form = document.getElementById("connection-form");
  if (!form) { return; }
  var head = form.querySelector(".modal-head");

  document.querySelectorAll('[data-modal="connection-modal"]').forEach(function (trigger) {
    trigger.addEventListener("click", function () {
      var id = trigger.getAttribute("data-connection_id");
      if (head) {
        head.childNodes[0].nodeValue = id ? "Edit connection " : "Add a connection ";
      }
      applyProvider(trigger.getAttribute("data-provider") || "github");

      /* The generic filler only fills fields that hold text, because writing a
       * row's value onto a tick box replaces the value it submits.  So the two
       * digest boxes are ticked here, and cleared here: the last connection's
       * answer left in this one's form is a quiet way to start mailing the
       * wrong people. */
      [["notify_application_owner", "data-notify_application_owner"],
       ["notify_technical_owner", "data-notify_technical_owner"]]
        .forEach(function (pair) {
          var box = form.querySelector('[name="' + pair[0] + '"]');
          if (box) { box.checked = trigger.getAttribute(pair[1]) === "1"; }
        });

      /* Several labels can apply at once, so they are tick boxes rather than a
       * field the generic filler understands. */
      var carried = (trigger.getAttribute("data-sensitivity") || "")
        .split(",").map(function (t) { return t.trim().toLowerCase(); });
      form.querySelectorAll('[name^="sensitivity:"]').forEach(function (box) {
        var label = box.getAttribute("name").slice("sensitivity:".length);
        box.checked = carried.indexOf(label.trim().toLowerCase()) !== -1;
      });
    });
  });

  /* Show the fields that belong to the host somebody picked.
   *
   * A GitHub App is a GitHub idea, an organization is not what GitLab calls a
   * group, and the API address defaults are different.  Offering all of it at
   * once means most of the form is wrong whichever you chose. */
  var select = document.getElementById("provider-select");

  var DEFAULTS = {
    github: {api: "https://api.github.com", web: "https://github.com",
             label: "Organization", placeholder: "acme",
             addressLabel: "Web address", token: "github_pat_... or ghp_..."},
    gitlab: {api: "https://gitlab.com/api/v4", web: "https://gitlab.com",
             label: "Group", placeholder: "acme/platform",
             addressLabel: "GitLab address", token: "glpat-..."},
    bitbucket: {api: "https://api.bitbucket.org/2.0", web: "https://bitbucket.org",
                label: "Workspace", placeholder: "acme",
                addressLabel: "Web address", token: "an access token"},
    azure: {api: "https://dev.azure.com", web: "https://dev.azure.com",
            label: "Organization", placeholder: "acme",
            addressLabel: "Azure DevOps address",
            token: "a personal access token with Code (read)"},
    assembla: {api: "https://api.assembla.com/v1", web: "https://app.assembla.com",
               label: "Space", placeholder: "acme",
               addressLabel: "Web address",
               token: "the API secret, with the key in the username"},
    beanstalk: {api: "", web: "https://acme.beanstalkapp.com",
                label: "Account", placeholder: "acme",
                addressLabel: "Account address",
                token: "an access token, with the username beside it"},
    codecommit: {api: "", web: "https://console.aws.amazon.com/codesuite/codecommit",
                 label: "Region", placeholder: "us-east-1",
                 addressLabel: "Console address",
                 token: "not used; the AWS CLI signs its own calls"},
    gcsr: {api: "https://sourcerepo.googleapis.com/v1",
           web: "https://source.cloud.google.com",
           label: "Project", placeholder: "acme-prod",
           addressLabel: "Web address",
           token: "not used; gcloud provides the token"},
    subversion: {api: "", web: "https://svn.example.com/repos",
                 label: "Server", placeholder: "repos",
                 addressLabel: "Subversion address",
                 token: "the password, with the username beside it"},
    perforce: {api: "ssl:perforce.example.com:1666", web: "",
               label: "Server", placeholder: "perforce",
               addressLabel: "P4PORT",
               token: "the password or ticket, with the user beside it"}
  };

  /* The two that cannot see history say so before somebody sets one up,
     rather than after a scan comes back thinner than expected. */
  var NO_HISTORY = {subversion: true, perforce: true};

  function applyProvider(name) {
    if (!DEFAULTS[name]) { name = "github"; }
    if (select) { select.value = name; }

    form.querySelectorAll("[data-for]").forEach(function (el) {
      el.hidden = el.getAttribute("data-for") !== name;
    });
    form.querySelectorAll("[data-help]").forEach(function (el) {
      el.hidden = el.getAttribute("data-help") !== name;
    });

    var note = form.querySelector("[data-provider-note]");
    if (note) { note.hidden = !NO_HISTORY[name]; }

    var spec = DEFAULTS[name];
    var label = form.querySelector('[data-label-for="organizations"]');
    if (label) { label.textContent = spec.label; }

    var orgs = form.querySelector('[name="organizations"]');
    if (orgs) { orgs.placeholder = spec.placeholder; }

    var addressLabel = form.querySelector('[data-label-for="web_url"]');
    if (addressLabel) { addressLabel.textContent = spec.addressLabel; }

    var token = form.querySelector('[name="token"]');
    if (token) { token.placeholder = spec.token; }

    /* Only ever fill in an address that is empty or still the other host's
     * default.  Somebody who typed their own Enterprise or self managed
     * address should not lose it because they changed the picker back. */
    ["api_url", "web_url"].forEach(function (field) {
      var input = form.querySelector('[name="' + field + '"]');
      if (!input) { return; }
      var key = field === "api_url" ? "api" : "web";
      var others = Object.keys(DEFAULTS).map(function (p) { return DEFAULTS[p][key]; });
      if (!input.value || others.indexOf(input.value) !== -1) {
        input.value = spec[key];
      }
      input.placeholder = spec[key];
    });

    /* A GitHub App cannot be chosen anywhere else, so do not leave it selected
     * where it would be refused on save. */
    var method = form.querySelector('[name="auth_method"]');
    if (method && name !== "github" && method.value === "app") { method.value = "pat"; }
  }

  /* GitLab's API address is the instance address with /api/v4 on the end, so
   * asking for both is asking somebody to type the same host twice and get one
   * of them subtly wrong.  It fills itself in as you type the address, and
   * stops the moment anybody edits it by hand: an instance that serves the API
   * somewhere else must still be able to say so. */
  var apiInput = form.querySelector('[name="api_url"]');
  var webInput = form.querySelector('[name="web_url"]');

  if (apiInput) {
    apiInput.addEventListener("input", function () { apiInput.dataset.touched = "1"; });
    apiInput.addEventListener("blur", tidyApi);
  }

  /* Mirrors the tidying the server does, so the box shows what will actually
   * be saved rather than something the server quietly rewrites afterwards. */
  function tidy(value) {
    value = (value || "").trim();
    if (!value) { return ""; }
    if (!/^https?:\/\//.test(value)) { value = "https://" + value.replace(/^\/+/, ""); }
    return value.replace(/\/+$/, "");
  }

  function deriveApi() {
    if (!apiInput || !webInput) { return; }
    if (!select || select.value !== "gitlab") { return; }
    if (apiInput.dataset.touched === "1") { return; }
    var host = tidy(webInput.value);
    if (host) { apiInput.value = host + "/api/v4"; }
  }

  /* And if somebody pastes the endpoint they just tried in a browser, cut it
   * back to the base rather than saving something that cannot work. */
  function tidyApi() {
    if (!apiInput || !select || select.value !== "gitlab") { return; }
    var value = tidy(apiInput.value);
    if (!value) { return; }
    var match = value.match(/^(.*?\/api\/v\d+)(\/.*)?$/);
    apiInput.value = match ? match[1] : value + "/api/v4";
  }

  if (webInput) {
    webInput.addEventListener("input", deriveApi);
    webInput.addEventListener("blur", function () {
      webInput.value = tidy(webInput.value);
      deriveApi();
    });
  }

  if (select) {
    select.addEventListener("change", function () {
      /* A new host means the old address is not theirs any more. */
      if (apiInput) { delete apiInput.dataset.touched; }
      applyProvider(select.value);
    });
  }
  applyProvider(select ? select.value : "github");

  /* ---- the branches past scans found ------------------------------------
   *
   * Typing a branch name from memory is how somebody ends up with a filter
   * that matches nothing, scans no code, and reports success.  The scanner
   * already walked these, so they are offered as something to click.
   *
   * Only for a connection that exists: a new one has no id and nothing has
   * ever been scanned under it, so the link stays hidden rather than offering
   * an empty list. */
  var picker = form.querySelector("[data-branch-picker]");
  var loadLink = form.querySelector("[data-branch-load]");
  var noteEl = form.querySelector("[data-branch-note]");
  var listEl = form.querySelector("[data-branch-list]");
  var filterEl = form.querySelector("[data-branch-filter]");
  var idField = form.querySelector('[name="connection_id"]');
  var box = form.querySelector('[name="branches"]');
  var loadedFor = null;
  var loaded = [];

  /* The endpoint sits under the same prefix the form posts to, so an install
   * served from a sub path does not need to be told about it twice. */
  function endpointFor(id) {
    return form.getAttribute("action").replace(/\/connections\/save$/,
                                               "/connections/" + id + "/branches");
  }

  function chosen() {
    return (box && box.value ? box.value : "").split(/[\n,]/)
      .map(function (line) { return line.trim(); })
      .filter(function (line) { return line !== ""; });
  }

  function add(name) {
    if (!box) { return; }
    var lines = chosen();
    var at = lines.indexOf(name);
    if (at === -1) { lines.push(name); } else { lines.splice(at, 1); }
    box.value = lines.join("\n");
    paint();
  }

  function paint() {
    if (!listEl) { return; }
    var wanted = (filterEl && filterEl.value ? filterEl.value : "").toLowerCase();
    var picked = chosen();
    listEl.textContent = "";
    var shown = 0;
    loaded.forEach(function (entry) {
      if (wanted && entry.name.toLowerCase().indexOf(wanted) === -1) { return; }
      shown += 1;
      var chip = document.createElement("button");
      chip.type = "button";
      chip.className = "branch-chip";
      chip.textContent = entry.name;
      if (picked.indexOf(entry.name) !== -1) { chip.setAttribute("data-on", "1"); }
      var count = document.createElement("span");
      count.className = "count";
      /* How many repositories carry it, so the two or three that are actually
       * the estate's branches stand out from one person's feature branch. */
      count.textContent = entry.repositories;
      chip.title = entry.repositories + " repository(s)" +
        (entry.default_for ? ", the default branch in " + entry.default_for : "");
      chip.appendChild(count);
      chip.addEventListener("click", function () { add(entry.name); });
      listEl.appendChild(chip);
    });
    if (!shown && wanted) {
      var none = document.createElement("span");
      none.className = "faint small";
      none.textContent = "Nothing found matches that.";
      listEl.appendChild(none);
    }
  }

  function describe(answer) {
    if (!answer.branches.length) {
      return answer.repositories
        ? "Nothing scanned under this one has named a branch yet."
        : "Nothing has been scanned under this connection yet.";
    }
    var text = answer.branches.length + " of " + answer.total + " name(s)";
    if (answer.branches.length === answer.total) {
      text = answer.total + " name(s)";
    }
    text += " across " + answer.repositories + " repository(s)";
    /* Say where they came from.  Names off old findings are only the branches
     * that carried one, which is not the same as every branch there is, and a
     * picker that implies otherwise is worse than one that admits it. */
    if (answer.source === "findings") {
      text += ", from findings only, so branches with nothing on them are missing";
    } else if (answer.source === "both") {
      text += ", from what scans walked plus older findings";
    }
    return text + ".";
  }

  function load(event) {
    if (event) { event.preventDefault(); }
    var id = idField && idField.value;
    if (!id) { return; }
    if (noteEl) { noteEl.textContent = " Loading\u2026"; }
    fetch(endpointFor(id), {credentials: "same-origin"})
      .then(function (response) {
        if (!response.ok) { throw new Error(response.status); }
        return response.json();
      })
      .then(function (answer) {
        loadedFor = id;
        loaded = answer.branches || [];
        if (noteEl) { noteEl.textContent = " " + describe(answer); }
        if (filterEl) { filterEl.hidden = loaded.length < 12; }
        if (loadLink) { loadLink.hidden = true; }
        paint();
      })
      .catch(function () {
        if (noteEl) {
          noteEl.textContent = " Could not read what past scans found.";
        }
        if (loadLink) { loadLink.hidden = false; }
      });
  }

  if (loadLink) { loadLink.addEventListener("click", load); }
  if (filterEl) { filterEl.addEventListener("input", paint); }
  if (box) { box.addEventListener("input", paint); }

  /* Opening the panel is what decides whether any of this applies, and to
   * which connection.  Reset first: the last one's names in this one's form
   * would be a quiet way to scan the wrong branches. */
  document.querySelectorAll('[data-modal="connection-modal"]').forEach(function (trigger) {
    trigger.addEventListener("click", function () {
      var id = trigger.getAttribute("data-connection_id") || "";
      if (picker) { picker.hidden = !id; }
      if (loadLink) { loadLink.hidden = false; }
      if (filterEl) { filterEl.hidden = true; filterEl.value = ""; }
      if (noteEl) { noteEl.textContent = ""; }
      if (listEl) { listEl.textContent = ""; }
      if (String(loadedFor) !== String(id)) { loaded = []; loadedFor = null; }
    });
  });

  /* The help panels are part of the form, so a viewer with JS off still sees
   * the GitHub one rather than nothing at all. */
})();
