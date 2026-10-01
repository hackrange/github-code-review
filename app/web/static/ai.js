/* The AI page: show the settings for the provider in use, offer the models it
 * lists, and fill the template box with the example.
 *
 * Its own file rather than a script tag, for the same reason as every other
 * page: the content security policy has no unsafe-inline for scripts. */
(function () {
  "use strict";

  var base = (document.querySelector('meta[name="gcr-base"]') || {}).content || "";
  var csrf = (document.querySelector('meta[name="gcr-csrf"]') || {}).content || "";

  var select = document.getElementById("ai-provider");
  if (!select) { return; }

  function apply() {
    document.querySelectorAll("[data-ai]").forEach(function (block) {
      block.hidden = block.getAttribute("data-ai") !== select.value;
    });
  }
  select.addEventListener("change", apply);
  apply();

  /* Fill the template with the example, but never over something typed. */
  var copy = document.getElementById("ai-copy-example");
  var template = document.querySelector('textarea[name="ai.custom_template"]');
  if (copy && template) {
    copy.addEventListener("click", function () {
      if (template.value.trim() && !window.confirm("Replace what is in the box with the example?")) {
        return;
      }
      template.value = template.getAttribute("placeholder") || "";
    });
  }

  /* A list of models from the saved key.  Picking one fills the box, which is
   * what gets saved; the box still takes a name typed by hand. */
  document.querySelectorAll(".ai-model-pick").forEach(function (holder) {
    var target = document.getElementById(holder.getAttribute("data-target"));
    var button = document.createElement("button");
    button.type = "button";
    button.className = "btn";
    button.textContent = "List models";
    var picker = document.createElement("select");
    picker.hidden = true;
    var note = document.createElement("span");
    note.className = "faint small";
    holder.appendChild(button);
    holder.appendChild(picker);
    holder.appendChild(note);

    picker.addEventListener("change", function () {
      if (picker.value && target) { target.value = picker.value; }
    });

    button.addEventListener("click", function () {
      button.disabled = true;
      note.textContent = " Asking...";
      fetch(base + "/ai/models", {
        method: "POST",
        headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json" },
        body: JSON.stringify({ provider: holder.getAttribute("data-provider") }),
        credentials: "same-origin"
      }).then(function (response) { return response.json(); }).then(function (data) {
        picker.textContent = "";
        if (!data.ok) {
          note.textContent = " " + (data.error || "Could not list models.");
          picker.hidden = true;
          return;
        }
        var first = document.createElement("option");
        first.value = "";
        first.textContent = "Pick one of " + data.models.length;
        picker.appendChild(first);
        data.models.forEach(function (model) {
          var option = document.createElement("option");
          option.value = model.id;
          option.textContent = model.name && model.name !== model.id
            ? model.name + " (" + model.id + ")" : model.id;
          if (target && model.id === target.value) { option.selected = true; }
          picker.appendChild(option);
        });
        picker.hidden = false;
        note.textContent = "";
      }).catch(function () {
        note.textContent = " Could not list models.";
      }).then(function () {
        button.disabled = false;
      });
    });
  });
})();
