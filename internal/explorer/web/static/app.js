// Lupetto Explorer: progressive enhancement only. Pages work without this file
// except for live log streaming and automatic reloads. Text is inserted with
// text nodes / textContent only; nothing from the server is parsed as HTML.
(function () {
  "use strict";

  function getJSON(url) {
    return fetch(url, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } })
      .then(function (response) {
        if (!response.ok) {
          return response.text().then(function (text) { throw new Error(text || response.statusText); });
        }
        return response.json();
      });
  }

  function field(object, path) {
    return path.split(".").reduce(function (value, key) {
      return value == null ? undefined : value[key];
    }, object);
  }

  // Reload the page once a JSON flag (e.g. status.refreshing) becomes false.
  function pollUntilIdle(element) {
    var url = element.getAttribute("data-poll-url");
    var path = element.getAttribute("data-poll-field");
    var delay = 2500;
    function tick() {
      getJSON(url).then(function (data) {
        if (!field(data, path)) {
          window.location.reload();
          return;
        }
        delay = 2500;
        window.setTimeout(tick, delay);
      }).catch(function () {
        delay = Math.min(delay * 2, 30000);
        window.setTimeout(tick, delay);
      });
    }
    window.setTimeout(tick, delay);
  }

  // Live job log: append chunks from the absolute stderr offset until done.
  function streamLog(log) {
    var url = log.getAttribute("data-log-url");
    var offset = Number(log.getAttribute("data-log-offset")) || 0;
    var status = document.getElementById("log-status");
    var delay = 1500;

    function setStatus(text) {
      if (status) { status.textContent = text; }
    }
    function nearBottom() {
      return log.scrollHeight - log.scrollTop - log.clientHeight < 40;
    }
    function appendMarker() {
      var marker = document.createElement("span");
      marker.className = "log-marker";
      marker.textContent = "\n[earlier output discarded]\n";
      log.appendChild(marker);
    }
    function tick() {
      getJSON(url + "?offset=" + encodeURIComponent(String(offset))).then(function (chunk) {
        var follow = nearBottom();
        if (chunk.truncated && chunk.offset > offset) {
          appendMarker();
        }
        if (chunk.text) {
          log.appendChild(document.createTextNode(chunk.text));
        }
        if (typeof chunk.nextOffset === "number") {
          offset = chunk.nextOffset;
        }
        if (follow) { log.scrollTop = log.scrollHeight; }
        if (chunk.done) {
          setStatus("Finished — reloading for the build record…");
          window.setTimeout(function () { window.location.reload(); }, 800);
          return;
        }
        delay = 1500;
        setStatus("Live — updating…");
        window.setTimeout(tick, delay);
      }).catch(function (error) {
        delay = Math.min(delay * 2, 30000);
        setStatus("Log update failed (" + error.message + "); retrying…");
        window.setTimeout(tick, delay);
      });
    }
    log.scrollTop = log.scrollHeight;
    window.setTimeout(tick, delay);
  }

  // Only one build runs at a time: disable build buttons while one is running.
  function guardBuildForms(forms) {
    getJSON("/jobs?format=json").then(function (data) {
      if (!data || !data.running) { return; }
      var running = (data.jobs || []).filter(function (job) { return job.state === "running"; })[0];
      forms.forEach(function (form) {
        var button = form.querySelector("button[type=submit]");
        if (!button) { return; }
        button.disabled = true;
        var note = document.createElement("span");
        note.className = "build-busy";
        if (running) {
          var link = document.createElement("a");
          link.href = "/jobs/" + encodeURIComponent(String(running.id));
          link.textContent = "job #" + running.id;
          note.appendChild(document.createTextNode("Build running: "));
          note.appendChild(link);
        } else {
          note.textContent = "A build is running";
        }
        form.appendChild(note);
      });
    }).catch(function () { /* the server still rejects concurrent builds with 409 */ });
    forms.forEach(function (form) {
      form.addEventListener("submit", function () {
        var button = form.querySelector("button[type=submit]");
        if (button) {
          // Defer so the submission itself is not cancelled by disabling.
          window.setTimeout(function () { button.disabled = true; }, 0);
        }
      });
    });
  }

  function init() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-poll-url][data-poll-field]"), pollUntilIdle);
    var log = document.querySelector("#job-log[data-log-url]");
    if (log) { streamLog(log); }
    var forms = Array.prototype.slice.call(document.querySelectorAll("form[data-build-form]"));
    if (forms.length) { guardBuildForms(forms); }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
