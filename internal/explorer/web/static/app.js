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
  // With data-poll-error-field/data-poll-unless-field, a reported error while
  // the "unless" value is still missing (e.g. lastError with no document)
  // stops polling and shows the error instead of retrying forever.
  function pollUntilIdle(element) {
    var url = element.getAttribute("data-poll-url");
    var path = element.getAttribute("data-poll-field");
    var errorPath = element.getAttribute("data-poll-error-field");
    var unlessPath = element.getAttribute("data-poll-unless-field");
    var delay = 2500;
    function showError(message) {
      element.className = "callout callout-bad";
      element.setAttribute("role", "alert");
      element.textContent = "";
      var strong = document.createElement("strong");
      strong.textContent = "Loading failed; polling stopped. Reload the page to retry.";
      var pre = document.createElement("pre");
      pre.className = "error-text";
      pre.textContent = message;
      element.appendChild(strong);
      element.appendChild(pre);
    }
    function tick() {
      getJSON(url).then(function (data) {
        if (errorPath && unlessPath) {
          var error = field(data, errorPath);
          if (error && !field(data, unlessPath)) {
            showError(String(error));
            return;
          }
        }
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

  // Keep at most this many characters of log text in the page, matching the
  // server's retained 1 MiB stderr tail; older text is dropped with a marker.
  var LOG_LIMIT = 1 << 20;

  // Live job log: append chunks from the absolute stderr offset until done.
  function streamLog(log) {
    var url = log.getAttribute("data-log-url");
    var offset = Number(log.getAttribute("data-log-offset")) || 0;
    var status = document.getElementById("log-status");
    var delay = 1500;
    var total = 0;
    Array.prototype.forEach.call(log.childNodes, function (node) {
      if (node.nodeType === 3) { total += node.length; }
    });

    function setStatus(text) {
      if (status) { status.textContent = text; }
    }
    function nearBottom() {
      return log.scrollHeight - log.scrollTop - log.clientHeight < 40;
    }
    function marker(text) {
      var span = document.createElement("span");
      span.className = "log-marker";
      span.textContent = text;
      return span;
    }
    function appendMarker() {
      log.appendChild(marker("\n[earlier output discarded]\n"));
    }
    // Drop the oldest text (and any markers inside it) beyond LOG_LIMIT.
    function trim() {
      if (total <= LOG_LIMIT) { return; }
      while (total > LOG_LIMIT && log.firstChild) {
        var first = log.firstChild;
        if (first.nodeType !== 3) {
          log.removeChild(first);
          continue;
        }
        var excess = total - LOG_LIMIT;
        if (first.length <= excess) {
          total -= first.length;
          log.removeChild(first);
        } else {
          first.deleteData(0, excess);
          total -= excess;
        }
      }
      while (log.firstChild && log.firstChild.nodeType !== 3) {
        log.removeChild(log.firstChild);
      }
      log.insertBefore(marker("[earlier output discarded]\n"), log.firstChild);
    }
    function tick() {
      getJSON(url + "?offset=" + encodeURIComponent(String(offset))).then(function (chunk) {
        var follow = nearBottom();
        if (chunk.truncated && chunk.offset > offset) {
          appendMarker();
        }
        if (chunk.text) {
          log.appendChild(document.createTextNode(chunk.text));
          total += chunk.text.length;
          trim();
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

  // Only one build runs at a time: disable build buttons while one is running
  // and restore them once the server reports no running build.
  function guardBuildForms(forms) {
    var guarded = false;
    function setBusy(running) {
      forms.forEach(function (form) {
        var button = form.querySelector("button[type=submit]");
        if (!button || form.getAttribute("data-submitting")) { return; }
        var old = form.querySelector(".build-busy");
        if (old) { form.removeChild(old); }
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
      guarded = true;
    }
    function setIdle() {
      forms.forEach(function (form) {
        if (form.getAttribute("data-submitting")) { return; }
        var button = form.querySelector("button[type=submit]");
        var note = form.querySelector(".build-busy");
        if (note) { form.removeChild(note); }
        if (button) { button.disabled = false; }
      });
      guarded = false;
    }
    function check() {
      getJSON("/jobs?format=json").then(function (data) {
        if (data && data.running) {
          var running = (data.jobs || []).filter(function (job) { return job.state === "running"; })[0];
          setBusy(running);
          window.setTimeout(check, 3000);
        } else if (guarded) {
          setIdle();
        }
      }).catch(function () {
        // The server still rejects concurrent builds with 409; keep checking
        // only while controls are disabled so they cannot stay stuck.
        if (guarded) { window.setTimeout(check, 10000); }
      });
    }
    check();
    forms.forEach(function (form) {
      form.addEventListener("submit", function () {
        form.setAttribute("data-submitting", "true");
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
