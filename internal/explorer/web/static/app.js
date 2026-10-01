// Lupetto Explorer: progressive enhancement only. Every page works without this
// file; it adds live build stages and log streaming, reloads after a status
// check or build finishes, opens the "Track a product" form as a dialog, and
// disables build buttons while a build runs. Server text is inserted with
// textContent / text nodes only; nothing from the server is parsed as HTML.
(function () {
  "use strict";

  var reloading = false;
  function reload() {
    if (reloading) { return; }
    var dialog = document.getElementById("track-dialog");
    if (dialog && dialog.open) {
      // Don't throw away what the user is typing; try again shortly.
      window.setTimeout(reload, 5000);
      return;
    }
    reloading = true;
    window.location.reload();
  }

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

  function withFormat(url) {
    return url + (url.indexOf("?") >= 0 ? "&" : "?") + "format=json";
  }

  // Reload once a JSON flag (e.g. status.refreshing) becomes false. With
  // data-poll-error-field/data-poll-unless-field, an error reported while the
  // "unless" value is still missing (e.g. lastError with no document) stops
  // polling and shows the error, so a failing load is not retried forever.
  function pollUntilIdle(element) {
    var url = element.getAttribute("data-poll-url");
    var path = element.getAttribute("data-poll-field");
    var errorPath = element.getAttribute("data-poll-error-field");
    var unlessPath = element.getAttribute("data-poll-unless-field");
    var delay = 2500;
    function showError(message) {
      var box = element.closest(".empty") || element;
      box.setAttribute("role", "alert");
      while (box.firstChild) { box.removeChild(box.firstChild); }
      var title = document.createElement("h2");
      title.textContent = "Loading failed";
      var note = document.createElement("p");
      note.textContent = "Polling stopped. Reload the page to try again.";
      var pre = document.createElement("pre");
      pre.className = "errtext";
      pre.textContent = message;
      box.appendChild(title);
      box.appendChild(note);
      box.appendChild(pre);
    }
    function tick() {
      getJSON(url).then(function (data) {
        if (errorPath && unlessPath) {
          var error = field(data, errorPath);
          if (error && !field(data, unlessPath)) { showError(String(error)); return; }
        }
        if (!field(data, path)) { reload(); return; }
        delay = 2500;
        window.setTimeout(tick, delay);
      }).catch(function () {
        delay = Math.min(delay * 2, 30000);
        window.setTimeout(tick, delay);
      });
    }
    window.setTimeout(tick, delay);
  }

  // ---- Live build stages -------------------------------------------------
  var STAGE_OK = { completed: "Done", loaded: "Loaded", published: "Published", signed: "Signed", attested: "Attested", ok: "Done" };
  function stageClass(status) {
    if (STAGE_OK[status]) { return "ok"; }
    if (status === "failed" || status === "running" || status === "skipped") { return status; }
    if (status === "not-attempted") { return "notattempted"; }
    if (status === "pending" || !status) { return "pending"; }
    return "unknown";
  }
  function stageText(status) {
    if (STAGE_OK[status]) { return STAGE_OK[status]; }
    switch (status) {
      case "failed": return "Failed";
      case "running": return "In progress";
      case "skipped": return "Skipped · not requested";
      case "not-attempted": return "Not attempted · earlier stage failed";
      case "pending": case "": case undefined: return "Waiting";
      default: return String(status);
    }
  }
  var STAGE_ICON = {
    ok: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    failed: '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>',
    running: '<circle cx="12" cy="12" r="8.5" stroke-dasharray="38 16"/><path d="M12 8v4l2.5 1.5"/>',
    skipped: '<circle cx="12" cy="12" r="8.5"/><path d="M8.5 12h7"/>',
    notattempted: '<circle cx="12" cy="12" r="8.5"/><path d="M8.5 12h7"/>',
    pending: '<circle cx="12" cy="12" r="8.5" stroke-dasharray="2 3.4"/>',
    unknown: '<circle cx="12" cy="12" r="8.5" stroke-dasharray="2 3.4"/>'
  };
  // Icon markup is a fixed constant above (never server text); parse it as SVG.
  function setStageIcon(li, cls) {
    var svg = li.querySelector(".name svg");
    if (!svg) { return; }
    var doc = new DOMParser().parseFromString('<svg xmlns="http://www.w3.org/2000/svg">' + STAGE_ICON[cls] + "</svg>", "image/svg+xml");
    while (svg.firstChild) { svg.removeChild(svg.firstChild); }
    Array.prototype.forEach.call(doc.documentElement.childNodes, function (node) {
      svg.appendChild(document.importNode(node, true));
    });
  }
  // A publish-only job keeps the server's reason on its skipped Load stage.
  function loadSkipReason(item, stage) {
    if (stage.name === "load" && stage.status === "skipped" && item.mode === "publish" && !item.load && item.loadReason) {
      return "Skipped · " + String(item.loadReason);
    }
    return "";
  }
  function applyStages(container, item) {
    (item.stages || []).forEach(function (stage) {
      var li = null;
      Array.prototype.forEach.call(container.querySelectorAll("[data-stage]"), function (el) {
        if (el.getAttribute("data-stage") === stage.name) { li = el; }
      });
      if (!li) { return; }
      var cls = stageClass(stage.status);
      if (!li.classList.contains(cls)) {
        li.className = "stage " + cls;
        setStageIcon(li, cls);
      }
      var state = li.querySelector("[data-stage-state]");
      if (state) { state.textContent = loadSkipReason(item, stage) || stageText(stage.status); }
    });
  }
  function liveStages(container) {
    var url = container.getAttribute("data-live-url");
    var delay = 2000;
    function tick() {
      getJSON(url).then(function (data) {
        var item = data && data.item;
        if (!item) { return; }
        applyStages(container, item);
        if (item.state !== "running") {
          // Let the log stream append its final bytes first, then reload for the record.
          window.setTimeout(reload, 1200);
          return;
        }
        delay = 2000;
        window.setTimeout(tick, delay);
      }).catch(function () {
        delay = Math.min(delay * 2, 30000);
        window.setTimeout(tick, delay);
      });
    }
    window.setTimeout(tick, delay);
  }

  // ---- Live build log ------------------------------------------------------
  // Keep at most this many characters, matching the server's 1 MiB tail.
  var LOG_LIMIT = 1 << 20;
  function streamLog(log) {
    var url = log.getAttribute("data-log-url");
    var offset = Number(log.getAttribute("data-log-offset")) || 0;
    var status = document.getElementById("log-status");
    var delay = 1500;
    var total = log.textContent.length;
    function setStatus(text) { if (status) { status.textContent = text; } }
    function nearBottom() { return log.scrollHeight - log.scrollTop - log.clientHeight < 40; }
    function marker(text) {
      var span = document.createElement("span");
      span.className = "t";
      span.textContent = text;
      return span;
    }
    function trim() {
      if (total <= LOG_LIMIT) { return; }
      while (total > LOG_LIMIT && log.firstChild) {
        var first = log.firstChild;
        if (first.nodeType !== 3) { log.removeChild(first); continue; }
        var excess = total - LOG_LIMIT;
        if (first.length <= excess) { total -= first.length; log.removeChild(first); } else { first.deleteData(0, excess); total -= excess; }
      }
      log.insertBefore(marker("[earlier output discarded]\n"), log.firstChild);
    }
    function tick() {
      getJSON(url + "?offset=" + encodeURIComponent(String(offset))).then(function (chunk) {
        var follow = nearBottom();
        if (chunk.truncated && chunk.offset > offset) { log.appendChild(marker("\n[earlier output discarded]\n")); }
        if (chunk.text) {
          log.appendChild(document.createTextNode(chunk.text));
          total += chunk.text.length;
          trim();
        }
        if (typeof chunk.nextOffset === "number") { offset = chunk.nextOffset; }
        if (follow) { log.scrollTop = log.scrollHeight; }
        if (chunk.done) {
          setStatus("Finished — reloading for the build record…");
          window.setTimeout(reload, 800);
          return;
        }
        delay = 1500;
        setStatus("Live");
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

  // ---- One build at a time -------------------------------------------------
  // Disable build buttons when a build starts after the page was rendered; when
  // the page was rendered during a build, reload once it finishes so the
  // buttons come back with fresh status.
  function guardBuilds(forms, renderedRunning) {
    var busy = false;
    function setBusy(item) {
      if (busy) { return; }
      busy = true;
      forms.forEach(function (form) {
        if (form.getAttribute("data-submitting")) { return; }
        var button = form.querySelector("button[type=submit]");
        if (button) { button.disabled = true; }
        var note = document.createElement("span");
        note.className = "btn-note";
        note.setAttribute("data-busy-note", "");
        if (item && item.detailURL) {
          var link = document.createElement("a");
          link.href = item.detailURL;
          link.textContent = "A build is running";
          note.appendChild(link);
        } else {
          note.textContent = "A build is running";
        }
        form.appendChild(note);
      });
    }
    function check() {
      getJSON("/builds?format=json").then(function (data) {
        if (data && data.running) {
          setBusy(data.shell && data.shell.runningBuild);
          window.setTimeout(check, 3000);
        } else if (busy || renderedRunning) {
          reload();
        }
      }).catch(function () {
        window.setTimeout(check, 10000);
      });
    }
    if (forms.length || renderedRunning) { check(); }
    forms.forEach(function (form) {
      form.addEventListener("submit", function () {
        form.setAttribute("data-submitting", "true");
        var button = form.querySelector("button[type=submit]");
        // Defer so the submission itself is not cancelled by disabling.
        if (button) { window.setTimeout(function () { button.disabled = true; }, 0); }
      });
    });
  }

  // ---- Track dialog ----------------------------------------------------------
  // The opener is a link to /products/track, which works without JavaScript.
  function trackDialog() {
    var dialog = document.getElementById("track-dialog");
    if (!dialog || typeof dialog.showModal !== "function") { return; }
    var opener = null;
    Array.prototype.forEach.call(document.querySelectorAll("a[data-opens=track-dialog]"), function (link) {
      link.addEventListener("click", function (event) {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) { return; }
        event.preventDefault();
        opener = link;
        var input = dialog.querySelector("input[name=package]");
        var preset = link.getAttribute("data-package");
        if (input && preset) { input.value = preset; }
        dialog.showModal();
        var target = preset ? dialog.querySelector("input[name=selector]") : input;
        if (target) { target.focus(); }
      });
    });
    Array.prototype.forEach.call(dialog.querySelectorAll("[data-closes]"), function (link) {
      link.addEventListener("click", function (event) {
        event.preventDefault();
        dialog.close();
      });
    });
    dialog.addEventListener("close", function () {
      if (opener) { opener.focus(); }
    });
  }

  function init() {
    trackDialog();
    Array.prototype.forEach.call(document.querySelectorAll("[data-poll-url][data-poll-field]"), pollUntilIdle);
    var live = Array.prototype.slice.call(document.querySelectorAll("[data-live-url]"));
    live.forEach(liveStages);
    var log = document.querySelector("#job-log[data-log-url]");
    if (log) { streamLog(log); }
    if (!live.length && !log) {
      var forms = Array.prototype.slice.call(document.querySelectorAll("form[data-build-form]"));
      guardBuilds(forms, document.body.hasAttribute("data-build-running"));
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
