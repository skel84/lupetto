// Lupetto mockup helpers. Loaded synchronously in <head> so the chosen direction
// and color mode apply before first paint. Everything else is progressive
// enhancement: pages work (with direction A, OS color mode) without JavaScript.
(function () {
  "use strict";
  var root = document.documentElement;
  var params = new URLSearchParams(location.search);
  var THEMES = { a: 1, b: 1 };
  var MODES = { auto: 1, light: 1, dark: 1 };

  function pick(key, allowed, fallback) {
    var v = params.get(key);
    if (v && allowed[v]) {
      try { localStorage.setItem("lupetto-mock-" + key, v); } catch (e) { /* private mode */ }
      return v;
    }
    try { v = localStorage.getItem("lupetto-mock-" + key); } catch (e) { v = null; }
    return v && allowed[v] ? v : fallback;
  }

  root.setAttribute("data-theme", pick("theme", THEMES, "a"));
  root.setAttribute("data-mode", pick("mode", MODES, "auto"));

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    // Mockup bar: mark the active direction/mode.
    document.querySelectorAll("[data-set-theme]").forEach(function (a) {
      a.setAttribute("aria-current", String(a.getAttribute("data-set-theme") === root.getAttribute("data-theme")));
    });
    document.querySelectorAll("[data-set-mode]").forEach(function (a) {
      a.setAttribute("aria-current", String(a.getAttribute("data-set-mode") === root.getAttribute("data-mode")));
    });

    // Client-side stand-in for server-side GET filtering (Images, Catalog, Packages).
    var q = (params.get("q") || "").trim().toLowerCase();
    var show = params.get("show") || "all";
    document.querySelectorAll("form[data-filter-form]").forEach(function (form) {
      var input = form.querySelector("input[name=q]");
      if (input) input.value = params.get("q") || "";
      var radio = form.querySelector("input[name=show][value='" + show + "']");
      if (radio) radio.checked = true;
      form.querySelectorAll("input[name=show]").forEach(function (r) {
        r.addEventListener("change", function () { form.submit(); });
      });
    });
    document.querySelectorAll("[data-filter-scope]").forEach(function (scope) {
      var any = false;
      scope.querySelectorAll("[data-filter-item]").forEach(function (item) {
        var text = (item.getAttribute("data-search") || item.textContent).toLowerCase();
        var tags = (item.getAttribute("data-tags") || "").split(" ");
        var rows = item.querySelectorAll("[data-filter-row]");
        var matchText = !q || text.indexOf(q) !== -1;
        var visibleRows = 0;
        if (rows.length) {
          rows.forEach(function (row) {
            var rowTags = (row.getAttribute("data-tags") || "").split(" ");
            var ok = matchText && (show === "all" || rowTags.indexOf(show) !== -1);
            row.hidden = !ok;
            if (ok) visibleRows++;
          });
          item.hidden = visibleRows === 0;
        } else {
          item.hidden = !(matchText && (show === "all" || tags.indexOf(show) !== -1));
        }
        if (!item.hidden) any = true;
      });
      var none = document.querySelector("[data-filter-empty]");
      if (none) none.hidden = any;
    });
    document.querySelectorAll("[data-echo-q]").forEach(function (el) { el.textContent = params.get("q") || ""; });

    // Track dialog: the link works without JS (full page); with JS it opens in place.
    var dialog = document.getElementById("track-dialog");
    if (dialog && typeof dialog.showModal === "function") {
      document.querySelectorAll("[data-opens=track-dialog]").forEach(function (a) {
        a.addEventListener("click", function (ev) {
          if (a.getAttribute("aria-disabled") === "true") { ev.preventDefault(); return; }
          ev.preventDefault();
          dialog.showModal();
          var first = dialog.querySelector("input:not([type=hidden]):not([disabled])");
          if (first) first.focus();
        });
      });
      dialog.querySelectorAll("[data-closes]").forEach(function (b) {
        b.addEventListener("click", function (ev) { ev.preventDefault(); dialog.close(); });
      });
    }
    document.querySelectorAll("a[aria-disabled=true]").forEach(function (a) {
      a.addEventListener("click", function (ev) { ev.preventDefault(); });
    });

    // One-shot confirmation after the (mock) tracking form submits back to Images.
    var flash = document.querySelector("[data-flash=tracked]");
    if (flash && params.get("tracked")) {
      var label = flash.querySelector("[data-flash-text]");
      if (label) label.textContent = params.get("tracked");
      flash.hidden = false;
    }
  });
})();
