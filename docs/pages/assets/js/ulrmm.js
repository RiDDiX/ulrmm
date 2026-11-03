// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

// Light or dark mode: the system setting until the reader picks one with the
// switch in the top bar; the pick is kept in this browser.
(function () {
  var root = document.documentElement;
  var key = "ulrmm-docs-theme";
  try {
    var saved = localStorage.getItem(key);
    if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
  } catch (e) {}

  function isDark() {
    var set = root.getAttribute("data-theme");
    if (set) return set === "dark";
    return !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  }

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.getElementById("theme-toggle");
    if (!button) return;
    // the theme renders it before the GitHub and Sponsor buttons; Tab follows the DOM
    var aux = document.querySelector(".main-header .aux-nav");
    if (aux) aux.after(button);
    button.hidden = false;
    button.setAttribute("aria-pressed", String(isDark()));
    button.addEventListener("click", function () {
      var next = isDark() ? "light" : "dark";
      root.setAttribute("data-theme", next);
      button.setAttribute("aria-pressed", String(next === "dark"));
      try {
        localStorage.setItem(key, next);
      } catch (e) {}
    });
  });
})();
