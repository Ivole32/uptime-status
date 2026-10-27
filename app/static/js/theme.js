// Applies the saved theme before first paint (loaded synchronously in <head>).
(function () {
  "use strict";
  var theme = null;
  try { theme = window.localStorage.getItem("uptime-theme"); } catch (e) { /* storage unavailable */ }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
