// Imprint and privacy policy pages.
"use strict";

(() => {
  const { renderLegalLinks, renderRichText, fmtDateTime } = UI;
  const $ = (id) => document.getElementById(id);
  const KINDS = { "/imprint": "imprint", "/privacy": "privacy" };

  function fail(message) {
    $("legal-title").textContent = "Page unavailable";
    $("legal-body").replaceChildren(UI.h("p", { class: "muted", text: message }));
  }

  async function load() {
    const kind = KINDS[window.location.pathname];
    if (!kind) return fail("This page does not exist.");
    try {
      const res = await fetch("/api/legal/" + kind, { headers: { Accept: "application/json" }, cache: "no-cache" });
      if (res.status === 404) return fail("This page has not been set up.");
      if (!res.ok) throw new Error("HTTP " + res.status);
      const page = await res.json();
      const site = page.site.title || "Status";
      $("site-title").textContent = site;
      $("legal-title").textContent = page.title;
      document.title = page.title + " · " + site;
      $("legal-updated").textContent = "Last updated " + fmtDateTime(page.updated_at);
      $("legal-updated").hidden = false;
      $("legal-body").replaceChildren(...renderRichText(page.content));
      renderLegalLinks($("legal-links"), page.legal);
    } catch (err) {
      fail("Could not load this page (" + err.message + ").");
    }
  }

  UI.setupThemeToggle($("theme-toggle"));
  load();
})();
