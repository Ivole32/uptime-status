// Public page of a single incident: its updates and post-mortem.
"use strict";

(() => {
  const { h, fmtDateTime, fmtDuration, renderRichText, statusTag, incidentTitle } = UI;
  const $ = (id) => document.getElementById(id);

  let timer = null;
  let loaded = false;

  function fail(message) {
    $("incident-title").textContent = "Incident unavailable";
    $("incident-facts").textContent = message;
    $("timeline").replaceChildren();
  }

  // What monitoring recorded, shown in the timeline next to the written updates.
  function recordedEvents(inc) {
    const slow = inc.kind === "degraded";
    const events = [{
      at: inc.started_at,
      tag: h("span", { class: "badge " + (slow ? "degraded" : "down"), text: "Detected" }),
      text: (slow ? "Response times rose well above normal" : "Checks started failing") + (inc.error ? " (" + inc.error + ")." : "."),
    }];
    if (inc.resolved_at) {
      events.push({
        at: inc.resolved_at,
        tag: h("span", { class: "badge up", text: "Recovered" }),
        text: slow ? "Response times are back to normal." : "Checks are passing again.",
      });
    }
    return events;
  }

  function render(page) {
    const inc = page.incident;
    const site = page.site.title || "Status";
    const title = incidentTitle(inc);
    const active = !inc.resolved_at;
    const slow = inc.kind === "degraded";
    $("site-title").textContent = site;
    document.title = title + " · " + site;
    $("incident-title").textContent = title;
    $("incident-tags").replaceChildren(
      h("span", { class: "badge " + (active ? (slow ? "degraded" : "down") : "up"), text: active ? "Ongoing" : "Resolved" }),
      h("span", { class: "badge", text: slow ? "Elevated latency" : "Outage" }));
    $("incident-facts").replaceChildren(...[
      h("span", {}, "Service ", h("b", { text: inc.monitor_name })),
      h("span", {}, "Started ", h("b", { text: fmtDateTime(inc.started_at) })),
      inc.resolved_at ? h("span", {}, "Resolved ", h("b", { text: fmtDateTime(inc.resolved_at) })) : null,
      h("span", {}, active ? "Ongoing for " : "Lasted ", h("b", { text: fmtDuration(inc.started_at, inc.resolved_at) })),
    ].filter(Boolean));

    $("postmortem").hidden = !inc.postmortem;
    if (inc.postmortem) {
      $("postmortem-date").textContent = "Published " + fmtDateTime(inc.postmortem_at);
      $("postmortem-body").replaceChildren(...renderRichText(inc.postmortem));
    }

    const written = inc.updates.map((u) => ({ at: u.created_at, tag: statusTag(u.status), body: renderRichText(u.message) }));
    const items = [...written, ...recordedEvents(inc)].sort((a, b) => new Date(b.at) - new Date(a.at));
    $("timeline").replaceChildren(...items.map((item) =>
      h("li", { class: "timeline-item" + (item.text ? " recorded" : "") },
        h("div", { class: "update-head" }, item.tag, h("time", { class: "muted small", datetime: item.at, text: fmtDateTime(item.at) })),
        item.text
          ? h("p", { class: "muted", text: item.text + " Recorded automatically by monitoring." })
          : h("div", { class: "legal-body update-body" }, item.body))));

    UI.renderLegalLinks($("legal-links"), page.legal);
    // Ongoing incidents keep getting updates, so check back like the status page does.
    clearTimeout(timer);
    if (active) timer = setTimeout(load, page.refresh_seconds * 1000);
  }

  async function load() {
    const m = /^\/incidents\/(\d{1,10})$/.exec(window.location.pathname);
    if (!m) return fail("This incident does not exist.");
    if (document.hidden) {
      document.addEventListener("visibilitychange", load, { once: true });
      return;
    }
    try {
      const res = await fetch("/api/incidents/" + m[1], { headers: { Accept: "application/json" }, cache: "no-cache" });
      if (res.status === 404) return fail("This incident does not exist or is no longer public.");
      if (!res.ok) throw new Error("HTTP " + res.status);
      render(await res.json());
      loaded = true;
    } catch (err) {
      // A failed refresh keeps what is shown and tries again later.
      if (loaded) timer = setTimeout(load, 30000);
      else fail("Could not load this incident (" + err.message + ").");
    }
  }

  UI.setupThemeToggle($("theme-toggle"));
  load();
})();
