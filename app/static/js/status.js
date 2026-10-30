// Public status page.
"use strict";

(() => {
  const { h, svg, icon, fmtDay, fmtMonth, fmtPct, fmtMs, fmtDateTime, fmtDuration, fmtTime, level } = UI;
  const $ = (id) => document.getElementById(id);

  const HERO = {
    operational: ["Operational", "Everything works"],
    degraded_performance: ["Degraded performance", "Some services are slower than usual"],
    partial_outage: ["Partial outage", "Some services are down"],
    major_outage: ["Major outage", "All services are down"],
    unknown: ["Waiting", "Waiting for the first checks"],
    empty: ["No services", "Nothing is monitored yet"],
  };
  const STATUS_TEXT = { up: "Operational", degraded: "Elevated latency", down: "Down", pending: "Pending", unknown: "No recent data" };

  // Day colour comes from the server: red for any outage, yellow if slow more often than normal.
  const DAY_CLASS = { up: "up", degraded: "warn", down: "down" };
  const DAY_TEXT = { up: "Operational", degraded: "Mostly elevated latency", down: "Outage" };
  const plural = (n, word) => n + " " + word + (n === 1 ? "" : "s");

  function dayLines(d) {
    const lines = [fmtDay(d.date)];
    if (d.uptime === null) return [...lines, "No data"];
    lines.push(DAY_TEXT[d.state], fmtPct(d.uptime, 3) + " uptime");
    if (d.avg_ms !== null && d.avg_ms !== undefined) lines.push("Avg response " + fmtMs(d.avg_ms));
    if (d.down_checks) lines.push(plural(d.down_checks, "failed check"));
    if (d.degraded_checks) lines.push(plural(d.degraded_checks, "slow check") + " (elevated latency)");
    return lines;
  }
  const dayClass = (d) => "s-" + (DAY_CLASS[d.state] || "none");

  let data = null;
  let monthOffset = 0; // 0 = current month, -1 = previous, ...
  let timer = null;
  let loading = false;

  // ---------- Tooltip ----------
  const tooltip = $("tooltip");
  function showTip(target, lines) {
    tooltip.replaceChildren(...lines.map((line, i) => (i === 0 ? h("strong", { text: line }) : h("div", { text: line }))));
    tooltip.hidden = false;
    const rect = target.getBoundingClientRect();
    const tip = tooltip.getBoundingClientRect();
    let left = rect.left + rect.width / 2 - tip.width / 2;
    left = Math.max(8, Math.min(left, window.innerWidth - tip.width - 8));
    let top = rect.top - tip.height - 8;
    if (top < 8) top = rect.bottom + 8;
    tooltip.style.left = left + "px";
    tooltip.style.top = top + "px";
  }
  const hideTip = () => { tooltip.hidden = true; };
  window.addEventListener("scroll", hideTip, { passive: true });

  function withTip(el, lines) {
    el.addEventListener("pointerenter", () => showTip(el, lines));
    el.addEventListener("pointerleave", hideTip);
    el.addEventListener("pointerdown", () => showTip(el, lines));
    return el;
  }

  // ---------- Hero ----------
  function renderHero() {
    const state = data.monitors.length === 0 ? "empty" : data.overall_status;
    const [label, title] = HERO[state] || HERO.unknown;
    const labelEl = $("hero-label");
    labelEl.textContent = label;
    labelEl.className = "hero-label s-" + state;
    $("hero-title").textContent = title;
    $("hero-pulse").className = "pulse s-" + (state === "empty" ? "unknown" : state);
    $("updated").textContent = "Updated " + fmtDateTime(data.generated_at);
    $("refresh-note").textContent = "Refreshes every " + data.refresh_seconds + " seconds";

    const title_ = data.site.title || "Status";
    $("site-title").textContent = title_;
    document.title = state === "operational" || state === "empty" ? title_ : label + " · " + title_;
    const desc = $("site-description");
    desc.textContent = data.site.description || "";
    desc.hidden = !data.site.description;
    UI.renderLegalLinks($("legal-links"), data.legal);
  }

  // ---------- Overall month view ----------
  function renderMonth() {
    const now = new Date();
    const month = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + monthOffset, 1));
    const daysInMonth = new Date(Date.UTC(month.getUTCFullYear(), month.getUTCMonth() + 1, 0)).getUTCDate();
    const todayIso = now.toISOString().slice(0, 10);
    const byDay = new Map(data.overall_days.map((d) => [d.date, d]));

    const grid = $("month-grid");
    grid.style.gridTemplateColumns = "repeat(" + daysInMonth + ", minmax(0, 1fr))";
    const cells = [];
    const values = [];
    for (let day = 1; day <= daysInMonth; day++) {
      const iso = new Date(Date.UTC(month.getUTCFullYear(), month.getUTCMonth(), day)).toISOString().slice(0, 10);
      const d = byDay.get(iso) || { date: iso, uptime: null };
      if (d.uptime !== null) values.push(d.uptime);
      const future = iso > todayIso;
      const cell = h("div", { class: "day-cell " + (future ? "s-none" : dayClass(d)) });
      withTip(cell, future ? [fmtDay(iso), "Upcoming"] : dayLines(d));
      cells.push(cell);
    }
    grid.replaceChildren(...cells);

    const avg = values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;
    $("overall-avg").textContent = fmtPct(avg);
    $("overall-sub").textContent = fmtMonth(month) + " · Daily uptime across all monitored services.";
    const mm = String(month.getUTCMonth() + 1).padStart(2, "0");
    $("month-start").textContent = mm + "/01";
    $("month-end").textContent = mm + "/" + daysInMonth;

    const first = data.overall_days.length ? data.overall_days[0].date.slice(0, 7) : null;
    const shown = month.toISOString().slice(0, 7);
    $("month-prev").disabled = !first || shown <= first || monthOffset <= -12;
    $("month-next").disabled = monthOffset >= 0;
  }

  // ---------- Monitors ----------
  function sparkline(points) {
    const values = points.map((p) => p.ms).filter((v) => v !== null);
    if (values.length < 2) return null;
    const el = svg("svg", { class: "spark", viewBox: "0 0 140 28", preserveAspectRatio: "none", "aria-hidden": "true" });
    const max = Math.max(...values) * 1.1 || 1;
    const step = 140 / (values.length - 1);
    const coords = values.map((v, i) => [i * step, 27 - (v / max) * 25]);
    const line = coords.map(([x, y]) => x.toFixed(1) + "," + y.toFixed(1)).join(" ");
    el.append(svg("polygon", { class: "area", points: "0,28 " + line + " 140,28" }), svg("polyline", { points: line }));
    return el;
  }

  function monitorRow(m) {
    const lvl = m.status === "down" ? "down" : level(m.uptime["90d"]);
    const bars = m.days.map((d) => withTip(h("span", { class: "bar " + dayClass(d) }), dayLines(d)));

    let link = null;
    if (m.url) {
      try {
        const u = new URL(m.url);
        if (u.protocol === "https:" || u.protocol === "http:") {
          link = h("a", { href: u.href, target: "_blank", rel: "noopener noreferrer nofollow", text: u.host });
        }
      } catch (e) { /* ignore malformed */ }
    }
    const descParts = [m.description, m.description && link ? " · " : null, link].filter(Boolean);

    return h("article", { class: "monitor", dataset: { name: m.name.toLowerCase() + " " + (m.description || "").toLowerCase() } },
      h("div", { class: "monitor-head" },
        h("div", { class: "monitor-title" },
          h("span", { class: "status-dot " + m.status, "aria-hidden": "true" }),
          h("h3", { text: m.name }),
          h("span", { class: "badge " + (m.status === "pending" ? "" : m.status), text: STATUS_TEXT[m.status] || m.status })),
        h("div", { class: "monitor-uptime " + lvl, text: fmtPct(m.uptime["90d"]) + " uptime" })),
      descParts.length ? h("p", { class: "monitor-desc" }, descParts) : null,
      h("div", { class: "bars", role: "img", "aria-label": "Daily uptime for the last 90 days, " + fmtPct(m.uptime["90d"]) + " overall" }, bars),
      h("div", { class: "axis" },
        h("span", {}, h("span", { class: "lg-only", text: "90 days ago" }), h("span", { class: "sm-only", text: "45 days ago" })),
        h("span", { text: "Today" })),
      h("div", { class: "monitor-stats" },
        h("span", {}, "Response ", h("b", { text: fmtMs(m.last_response_ms) })),
        h("span", {}, "24h avg ", h("b", { text: fmtMs(m.avg_response_ms_24h) })),
        h("span", {}, "24h ", h("b", { text: fmtPct(m.uptime["24h"]) })),
        h("span", {}, "7d ", h("b", { text: fmtPct(m.uptime["7d"]) })),
        h("span", {}, "30d ", h("b", { text: fmtPct(m.uptime["30d"]) })),
        sparkline(m.response_24h)));
  }

  function renderMonitors() {
    const list = $("monitor-list");
    if (!data.monitors.length) {
      list.replaceChildren(h("p", { class: "empty", text: "No services have been added yet." }));
      return;
    }
    list.replaceChildren(...data.monitors.map(monitorRow));
    applySearch();
  }

  function applySearch() {
    const q = $("search").value.trim().toLowerCase();
    let visible = 0;
    for (const row of $("monitor-list").querySelectorAll(".monitor")) {
      const show = !q || row.dataset.name.includes(q);
      row.hidden = !show;
      if (show) visible++;
    }
    $("no-results").hidden = visible > 0 || !data || !data.monitors.length;
    $("monitor-list").hidden = visible === 0 && data && data.monitors.length > 0;
  }

  // ---------- Incidents ----------
  function incidentCard(inc, active) {
    const slow = inc.kind === "degraded";
    const meta = active
      ? (slow ? "Slow since " : "Down since ") + fmtDateTime(inc.started_at) + " · " + fmtDuration(inc.started_at, null)
      : fmtDateTime(inc.started_at) + " – " + fmtTime(inc.resolved_at) + " · " + fmtDuration(inc.started_at, inc.resolved_at);
    const title = slow ? (active ? " has elevated latency" : " had elevated latency") : (active ? " is down" : " was down");
    return h("div", { class: "card incident" + (active ? " active" : "") + (slow ? " degraded" : "") },
      h("div", { class: "incident-top" },
        h("span", { class: "incident-title", text: inc.monitor_name + title }),
        h("span", { class: "badge " + (active ? (slow ? "degraded" : "down") : "up"), text: active ? "Ongoing" : "Resolved" })),
      h("p", { class: "incident-meta", text: meta + (inc.error ? " · " + inc.error : "") }));
  }

  function renderIncidents() {
    const { active, past } = data.incidents;
    const activeEl = $("active-incidents");
    activeEl.replaceChildren(
      ...(active.length
        ? active.map((i) => incidentCard(i, true))
        : [h("div", { class: "card empty" }, h("strong", { text: "No active incidents" }), h("p", { class: "small", text: "All monitored services are currently stable." }))])
    );

    const pastEl = $("past-incidents");
    if (!past.length) {
      pastEl.replaceChildren(h("div", { class: "card empty", text: "No incidents in the last 90 days." }));
      return;
    }
    const groups = new Map();
    for (const inc of past) {
      const d = new Date(inc.started_at);
      const key = fmtMonth(new Date(Date.UTC(d.getFullYear(), d.getMonth(), 1)));
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(inc);
    }
    pastEl.replaceChildren(...[...groups].map(([month, items]) =>
      h("div", { class: "incident-group" }, h("h3", { text: month }), h("div", { class: "card list" }, items.map((i) => incidentCard(i, false))))));
  }

  // ---------- Loading ----------
  async function load() {
    if (loading) return;
    loading = true;
    const btn = $("refresh-btn");
    btn.disabled = true;
    try {
      const res = await fetch("/api/status", { headers: { Accept: "application/json" }, cache: "no-store" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      data = await res.json();
      renderHero();
      renderMonth();
      renderMonitors();
      renderIncidents();
    } catch (err) {
      $("updated").textContent = "Could not load status (" + err.message + ")";
    } finally {
      loading = false;
      btn.disabled = false;
      schedule();
    }
  }

  function schedule() {
    clearTimeout(timer);
    const seconds = data ? data.refresh_seconds : 30;
    timer = setTimeout(() => { if (!document.hidden) load(); else schedule(); }, seconds * 1000);
  }

  document.addEventListener("visibilitychange", () => { if (!document.hidden && data) load(); });
  $("refresh-btn").append(icon("refresh"), "Refresh");
  $("refresh-btn").addEventListener("click", load);
  $("search-label").prepend(icon("search"));
  $("search").addEventListener("input", applySearch);
  $("month-prev").addEventListener("click", () => { monthOffset--; renderMonth(); });
  $("month-next").addEventListener("click", () => { monthOffset = Math.min(0, monthOffset + 1); renderMonth(); });
  UI.setupThemeToggle($("theme-toggle"));
  load();
})();
