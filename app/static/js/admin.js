// Admin dashboard.
"use strict";

(() => {
  const { h, fmtDateTime, fmtRelative, fmtMs, fmtInterval, fmtDuration } = UI;
  const $ = (id) => document.getElementById(id);

  let csrfToken = null;
  let monitors = [];
  let editingId = null;
  let refreshTimer = null;

  // ---------- API ----------
  class ApiError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }

  async function api(method, path, body) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
    const res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
    if (res.status === 204) return null;
    let payload = null;
    try { payload = await res.json(); } catch (e) { /* non-JSON */ }
    if (!res.ok) {
      if (res.status === 401 && !path.endsWith("/login")) showLogin();
      let message = (payload && payload.detail) || "Request failed (" + res.status + ")";
      if (payload && Array.isArray(payload.errors) && payload.errors.length) {
        message = payload.errors.map((e) => (e.field ? e.field.replace(/_/g, " ") + ": " : "") + e.message.replace(/^Value error, /, "")).join("\n");
      }
      throw new ApiError(res.status, message);
    }
    return payload;
  }

  function notify(message, isError) {
    const el = h("div", { class: "notice" + (isError ? " err" : ""), role: "status", text: message });
    document.body.append(el);
    setTimeout(() => el.remove(), 3500);
  }

  function showError(el, message) {
    el.textContent = message || "";
    el.hidden = !message;
  }

  // ---------- Views ----------
  function showLogin() {
    csrfToken = null;
    clearInterval(refreshTimer);
    $("app-view").hidden = true;
    $("logout-btn").hidden = true;
    $("login-view").hidden = false;
    $("login-form").elements.username.focus();
  }

  async function showApp() {
    $("login-view").hidden = true;
    $("app-view").hidden = false;
    $("logout-btn").hidden = false;
    await Promise.all([loadMonitors(), loadIncidents(), loadSettings()]);
    clearInterval(refreshTimer);
    refreshTimer = setInterval(() => {
      if (!document.hidden && !$("monitor-dialog").open) { loadMonitors(); loadIncidents(); }
    }, 15000);
  }

  // ---------- Login ----------
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector("button[type=submit]");
    showError($("login-error"), "");
    submit.disabled = true;
    try {
      const result = await api("POST", "/api/auth/login", {
        username: form.elements.username.value.trim(),
        password: form.elements.password.value,
      });
      csrfToken = result.csrf_token;
      form.reset();
      await showApp();
    } catch (err) {
      showError($("login-error"), err.message);
      form.elements.password.value = "";
    } finally {
      submit.disabled = false;
    }
  });

  $("logout-btn").addEventListener("click", async () => {
    try { await api("POST", "/api/auth/logout"); } catch (e) { /* already logged out */ }
    showLogin();
  });

  // ---------- Monitors ----------
  async function loadMonitors() {
    try {
      monitors = await api("GET", "/api/admin/monitors");
      renderMonitors();
    } catch (err) {
      if (err.status !== 401) notify(err.message, true);
    }
  }

  function statusBadge(m) {
    if (!m.enabled) return h("span", { class: "badge paused", text: "Paused" });
    if (m.status === "up") return h("span", { class: "badge up", text: "Up" });
    if (m.status === "down") return h("span", { class: "badge down", text: "Down", title: m.last_error || "" });
    return h("span", { class: "badge", text: "Pending" });
  }

  function renderMonitors() {
    $("monitor-count").textContent = monitors.length + " monitor" + (monitors.length === 1 ? "" : "s");
    const body = $("monitor-rows");
    if (!monitors.length) {
      body.replaceChildren(h("tr", {}, h("td", { colspan: "6", class: "empty", text: "No monitors yet. Add your first domain." })));
      return;
    }
    body.replaceChildren(...monitors.map((m) =>
      h("tr", {},
        h("td", {},
          h("strong", { text: m.name }),
          !m.is_public ? h("span", { class: "badge", text: "Hidden" }) : null,
          h("span", { class: "target", text: m.url })),
        h("td", {}, statusBadge(m), m.status === "down" && m.last_error ? h("span", { class: "target", text: m.last_error }) : null),
        h("td", { text: fmtInterval(m.interval_seconds) }),
        h("td", { text: fmtRelative(m.last_checked_at), title: fmtDateTime(m.last_checked_at) }),
        h("td", { class: "mono", text: fmtMs(m.last_response_ms) }),
        h("td", { class: "actions" },
          h("button", { class: "btn sm", type: "button", text: "Check now", disabled: !m.enabled, onclick: () => checkNow(m) }),
          h("button", { class: "btn sm", type: "button", text: "Edit", onclick: () => openEditor(m) }),
          h("button", { class: "btn sm danger", type: "button", text: "Delete", onclick: () => deleteMonitor(m) })))));
  }

  async function checkNow(m) {
    try {
      await api("POST", "/api/admin/monitors/" + m.id + "/check");
      notify("Check queued for " + m.name);
      setTimeout(loadMonitors, 2500);
    } catch (err) { notify(err.message, true); }
  }

  async function deleteMonitor(m) {
    const ok = await confirmDialog("Delete monitor?", "“" + m.name + "” and its complete history will be removed permanently.");
    if (!ok) return;
    try {
      await api("DELETE", "/api/admin/monitors/" + m.id);
      notify("Deleted " + m.name);
      loadMonitors();
      loadIncidents();
    } catch (err) { notify(err.message, true); }
  }

  // ---------- Editor ----------
  const dialog = $("monitor-dialog");
  const form = $("monitor-form");

  async function openEditor(m) {
    editingId = m ? m.id : null;
    form.reset();
    showError($("monitor-error"), "");
    $("monitor-dialog-title").textContent = m ? "Edit monitor" : "Add monitor";
    $("recent-checks").hidden = !m;
    if (m) {
      for (const key of ["name", "url", "description", "interval_seconds", "timeout_seconds", "sort_order"]) {
        form.elements[key].value = m[key] === null ? "" : m[key];
      }
      for (const key of ["enabled", "is_public", "show_url"]) form.elements[key].checked = m[key];
      $("recent-list").replaceChildren(h("div", {}, "Loading…"));
    }
    dialog.showModal();
    if (m) loadRecentChecks(m.id);
  }

  async function loadRecentChecks(id) {
    try {
      const checks = await api("GET", "/api/admin/monitors/" + id + "/checks?limit=50");
      $("recent-list").replaceChildren(...(checks.length
        ? checks.map((c) => h("div", {},
            h("span", { text: fmtDateTime(c.checked_at) }),
            h("span", { class: "badge " + (c.ok ? "up" : "down"), text: c.ok ? "Up" : (c.error || "Down") }),
            h("span", { class: "mono", text: fmtMs(c.response_ms) })))
        : [h("div", {}, "No checks yet.")]));
    } catch (err) {
      $("recent-list").replaceChildren(h("div", {}, err.message));
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const els = form.elements;
    const body = {
      name: els.name.value.trim(),
      url: els.url.value.trim(),
      description: els.description.value.trim() || null,
      interval_seconds: parseInt(els.interval_seconds.value, 10),
      timeout_seconds: parseInt(els.timeout_seconds.value, 10),
      sort_order: parseInt(els.sort_order.value || "0", 10),
      enabled: els.enabled.checked,
      is_public: els.is_public.checked,
      show_url: els.show_url.checked,
    };
    const submit = form.querySelector("button[type=submit]");
    submit.disabled = true;
    try {
      if (editingId === null) await api("POST", "/api/admin/monitors", body);
      else await api("PUT", "/api/admin/monitors/" + editingId, body);
      dialog.close();
      notify(editingId === null ? "Monitor added" : "Monitor saved");
      loadMonitors();
      setTimeout(loadMonitors, 3000);
    } catch (err) {
      showError($("monitor-error"), err.message);
    } finally {
      submit.disabled = false;
    }
  });

  $("monitor-cancel").addEventListener("click", () => dialog.close());
  $("add-btn").addEventListener("click", () => openEditor(null));

  // ---------- Confirm ----------
  function confirmDialog(title, text) {
    const d = $("confirm-dialog");
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    return new Promise((resolve) => {
      const done = (value) => {
        d.close();
        $("confirm-ok").removeEventListener("click", yes);
        $("confirm-cancel").removeEventListener("click", no);
        d.removeEventListener("cancel", no);
        resolve(value);
      };
      const yes = () => done(true);
      const no = () => done(false);
      $("confirm-ok").addEventListener("click", yes);
      $("confirm-cancel").addEventListener("click", no);
      d.addEventListener("cancel", no);
      d.showModal();
    });
  }

  // ---------- Incidents ----------
  async function loadIncidents() {
    try {
      const incidents = await api("GET", "/api/admin/incidents?limit=100");
      const body = $("incident-rows");
      if (!incidents.length) {
        body.replaceChildren(h("tr", {}, h("td", { colspan: "5", class: "empty", text: "No incidents recorded." })));
        return;
      }
      body.replaceChildren(...incidents.map((inc) =>
        h("tr", {},
          h("td", {}, h("strong", { text: inc.monitor_name }), inc.resolved_at ? null : h("span", { class: "badge down", text: "Ongoing" })),
          h("td", { text: fmtDateTime(inc.started_at) }),
          h("td", { text: fmtDuration(inc.started_at, inc.resolved_at) }),
          h("td", { text: inc.error || "—" }),
          h("td", { class: "actions" },
            h("button", { class: "btn sm danger", type: "button", text: "Delete", onclick: () => deleteIncident(inc) })))));
    } catch (err) {
      if (err.status !== 401) notify(err.message, true);
    }
  }

  async function deleteIncident(inc) {
    const ok = await confirmDialog("Delete incident?", "The incident for “" + inc.monitor_name + "” will be removed from the public history. Uptime statistics are not changed.");
    if (!ok) return;
    try {
      await api("DELETE", "/api/admin/incidents/" + inc.id);
      loadIncidents();
    } catch (err) { notify(err.message, true); }
  }

  // ---------- Settings ----------
  async function loadSettings() {
    try {
      const s = await api("GET", "/api/admin/settings");
      const f = $("settings-form");
      f.elements.title.value = s.title || "";
      f.elements.description.value = s.description || "";
    } catch (err) {
      if (err.status !== 401) notify(err.message, true);
    }
  }

  $("settings-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const f = event.currentTarget;
    showError($("settings-error"), "");
    try {
      await api("PUT", "/api/admin/settings", {
        title: f.elements.title.value.trim(),
        description: f.elements.description.value.trim() || null,
      });
      notify("Settings saved");
    } catch (err) {
      showError($("settings-error"), err.message);
    }
  });

  // ---------- Boot ----------
  UI.setupThemeToggle($("theme-toggle"));
  (async () => {
    try {
      const me = await api("GET", "/api/auth/me");
      if (me.authenticated) {
        csrfToken = me.csrf_token;
        await showApp();
      } else {
        showLogin();
      }
    } catch (e) {
      showLogin();
    }
  })();
})();
