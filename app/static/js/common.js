// Shared helpers. All DOM is built with textContent / attributes, never innerHTML,
// so API data can never be interpreted as markup.
"use strict";

const UI = (() => {
  const SVG_NS = "http://www.w3.org/2000/svg";

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    applyAttrs(el, attrs);
    append(el, children);
    return el;
  }

  function svg(tag, attrs, ...children) {
    const el = document.createElementNS(SVG_NS, tag);
    applyAttrs(el, attrs);
    append(el, children);
    return el;
  }

  function applyAttrs(el, attrs) {
    if (!attrs) return;
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") el.setAttribute("class", value);
      else if (key === "text") el.textContent = value;
      else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
      else if (key === "dataset") Object.assign(el.dataset, value);
      else el.setAttribute(key, value === true ? "" : String(value));
    }
  }

  function append(el, children) {
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
  }

  // Small inline icons (paths only, no external sprites).
  const ICONS = {
    sun: ["M12 4V2M12 22v-2M4.9 4.9 3.5 3.5M20.5 20.5l-1.4-1.4M4 12H2M22 12h-2M4.9 19.1l-1.4 1.4M20.5 3.5l-1.4 1.4", "circle"],
    moon: ["M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"],
    refresh: ["M21 12a9 9 0 1 1-2.6-6.4M21 3v6h-6"],
    search: ["m21 21-4.3-4.3M11 18a7 7 0 1 1 0-14 7 7 0 0 1 0 14Z"],
  };

  function icon(name) {
    const [d, extra] = ICONS[name];
    const el = svg("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" });
    el.append(svg("path", { d }));
    if (extra === "circle") el.append(svg("circle", { cx: "12", cy: "12", r: "4" }));
    return el;
  }

  function setupThemeToggle(button) {
    if (!button) return;
    const render = () => {
      const dark = document.documentElement.getAttribute("data-theme") !== "light";
      button.replaceChildren(icon(dark ? "sun" : "moon"));
      button.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
      button.title = button.getAttribute("aria-label");
    };
    button.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("uptime-theme", next); } catch (e) { /* ignore */ }
      render();
    });
    render();
  }

  const dateTimeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  const timeFmt = new Intl.DateTimeFormat(undefined, { timeStyle: "short" });
  const dayFmt = new Intl.DateTimeFormat(undefined, { weekday: "short", day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
  const monthFmt = new Intl.DateTimeFormat(undefined, { month: "long", year: "numeric", timeZone: "UTC" });

  const parse = (iso) => (iso ? new Date(iso) : null);
  const fmtDateTime = (iso) => (iso ? dateTimeFmt.format(parse(iso)) : "—");
  const fmtTime = (iso) => (iso ? timeFmt.format(parse(iso)) : "—");
  const fmtDay = (isoDate) => dayFmt.format(new Date(isoDate + "T00:00:00Z"));
  const fmtMonth = (date) => monthFmt.format(date);

  function fmtPct(value, digits = 2) {
    if (value === null || value === undefined) return "—";
    if (value >= 100) return "100%";
    return value.toFixed(digits) + "%";
  }

  function fmtMs(ms) {
    if (ms === null || ms === undefined) return "—";
    return ms >= 1000 ? (ms / 1000).toFixed(2) + " s" : Math.round(ms) + " ms";
  }

  function fmtDuration(fromIso, toIso) {
    const ms = (toIso ? parse(toIso) : new Date()) - parse(fromIso);
    const min = Math.max(0, Math.round(ms / 60000));
    if (min < 1) return "< 1 min";
    if (min < 60) return min + " min";
    const hours = Math.floor(min / 60);
    if (hours < 48) return hours + " h " + (min % 60) + " min";
    return Math.floor(hours / 24) + " d " + (hours % 24) + " h";
  }

  function fmtRelative(iso) {
    if (!iso) return "never";
    const sec = Math.round((Date.now() - parse(iso)) / 1000);
    if (sec < 10) return "just now";
    if (sec < 60) return sec + " s ago";
    if (sec < 3600) return Math.round(sec / 60) + " min ago";
    if (sec < 86400) return Math.round(sec / 3600) + " h ago";
    return Math.round(sec / 86400) + " d ago";
  }

  function fmtInterval(seconds) {
    if (seconds % 3600 === 0) return seconds / 3600 + " h";
    if (seconds % 60 === 0) return seconds / 60 + " min";
    return seconds + " s";
  }

  // Uptime → colour class for bars and labels.
  function level(uptime) {
    if (uptime === null || uptime === undefined) return "none";
    if (uptime >= 99.9) return "up";
    if (uptime >= 98) return "warn";
    return "down";
  }

  // ---------- Legal pages ----------
  const LEGAL_PATHS = { imprint: "/imprint", privacy: "/privacy" };
  const LINK_PROTOCOLS = ["https:", "http:", "mailto:", "tel:"];

  // Footer links to the configured legal pages; the paths are ours, never taken from the API.
  function renderLegalLinks(container, pages) {
    if (!container) return;
    const links = (pages || []).filter((p) => LEGAL_PATHS[p.kind]).map((p) => h("a", { href: LEGAL_PATHS[p.kind], text: p.title }));
    container.replaceChildren(...links);
    container.hidden = !links.length;
  }

  function safeUrl(raw) {
    let url;
    try { url = new URL(raw, window.location.origin); } catch (e) { return null; }
    return LINK_PROTOCOLS.includes(url.protocol) ? url : null;
  }

  // Inline markup: **bold** and [text](url). The character classes stop at the next
  // delimiter, so matching stays linear even on hostile input.
  const INLINE = /\*\*([^*]+)\*\*|\[([^[\]]+)\]\(([^()\s]+)\)/g;

  function inline(text) {
    const out = [];
    let last = 0;
    for (const m of text.matchAll(INLINE)) {
      if (m.index > last) out.push(text.slice(last, m.index));
      if (m[1] !== undefined) {
        out.push(h("strong", {}, inline(m[1])));
      } else {
        const url = safeUrl(m[3]);
        if (!url) {
          out.push(m[0]); // unsupported scheme: show the source text, never a link
        } else {
          const external = /^https?:$/.test(url.protocol) && url.origin !== window.location.origin;
          out.push(h("a", external
            ? { href: url.href, text: m[2], target: "_blank", rel: "noopener noreferrer" }
            : { href: url.href, text: m[2] }));
        }
      }
      last = m.index + m[0].length;
    }
    if (last < text.length) out.push(text.slice(last));
    return out;
  }

  // A small Markdown subset for legal texts, built as DOM nodes. Nothing is ever parsed
  // as HTML, so tags in the text show up literally.
  function renderRichText(source) {
    const blocks = [];
    let para = null;
    let list = null;
    for (const raw of String(source || "").split("\n")) {
      const line = raw.trim();
      let m;
      if (!line) {
        para = list = null;
      } else if ((m = /^(#{1,3}) (.+)$/.exec(line))) {
        para = list = null;
        blocks.push(h("h" + (m[1].length + 1), {}, inline(m[2])));
      } else if ((m = /^(?:([-*])|(\d{1,9})[.)]) (.+)$/.exec(line))) {
        para = null;
        const tag = m[1] ? "ul" : "ol";
        if (!list || list.tagName.toLowerCase() !== tag) {
          list = h(tag, tag === "ol" && m[2] !== "1" ? { start: String(parseInt(m[2], 10)) } : {});
          blocks.push(list);
        }
        list.append(h("li", {}, inline(m[3])));
      } else if (para) {
        para.append(h("br"), ...inline(line));
      } else {
        list = null;
        para = h("p", {}, inline(line));
        blocks.push(para);
      }
    }
    return blocks;
  }

  return { h, svg, icon, setupThemeToggle, fmtDateTime, fmtTime, fmtDay, fmtMonth, fmtPct, fmtMs, fmtDuration, fmtRelative, fmtInterval, level, renderLegalLinks, renderRichText };
})();
