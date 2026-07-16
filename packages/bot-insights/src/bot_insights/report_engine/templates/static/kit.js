/* Hydrolix report-kit — vanilla-JS shim.
   Binds click/keyboard handlers to elements rendered by the Jinja
   macros via data-hx-* attributes. Drop this <script src> anywhere
   after the macro-rendered DOM (end of <body> is ideal).

   The components themselves degrade reasonably without this script:
     • IOC tabs: all panels stack open.
     • Drawer: shows the first tab; collapse button is inert.
     • Drawer filter: no-op.
     • Copy buttons: user can still select+copy the surrounding text.

   No frameworks, no globals beyond a single HX namespace. ~120 lines. */

(function () {
  "use strict";
  const NS = (window.HX = window.HX || {});

  // ─── Clipboard + download helpers ─────────────────────────────────
  function writeClip(text) {
    try { navigator.clipboard.writeText(text); }
    catch (e) { /* sandboxed iframes can block this; swallow */ }
  }
  function downloadText(filename, body, mime) {
    const blob = new Blob([body], { type: mime || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }
  function flash(btn, ok) {
    const orig = btn.innerHTML;
    btn.classList.add("is-copied");
    btn.innerHTML = ok || "✓ Copied";
    setTimeout(() => { btn.classList.remove("is-copied"); btn.innerHTML = orig; }, 1400);
  }
  NS.writeClip = writeClip;
  NS.downloadText = downloadText;

  // ─── Copy buttons ─────────────────────────────────────────────────
  document.addEventListener("click", function (e) {
    const btn = e.target.closest("[data-hx-copy]");
    if (!btn) return;
    if (btn.dataset.hxCopyStop === "1") e.stopPropagation();
    writeClip(btn.dataset.hxCopy);
    flash(btn);
  });

  // ─── IOC tab panel (kit/_ioc_tabs.html) ───────────────────────────
  document.querySelectorAll("[data-hx-ioc-tabs]").forEach(function (root) {
    const tabs = root.querySelectorAll("[data-hx-tab]");
    const panels = root.querySelectorAll("[data-hx-panel]");
    function show(id) {
      tabs.forEach(t => {
        const on = t.dataset.hxTab === id;
        t.classList.toggle("is-active", on);
        t.setAttribute("aria-selected", on);
      });
      panels.forEach(p => { p.hidden = p.dataset.hxPanel !== id; });
    }
    function activePanel() {
      const active = root.querySelector("[data-hx-tab].is-active");
      return root.querySelector('[data-hx-panel="' + active.dataset.hxTab + '"]');
    }
    tabs.forEach(t => t.addEventListener("click", () => show(t.dataset.hxTab)));
    const copyBtn = root.querySelector("[data-hx-ioc-copy]");
    if (copyBtn) copyBtn.addEventListener("click", () => {
      writeClip(activePanel().textContent);
      flash(copyBtn);
    });
    const dlBtn = root.querySelector("[data-hx-ioc-download]");
    if (dlBtn) dlBtn.addEventListener("click", () => {
      const p = activePanel();
      downloadText(p.dataset.hxFilename || "ioc.txt", p.textContent);
    });
  });

  // ─── IOC drawer (kit/_ioc_drawer.html) ────────────────────────────
  document.querySelectorAll("[data-hx-drawer]").forEach(function (root) {
    const tabs = root.querySelectorAll("[data-hx-drawer-tab]");
    const panels = root.querySelectorAll("[data-hx-drawer-panel]");
    const filterInput = root.querySelector("[data-hx-drawer-filter]");

    function show(id) {
      tabs.forEach(t => t.classList.toggle("is-active", t.dataset.hxDrawerTab === id));
      panels.forEach(p => { p.hidden = p.dataset.hxDrawerPanel !== id; });
      if (filterInput) { filterInput.value = ""; applyFilter(""); }
    }
    function activePanel() {
      const active = root.querySelector("[data-hx-drawer-tab].is-active");
      return root.querySelector('[data-hx-drawer-panel="' + active.dataset.hxDrawerTab + '"]');
    }
    function applyFilter(q) {
      const ql = q.toLowerCase();
      activePanel().querySelectorAll("[data-hx-item]").forEach(item => {
        item.hidden = ql && item.dataset.hxItem.indexOf(ql) === -1;
      });
    }
    tabs.forEach(t => t.addEventListener("click", () => show(t.dataset.hxDrawerTab)));
    if (filterInput) filterInput.addEventListener("input", e => applyFilter(e.target.value));

    const items = (panel) => Array.from(panel.querySelectorAll("[data-hx-item]:not([hidden]) code")).map(c => c.textContent);

    const copyAll = root.querySelector("[data-hx-drawer-copy]");
    if (copyAll) copyAll.addEventListener("click", () => {
      writeClip(items(activePanel()).join("\n"));
      flash(copyAll);
    });
    const dlAll = root.querySelector("[data-hx-drawer-download]");
    if (dlAll) dlAll.addEventListener("click", () => {
      const p = activePanel();
      downloadText(p.dataset.hxFilename || "ioc.txt", items(p).join("\n"));
    });
    root.querySelectorAll("[data-hx-extra-download]").forEach(btn => {
      btn.addEventListener("click", () => {
        const body = document.getElementById(btn.dataset.hxExtraBodyId);
        if (body) downloadText(btn.dataset.hxExtraDownload, body.textContent);
      });
    });

    // Collapse → look for a sibling [data-hx-rail] and swap visibility.
    const collapseBtn = root.querySelector("[data-hx-drawer-collapse]");
    if (collapseBtn) collapseBtn.addEventListener("click", () => setDrawer(false));
  });

  // ─── Drawer ↔ rail toggle ─────────────────────────────────────────
  // The host page provides both <hx-drawer> AND <hx-rail> in the same
  // grid cell; we hide one based on the body's data-hx-drawer-state.
  // Any element with [data-hx-drawer-toggle] toggles it.
  function setDrawer(open) {
    const body = document.body;
    const host = document.querySelector("[data-hx-drawer-host]") || body;
    host.setAttribute("data-hx-drawer-state", open ? "open" : "collapsed");
    document.querySelectorAll("[data-hx-drawer]").forEach(d => { d.hidden = !open; });
    document.querySelectorAll("[data-hx-rail]").forEach(r => { r.hidden = open; });
    document.querySelectorAll("[data-hx-drawer-toggle]").forEach(t => {
      t.innerHTML = open ? "⇱ Hide IOCs" : "⇰ Show IOCs";
    });
  }
  NS.setDrawer = setDrawer;

  document.addEventListener("click", e => {
    if (e.target.closest("[data-hx-rail-expand]")) setDrawer(true);
    if (e.target.closest("[data-hx-drawer-toggle]")) {
      const open = (document.querySelector("[data-hx-drawer-host]") || document.body)
        .getAttribute("data-hx-drawer-state") !== "collapsed";
      setDrawer(!open);
    }
  });
  document.addEventListener("keydown", e => {
    if (e.key === "Enter" || e.key === " ") {
      if (e.target.matches("[data-hx-rail-expand]")) { e.preventDefault(); setDrawer(true); }
    }
  });
})();
