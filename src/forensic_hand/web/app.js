// forensic-hand workbench. Plain JavaScript; it talks only to the server on this computer.
// The server records every action in the case ledger. This page holds no evidence of its own.

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const kid of kids) if (kid != null) node.append(kid);
  return node;
};

// ------------------------------------------------------------------ token and server calls

const TOKEN = (() => {
  const match = location.hash.match(/t=([A-Za-z0-9_-]+)/);
  if (match) {
    sessionStorage.setItem("fh-token", match[1]);
    history.replaceState(null, "", location.pathname);
  }
  return sessionStorage.getItem("fh-token") || "";
})();
const withToken = (url) => `${url}${url.includes("?") ? "&" : "?"}t=${encodeURIComponent(TOKEN)}`;

async function api(path, body) {
  const options = { headers: { "X-FHand-Token": TOKEN } };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data = null;
  try { data = await response.json(); } catch { /* not JSON */ }
  if (!response.ok) throw new Error((data && data.error) || `The request failed (${response.status}).`);
  return data;
}

const images = new Map();
function loadImage(url) {
  if (!images.has(url)) {
    images.set(url, new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => { images.delete(url); reject(new Error("A picture could not be loaded.")); };
      img.src = url;
    }));
  }
  return images.get(url);
}
const cropUrl = (id) => withToken(`/api/crop/${id}.png`);
const chartUrl = (id) => withToken(`/api/exhibit/${id}.png`);

let toastTimer = 0;
function toast(message, isError = false) {
  const box = $("#toast");
  box.textContent = message;
  box.classList.toggle("error", isError);
  box.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => box.classList.remove("show"), isError ? 7000 : 3500);
}
async function act(work, done) {
  try {
    const result = await work();
    await refresh();
    if (done) toast(typeof done === "function" ? done(result) : done);
    return result;
  } catch (error) {
    toast(error.message, true);
    return null;
  }
}

// ------------------------------------------------------------------ state

let S = null;                       // the last state from the server
const ui = {
  tab: "document",
  item: null, page: 1,              // document view
  focus: { type: "case", id: null }, // what the right panel shows
  compare: [], chart: [],           // crop ids
  measureCrop: null,
};
const byId = (list, key, id) => (list || []).find((x) => x[key] === id);
const evidence = (id) => byId(S.evidence, "id", id);
const crop = (id) => byId(S.crops, "crop_id", id);
const pageOf = (id, page) => (S.pages[id] || [])[page - 1];
const roleWord = { questioned: "Questioned", known: "Known", other: "Other" };

async function refresh() {
  S = await api("/api/state");
  ui.compare = ui.compare.filter((id) => crop(id));
  ui.chart = ui.chart.filter((p) => crop(p.crop_id));
  renderAll();
}

function renderAll() {
  $("#caseTitle").textContent = S.case.title;
  $("#caseSub").textContent = `Case ${S.case.case_id.slice(0, 8)} · forensic-hand ${S.tool.version}`;
  renderItems();
  renderCrops();
  renderCharts();
  renderStatus();
  renderInspector();
  if (ui.tab === "document") doc.render();
  if (ui.tab === "compare") cmp.build();
  if (ui.tab === "measure") ms.build();
  if (ui.tab === "chart") chart.build();
}

function renderStatus() {
  const last = S.seals[S.seals.length - 1];
  const seal = last
    ? `Last seal ${last.seal_no}: ${last.sha256.slice(0, 12)}…${last.timestamp ? ` · time stamp ${last.timestamp}` : " · no trusted time stamp"}`
    : "Not sealed yet";
  $("#status").replaceChildren(
    el("span", { text: `Ledger: ${S.ledger.count} events · head ${S.ledger.head.slice(0, 12)}…` }),
    el("span", { text: seal }),
    el("span", { text: "Decision support only. Not a verdict tool." }),
  );
}

// ------------------------------------------------------------------ left rail

function counts(c) {
  if (!c) return null;
  return el("span", { class: "flags" },
    c.warning ? el("span", { class: "dot warning", title: `${c.warning} warning(s)`, text: String(c.warning) }) : null,
    c.notice ? el("span", { class: "dot notice", title: `${c.notice} note(s)`, text: String(c.notice) }) : null);
}

function renderItems() {
  const list = $("#itemList");
  list.replaceChildren(...S.evidence.map((item) => {
    const pages = (S.pages[item.id] || []).length;
    const button = el("button", {
      type: "button", "aria-current": ui.item === item.id ? "true" : "false",
      onclick: () => { openItem(item.id, 1); setFocus("item", item.id); },
    },
    el("span", { class: `badge ${item.role}`, text: item.id }),
    el("span", { class: "item-name" }, item.name,
      el("span", { class: "item-sub", text: `${roleWord[item.role]} · ${item.media_type.toUpperCase()} · ${pages} page${pages === 1 ? "" : "s"}${item.doc_date ? ` · ${item.doc_date}` : ""}` })),
    counts(item.counts));
    return el("li", {}, button);
  }));
}

function toggle(list, value, max) {
  const index = list.indexOf(value);
  if (index >= 0) { list.splice(index, 1); return false; }
  if (list.length >= max) { toast(`You can choose up to ${max}.`, true); return false; }
  list.push(value);
  return true;
}

function renderCrops() {
  $("#cropCount").textContent = S.crops.length ? `(${S.crops.length})` : "";
  $("#cropEmpty").hidden = S.crops.length > 0;
  $("#cropGrid").replaceChildren(...S.crops.map((c) => {
    const inCompare = ui.compare.includes(c.crop_id);
    const inChart = ui.chart.some((p) => p.crop_id === c.crop_id);
    return el("div", {
      class: "tile", tabindex: "0", "aria-current": ui.focus.type === "crop" && ui.focus.id === c.crop_id ? "true" : "false",
      onclick: () => setFocus("crop", c.crop_id),
      onkeydown: (e) => { if (e.key === "Enter") setFocus("crop", c.crop_id); },
    },
    el("img", { src: cropUrl(c.crop_id), alt: `Crop ${c.crop_id}`, loading: "lazy" }),
    el("div", { class: "cap" }, el("b", { text: `${c.crop_id} · ${c.evidence_id} p${c.page}` }), el("span", { text: c.label || "No name" })),
    el("div", { class: "acts" },
      el("button", { type: "button", "aria-pressed": String(inCompare), title: "Add to Compare",
        onclick: (e) => { e.stopPropagation(); toggle(ui.compare, c.crop_id, 4); renderCrops(); if (ui.tab === "compare") cmp.build(); }, text: inCompare ? "In compare" : "Compare +" }),
      el("button", { type: "button", "aria-pressed": String(inChart), title: "Add to Chart",
        onclick: (e) => {
          e.stopPropagation();
          const at = ui.chart.findIndex((p) => p.crop_id === c.crop_id);
          if (at >= 0) ui.chart.splice(at, 1);
          else if (ui.chart.length < 12) ui.chart.push({ crop_id: c.crop_id, label: c.label || "" });
          renderCrops(); if (ui.tab === "chart") chart.build();
        }, text: inChart ? "In chart" : "Chart +" }),
      el("button", { type: "button", title: "Measure this crop",
        onclick: (e) => { e.stopPropagation(); ui.measureCrop = c.crop_id; showTab("measure"); }, text: "Measure" })));
  }));
}

function renderCharts() {
  $("#chartEmpty").hidden = S.exhibits.length > 0;
  $("#chartList").replaceChildren(...S.exhibits.map((x) => el("li", {},
    el("button", {
      type: "button", "aria-current": ui.focus.type === "chart" && ui.focus.id === x.exhibit_id ? "true" : "false",
      onclick: () => { setFocus("chart", x.exhibit_id); chart.show(x.exhibit_id); showTab("chart"); },
    },
    el("span", { class: "badge", text: x.exhibit_id }),
    el("span", { class: "item-name" }, x.title, el("span", { class: "item-sub", text: x.to_scale ? `To scale, ${x.scale_dpi} DPI` : "NOT TO SCALE" })),
    null))));
}

// ------------------------------------------------------------------ right panel

function setFocus(type, id) {
  ui.focus = { type, id };
  renderInspector();
  renderCrops();
  renderCharts();
}

function findingNode(f) {
  return el("div", { class: `finding ${f.level}` },
    el("div", { class: "t" }, f.title, " ", el("span", { class: "code", text: f.code })),
    f.detail ? el("div", { text: f.detail }) : null,
    el("div", { class: "lim", text: `What this does not prove: ${f.limits}` }));
}

function facts(rows) {
  const dl = el("dl", { class: "facts" });
  for (const [k, v] of rows) if (v != null && v !== "") dl.append(el("dt", { text: k }), el("dd", { text: String(v) }));
  return dl;
}

function notesSection(target) {
  const notes = S.notes.filter((n) => n.target === target);
  const area = el("textarea", { maxlength: "5000", placeholder: "Write an observation. It is recorded with the time." });
  const section = el("section", {},
    el("h2", { text: `Notes (${notes.length})` }),
    ...notes.map((n) => el("div", { class: `note${n.superseded_by ? " old" : ""}` },
      n.text,
      el("div", { class: "meta", text: `${n.note_id} · ${n.created}${n.superseded_by ? ` · replaced by ${n.superseded_by}` : ""}${n.supersedes ? ` · replaces ${n.supersedes}` : ""}` }),
      n.superseded_by ? null : el("button", { class: "btn small", type: "button", text: "Correct",
        onclick: () => { area.value = n.text; area.dataset.supersedes = n.note_id; area.focus(); } }))),
    area,
    el("div", { class: "row-actions" },
      el("button", { class: "btn primary", type: "button", text: "Add note", onclick: async () => {
        const text = area.value.trim();
        if (!text) return toast("Write the note first.", true);
        const body = { target, text };
        if (area.dataset.supersedes) body.supersedes = area.dataset.supersedes;
        await act(() => api("/api/note", body), (n) => `${n.note_id} saved.`);
      } })));
  return section;
}

function renderInspector() {
  const box = $("#inspector");
  const { type, id } = ui.focus;
  const parts = [];
  if (type === "item" && evidence(id)) {
    const item = evidence(id);
    const check = S.files[id];
    parts.push(el("section", {},
      el("h2", { text: `${roleWord[item.role]} item ${item.id}` }),
      el("h3", { text: item.name }),
      facts([["Type", item.media_type.toUpperCase()], ["Size", `${item.size.toLocaleString()} bytes`],
        ["Signer", item.signer], ["Document date", item.doc_date || "not given"], ["Note", item.note]]),
      el("p", { class: "mono", text: `SHA-256 ${item.sha256}` })));
    parts.push(el("section", {}, el("h2", { text: "Screening notes" }),
      check ? (check.findings.length ? el("div", {}, ...check.findings.map(findingNode)) : el("p", { class: "muted", text: "Nothing to report." }))
        : el("p", { class: "muted", text: "Not checked yet. Run: fhand check <case>" })));
    parts.push(notesSection(item.id));
  } else if (type === "crop" && crop(id)) {
    const c = crop(id);
    const measures = S.measurements.filter((m) => m.crop_id === id);
    parts.push(el("section", {},
      el("h2", { text: `Crop ${c.crop_id}` }),
      el("img", { class: "inspector-thumb", src: cropUrl(c.crop_id), alt: `Crop ${c.crop_id}` }),
      el("h3", { text: c.label || "No name" }),
      facts([["From", `${c.evidence_id}, page ${c.page}`], ["Area", `${c.box.join(", ")} ${c.units}`],
        ["Pixels", `${c.width} × ${c.height}`], ["Resolution", c.dpi ? `${c.dpi[0]} × ${c.dpi[1]} DPI` : "not known (no mm)"],
        ["Made by", c.method === "pixels" ? "exact pixels of the file" : `PDFium drawing at ${c.render_dpi} DPI`]]),
      el("p", { class: "mono", text: `SHA-256 ${c.sha256}` }),
      el("div", { class: "row-actions" },
        el("button", { class: "btn", type: "button", text: "Measure", onclick: () => { ui.measureCrop = id; showTab("measure"); } }),
        el("button", { class: "btn", type: "button", text: "Show on page", onclick: () => { openItem(c.evidence_id, c.page); showTab("document"); } }))));
    parts.push(el("section", {}, el("h2", { text: `Measurements (${measures.length})` }),
      ...measures.map((m) => el("div", { class: "note" }, describeMeasure(m), m.note ? el("div", { class: "meta", text: m.note }) : null))));
    parts.push(notesSection(c.crop_id));
  } else if (type === "chart" && byId(S.exhibits, "exhibit_id", id)) {
    const x = byId(S.exhibits, "exhibit_id", id);
    parts.push(el("section", {},
      el("h2", { text: `Chart ${x.exhibit_id}` }),
      el("h3", { text: x.title }),
      facts([["Kind", x.kind], ["Scale", x.to_scale ? `${x.scale_dpi} DPI for every panel` : "NOT TO SCALE"],
        ["Size", `${x.width} × ${x.height} px`], ["Made", x.created]]),
      el("p", { class: "mono", text: `SHA-256 ${x.sha256}` }),
      el("div", { class: "row-actions" }, el("a", { class: "btn", href: chartUrl(x.exhibit_id), target: "_blank", rel: "noopener", text: "Open full size" }))));
    parts.push(notesSection(x.exhibit_id));
  } else {
    parts.push(el("section", {}, el("h2", { text: "Case" }), el("h3", { text: S.case.title }),
      facts([["Items", S.evidence.length], ["Crops", S.crops.length], ["Charts", S.exhibits.length], ["Seals", S.seals.length]])));
    parts.push(el("section", {}, el("h2", { text: "Case notes from screening" }),
      S.case_findings ? (S.case_findings.length ? el("div", {}, ...S.case_findings.map(findingNode)) : el("p", { class: "muted", text: "Nothing to report." }))
        : el("p", { class: "muted", text: "Not checked yet." })));
    if (S.clone_check) {
      parts.push(el("section", {}, el("h2", { text: "Copy check" }),
        S.clone_check.findings.length ? el("div", {}, ...S.clone_check.findings.map(findingNode)) : el("p", { class: "muted", text: `No near-identical crops among ${S.clone_check.crops.length}.` })));
    }
    parts.push(notesSection("case"));
  }
  box.replaceChildren(...parts);
}

// ------------------------------------------------------------------ canvas viewer

class Viewer {
  constructor(canvas, draw) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.draw = draw;
    this.scale = 1; this.ox = 0; this.oy = 0;
    this.onChange = null; this.overlay = null;
    this.resizeObserver = new ResizeObserver(() => this.resize());
    this.resizeObserver.observe(canvas.parentElement);
    this.resize();
  }
  resize() {
    const r = this.canvas.parentElement.getBoundingClientRect();
    this.w = Math.max(1, r.width); this.h = Math.max(1, r.height);
    this.dpr = window.devicePixelRatio || 1;
    this.canvas.width = Math.round(this.w * this.dpr);
    this.canvas.height = Math.round(this.h * this.dpr);
    this.canvas.style.width = `${this.w}px`;
    this.canvas.style.height = `${this.h}px`;
    // Until the examiner zooms or moves, keep the content fitted when the area changes size.
    if (this.fitArgs) this.fit(...this.fitArgs);
    else this.render();
  }
  fit(width, height, x0 = 0, y0 = 0, pad = 28) {
    this.fitArgs = [width, height, x0, y0, pad];
    const s = Math.min((this.w - 2 * pad) / width, (this.h - 2 * pad) / height);
    this.scale = s > 0 && Number.isFinite(s) ? s : 1;
    this.ox = (this.w - width * this.scale) / 2 - x0 * this.scale;
    this.oy = (this.h - height * this.scale) / 2 - y0 * this.scale;
    this.changed();
  }
  toWorld(sx, sy) { return [(sx - this.ox) / this.scale, (sy - this.oy) / this.scale]; }
  zoomAt(factor, sx = this.w / 2, sy = this.h / 2) {
    this.fitArgs = null;
    const next = Math.min(64, Math.max(0.02, this.scale * factor));
    const k = next / this.scale;
    this.ox = sx - (sx - this.ox) * k; this.oy = sy - (sy - this.oy) * k; this.scale = next;
    this.changed();
  }
  panBy(dx, dy) { this.fitArgs = null; this.ox += dx; this.oy += dy; this.changed(); }
  setView(scale, ox, oy) { this.fitArgs = null; this.scale = scale; this.ox = ox; this.oy = oy; this.render(); }
  changed() { this.render(); if (this.onChange) this.onChange(this); }
  render() {
    const c = this.ctx;
    c.setTransform(1, 0, 0, 1, 0, 0);
    c.clearRect(0, 0, this.canvas.width, this.canvas.height);
    c.setTransform(this.dpr * this.scale, 0, 0, this.dpr * this.scale, this.dpr * this.ox, this.dpr * this.oy);
    // From 2x zoom, show real pixels (no smoothing): the examiner sees what the file holds.
    c.imageSmoothingEnabled = this.scale < 2;
    c.imageSmoothingQuality = "high";
    if (this.draw) this.draw(c, this);
    c.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    if (this.overlay) this.overlay(c, this);
  }
  destroy() { this.resizeObserver.disconnect(); }
}

// Pointer handling shared by the views. handlers: down(world, e) -> bool (true = the view takes the drag)
function attachPointer(viewer, wrap, handlers = {}) {
  let drag = null;
  viewer.canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = viewer.canvas.getBoundingClientRect();
    viewer.zoomAt(Math.exp(-e.deltaY * 0.0015), e.clientX - r.left, e.clientY - r.top);
  }, { passive: false });
  viewer.canvas.addEventListener("pointerdown", (e) => {
    const r = viewer.canvas.getBoundingClientRect();
    const sx = e.clientX - r.left, sy = e.clientY - r.top;
    const world = viewer.toWorld(sx, sy);
    const custom = !(e.button === 1 || e.shiftKey || spaceDown) && handlers.down && handlers.down(world, e);
    drag = { custom, sx, sy, moved: false };
    viewer.canvas.setPointerCapture(e.pointerId);
    if (!custom) wrap.classList.add("dragging");
  });
  viewer.canvas.addEventListener("pointermove", (e) => {
    const r = viewer.canvas.getBoundingClientRect();
    const sx = e.clientX - r.left, sy = e.clientY - r.top;
    if (handlers.hover) handlers.hover(viewer.toWorld(sx, sy));
    if (!drag) return;
    if (Math.hypot(sx - drag.sx, sy - drag.sy) > 3) drag.moved = true;
    if (drag.custom) handlers.move && handlers.move(viewer.toWorld(sx, sy), e);
    else { viewer.panBy(sx - drag.sx, sy - drag.sy); drag.sx = sx; drag.sy = sy; }
  });
  const end = (e) => {
    if (!drag) return;
    const r = viewer.canvas.getBoundingClientRect();
    const world = viewer.toWorld(e.clientX - r.left, e.clientY - r.top);
    if (drag.custom && handlers.up) handlers.up(world, e, drag.moved);
    if (!drag.custom && !drag.moved && handlers.click) handlers.click(world, e);
    drag = null;
    wrap.classList.remove("dragging");
  };
  viewer.canvas.addEventListener("pointerup", end);
  viewer.canvas.addEventListener("pointercancel", end);
}
let spaceDown = false;
addEventListener("keydown", (e) => { if (e.code === "Space" && !isTyping(e)) spaceDown = true; });
addEventListener("keyup", (e) => { if (e.code === "Space") spaceDown = false; });
const isTyping = (e) => ["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName);

// ------------------------------------------------------------------ document view

const doc = {
  viewer: null, img: null, tool: "pan", box: null, pending: null,
  init() {
    const wrap = $("#docCanvas").parentElement;
    this.viewer = new Viewer($("#docCanvas"), (c, v) => this.drawWorld(c, v));
    this.viewer.onChange = () => { $("#docZoom").textContent = this.img ? `${Math.round(this.viewer.scale * this.unitsToPreview() * 100)}%` : ""; };
    attachPointer(this.viewer, wrap, {
      down: (w) => {
        if (this.tool !== "crop" || !this.img) return false;
        this.box = [w, w];
        return true;
      },
      move: (w) => { if (this.box) { this.box[1] = w; this.viewer.render(); } },
      up: () => this.finishBox(),
    });
    this.setTool("pan");
    $("#toolPan").onclick = () => this.setTool("pan");
    $("#toolCrop").onclick = () => this.setTool("crop");
    $("#docPrev").onclick = () => this.step(-1);
    $("#docNext").onclick = () => this.step(1);
    document.querySelectorAll("[data-zoom]").forEach((b) => {
      b.onclick = () => this.zoom(b.dataset.zoom);
    });
  },
  setTool(tool) {
    this.tool = tool;
    $("#toolPan").setAttribute("aria-pressed", String(tool === "pan"));
    $("#toolCrop").setAttribute("aria-pressed", String(tool === "crop"));
    const wrap = $("#docCanvas").parentElement;
    wrap.classList.toggle("crop", tool === "crop");
    wrap.classList.toggle("pan", tool === "pan");
  },
  zoom(kind) {
    if (!this.img) return;
    if (kind === "fit") this.viewer.fit(this.img.naturalWidth, this.img.naturalHeight);
    else this.viewer.zoomAt(kind === "in" ? 1.25 : 0.8);
  },
  step(delta) {
    if (!ui.item) return;
    const total = (S.pages[ui.item] || []).length;
    const next = ui.page + delta;
    if (next >= 1 && next <= total) openItem(ui.item, next);
  },
  geo() { return ui.item ? pageOf(ui.item, ui.page) : null; },
  // Page units (px or pt) per pixel of the preview picture.
  unitsPerPreview() { const g = this.geo(); return g && this.img ? g.width / this.img.naturalWidth : 1; },
  unitsToPreview() { return 1 / this.unitsPerPreview(); },
  async load() {
    const g = this.geo();
    this.img = null;
    $("#docHint").hidden = true;
    if (!g) { $("#docHint").textContent = "This item has no pages that the workbench can show."; $("#docHint").hidden = false; this.viewer.render(); return; }
    const width = Math.round(Math.min(3000, g.units === "px" ? g.width : (g.width / 72) * 200));
    const url = withToken(`/api/page/${ui.item}/${ui.page}?w=${width}`);
    try {
      const img = await loadImage(url);
      if (this.geo() !== g) return;
      this.img = img;
      this.viewer.fit(img.naturalWidth, img.naturalHeight);
    } catch (error) {
      toast(error.message, true);
    }
  },
  render() {
    const item = ui.item && evidence(ui.item);
    $("#docName").textContent = item ? `${item.id} · ${item.name}` : "No item open";
    const total = item ? (S.pages[item.id] || []).length : 0;
    $("#docPage").textContent = item ? `page ${ui.page} of ${total}` : "–";
    $("#docPrev").disabled = !item || ui.page <= 1;
    $("#docNext").disabled = !item || ui.page >= total;
    this.viewer.render();
  },
  drawWorld(c, v) {
    if (!this.img) return;
    c.drawImage(this.img, 0, 0);
    const k = this.unitsToPreview();
    c.lineWidth = 1.5 / v.scale;
    c.font = `${12 / v.scale}px system-ui, sans-serif`;
    for (const cr of S.crops.filter((x) => x.evidence_id === ui.item && x.page === ui.page)) {
      const [x0, y0, x1, y1] = cr.box.map((n) => n * k);
      c.strokeStyle = ui.focus.id === cr.crop_id ? "#ffcc66" : "rgba(255, 196, 80, .85)";
      c.setLineDash([]);
      c.strokeRect(x0, y0, x1 - x0, y1 - y0);
      c.fillStyle = "rgba(20, 16, 6, .85)";
      const label = cr.crop_id;
      const tw = c.measureText(label).width + 8 / v.scale;
      c.fillRect(x0, y0 - 16 / v.scale, tw, 16 / v.scale);
      c.fillStyle = "#ffd88a";
      c.fillText(label, x0 + 4 / v.scale, y0 - 4 / v.scale);
    }
    if (this.box) {
      const [[ax, ay], [bx, by]] = this.box;
      c.strokeStyle = "#9ec5ff";
      c.setLineDash([6 / v.scale, 4 / v.scale]);
      c.strokeRect(Math.min(ax, bx), Math.min(ay, by), Math.abs(bx - ax), Math.abs(by - ay));
      c.setLineDash([]);
    }
  },
  finishBox() {
    const g = this.geo();
    if (!this.box || !g) return;
    const [[ax, ay], [bx, by]] = this.box;
    this.box = null;
    const k = this.unitsPerPreview();
    const clamp = (v, hi) => Math.max(0, Math.min(hi, v));
    let box = [clamp(Math.min(ax, bx) * k, g.width), clamp(Math.min(ay, by) * k, g.height),
      clamp(Math.max(ax, bx) * k, g.width), clamp(Math.max(ay, by) * k, g.height)];
    if (g.units === "px") box = box.map(Math.round);
    else box = box.map((n) => Math.round(n * 100) / 100);
    this.viewer.render();
    if (box[2] - box[0] < 4 || box[3] - box[1] < 4) return toast("The box is too small. Drag a larger box.", true);
    openCropDialog(box, g);
  },
};

async function openItem(id, page) {
  ui.item = id; ui.page = page;
  renderItems();
  if (ui.tab !== "document") showTab("document");
  doc.render();
  await doc.load();
}

function openCropDialog(box, g) {
  const dialog = $("#dlgCrop");
  const item = evidence(ui.item);
  $("#cropInfo").textContent = `${item.id}, page ${ui.page}: ${box.join(", ")} ${g.units}`;
  $("#cropLabel").value = "";
  const select = $("#cropDpi");
  const isPdf = g.units === "pt";
  $("#cropDpiField").hidden = !isPdf;
  if (isPdf) {
    const scan = g.dpi ? g.dpi[0] : null;
    const options = [...new Set([scan, 150, 300, 600].filter(Boolean))];
    select.replaceChildren(...options.map((d) => el("option", { value: String(d), text: d === scan ? `${d} DPI (resolution of the scan)` : `${d} DPI` })));
    select.value = String(scan || 300);
    $("#cropNote").textContent = "A PDF crop is a new drawing of the page area at this resolution. Above the scan resolution, no new detail appears.";
  } else {
    $("#cropNote").textContent = `The crop keeps the exact pixels of the file${g.dpi ? ` (${g.dpi[0]} DPI)` : " (resolution not known: no mm)"}.`;
  }
  dialog.returnValue = "";
  $("#cropLabel").onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); dialog.close("ok"); } };
  dialog.onclose = async () => {
    if (dialog.returnValue !== "ok") return;
    const body = { evidence_id: item.id, page: ui.page, box, label: $("#cropLabel").value.trim() || null };
    if (isPdf) body.dpi = Number(select.value);
    const made = await act(() => api("/api/crop", body), (c) => `${c.crop_id} saved (${c.width} × ${c.height} px).`);
    if (made) setFocus("crop", made.crop_id);
  };
  dialog.showModal();
  $("#cropLabel").focus();
}

// ------------------------------------------------------------------ compare view

function commonScale(crops) {
  if (!crops.length || crops.some((c) => !c.dpi)) return null;
  let s = Math.min(600, Math.max(...crops.map((c) => Math.max(...c.dpi))));
  const widest = Math.max(...crops.map((c) => Math.max(c.width * s / c.dpi[0], c.height * s / c.dpi[1])));
  if (widest > 2400) s = Math.floor(s * 2400 / widest);
  return Math.max(s, 1);
}
function panelSize(c, scale, height) {
  if (scale) return [Math.max(1, Math.round(c.width * scale / c.dpi[0])), Math.max(1, Math.round(c.height * scale / c.dpi[1]))];
  return [Math.max(1, Math.round(c.width * height / c.height)), height];
}

function tinted(img, size, color) {
  const canvas = el("canvas");
  [canvas.width, canvas.height] = size;
  const c = canvas.getContext("2d");
  c.imageSmoothingQuality = "high";
  c.drawImage(img, 0, 0, size[0], size[1]);
  const data = c.getImageData(0, 0, size[0], size[1]);
  const p = data.data;
  for (let i = 0; i < p.length; i += 4) {
    const gray = (p[i] + p[i + 1] + p[i + 2]) / 3;
    if (color === "red") { p[i] = 255; p[i + 1] = gray; p[i + 2] = gray; }
    else { p[i] = gray; p[i + 1] = gray; p[i + 2] = 255; }
    p[i + 3] = 255;
  }
  c.putImageData(data, 0, 0);
  return canvas;
}

const cmp = {
  viewers: [], ov: { dx: 0, dy: 0, rotation: 0, scale: 1, opacity: 0.8 },
  init() {
    for (const id of ["#cmpSame", "#cmpLink", "#cmpOverlay"]) $(id).onchange = () => this.build();
    $("#cmpFit").onclick = () => this.fitAll();
    $("#cmpClear").onclick = () => { ui.compare = []; renderCrops(); this.build(); };
    $("#ovOpacity").oninput = (e) => { this.ov.opacity = Number(e.target.value); this.redraw(); };
    $("#ovRot").oninput = (e) => { this.ov.rotation = Number(e.target.value); this.syncOutputs(); this.redraw(); };
    $("#ovScale").oninput = (e) => { this.ov.scale = Number(e.target.value); this.syncOutputs(); this.redraw(); };
    $("#ovReset").onclick = () => { Object.assign(this.ov, { dx: 0, dy: 0, rotation: 0, scale: 1 }); this.syncOutputs(); this.redraw(); };
    $("#ovSave").onclick = () => this.saveOverlay();
  },
  syncOutputs() {
    $("#ovRot").value = String(this.ov.rotation);
    $("#ovScale").value = String(this.ov.scale);
    $("#ovRotOut").textContent = `${this.ov.rotation.toFixed(1)}°`;
    $("#ovScaleOut").textContent = `${this.ov.scale.toFixed(3)}×`;
  },
  redraw() { for (const v of this.viewers) v.render(); },
  fitAll() { for (const v of this.viewers) v.fitBox && v.fitBox(); },
  async build() {
    for (const v of this.viewers) v.destroy();
    this.viewers = [];
    const panes = $("#cmpPanes");
    panes.replaceChildren();
    const crops = ui.compare.map(crop).filter(Boolean);
    $("#cmpChips").replaceChildren(...(crops.length ? crops.map((c) => el("span", { class: "chip" }, c.crop_id,
      el("button", { type: "button", "aria-label": `Remove ${c.crop_id}`, text: "×", onclick: () => { toggle(ui.compare, c.crop_id, 4); renderCrops(); this.build(); } })))
      : [el("span", { class: "muted", text: "No crops chosen." })]));
    $("#cmpHint").hidden = crops.length > 0;
    const overlay = $("#cmpOverlay").checked && crops.length === 2;
    $("#cmpOverlay").disabled = crops.length !== 2;
    $("#ovControls").hidden = !overlay;
    if (!crops.length) return;
    const same = $("#cmpSame").checked;
    const scale = same ? commonScale(crops) : null;
    const height = Math.min(600, Math.max(...crops.map((c) => c.height)));
    const imgs = await Promise.all(crops.map((c) => loadImage(cropUrl(c.crop_id)).catch(() => null)));
    if (overlay) return this.buildOverlay(crops, imgs, scale, height);
    panes.style.gridTemplateColumns = `repeat(${crops.length <= 2 ? crops.length : 2}, minmax(0, 1fr))`;
    const sizes = crops.map((c) => (same ? panelSize(c, scale, height) : [c.width, c.height]));
    const bw = Math.max(...sizes.map((s) => s[0])), bh = Math.max(...sizes.map((s) => s[1]));
    crops.forEach((c, i) => {
      const canvas = el("canvas");
      const wrap = el("div", { class: "canvas-wrap pan" }, canvas);
      const note = same ? (scale ? `same scale: ${scale} DPI` : "NOT TO SCALE (a crop has no resolution)") : "own pixels";
      panes.append(el("div", { class: "pane" },
        el("header", {}, el("b", { text: c.crop_id }), el("span", { class: "muted", text: `${c.evidence_id} p${c.page} · ${c.label || "no name"} · ${note}` })), wrap));
      const size = sizes[i];
      const v = new Viewer(canvas, (ctx) => {
        ctx.fillStyle = "#fff";
        ctx.fillRect(0, 0, size[0], size[1]);
        if (imgs[i]) ctx.drawImage(imgs[i], 0, 0, size[0], size[1]);
      });
      v.fitBox = () => v.fit(bw, bh);
      attachPointer(v, wrap);
      v.onChange = (src) => { if ($("#cmpLink").checked) for (const o of this.viewers) if (o !== src) o.setView(src.scale, src.ox, src.oy); };
      this.viewers.push(v);
    });
    requestAnimationFrame(() => this.fitAll());
  },
  buildOverlay(crops, imgs, scale, height) {
    const panes = $("#cmpPanes");
    panes.style.gridTemplateColumns = "minmax(0, 1fr)";
    const [a, b] = crops;
    const sizeA = panelSize(a, scale, height), sizeB = panelSize(b, scale, height);
    const tintA = imgs[0] && tinted(imgs[0], sizeA, "red");
    const tintB = imgs[1] && tinted(imgs[1], sizeB, "blue");
    const canvas = el("canvas");
    const wrap = el("div", { class: "canvas-wrap" }, canvas);
    panes.append(el("div", { class: "pane" },
      el("header", {}, el("span", { class: "legend-a", text: `Red: ${a.crop_id}` }), el("span", { class: "legend-b", text: `Blue: ${b.crop_id}` }),
        el("span", { class: "muted", text: scale ? `same scale: ${scale} DPI` : "NOT TO SCALE" })), wrap));
    const ov = this.ov;
    const v = new Viewer(canvas, (ctx) => {
      const w = Math.max(sizeA[0], sizeB[0] * ov.scale) + 80, h = Math.max(sizeA[1], sizeB[1] * ov.scale) + 80;
      ctx.fillStyle = "#fff";
      ctx.fillRect(-w / 2 - Math.abs(ov.dx), -h / 2 - Math.abs(ov.dy), w + 2 * Math.abs(ov.dx), h + 2 * Math.abs(ov.dy));
      ctx.globalCompositeOperation = "multiply";
      if (tintA) ctx.drawImage(tintA, -sizeA[0] / 2, -sizeA[1] / 2);
      if (tintB) {
        ctx.save();
        ctx.globalAlpha = ov.opacity;
        ctx.translate(ov.dx, ov.dy);
        ctx.rotate((-ov.rotation * Math.PI) / 180);       // same turn direction as the saved chart
        ctx.drawImage(tintB, (-sizeB[0] * ov.scale) / 2, (-sizeB[1] * ov.scale) / 2, sizeB[0] * ov.scale, sizeB[1] * ov.scale);
        ctx.restore();
      }
      ctx.globalCompositeOperation = "source-over";
    });
    let last = null;
    attachPointer(v, wrap, {
      down: (w) => { last = w; return true; },
      move: (w) => { ov.dx += w[0] - last[0]; ov.dy += w[1] - last[1]; last = w; v.render(); },
      up: () => { ov.dx = Math.round(ov.dx * 10) / 10; ov.dy = Math.round(ov.dy * 10) / 10; },
    });
    const bw = Math.max(sizeA[0], sizeB[0]) + 80, bh = Math.max(sizeA[1], sizeB[1]) + 80;
    v.fitBox = () => v.fit(bw, bh, -bw / 2, -bh / 2);
    this.viewers.push(v);
    this.syncOutputs();
    requestAnimationFrame(() => v.fitBox());
  },
  async saveOverlay() {
    const [a, b] = ui.compare;
    const title = await askTitle("Overlay chart", `Overlay of ${a} (red) and ${b} (blue)`);
    if (!title) return;
    const ov = this.ov;
    const made = await act(() => api("/api/exhibit", { title, kind: "overlay",
      overlay: { a, b, dx: ov.dx, dy: ov.dy, rotation: ov.rotation, scale: ov.scale } }), (x) => `${x.exhibit_id} saved.`);
    if (made) { setFocus("chart", made.exhibit_id); chart.show(made.exhibit_id); }
  },
};

// ------------------------------------------------------------------ measure view

function lineValues(p, q, dpi) {
  let dx = q[0] - p[0], dy = q[1] - p[1];
  const px = Math.hypot(dx, dy);
  let mm = null;
  if (dpi) { dx /= dpi[0]; dy /= dpi[1]; mm = Math.hypot(dx, dy) * 25.4; }
  const angle = (((Math.atan2(-dy, dx) * 180) / Math.PI) % 180 + 180) % 180;
  return { px, mm, angle };
}
function describeMeasure(m) {
  if (m.kind === "line") {
    const len = m.length_mm != null ? `${m.length_mm.toFixed(2)} mm` : `${m.length_px} px`;
    return `${m.measure_id}: line ${len}, angle ${m.angle_deg.toFixed(1)}°`;
  }
  return `${m.measure_id}: angle between lines ${m.angle_between_deg.toFixed(1)}°`;
}

const ms = {
  viewer: null, img: null, tool: "line", pts: [], hover: null,
  init() {
    const wrap = $("#msCanvas").parentElement;
    this.viewer = new Viewer($("#msCanvas"), (c, v) => this.drawWorld(c, v));
    attachPointer(this.viewer, wrap, {
      click: (w) => this.addPoint(w),
      hover: (w) => { this.hover = w; if (this.pts.length % 2 === 1) this.viewer.render(); },
    });
    $("#msLine").onclick = () => this.setTool("line");
    $("#msAngle").onclick = () => this.setTool("angle");
    $("#msClear").onclick = () => this.clear();
    $("#msCrop").onchange = (e) => { ui.measureCrop = e.target.value; this.load(); };
    $("#msSave").onclick = () => this.save();
  },
  need() { return this.tool === "line" ? 2 : 4; },
  setTool(tool) {
    this.tool = tool;
    $("#msLine").setAttribute("aria-pressed", String(tool === "line"));
    $("#msAngle").setAttribute("aria-pressed", String(tool === "angle"));
    this.clear();
  },
  clear() { this.pts = []; this.readout(); this.viewer.render(); },
  crop() { return ui.measureCrop && crop(ui.measureCrop); },
  build() {
    const select = $("#msCrop");
    select.replaceChildren(...S.crops.map((c) => el("option", { value: c.crop_id, text: `${c.crop_id} · ${c.evidence_id} p${c.page}${c.label ? ` · ${c.label}` : ""}` })));
    if (!this.crop() && S.crops.length) ui.measureCrop = S.crops[0].crop_id;
    if (ui.measureCrop) select.value = ui.measureCrop;
    $("#msHint").hidden = S.crops.length > 0;
    this.load();
  },
  async load() {
    const c = this.crop();
    this.pts = [];
    this.readout();
    if (!c) { this.img = null; this.viewer.render(); return; }
    try {
      this.img = await loadImage(cropUrl(c.crop_id));
      this.viewer.fit(c.width, c.height);
    } catch (error) { toast(error.message, true); }
  },
  addPoint(w) {
    const c = this.crop();
    if (!c) return;
    if (this.pts.length >= this.need()) this.pts = [];
    const x = Math.max(0, Math.min(c.width, w[0])), y = Math.max(0, Math.min(c.height, w[1]));
    this.pts.push([Math.round(x * 100) / 100, Math.round(y * 100) / 100]);
    this.readout();
    this.viewer.render();
  },
  readout() {
    const c = this.crop();
    const out = $("#msReadout");
    const done = this.pts.length === this.need();
    $("#msSave").disabled = !done;
    if (!c) { out.textContent = "Choose a crop."; return; }
    const unit = c.dpi ? "" : " (no resolution: pixels only)";
    if (this.tool === "line") {
      if (!done) { out.textContent = `Click ${2 - this.pts.length} point(s) on the line.${unit}`; return; }
      const r = lineValues(this.pts[0], this.pts[1], c.dpi);
      out.textContent = `Length ${r.mm != null ? `${r.mm.toFixed(2)} mm` : `${r.px.toFixed(1)} px`} · angle ${r.angle.toFixed(1)}°`;
    } else {
      if (!done) { out.textContent = `Click ${4 - this.pts.length} more point(s): first line, then second line.${unit}`; return; }
      const a = lineValues(this.pts[0], this.pts[1], c.dpi).angle, b = lineValues(this.pts[2], this.pts[3], c.dpi).angle;
      const between = (((b - a) % 180) + 180) % 180;
      out.textContent = `Angle between the lines ${between.toFixed(1)}°`;
    }
  },
  drawWorld(c, v) {
    const cr = this.crop();
    if (!this.img || !cr) return;
    c.fillStyle = "#fff";
    c.fillRect(0, 0, cr.width, cr.height);
    c.drawImage(this.img, 0, 0);
    const line = (p, q, color, dash = []) => {
      c.strokeStyle = color; c.setLineDash(dash.map((d) => d / v.scale)); c.lineWidth = 2 / v.scale;
      c.beginPath(); c.moveTo(p[0], p[1]); c.lineTo(q[0], q[1]); c.stroke(); c.setLineDash([]);
    };
    const dot = (p, color) => { c.fillStyle = color; c.beginPath(); c.arc(p[0], p[1], 4 / v.scale, 0, Math.PI * 2); c.fill(); };
    for (const m of S.measurements.filter((x) => x.crop_id === cr.crop_id)) {
      for (let i = 0; i < m.points.length; i += 2) line(m.points[i], m.points[i + 1], "rgba(40, 140, 220, .85)");
    }
    for (let i = 0; i < this.pts.length; i += 2) {
      const p = this.pts[i], q = this.pts[i + 1] || this.hover;
      if (q) line(p, q, "#e8590c", i + 1 < this.pts.length ? [] : [6, 4]);
    }
    for (const p of this.pts) dot(p, "#e8590c");
  },
  async save() {
    const c = this.crop();
    if (!c || this.pts.length !== this.need()) return;
    const note = $("#msNote").value.trim() || null;
    const made = await act(() => api("/api/measure", { crop_id: c.crop_id, kind: this.tool, points: this.pts, note }),
      (m) => `${m.measure_id} saved.`);
    if (made) { $("#msNote").value = ""; this.pts = []; this.readout(); this.viewer.render(); }
  },
};

// ------------------------------------------------------------------ chart view

const chart = {
  shown: null,
  init() {
    $("#chartForm").onsubmit = (e) => { e.preventDefault(); this.make(); };
  },
  build() {
    const list = $("#chartPanels");
    $("#chartPanelsEmpty").hidden = ui.chart.length > 0;
    $("#chartMake").disabled = !ui.chart.length;
    list.replaceChildren(...ui.chart.map((p, i) => {
      const input = el("input", { type: "text", value: p.label, maxlength: "120", placeholder: `Label for ${p.crop_id}`,
        "aria-label": `Label for ${p.crop_id}`, oninput: (e) => { p.label = e.target.value; } });
      const move = (d) => { const j = i + d; if (j < 0 || j >= ui.chart.length) return; [ui.chart[i], ui.chart[j]] = [ui.chart[j], ui.chart[i]]; this.build(); };
      return el("li", {}, el("img", { src: cropUrl(p.crop_id), alt: p.crop_id }),
        el("div", {}, el("b", { text: p.crop_id }), input),
        el("div", { class: "ops" },
          el("button", { class: "btn icon", type: "button", "aria-label": "Move up", text: "↑", onclick: () => move(-1) }),
          el("button", { class: "btn icon", type: "button", "aria-label": "Move down", text: "↓", onclick: () => move(1) }),
          el("button", { class: "btn icon", type: "button", "aria-label": "Remove", text: "×", onclick: () => { ui.chart.splice(i, 1); renderCrops(); this.build(); } })));
    }));
    if (this.shown) this.show(this.shown);
  },
  show(id) {
    const x = byId(S.exhibits, "exhibit_id", id);
    if (!x) return;
    this.shown = id;
    $("#chartPreview").replaceChildren(
      el("img", { src: chartUrl(id), alt: x.title }),
      el("figcaption", { class: "muted", text: `${x.exhibit_id} · ${x.title} · ${x.to_scale ? `${x.scale_dpi} DPI for every panel` : "NOT TO SCALE"} · SHA-256 ${x.sha256.slice(0, 16)}…` }));
  },
  async make() {
    const title = $("#chartTitle").value.trim();
    if (!title) return toast("Give the chart a title.", true);
    const panels = ui.chart.map((p) => ({ crop_id: p.crop_id, label: p.label.trim() || null }));
    const made = await act(() => api("/api/exhibit", { title, panels }), (x) => `${x.exhibit_id} saved.`);
    if (made) { this.show(made.exhibit_id); setFocus("chart", made.exhibit_id); }
  },
};

// ------------------------------------------------------------------ top actions

function showTab(tab) {
  ui.tab = tab;
  for (const name of ["document", "compare", "measure", "chart"]) {
    $(`#view-${name}`).hidden = name !== tab;
    $(`#tab-${name}`).setAttribute("aria-selected", String(name === tab));
  }
  if (tab === "document") { doc.render(); doc.viewer.resize(); }
  if (tab === "compare") cmp.build();
  if (tab === "measure") { ms.viewer.resize(); ms.build(); }
  if (tab === "chart") chart.build();
}

function askTitle(heading, suggestion) {
  const dialog = $("#dlgTitle");
  const input = $("#titleInput");
  $("#titleHead").textContent = heading;
  input.value = suggestion;
  dialog.returnValue = "";
  input.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); dialog.close("ok"); } };
  return new Promise((resolve) => {
    dialog.onclose = () => resolve(dialog.returnValue === "ok" ? input.value.trim() || null : null);
    dialog.showModal();
    input.select();
  });
}

function clonesDialog(result) {
  const name = (id) => { const c = crop(id); return c ? `${id} (${c.evidence_id} p${c.page})` : id; };
  const pairs = [...result.pairs].sort((x, y) => (y.score ?? -1) - (x.score ?? -1));
  const body = $("#clonesBody");
  body.replaceChildren(...[
    el("p", { class: "muted", text: `${result.crops.length} crop(s) compared. ${result.settings.status}` }),
    ...(result.findings.length ? result.findings.map(findingNode) : [el("p", { text: "No pair matches point for point." })]),
    result.skipped.length ? el("p", { class: "muted", text: `Skipped (no clear ink): ${result.skipped.join(", ")}` }) : null,
    pairs.length ? el("table", { class: "pairs" },
      el("tr", {}, el("th", { text: "Crop" }), el("th", { text: "Crop" }), el("th", { text: "Match score" })),
      ...pairs.map((p) => el("tr", {}, el("td", { text: name(p.a) }), el("td", { text: name(p.b) }),
        el("td", {}, p.score == null ? el("span", { class: "muted", text: p.reason || "not compared" })
          : el("span", {}, p.score.toFixed(3), (() => { const bar = el("span", { class: "score-bar" }); bar.style.width = `${Math.max(2, p.score * 80)}px`; return bar; })())))))
      : null,
    el("p", { class: "muted small", text: "1.000 means the same ink point for point. Two genuine signatures never match exactly. A very high score fits a digital copy, or two scans of the same paper. Crop tightly: printed lines are removed, but other marks in a crop lower the score." }),
  ].filter(Boolean));
  $("#dlgClones").showModal();
}

function initActions() {
  document.querySelectorAll(".tabs [data-tab]").forEach((b) => { b.onclick = () => showTab(b.dataset.tab); });
  $("#btnClones").onclick = async () => {
    if (S.crops.length < 2) return toast("Make at least two crops first.", true);
    $("#btnClones").disabled = true;
    const result = await act(() => api("/api/clones", {}));
    $("#btnClones").disabled = false;
    if (result) clonesDialog(result);
  };
  $("#btnSeal").onclick = () => {
    const dialog = $("#dlgSeal");
    $("#sealStamp").checked = false;
    dialog.returnValue = "";
    dialog.onclose = () => {
      if (dialog.returnValue !== "ok") return;
      act(() => api("/api/seal", { timestamp: $("#sealStamp").checked }),
        (s) => `Seal ${s.seal_no} made${s.timestamp ? `, time stamp ${s.timestamp.gen_time}` : ""}.`);
    };
    dialog.showModal();
  };
  $("#btnReport").onclick = async () => {
    const tab = window.open("about:blank", "_blank");
    const done = await act(() => api("/api/report", {}), tab ? "Report written." : null);
    if (done && tab) tab.location = withToken("/report");
    else if (tab) tab.close();
    else if (done) toast("Report written to reports/report.html in the case folder. The browser blocked the new tab; allow pop-ups for this page to open it here.");
  };
  addEventListener("keydown", (e) => {
    if (isTyping(e) || e.ctrlKey || e.metaKey || e.altKey || document.querySelector("dialog[open]")) return;
    const key = e.key.toLowerCase();
    if (ui.tab === "document") {
      if (key === "c") doc.setTool("crop");
      else if (key === "h") doc.setTool("pan");
      else if (key === "0") doc.zoom("fit");
      else if (key === "+" || key === "=") doc.zoom("in");
      else if (key === "-") doc.zoom("out");
      else if (key === "pagedown") doc.step(1);
      else if (key === "pageup") doc.step(-1);
    } else if (ui.tab === "measure") {
      if (key === "l") ms.setTool("line");
      else if (key === "a") ms.setTool("angle");
      else if (key === "escape") ms.clear();
    } else if (ui.tab === "compare" && $("#cmpOverlay").checked) {
      const step = e.shiftKey ? 1 : 0.1;
      if (key === "[") { cmp.ov.rotation = Math.max(-15, cmp.ov.rotation - step); cmp.syncOutputs(); cmp.redraw(); }
      if (key === "]") { cmp.ov.rotation = Math.min(15, cmp.ov.rotation + step); cmp.syncOutputs(); cmp.redraw(); }
    }
  });
}

// ------------------------------------------------------------------ start

async function start() {
  if (!TOKEN) {
    $("#caseTitle").textContent = "No key";
    $("#docHint").textContent = "Open the workbench with the address that `fhand serve` printed. It holds a one-time key.";
    return;
  }
  doc.init(); cmp.init(); ms.init(); chart.init(); initActions();
  try {
    await refresh();
    if (S.evidence.length) await openItem(S.evidence[0].id, 1);
  } catch (error) {
    $("#caseTitle").textContent = "Cannot reach the workbench";
    $("#docHint").textContent = error.message;
  }
}
start();
