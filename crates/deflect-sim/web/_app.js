
// ---- palette (resolved once) ---------------------------------------------
const rootCss = getComputedStyle(document.documentElement);
const V = (n) => rootCss.getPropertyValue(n).trim();
const INK = [V("--ink-0"), V("--ink-1"), V("--ink-2"), V("--ink-3")];
const EMBER = V("--ember");
const BG = V("--bg");
const MONO = '"JetBrains Mono", ui-monospace, monospace';

// verdict -> particle tone (0 pass bright .. 3 drop ember)
const VTONE = [INK[0], INK[1], INK[2], EMBER];

const CLASSES = [
  { name: "Legitimate",   glyph: "circle",   catcher: "reaches core" },
  { name: "SYN flood",    glyph: "triangle", catcher: "syncookie" },
  { name: "Flag anomaly", glyph: "cross",    catcher: "signature" },
  { name: "Reflection",   glyph: "diamond",  catcher: "reflect" },
  { name: "Volumetric",   glyph: "square",   catcher: "ratelimit" },
  { name: "Novel flood",  glyph: "pentagon", catcher: "fingerprint" },
];
const VERDICTS = ["Pass", "Challenge", "RateLimit", "Drop"];
const VSHORT = ["PASS", "CHAL", "RATE", "DROP"];

// stage code 1..5 -> defending ring; 0 = passed to core.
const STAGES = [
  { code: 1, frac: 1.00, name: "signature",   cap: "illegal TCP flags",   adaptive: false },
  { code: 2, frac: 0.82, name: "reflect",     cap: "unsolicited replies", adaptive: false },
  { code: 3, frac: 0.64, name: "syncookie",   cap: "SYN flood challenge",  adaptive: true },
  { code: 4, frac: 0.46, name: "ratelimit",   cap: "per-/24 governor",     adaptive: true },
  { code: 5, frac: 0.30, name: "fingerprint", cap: "learned novel flood",  adaptive: true },
];
const RING = {}; STAGES.forEach((s) => (RING[s.code] = s));
const CORE_FRAC = 0.12;

// left-hemisphere spawn arc (radians; π points left)
const A0 = Math.PI * 0.60, A1 = Math.PI * 1.40;

// ---- glyphs ---------------------------------------------------------------
function glyphPath(kind, cx, cy, r) {
  const p = new Path2D();
  if (kind === "circle") { p.arc(cx, cy, r, 0, Math.PI * 2); return p; }
  if (kind === "cross") {
    p.moveTo(cx - r, cy - r); p.lineTo(cx + r, cy + r);
    p.moveTo(cx + r, cy - r); p.lineTo(cx - r, cy + r); return p;
  }
  const sides = { triangle: 3, diamond: 4, square: 4, pentagon: 5 }[kind] || 4;
  const rot = kind === "square" ? Math.PI / 4 : -Math.PI / 2;
  const rr = kind === "square" ? r * 1.12 : r;
  for (let i = 0; i < sides; i++) {
    const a = rot + (i / sides) * Math.PI * 2;
    const x = cx + Math.cos(a) * rr, y = cy + Math.sin(a) * rr;
    if (i === 0) p.moveTo(x, y); else p.lineTo(x, y);
  }
  p.closePath(); return p;
}
function glyphMiniSvg(kind) {
  const s = 14, c = 7, r = 4.6, col = V("--ink-1");
  const st = `stroke="${col}" fill="none" stroke-width="1.1" stroke-linejoin="round"`;
  if (kind === "circle") return `<svg class="glyph-mini" viewBox="0 0 ${s} ${s}"><circle cx="${c}" cy="${c}" r="${r}" ${st}/></svg>`;
  if (kind === "cross") return `<svg class="glyph-mini" viewBox="0 0 ${s} ${s}"><path d="M${c-r} ${c-r}L${c+r} ${c+r}M${c+r} ${c-r}L${c-r} ${c+r}" ${st} stroke-linecap="round"/></svg>`;
  const sides = { triangle: 3, diamond: 4, square: 4, pentagon: 5 }[kind];
  const rot = kind === "square" ? Math.PI / 4 : -Math.PI / 2;
  const rr = kind === "square" ? r * 1.1 : r;
  let d = "";
  for (let i = 0; i < sides; i++) { const a = rot + (i / sides) * Math.PI * 2; d += (i ? "L" : "M") + (c + Math.cos(a) * rr).toFixed(1) + " " + (c + Math.sin(a) * rr).toFixed(1); }
  return `<svg class="glyph-mini" viewBox="0 0 ${s} ${s}"><path d="${d}Z" ${st}/></svg>`;
}

// ---- state ----------------------------------------------------------------
const el = (id) => document.getElementById(id);
const canvas = el("scope");
const ctx = canvas.getContext("2d");
let trail, trailCtx, bands, bandsCtx;

const state = {
  pps: 6000, solicitedPermil: 120,
  weights: [1.0, 1.0, 0.6, 1.0, 1.2, 1.0],
  seed: 2600712, speed: 8, running: true,
};
let sim = null, particles = [], coreEnergy = 0;
const stageCount = [0, 0, 0, 0, 0, 0]; // index = stage code (0=core)
let feedLines = [], feedSeq = 0, armed = false;
const MAX_PARTICLES = 700;

// ---- controls -------------------------------------------------------------
const SLIDERS = [
  { key: "pps", label: "Offered load", min: 500, max: 12000, step: 250, unit: "pps", get: () => state.pps, set: (v) => (state.pps = v) },
  ...CLASSES.map((c, i) => ({ key: "w" + i, label: c.name, glyph: c.glyph, min: 0, max: 200, step: 5, get: () => Math.round(state.weights[i] * 100), set: (v) => (state.weights[i] = v / 100), fmt: (v) => (v / 100).toFixed(2) + "×" })),
  { key: "sol", label: "Solicited replies", min: 0, max: 100, step: 1, unit: "%", get: () => Math.round(state.solicitedPermil / 10), set: (v) => (state.solicitedPermil = v * 10) },
  { key: "speed", label: "Sim speed", min: 1, max: 24, step: 1, unit: "/s", get: () => state.speed, set: (v) => (state.speed = v) },
];
function buildSliders() {
  el("sliders").innerHTML = SLIDERS.map((s) =>
    `<div class="slider"><div class="row"><label>${s.glyph ? glyphMiniSvg(s.glyph) : ""}${s.label}</label><span class="val" id="v-${s.key}"></span></div>` +
    `<input type="range" id="r-${s.key}" min="${s.min}" max="${s.max}" step="${s.step}" value="${s.get()}"></div>`).join("");
  for (const s of SLIDERS) {
    const inp = el("r-" + s.key);
    inp.addEventListener("input", () => { s.set(Number(inp.value)); paintVal(s); applyParams(); });
    paintVal(s);
  }
}
function paintVal(s) { el("v-" + s.key).textContent = s.fmt ? s.fmt(Number(el("r-" + s.key).value)) : s.get() + (s.unit ? " " + s.unit : ""); }
function syncSliders() { for (const s of SLIDERS) { const i = el("r-" + s.key); if (i) { i.value = s.get(); paintVal(s); } } el("seed").value = state.seed; }

const PRESETS = [
  { name: "SYN storm", pps: 9000, w: [0.4, 2, 0, 0, 0, 0] },
  { name: "Reflection", pps: 7000, w: [0.4, 0, 0, 2, 0, 0], sol: 150 },
  { name: "Flag anomaly", pps: 4000, w: [0.4, 0, 2, 0, 0, 0] },
  { name: "Volumetric", pps: 10000, w: [0.4, 0, 0, 0, 2, 0] },
  { name: "Novel flood", pps: 9000, w: [0.5, 0, 0, 0, 0, 2] },
  { name: "Mixed", pps: 8000, w: [0.6, 1, 1, 1, 1, 1] },
];
function buildPresets() {
  el("presets").innerHTML = "";
  for (const p of PRESETS) {
    const b = document.createElement("button");
    b.textContent = p.name;
    b.addEventListener("click", () => { state.pps = p.pps; state.weights = p.w.slice(); if (p.sol != null) state.solicitedPermil = p.sol; syncSliders(); restart(); });
    el("presets").appendChild(b);
  }
}

// ---- panels (static scaffolds) -------------------------------------------
function buildMetrics() {
  el("metrics").innerHTML = `
    <div class="metric"><span class="k">Packets</span><span class="v" id="m-pkt">0</span></div>
    <div class="metric"><span class="k">Reached core</span><span class="v" id="m-pass">0</span></div>
    <div class="metric"><span class="k">Mitigated</span><span class="v em" id="m-mit">0<small>%</small></span></div>
    <div class="metric"><span class="k">Detector</span><span class="v"><span class="defcon" id="m-defcon" data-on="calm">Calm</span></span></div>
    <div class="metric"><span class="k">Learner</span><span class="v" id="m-fp" style="color:var(--ink-3)">idle</span></div>`;
}
function buildStages() {
  el("stages").innerHTML = STAGES.map((s, i) =>
    `<div class="stage" id="st-${s.code}" data-armed="0"><span class="ix">${String(i + 1).padStart(2, "0")}</span>` +
    `<span class="nm">deflect-${s.name}<span class="cap">${s.cap}</span></span><span class="ct" id="sc-${s.code}">0</span></div>`).join("");
  el("legend").innerHTML = CLASSES.map((c) => `<span class="lg">${glyphMiniSvg(c.glyph)}${c.name}</span>`).join("");
}
function buildField() {
  let h = `<div class="hd"></div>` + VSHORT.map((v) => `<div class="hd">${v}</div>`).join("");
  for (let c = 0; c < 6; c++) {
    h += `<div class="rl">${glyphMiniSvg(CLASSES[c].glyph)}<span style="overflow:hidden;text-overflow:ellipsis">${CLASSES[c].name}</span></div>`;
    for (let v = 0; v < 4; v++) h += `<div class="cell" id="cell-${c}-${v}"><span></span></div>`;
  }
  el("field").innerHTML = h;
}

// ---- simulation -----------------------------------------------------------
const f32 = () => new Float32Array(state.weights);
function makeSim() {
  if (sim) sim.free();
  sim = new Simulation(state.seed, state.pps, state.solicitedPermil, f32());
  particles = []; coreEnergy = 0; acc = 0;
  stageCount.fill(0); feedLines = []; feedSeq = 0;
  if (trailCtx) { trailCtx.fillStyle = BG; trailCtx.fillRect(0, 0, trail.width, trail.height); }
}
function applyParams() { if (sim) sim.setParams(state.pps, state.solicitedPermil, f32()); }
function restart() { applyParams(); makeSim(); }

function geom() {
  const w = canvas.clientWidth, h = canvas.clientHeight;
  return { w, h, cx: w * 0.72, cy: h * 0.5, maxR: Math.max(h * 0.62, w * 0.5) };
}

function spawn(cls, verdict, stage, lane) {
  stageCount[stage]++;
  if (particles.length >= MAX_PARTICLES) return;
  const ang = A0 + (lane / 256) * (A1 - A0) + (Math.random() - 0.5) * 0.05;
  const targetFrac = stage === 0 ? CORE_FRAC : RING[stage].frac;
  const g = geom();
  const r = g.maxR * 1.12;
  particles.push({ ang, frac: 1.12, cls, verdict, stage, targetFrac, phase: "travel", t: 0, orbit: 0, px: g.cx + Math.cos(ang) * r, py: g.cy + Math.sin(ang) * r });
}

function stepSim() {
  const ev = sim.tick();
  for (let i = 0; i + 3 < ev.length; i += 4) {
    spawn(ev[i], ev[i + 1], ev[i + 2], ev[i + 3]);
    if ((feedSeq & 7) === 0) pushFeed(ev[i], ev[i + 1], ev[i + 2]);
    feedSeq++;
  }
  armed = sim.engaged() === 1;
  const fp = sim.fingerprintActive() === 1;
  el("m-defcon").dataset.on = armed ? "mit" : "calm";
  el("m-defcon").textContent = armed ? "Mitigating" : "Calm";
  const fpEl = el("m-fp");
  fpEl.textContent = fp ? "locked" : "idle";
  fpEl.style.color = fp ? "var(--ember)" : "var(--ink-3)";
  for (const s of STAGES) el("st-" + s.code).dataset.armed = (armed && s.adaptive) || (s.code === 5 && fp) ? "1" : "0";
  el("st-5").dataset.fp = fp ? "1" : "0";
}
function pushFeed(cls, verdict, stage) {
  const where = stage === 0 ? "core" : RING[stage].name;
  feedLines.unshift({ seq: feedSeq, cls, verdict, where });
  if (feedLines.length > 15) feedLines.pop();
}

function update(dt) {
  const speed = 0.9;
  for (const p of particles) {
    if (p.phase === "travel") {
      p.frac -= speed * dt;
      if (p.frac <= p.targetFrac) { p.frac = p.targetFrac; p.t = 0; p.phase = p.verdict === 0 ? "core" : p.verdict === 3 ? "drop" : p.verdict === 1 ? "chal" : "rate"; }
    } else if (p.phase === "core") { p.frac -= speed * 1.1 * dt; if (p.frac <= CORE_FRAC) { coreEnergy = Math.min(1.5, coreEnergy + 0.06); p.phase = "dead"; } }
    else if (p.phase === "chal") { p.t += dt; p.frac += speed * 0.45 * dt; if (p.t > 0.5) p.phase = "dead"; }
    else if (p.phase === "rate") { p.t += dt; p.orbit += 2 * dt; if (p.t > 0.7) p.phase = "dead"; }
    else if (p.phase === "drop") { p.t += dt; if (p.t > 0.32) p.phase = "dead"; }
  }
  particles = particles.filter((p) => p.phase !== "dead");
  coreEnergy *= Math.pow(0.5, dt / 0.7);
}

// ---- code bands (offscreen, regenerated occasionally) --------------------
const LEX = ["DROP sig", "PASS ack", "RATE gov/24", "CHAL cookie", "FP 0x1337de", "verdict=worst", "observe()", "classify()", "synthesize(55)", "note_outbound", "siphash-2-4", "misra-gries", "NO_EXPORT", "src=10.", "bytes=1400", "tcp.flags", "SYN|FIN", "NULL/XMAS", "obs.ts_nanos", "/24 bucket", "retry_after", "amp:53", "amp:123", "leading_frag", "ext_hdr<=8"];
function bandText(n) { let s = ""; while (s.length < n) s += LEX[(Math.random() * LEX.length) | 0] + "   "; return s.slice(0, n); }
function drawBands() {
  const { w, h, cx, cy, maxR } = geom();
  bandsCtx.clearRect(0, 0, w, h);
  // faint instrument grid: concentric hairlines
  bandsCtx.strokeStyle = V("--line");
  bandsCtx.lineWidth = 1;
  for (let i = 1; i <= 9; i++) { bandsCtx.globalAlpha = 0.5; bandsCtx.beginPath(); bandsCtx.arc(cx, cy, maxR * (i / 9), 0, Math.PI * 2); bandsCtx.stroke(); }
  // radial ticks around the left arc
  bandsCtx.globalAlpha = 0.6; bandsCtx.strokeStyle = V("--ink-3");
  for (let i = 0; i <= 40; i++) {
    const a = A0 + (i / 40) * (A1 - A0);
    const r0 = maxR * 1.0, r1 = maxR * (i % 5 === 0 ? 1.05 : 1.025);
    bandsCtx.beginPath(); bandsCtx.moveTo(cx + Math.cos(a) * r0, cy + Math.sin(a) * r0); bandsCtx.lineTo(cx + Math.cos(a) * r1, cy + Math.sin(a) * r1); bandsCtx.stroke();
  }
  // curved code bands between rings
  const bandFracs = [0.91, 0.73, 0.55, 0.38];
  for (const bf of bandFracs) {
    const rMid = maxR * bf;
    const fs = Math.max(6.5, maxR * 0.014);
    bandsCtx.font = `400 ${fs}px ${MONO}`;
    bandsCtx.fillStyle = V("--ink-3");
    bandsCtx.globalAlpha = bf > 0.6 ? 0.9 : 0.6;
    bandsCtx.textAlign = "center"; bandsCtx.textBaseline = "middle";
    const step = (fs * 0.62) / rMid;
    const txt = bandText(Math.ceil((A1 - A0) / step) + 2);
    let k = 0;
    for (let a = A0; a < A1; a += step, k++) {
      const ch = txt[k] || " ";
      const x = cx + Math.cos(a) * rMid, y = cy + Math.sin(a) * rMid;
      bandsCtx.save(); bandsCtx.translate(x, y); bandsCtx.rotate(a + Math.PI / 2); bandsCtx.fillText(ch, 0, 0); bandsCtx.restore();
    }
  }
  bandsCtx.globalAlpha = 1;
}

// ---- render ---------------------------------------------------------------
function draw(dt) {
  const { w, h, cx, cy, maxR } = geom();

  // trail layer: fade, then plot each particle's filament segment
  trailCtx.globalCompositeOperation = "source-over";
  trailCtx.fillStyle = BG; trailCtx.globalAlpha = 0.09; trailCtx.fillRect(0, 0, w, h);
  trailCtx.globalAlpha = 1;
  for (const p of particles) {
    const r = maxR * p.frac;
    const a = p.ang + (p.phase === "rate" ? p.orbit : 0);
    const x = cx + Math.cos(a) * r, y = cy + Math.sin(a) * r;
    let tone = VTONE[p.verdict], alpha = 0.5;
    if (p.phase === "drop") { tone = EMBER; alpha = 0.9; }
    else if (p.phase === "core") { tone = INK[0]; alpha = 0.8; }
    else if (p.phase === "travel") { alpha = p.verdict === 0 ? 0.6 : 0.42; }
    trailCtx.strokeStyle = tone; trailCtx.globalAlpha = alpha; trailCtx.lineWidth = p.verdict === 0 ? 1.1 : 0.8;
    trailCtx.beginPath(); trailCtx.moveTo(p.px, p.py); trailCtx.lineTo(x, y); trailCtx.stroke();
    p.px = x; p.py = y;
  }
  trailCtx.globalAlpha = 1;

  // compose
  ctx.clearRect(0, 0, w, h);
  ctx.drawImage(bands, 0, 0, w, h);
  ctx.globalCompositeOperation = "lighter";
  ctx.drawImage(trail, 0, 0, w, h);
  ctx.globalCompositeOperation = "source-over";

  // defense rings (crisp, left arc emphasised); labels fan along the upper-left
  STAGES.forEach((s, i) => {
    const r = maxR * s.frac;
    const hot = armed && s.adaptive;
    ctx.beginPath(); ctx.arc(cx, cy, r, A0 - 0.25, A1 + 0.25);
    ctx.strokeStyle = hot ? INK[1] : V("--line-2");
    ctx.globalAlpha = hot ? 0.85 : 0.55;
    ctx.lineWidth = hot ? 1.4 : 1;
    ctx.setLineDash(s.adaptive ? [2, 6] : []);
    ctx.stroke(); ctx.setLineDash([]);
    // label staggered up-left so rings never overprint each other
    const la = 3.44 + i * 0.165;
    const lx = cx + Math.cos(la) * r, ly = cy + Math.sin(la) * r;
    ctx.globalAlpha = hot ? 0.5 : 0.3; ctx.strokeStyle = hot ? INK[1] : INK[3]; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(cx + Math.cos(la) * (r - 7), cy + Math.sin(la) * (r - 7)); ctx.lineTo(lx, ly); ctx.stroke();
    ctx.globalAlpha = hot ? 0.95 : 0.6; ctx.fillStyle = hot ? INK[0] : INK[2];
    ctx.font = `500 9.5px ${MONO}`; ctx.textAlign = "center"; ctx.textBaseline = "bottom";
    ctx.fillText(s.name.toUpperCase(), lx, ly - 4);
  });
  ctx.globalAlpha = 1;

  // core
  const coreR = maxR * CORE_FRAC;
  const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, coreR * (1.5 + coreEnergy));
  g.addColorStop(0, INK[0]); g.addColorStop(0.45, INK[0] + "55"); g.addColorStop(1, INK[0] + "00");
  ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, coreR * (1.5 + coreEnergy), 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = INK[1]; ctx.globalAlpha = 0.8; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.arc(cx, cy, coreR * 0.55, 0, Math.PI * 2); ctx.stroke(); ctx.globalAlpha = 1;

  // particle heads (class shape)
  const gs = Math.max(2.2, maxR * 0.012);
  for (const p of particles) {
    const r = maxR * p.frac;
    const a = p.ang + (p.phase === "rate" ? p.orbit : 0);
    const x = cx + Math.cos(a) * r, y = cy + Math.sin(a) * r;
    let tone = VTONE[p.verdict], alpha = 1;
    if (p.phase === "drop") { tone = EMBER; alpha = 1 - p.t / 0.32; }
    else if (p.phase === "chal") { alpha = 1 - p.t / 0.5; }
    else if (p.phase === "rate") { alpha = 1 - p.t / 0.7; }
    else if (p.phase === "core") { tone = INK[0]; }
    ctx.globalAlpha = Math.max(0, alpha); ctx.strokeStyle = tone; ctx.fillStyle = tone; ctx.lineWidth = 1.1;
    const path = glyphPath(CLASSES[p.cls].glyph, x, y, gs);
    if (CLASSES[p.cls].glyph === "circle") { ctx.globalAlpha *= 0.85; ctx.fill(path); } else ctx.stroke(path);
  }
  ctx.globalAlpha = 1;
}

// ---- stats ----------------------------------------------------------------
function refreshStats() {
  const t = sim.totals();
  let pkt = 0, pass = 0, atk = 0, atkMit = 0;
  for (let c = 0; c < 6; c++) {
    const b = c * 4, sum = t[b] + t[b + 1] + t[b + 2] + t[b + 3];
    pkt += sum; pass += t[b];
    if (c >= 1) { atk += sum; atkMit += t[b + 1] + t[b + 2] + t[b + 3]; }
    // field cells
    const cmax = Math.max(1, sum);
    for (let v = 0; v < 4; v++) {
      const cell = el(`cell-${c}-${v}`); if (!cell) continue;
      const frac = t[b + v] / cmax;
      if (v === 3) cell.style.background = `color-mix(in oklab, ${EMBER} ${Math.round(frac * 88)}%, #0c0f16)`;
      else cell.style.background = `color-mix(in oklab, ${INK[0]} ${Math.round(frac * 70)}%, #0c0f16)`;
      const span = cell.firstChild;
      span.textContent = frac > 0.14 ? Math.round(frac * 100) : "";
      span.style.color = v === 3 && frac > 0.5 ? "#0c0f16" : frac > 0.6 ? "#0c0f16" : "var(--ink-0)";
    }
  }
  el("m-pkt").textContent = pkt >= 1e6 ? (pkt / 1e6).toFixed(2) + "M" : pkt >= 1e3 ? (pkt / 1e3).toFixed(1) + "k" : pkt;
  el("m-pass").textContent = pass >= 1e3 ? (pass / 1e3).toFixed(1) + "k" : pass;
  const pct = atk ? Math.round((atkMit / atk) * 100) : 0;
  el("m-mit").innerHTML = `${pct}<small>%</small>`;
  el("eff").innerHTML = `Effectiveness on attack traffic <b>${atk ? pct + "%" : "—"}</b>`;
  for (const s of STAGES) el("sc-" + s.code).textContent = stageCount[s.code].toLocaleString();
  // feed
  el("feed").innerHTML = feedLines.map((l) =>
    `<div class="ln"><span class="seq">${String(l.seq).padStart(5, "0")}</span>` +
    `<span class="cls">${CLASSES[l.cls].name} → ${l.where}</span>` +
    `<span class="vd" data-v="${l.verdict}">${VSHORT[l.verdict]}</span></div>`).join("");
}

// ---- bounded render engine (explicit state machine) -----------------------
// The loop runs only while running && visible && inView, is capped at FPS_CAP,
// and fully stops otherwise — a hidden tab, an off-screen scope, or a paused
// sim each cost zero per-frame work. Nothing here is unbounded.
const FPS_CAP = 30;
const MIN_FRAME = 1000 / FPS_CAP;
const reduceMotion = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

let rafId = 0, prevTs = 0, acc = 0, statT = 0, bandT = 0;
let visible = typeof document === "undefined" ? true : !document.hidden;
let inView = true;

function canRun() { return !!sim && state.running && visible && inView; }
function renderOnce() { if (sim) { update(0); draw(0); refreshStats(); } }

function pump(ts) {
  rafId = 0;
  if (!canRun()) return;                 // suspended — stay fully stopped
  rafId = requestAnimationFrame(pump);
  if (!prevTs) prevTs = ts;
  const elapsed = ts - prevTs;
  if (elapsed < MIN_FRAME) return;       // frame cap: no heavy work this wakeup
  const dt = Math.min(0.05, elapsed / 1000);
  prevTs = ts;
  acc += dt;
  const iv = 1 / state.speed; let g = 0;
  while (acc >= iv && g++ < 4) { stepSim(); acc -= iv; }
  update(dt); draw(dt);
  statT += dt; if (statT > 0.2) { statT = 0; refreshStats(); }
  bandT += dt; if (bandT > 4) { bandT = 0; drawBands(); }
}

function startLoop() { if (!rafId && canRun()) { prevTs = 0; rafId = requestAnimationFrame(pump); } }
function stopLoop() { if (rafId) { cancelAnimationFrame(rafId); rafId = 0; } }
function sync() { if (canRun()) startLoop(); else { stopLoop(); renderOnce(); } }

function fit() {
  const r = canvas.getBoundingClientRect();
  const cssW = Math.max(1, r.width), cssH = Math.max(1, r.height);
  // Bound the backing store so a large or hi-DPI display cannot explode GPU work.
  const BUDGET = 1_800_000;
  let scale = Math.min(window.devicePixelRatio || 1, 2);
  if (cssW * cssH * scale * scale > BUDGET) scale = Math.max(1, Math.sqrt(BUDGET / (cssW * cssH)));
  for (const cv of [canvas, trail, bands]) { cv.width = Math.round(cssW * scale); cv.height = Math.round(cssH * scale); }
  ctx.setTransform(scale, 0, 0, scale, 0, 0);
  trailCtx.setTransform(scale, 0, 0, scale, 0, 0);
  bandsCtx.setTransform(scale, 0, 0, scale, 0, 0);
  trailCtx.fillStyle = BG; trailCtx.fillRect(0, 0, trail.width, trail.height);
  drawBands();
  if (!canRun()) renderOnce();
}

function setRun() { const r = el("btn-run"); r.textContent = state.running ? "Pause" : "Run"; r.dataset.run = state.running ? "1" : "0"; }
function wireControls() {
  el("btn-run").addEventListener("click", () => { state.running = !state.running; setRun(); sync(); });
  el("btn-step").addEventListener("click", () => { state.running = false; setRun(); stopLoop(); if (sim) { stepSim(); update(0.05); draw(0); refreshStats(); } });
  el("btn-reset").addEventListener("click", () => { restart(); sync(); });
  el("btn-mutate").addEventListener("click", () => {
    state.seed = Math.floor(Math.random() * 2e9);
    state.pps = 2000 + Math.floor(Math.random() * 9000);
    state.solicitedPermil = Math.floor(Math.random() * 300);
    state.weights = CLASSES.map((_, i) => (i === 0 ? 0.4 + Math.random() * 0.4 : Math.random() * Math.random() * 2));
    syncSliders(); restart(); sync();
  });
  el("seed").addEventListener("change", (e) => { const v = parseInt(e.target.value, 10); state.seed = Number.isFinite(v) ? v : 0; restart(); sync(); });
  setRun();
}

let fitPending = false;
function scheduleFit() { if (fitPending) return; fitPending = true; requestAnimationFrame(() => { fitPending = false; fit(); }); }

// ---- boot -----------------------------------------------------------------
async function boot() {
  trail = document.createElement("canvas"); trailCtx = trail.getContext("2d");
  bands = document.createElement("canvas"); bandsCtx = bands.getContext("2d");
  buildMetrics(); buildSliders(); buildPresets(); buildStages(); buildField(); wireControls();
  fit();
  new ResizeObserver(scheduleFit).observe(canvas);
  if (typeof document !== "undefined") document.addEventListener("visibilitychange", () => { visible = !document.hidden; sync(); });
  if (typeof IntersectionObserver === "function") {
    new IntersectionObserver((es) => { inView = es.some((e) => e.isIntersecting); sync(); }, { threshold: 0 }).observe(canvas);
  }
  try { await __wbg_init("./deflect_sim_bg.wasm"); }
  catch (e) { el("loading").textContent = "WASM load failed: " + e; return; }
  makeSim();
  el("loading").hidden = true;
  if (reduceMotion) { state.running = false; setRun(); for (let i = 0; i < 16; i++) stepSim(); }
  sync();
}
boot();
</script>
