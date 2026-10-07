/* GraphOps SOC dashboard — zero hardcoded data.
 * Everything renders from the API:
 *   GET  /health        -> node/edge counts
 *   GET  /graph         -> {nodes, edges}
 *   POST /hunt          -> {findings}
 *   POST /blast-radius  -> {blast_radius, actions}   (body: {node_id})
 * API base resolution (first match wins):
 *   1. ?api=https://... query param
 *   2. window.GRAPHOPS_API_BASE
 *   3. same-origin /api            (Vercel / any single-host deploy)
 *   4. http://localhost:8000      (local dev: uvicorn graphops.api.server:app)
 * If the API is down, an explicit offline state is shown — nothing is faked.
 */
'use strict';

/* ================= API contract ================= */
const API_BASE = (() => {
  const q = new URLSearchParams(location.search).get('api');
  if (q) return q.replace(/\/+$/, '');
  if (window.GRAPHOPS_API_BASE) return String(window.GRAPHOPS_API_BASE).replace(/\/+$/, '');
  if (location.protocol.startsWith('http')) return '/api';
  return 'http://localhost:8000';
})();
const EP_HEALTH = API_BASE + '/health';
const EP_HUNT = API_BASE + '/hunt';
const EP_BLAST = API_BASE + '/blast-radius';
const EP_GRAPH = API_BASE + '/graph';
const EP_DECISIONS = API_BASE + '/decisions';
const EP_DEMO_SCENARIOS = API_BASE + '/demo-scenarios';
const START_CMD = 'uvicorn graphops.api.server:app';
const HUNT_AUTORELOAD_MS = 45000; // findings feed auto-refresh interval
const HUNT_DEFAULT_LIMIT = 10;

const ETYPE_COLORS = {
  host: '#38bdf8',
  user: '#a78bfa',
  ip: '#fbbf24',
  process: '#34d399',
  alert: '#f87171',
};
const ETYPE_DEFAULT = '#94a3b8';

/* ================= state ================= */
const state = {
  nodes: [],          // normalized: {id, etype, label, x, y, r, degree}
  edges: [],          // normalized: {source: <node>, target: <node>}
  nodeById: new Map(),
  findings: [],
  blast: null,        // {sourceId, rows: [{id, distance, risk}], actions: [...]}
  attackPath: new Set(), // node ids highlighted by demo scenario
  blastSet: new Set(),   // node ids in current blast radius
  exfilSet: new Set(),   // blast nodes at distance<=1 that are external IPs (exfil risk overlay)
  dpdpRegulatedSet: new Set(), // blast nodes holding regulated data (crimson halo)
  decisions: new Map(),  // "action|target" -> "approved" | "rejected" (analyst audit trail)
  drawerFinding: null,   // finding currently shown in the evidence drawer
  autoRefreshOn: true,   // hunt feed polling
  hovered: null,
  dragged: null,
  layoutDone: false,
  apiUp: false,
  // hunt filters + pagination (contract: GET /hunt?severity=&method=&limit=&offset=;
  // falls back to POST /hunt + client-side filter/paginate when the backend lacks it)
  hunt: { severity: '', method: '', limit: HUNT_DEFAULT_LIMIT, offset: 0, total: null, serverMode: 'get' },
  // red-team replay (contract: GET /demo-scenarios; POST /demo-scenarios/{id}/run)
  scenarios: [], scenariosState: 'idle', lastScenarioRun: null,
};

/* ================= dom ================= */
const $ = (id) => document.getElementById(id);
const el = {
  apiStatus: $('apiStatus'), healthLine: $('healthLine'),
  offlineBanner: $('offlineBanner'),
  btnRunHunt: $('btnRunHunt'), btnDemo: $('btnDemo'),
  huntStatus: $('huntStatus'), findingsList: $('findingsList'),
  canvas: $('graphCanvas'), canvasWrap: $('canvasWrap'), tooltip: $('tooltip'),
  canvasStatus: $('canvasStatus'),
  blastEmpty: $('blastEmpty'), blastResults: $('blastResults'),
  blastSource: $('blastSource'), blastRows: $('blastRows'), actionsList: $('actionsList'),
  dpdpCard: $('dpdpCard'), btnBlastTour: $('btnBlastTour'),
  footStamp: $('footStamp'),
  toasts: $('toasts'), drawer: $('drawer'), drawerSub: $('drawerSub'),
  drawerBody: $('drawerBody'), btnDrawerClose: $('btnDrawerClose'),
  autoRefresh: $('autoRefresh'),
  huntSeverity: $('huntSeverity'), huntMethod: $('huntMethod'), huntLimit: $('huntLimit'),
  pageBar: $('pageBar'), pageInfo: $('pageInfo'),
  btnPrevPage: $('btnPrevPage'), btnNextPage: $('btnNextPage'),
  scenarioStatus: $('scenarioStatus'), scenarioList: $('scenarioList'),
  scenarioResult: $('scenarioResult'),
};

/* ================= toasts ================= */
function toast(msg, type = 'info') {
  if (!el.toasts) return;
  const t = document.createElement('div');
  t.className = 'toast ' + (['ok', 'err', 'warn'].includes(type) ? type : 'info');
  t.textContent = String(msg);
  el.toasts.appendChild(t);
  const g = window.gsap;
  if (g) g.from(t, { x: 60, opacity: 0, duration: 0.35, ease: 'power3.out' });
  setTimeout(() => {
    if (g) g.to(t, { x: 60, opacity: 0, duration: 0.3, ease: 'power2.in', onComplete: () => t.remove() });
    else t.remove();
  }, 4200);
  while (el.toasts.children.length > 5) el.toasts.firstChild.remove();
}

/* ================= helpers ================= */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function sevClass(sev) {
  const s = String(sev || 'info').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(s) ? 'sev-' + s : 'sev-info';
}
function priClass(p) {
  const s = String(p || '').toLowerCase().replace(/\s+/g, '');
  if (s === 'p1' || s === 'critical' || s === 'high') return 'pri-p1';
  if (s === 'p2') return 'pri-p2';
  if (s === 'p3' || s === 'medium') return 'pri-p3';
  return 'pri-p4';
}
function fmtRisk(r) {
  if (r === null || r === undefined || r === '') return '—';
  const n = Number(r);
  return Number.isFinite(n) ? (n <= 1 ? n.toFixed(2) : n.toFixed(1)) : esc(r);
}
async function apiFetch(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.json();
}

/* ---- defensive field normalization (API shapes may vary slightly) ---- */
function nodeIdOf(n) { return n && (n.id ?? n.node_id ?? n.name); }
function nodeTypeOf(n) { return String(n && (n.etype ?? n.type ?? 'unknown')).toLowerCase(); }
function nodeLabelOf(n) { return (n && (n.label ?? n.name ?? n.id ?? n.node_id)) ?? ''; }
function edgeEnd(e, key) {
  // API shapes: {src,dst} (current) or {source,target} / {from,to} (legacy)
  const v = e && (e[key] ?? (key === 'source' ? (e.src ?? e.from) : (e.dst ?? e.to)));
  return (v && typeof v === 'object') ? nodeIdOf(v) : v;
}

/* ================= boot ================= */
window.addEventListener('DOMContentLoaded', init);

async function init() {
  el.footStamp.textContent = 'loaded ' + new Date().toLocaleString();
  const footApi = document.getElementById('footApi');
  if (footApi) footApi.textContent = API_BASE;
  sizeCanvas();
  window.addEventListener('resize', () => { sizeCanvas(); draw(); });
  wireCanvas();
  el.btnRunHunt.addEventListener('click', () => { state.hunt.offset = 0; runHunt(); });
  el.btnDemo.addEventListener('click', runDemoScenario);
  el.btnDrawerClose.addEventListener('click', closeDrawer);
  el.autoRefresh.addEventListener('change', () => setAutoRefresh(el.autoRefresh.checked));
  wireHuntFilters();
  if (el.btnBlastTour) el.btnBlastTour.addEventListener('click', tourBlastView);
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape' && !el.drawer.hidden) closeDrawer();
  });
  exposeBridge();

  const up = await checkHealth();
  if (!up) { setOffline(); if (window.UI) UI.bootDone(); return; }
  setOnline();
  setAutoRefresh(true); // findings feed: live polling
  await loadGraph();
  await loadScenarios();
  if (window.UI) UI.bootDone();
}

/* findings feed auto-refresh: silent hunts every HUNT_AUTORELOAD_MS */
let autoTimer = null;
function setAutoRefresh(on) {
  state.autoRefreshOn = !!on;
  if (el.autoRefresh) el.autoRefresh.checked = !!on;
  if (autoTimer) { clearInterval(autoTimer); autoTimer = null; }
  if (on && state.apiUp) {
    autoTimer = setInterval(() => {
      if (state.apiUp && !document.hidden) runHunt({ silent: true });
    }, HUNT_AUTORELOAD_MS);
  }
}

async function checkHealth() {
  try {
    const h = await apiFetch(EP_HEALTH);
    const nodes = h.nodes ?? h.node_count ?? h.graph?.nodes ?? h.stats?.nodes;
    const edges = h.edges ?? h.edge_count ?? h.graph?.edges ?? h.stats?.edges;
    state.apiUp = true;
    if (nodes !== undefined || edges !== undefined) {
      el.healthLine.innerHTML =
        `nodes <b>${esc(nodes ?? '?')}</b> · edges <b>${esc(edges ?? '?')}</b> · <span style="color:var(--green)">online</span>`;
    } else {
      el.healthLine.innerHTML = `<span style="color:var(--green)">online</span> (no counts in /health)`;
    }
    return true;
  } catch (e) {
    state.apiUp = false;
    return false;
  }
}

function setOffline() {
  el.apiStatus.className = 'status-dot offline';
  el.healthLine.innerHTML = '<span style="color:var(--red)">offline</span>';
  el.offlineBanner.hidden = false;
  el.offlineBanner.querySelector('code').textContent = START_CMD;
  el.btnRunHunt.disabled = true;
  el.btnDemo.disabled = true;
  el.huntStatus.textContent = 'Cannot run hunt — API is offline.';
  el.canvasStatus.textContent = 'no data (API offline)';
  if (el.scenarioStatus) el.scenarioStatus.textContent = 'Red-team replay unavailable — API is offline.';
  if (el.btnBlastTour) el.btnBlastTour.hidden = true;
  if (autoTimer) { clearInterval(autoTimer); autoTimer = null; } // halt feed polling
}
function setOnline() {
  el.apiStatus.className = 'status-dot online';
  el.offlineBanner.hidden = true;
  el.btnRunHunt.disabled = false;
  el.btnDemo.disabled = false;
}

/* ================= graph ================= */
async function loadGraph() {
  el.canvasStatus.textContent = 'fetching graph…';
  try {
    const g = await apiFetch(EP_GRAPH);
    const rawNodes = g.nodes ?? [];
    const rawEdges = g.edges ?? [];
    state.nodes = rawNodes
      .map((n) => ({
        id: String(nodeIdOf(n) ?? ''),
        etype: nodeTypeOf(n),
        label: String(nodeLabelOf(n)),
        // contract: nodes may carry data_classification (public/internal/confidential/regulated)
        // + regulated_reachable from /blast-radius rows; all optional, all defensive
        dc: String(n.data_classification ?? n.classification ?? '').toLowerCase() || '',
        x: 0, y: 0, r: 7, degree: 0,
      }))
      .filter((n) => n.id);
    state.nodeById = new Map(state.nodes.map((n) => [n.id, n]));
    state.edges = rawEdges
      .map((e) => {
        const s = state.nodeById.get(String(edgeEnd(e, 'source') ?? ''));
        const t = state.nodeById.get(String(edgeEnd(e, 'target') ?? ''));
        return (s && t) ? { source: s, target: t, etype: String(e.etype ?? e.type ?? '') } : null;
      })
      .filter(Boolean);
    for (const e of state.edges) { e.source.degree++; e.target.degree++; }
    for (const n of state.nodes) n.r = 6 + Math.min(8, n.degree * 1.6);

    // authoritative counts from /graph itself
    el.healthLine.innerHTML =
      `nodes <b>${state.nodes.length}</b> · edges <b>${state.edges.length}</b> · <span style="color:var(--green)">online</span>`;
    if (window.UI) {
      UI.countUp(document.getElementById('statNodes'), state.nodes.length);
      UI.countUp(document.getElementById('statEdges'), state.edges.length);
    }
    // keep the 3D view in sync if it is initialized
    if (window.Graph3D) pushGraphTo3D();

    if (state.nodes.length === 0) {
      el.canvasStatus.textContent = 'graph is empty';
      draw();
      return;
    }
    runLayoutProgressive();
  } catch (e) {
    el.canvasStatus.textContent = 'failed to load graph: ' + e.message;
  }
}

/* Force-directed layout: repulsion + springs + gravity, ~120 iterations.
 * Runs progressively (a few iterations per frame) so the graph visibly settles. */
function runLayoutProgressive() {
  const nodes = state.nodes;
  const W = el.canvasWrap.clientWidth, H = el.canvasWrap.clientHeight;
  nodes.forEach((n, i) => {
    const a = (i / Math.max(1, nodes.length)) * Math.PI * 2;
    n.x = W / 2 + Math.cos(a) * Math.min(W, H) * 0.32 + (Math.random() - 0.5) * 30;
    n.y = H / 2 + Math.sin(a) * Math.min(W, H) * 0.32 + (Math.random() - 0.5) * 30;
    n.fx = 0; n.fy = 0;
  });
  const k = Math.sqrt((W * H) / Math.max(1, nodes.length));
  const rest = Math.max(60, k * 0.85);
  const TOTAL = 120, PER_FRAME = 12;
  let iter = 0;
  state.layoutDone = false;
  el.canvasStatus.textContent = 'laying out…';

  function step() {
    for (let s = 0; s < PER_FRAME && iter < TOTAL; s++, iter++) {
      const temp = 1 - iter / TOTAL; // cooling
      // repulsion (all pairs)
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx * dx + dy * dy;
          if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
          const d = Math.sqrt(d2);
          const f = (k * k) / d;
          const ux = dx / d, uy = dy / d;
          a.fx += ux * f; a.fy += uy * f;
          b.fx -= ux * f; b.fy -= uy * f;
        }
      }
      // springs along edges
      for (const e of state.edges) {
        const a = e.source, b = e.target;
        const dx = b.x - a.x, dy = b.y - a.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (d - rest) * 0.06;
        const ux = dx / d, uy = dy / d;
        a.fx += ux * f * d * 0.05; a.fy += uy * f * d * 0.05;
        b.fx -= ux * f * d * 0.05; b.fy -= uy * f * d * 0.05;
      }
      // gravity to center + apply with cooling
      const maxD = 26 * temp + 2;
      for (const n of nodes) {
        if (n === state.dragged) { n.fx = 0; n.fy = 0; continue; }
        n.fx += (W / 2 - n.x) * 0.012;
        n.fy += (H / 2 - n.y) * 0.012;
        const dx = Math.max(-maxD, Math.min(maxD, n.fx));
        const dy = Math.max(-maxD, Math.min(maxD, n.fy));
        n.x = Math.max(24, Math.min(W - 24, n.x + dx));
        n.y = Math.max(24, Math.min(H - 24, n.y + dy));
        n.fx = 0; n.fy = 0;
      }
    }
    draw();
    if (iter < TOTAL) {
      el.canvasStatus.textContent = `laying out… ${iter}/${TOTAL}`;
      requestAnimationFrame(step);
    } else {
      state.layoutDone = true;
      el.canvasStatus.textContent = `${nodes.length} nodes · ${state.edges.length} edges`;
      draw();
    }
  }
  requestAnimationFrame(step);
}

/* ================= canvas rendering ================= */
let ctx, dpr = 1;
function sizeCanvas() {
  const c = el.canvas;
  dpr = window.devicePixelRatio || 1;
  const w = el.canvasWrap.clientWidth, h = el.canvasWrap.clientHeight;
  c.width = Math.max(1, w * dpr); c.height = Math.max(1, h * dpr);
  ctx = c.getContext('2d');
}

function draw() {
  if (!ctx) return;
  const W = el.canvasWrap.clientWidth, H = el.canvasWrap.clientHeight;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  const t = performance.now() / 1000;

  // edges
  for (const e of state.edges) {
    const inPath = state.attackPath.has(e.source.id) && state.attackPath.has(e.target.id);
    ctx.strokeStyle = inPath ? 'rgba(248,113,113,0.75)' : 'rgba(71,85,105,0.5)';
    ctx.lineWidth = inPath ? 2 : 1;
    if (inPath) { ctx.shadowColor = '#f87171'; ctx.shadowBlur = 8; }
    ctx.beginPath();
    ctx.moveTo(e.source.x, e.source.y);
    ctx.lineTo(e.target.x, e.target.y);
    ctx.stroke();
    ctx.shadowBlur = 0;
  }

  // nodes
  const showAllLabels = state.nodes.length > 0 && state.nodes.length <= 50;
  for (const n of state.nodes) {
    const color = ETYPE_COLORS[n.etype] || ETYPE_DEFAULT;
    const isBlast = state.blastSet.has(n.id);
    const isPath = state.attackPath.has(n.id);
    const isExfil = state.exfilSet.has(n.id);
    const isRegulated = state.dpdpRegulatedSet.has(n.id) || n.dc === 'regulated';
    const isHover = state.hovered === n;

    if (isRegulated) { // regulated data: crimson halo (DPDP overlay)
      const pr = n.r + 12 + Math.sin(t * 4.5) * 2.5;
      ctx.strokeStyle = 'rgba(255,45,85,0.9)'; ctx.lineWidth = 2.5;
      ctx.shadowColor = '#ff2d55'; ctx.shadowBlur = 16;
      ctx.beginPath(); ctx.arc(n.x, n.y, pr, 0, Math.PI * 2); ctx.stroke();
      ctx.shadowBlur = 0;
    }
    if (isPath) { // pulsing attack-path ring
      const pr = n.r + 9 + Math.sin(t * 5) * 3;
      ctx.strokeStyle = 'rgba(248,113,113,0.9)'; ctx.lineWidth = 2.5;
      ctx.shadowColor = '#f87171'; ctx.shadowBlur = 14;
      ctx.beginPath(); ctx.arc(n.x, n.y, pr, 0, Math.PI * 2); ctx.stroke();
      ctx.shadowBlur = 0;
    }
    if (isBlast) { // steady blast-radius ring
      ctx.strokeStyle = 'rgba(34,211,238,0.95)'; ctx.lineWidth = 2;
      ctx.shadowColor = '#22d3ee'; ctx.shadowBlur = 10;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 6, 0, Math.PI * 2); ctx.stroke();
      ctx.shadowBlur = 0;
    }
    if (isExfil) { // exfil-risk: amber dashed ring over suspected C2 endpoints
      ctx.strokeStyle = 'rgba(248,113,113,0.95)'; ctx.lineWidth = 2.5;
      ctx.setLineDash([6, 4]); ctx.lineDashOffset = -t * 22;
      ctx.shadowColor = '#f87171'; ctx.shadowBlur = 12;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 12, 0, Math.PI * 2); ctx.stroke();
      ctx.shadowBlur = 0; ctx.setLineDash([]);
    }
    ctx.fillStyle = color;
    ctx.shadowColor = color; ctx.shadowBlur = isHover ? 18 : 8;
    ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2); ctx.fill();
    ctx.shadowBlur = 0;

    if (showAllLabels || isHover) {
      ctx.font = '11px ui-monospace, monospace';
      ctx.fillStyle = isHover ? '#fff' : 'rgba(219,230,245,0.75)';
      ctx.textAlign = 'center';
      const label = n.label.length > 22 ? n.label.slice(0, 21) + '…' : n.label;
      ctx.fillText(label, n.x, n.y - n.r - 6);
    }
  }
}

/* ================= canvas interaction ================= */
function wireCanvas() {
  const c = el.canvas;
  const pos = (ev) => {
    const r = c.getBoundingClientRect();
    return { x: ev.clientX - r.left, y: ev.clientY - r.top };
  };
  const nearest = (p) => {
    let best = null, bd = 1e9;
    for (const n of state.nodes) {
      const d = Math.hypot(n.x - p.x, n.y - p.y);
      if (d < n.r + 8 && d < bd) { bd = d; best = n; }
    }
    return best;
  };

  c.addEventListener('mousemove', (ev) => {
    const p = pos(ev);
    if (state.dragged) {
      state.dragged.x = p.x; state.dragged.y = p.y;
      draw(); return;
    }
    const n = nearest(p);
    state.hovered = n;
    if (n) {
      el.tooltip.hidden = false;
      el.tooltip.style.left = Math.min(p.x + 16, el.canvasWrap.clientWidth - 270) + 'px';
      el.tooltip.style.top = Math.max(p.y - 10, 8) + 'px';
      el.tooltip.innerHTML =
        `<span class="tt-id">${esc(n.label)}</span><br>` +
        `<span class="tt-type">${esc(n.etype)} · degree ${n.degree}${n.dc ? ` · <span class="dc dc-${n.dc}">${esc(n.dc)}</span>` : ''}</span><br>` +
        `<span class="muted">${state.dpdpRegulatedSet.has(n.id) ? 'regulated data — click → blast radius + DPDP' : 'click → blast radius'}</span>`;
      c.style.cursor = 'pointer';
    } else {
      el.tooltip.hidden = true;
      c.style.cursor = 'grab';
    }
    draw();
  });
  c.addEventListener('mouseleave', () => {
    state.hovered = null; el.tooltip.hidden = true; draw();
  });
  c.addEventListener('mousedown', (ev) => {
    const n = nearest(pos(ev));
    if (n) state.dragged = n;
  });
  window.addEventListener('mouseup', () => { state.dragged = null; });
  c.addEventListener('click', (ev) => {
    const n = nearest(pos(ev));
    if (n) handleNodeClick(n.id);
  });
}

/* ================= hunt ================= */
/* ================= hunt (filters + pagination + 45s auto-refresh) =================
 * Contract: GET /hunt gains ?severity=&method=&limit=&offset=.
 * Falls back to POST /hunt + client-side filter/paginate when the backend lacks GET /hunt.
 * Everything rendered comes from the API; auto-refresh keeps current filters;
 * offline halts polling (setOffline clears the timer).
 */
function wireHuntFilters() {
  el.huntSeverity.addEventListener('change', () => {
    state.hunt.severity = el.huntSeverity.value;
    state.hunt.offset = 0;
    runHunt();
  });
  el.huntMethod.addEventListener('change', () => {
    state.hunt.method = el.huntMethod.value;
    state.hunt.offset = 0;
    runHunt();
  });
  el.huntLimit.addEventListener('change', () => {
    state.hunt.limit = Number(el.huntLimit.value) || HUNT_DEFAULT_LIMIT;
    state.hunt.offset = 0;
    runHunt();
  });
  el.btnPrevPage.addEventListener('click', () => {
    state.hunt.offset = Math.max(0, state.hunt.offset - state.hunt.limit);
    runHunt({ silent: true });
  });
  el.btnNextPage.addEventListener('click', () => {
    state.hunt.offset += state.hunt.limit;
    runHunt({ silent: true });
  });
}

async function runHunt({ silent = false } = {}) {
  el.btnRunHunt.disabled = true;
  if (!silent) {
    el.huntStatus.textContent = 'hunting…';
    renderHuntSkeletons();
  }
  const f = state.hunt;
  let raw = [];
  let total = null;
  try {
    if (f.serverMode === 'get') {
      // contract path: GET /hunt?severity=&method=&limit=&offset=
      const params = new URLSearchParams();
      if (f.severity) params.set('severity', f.severity);
      if (f.method) params.set('method', f.method);
      params.set('limit', String(f.limit));
      params.set('offset', String(f.offset));
      try {
        const data = await apiFetch(EP_HUNT + '?' + params.toString());
        raw = data.findings ?? data.results ?? [];
        total = data.total ?? data.count ?? (Array.isArray(raw) ? raw.length : null);
      } catch (e) {
        if (/HTTP 404|HTTP 405|HTTP 501/.test(e.message)) {
          // backend build without GET /hunt — downgrade once per session
          f.serverMode = 'post';
          toast('This backend build has no GET /hunt — filters applied client-side', 'warn');
        } else throw e;
      }
    }
    if (f.serverMode === 'post') {
      // legacy path: POST /hunt ignores params; filter + paginate client-side over real data
      const data = await apiFetch(EP_HUNT, { method: 'POST' });
      let arr = data.findings ?? data.results ?? [];
      if (f.severity) arr = arr.filter((x) => String(x.severity ?? x.level ?? '').toLowerCase() === f.severity);
      if (f.method) {
        const m = f.method.toLowerCase();
        arr = arr.filter((x) => String(x.detection_method ?? x.method ?? '').toLowerCase() === m);
      }
      total = arr.length;
      raw = arr.slice(f.offset, f.offset + f.limit);
    }
    state.findings = raw.map(normalizeFinding).filter((x) => x.title);
    state.hunt.total = total;
    renderFindings();
    renderPageBar();
    populateMethodOptions(raw);
    if (!silent && window.UI) {
      UI.animateFindings();
      UI.countUp(document.getElementById('statFindings'), total ?? state.findings.length, { dur: 0.7 });
    }
    const stamp = ` · ${new Date().toLocaleTimeString()}`;
    const bits = [];
    if (f.severity) bits.push('sev=' + f.severity);
    if (f.method) bits.push('method=' + f.method);
    const filterNote = bits.length ? ` · filters: ${bits.join(', ')}` : '';
    const totalNote = total !== null ? ` of ${total}` : '';
    el.huntStatus.innerHTML =
      state.findings.length === 0
        ? `Hunt complete — no findings returned${filterNote}.${stamp}`
        : `Hunt complete — <b>${state.findings.length}</b> finding${state.findings.length > 1 ? 's' : ''}${totalNote}${filterNote}${stamp}` +
          (state.autoRefreshOn ? ' · <span class="feed-stamp"><span class="live-dot"></span>auto-refresh on</span>' : '');
  } catch (e) {
    el.huntStatus.textContent = 'Hunt failed: ' + e.message;
    el.findingsList.innerHTML = '';
    if (!state.apiUp || /Failed to fetch|NetworkError/i.test(e.message)) setOffline();
    else if (!silent) toast('Hunt failed: ' + e.message, 'err');
  } finally {
    el.btnRunHunt.disabled = !state.apiUp;
  }
}

/* method filter options are built ONLY from detection_method values the API
 * has actually returned — never invented, so a value is always valid to send. */
function populateMethodOptions(raw) {
  if (!el.huntMethod) return;
  const seen = new Set();
  for (const x of raw) {
    const m = String(x.detection_method ?? x.method ?? '').trim();
    if (m && !seen.has(m)) {
      seen.add(m);
      const o = document.createElement('option');
      o.value = m;
      o.textContent = 'method: ' + (m.length > 26 ? m.slice(0, 25) + '…' : m);
      el.huntMethod.appendChild(o);
    }
  }
  if (seen.size > 0) el.huntMethod.disabled = false;
}

function renderPageBar() {
  const f = state.hunt;
  const total = f.total;
  const show = total !== null && total > f.limit;
  if (el.pageBar) el.pageBar.hidden = !show;
  if (!show) return;
  const from = total === 0 ? 0 : f.offset + 1;
  const to = Math.min(total, f.offset + f.limit);
  const page = Math.floor(f.offset / f.limit) + 1;
  const pages = Math.max(1, Math.ceil(total / f.limit));
  el.pageInfo.textContent = `${from}–${to} of ${total} · page ${page}/${pages}`;
  el.btnPrevPage.disabled = f.offset <= 0;
  el.btnNextPage.disabled = f.offset + f.limit >= total;
}

function renderHuntSkeletons() {
  el.findingsList.innerHTML = '';
  for (let i = 0; i < 3; i++) {
    const s = document.createElement('div');
    s.className = 'finding skel';
    s.innerHTML = '<div class="skel-line w40"></div><div class="skel-line w90"></div><div class="skel-line w70"></div>';
    el.findingsList.appendChild(s);
  }
}

function normalizeFinding(f) {
  const ev = f.evidence ?? f.evidence_strings ?? f.details ?? [];
  const nodes = f.nodes ?? f.involved_nodes ?? f.node_ids ?? f.entities ?? [];
  return {
    title: String(f.title ?? f.name ?? ''),
    severity: String(f.severity ?? f.level ?? 'info'),
    method: String(f.detection_method ?? f.method ?? ''),
    evidence: (Array.isArray(ev) ? ev : [ev]).map(String).filter(Boolean),
    nodes: (Array.isArray(nodes) ? nodes : [nodes])
      .map((n) => String((n && typeof n === 'object' ? nodeIdOf(n) : n) ?? ''))
      .filter(Boolean),
  };
}

function renderFindings() {
  el.findingsList.innerHTML = '';
  if (state.findings.length === 0) {
    el.findingsList.innerHTML = '<p class="empty">No findings. The graph may be clean — or the hunt rules returned nothing.</p>';
    return;
  }
  for (const f of state.findings) {
    const card = document.createElement('div');
    card.className = 'finding finding-clickable ' + sevClass(f.severity);
    const evHtml = f.evidence.length
      ? `<ul class="evidence">${f.evidence.map((e) => `<li>${esc(e)}</li>`).join('')}</ul>`
      : '<p class="muted small" style="margin:6px 0 0">no evidence strings returned</p>';
    const chips = f.nodes.length
      ? `<div class="nodes-label">involved nodes — click for blast radius</div>
         <div class="node-chips">${[...new Set(f.nodes)].map((id) =>
           `<button class="node-chip" data-node="${esc(id)}">${esc(id)}</button>`).join('')}</div>`
      : '<p class="muted small" style="margin:6px 0 0">no node ids attached</p>';
    card.innerHTML =
      `<div class="finding-top"><span class="finding-title" title="open evidence chain">` +
      `${esc(f.title)} <span style="color:var(--cyan)">↗</span></span>` +
      `<span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span></div>` +
      evHtml + chips;
    el.findingsList.appendChild(card);
  }
  el.findingsList.querySelectorAll('.node-chip').forEach((b) =>
    b.addEventListener('click', (ev) => { ev.stopPropagation(); handleNodeClick(b.dataset.node); }));
  // click the title to open the evidence-chain drawer
  [...el.findingsList.children].forEach((card, i) => {
    const t = card.querySelector('.finding-title');
    if (t) t.addEventListener('click', () => openDrawer(state.findings[i]));
  });
}

/* ---- demo attack scenario: hunt, then highlight finding nodes as the attack path ---- */
async function runDemoScenario() {
  el.btnDemo.disabled = true;
  el.canvasStatus.textContent = 'running demo scenario… (POST /hunt)';
  await runHunt();
  state.attackPath = new Set(state.findings.flatMap((f) => f.nodes));
  if (window.Graph3D) window.Graph3D.setAttackPath(state.attackPath);
  if (state.attackPath.size > 0) {
    el.canvasStatus.textContent =
      `attack path highlighted — ${state.attackPath.size} node${state.attackPath.size > 1 ? 's' : ''} from ${state.findings.length} finding${state.findings.length > 1 ? 's' : ''}`;
    pulseLoop();
  } else {
    el.canvasStatus.textContent = 'demo scenario found no attack path (no finding nodes)';
  }
  draw();
  el.btnDemo.disabled = !state.apiUp;
}

/* keep the pulse animation alive while an attack path or exfil-risk is highlighted */
let pulsing = false;
function pulseLoop() {
  if (pulsing) return;
  pulsing = true;
  (function tick() {
    if (state.attackPath.size === 0 && state.exfilSet.size === 0) { pulsing = false; draw(); return; }
    draw();
    requestAnimationFrame(tick);
  })();
}
function ensurePulse() { if (state.attackPath.size > 0 || state.exfilSet.size > 0) pulseLoop(); }

/* ================= blast radius ================= */
async function runBlastRadius(nodeId) {
  el.blastEmpty.hidden = true;
  el.blastResults.hidden = true;
  el.blastSource.textContent = `computing for ${nodeId}…`;
  try {
    const data = await apiFetch(EP_BLAST, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: nodeId }),
    });
    const rawBr = data.blast_radius ?? data.blastRadius ?? data.nodes ?? [];
    // API returns a dict {nodeId: {distance, risk_score}}; also accept list forms
    const list = Array.isArray(rawBr)
      ? rawBr
      : (rawBr && typeof rawBr === 'object'
          ? Object.entries(rawBr).map(([id, v]) => ({ id, ...((v && typeof v === 'object') ? v : {}) }))
          : []);
    const rows = list
      .map((r) => {
        const id = String(r.id ?? r.node_id ?? nodeIdOf(r) ?? '');
        const node = state.nodeById.get(id);
        // contract: rows may carry data_classification + regulated_reachable (all optional)
        const dc = String(r.data_classification ?? r.classification ?? node?.dc ?? '').toLowerCase() || '';
        return {
          id,
          distance: r.distance ?? r.hops ?? r.depth ?? '—',
          risk: r.risk ?? r.score ?? r.risk_score ?? null,
          dc,
          regulatedReachable: r.regulated_reachable === true || r.regulatedReachable === true,
        };
      })
      .filter((r) => r.id)
      .sort((a, b) => (Number(a.distance) || 0) - (Number(b.distance) || 0));
    const rawActions = data.actions ?? data.recommendations ?? [];
    const actions = (Array.isArray(rawActions) ? rawActions : []).map((a) => ({
      text: String(a.action ?? a.title ?? a.name ?? ''),
      target: String(a.target ?? a.node_id ?? ''),
      desc: String(a.description ?? a.detail ?? a.rationale ?? ''),
      priority: String(a.priority ?? a.severity ?? 'P3'),
    })).filter((a) => a.text);

    // exfil-risk overlay: external IP nodes at distance <= 1 from the
    // compromised source are the suspected C2 / exfil endpoints (real etype
    // from /graph — no invented regulated-data labels).
    state.exfilSet = new Set();
    for (const r of rows) {
      const node = state.nodeById.get(r.id);
      if (node && node.etype === 'ip' && Number(r.distance) <= 1) {
        r.exfil = true;
        state.exfilSet.add(r.id);
      }
    }

    state.blast = {
      sourceId: nodeId, rows, actions, exfilCount: state.exfilSet.size,
      // contract: /blast-radius gains regulated_datasets + notification_scope (all optional)
      regulatedDatasets: data.regulated_datasets ?? data.regulatedDatasets ?? null,
      notificationScope: data.notification_scope ?? data.notificationScope ?? null,
    };
    state.blastSet = new Set(rows.map((r) => r.id));
    // regulated-data overlay: crimson halo on nodes holding regulated data
    state.dpdpRegulatedSet = new Set(
      rows.filter((r) => r.dc === 'regulated' || r.regulatedReachable).map((r) => r.id));
    await loadDecisions(); // merge persisted analyst audit state into the queue
    renderBlast();
    renderDpdp();
    if (window.Graph3D && typeof window.Graph3D.setRegulated === 'function') {
      window.Graph3D.setRegulated(state.dpdpRegulatedSet);
    }
    if (el.btnBlastTour) el.btnBlastTour.hidden = false;
    ensurePulse();
    toast(`Blast radius: ${rows.length} nodes · ${state.exfilSet.size} exfil-risk · ${state.dpdpRegulatedSet.size} regulated · ${actions.length} actions awaiting approval`, 'ok');
    if (window.Graph3D && typeof window.Graph3D.flyTo === 'function') window.Graph3D.flyTo(nodeId);
  } catch (e) {
    el.blastSource.textContent = 'blast-radius failed: ' + e.message;
    el.blastEmpty.hidden = false;
    el.blastEmpty.textContent = 'Blast-radius request failed: ' + e.message;
    if (/Failed to fetch|NetworkError/i.test(e.message)) setOffline();
  }
}

/* Reversibility map for the containment decision queue.
 * Every action GraphOps recommends is non-destructive and reversible by design
 * (isolate / block / revoke / reset / collect). Nothing auto-executes, ever. */
const REVERSIBLE_ACTIONS = {
  'isolate host': true,
  'block IP at firewall': true,
  'revoke user sessions': true,
  'force password reset': true,
  'collect artifacts': true,
  'isolate_host': true,
  'reset_credentials': true,
};
function actionKey(a, t) { return `${a}|${t}`; }
function isReversible(a) {
  const s = String(a).toLowerCase();
  return Object.keys(REVERSIBLE_ACTIONS).some((k) => s.includes(k));
}

async function loadDecisions() {
  // merge persisted analyst decisions so action rows show their audit state
  try {
    const d = await apiFetch(EP_DECISIONS + '?limit=200');
    for (const r of d.decisions ?? []) {
      const a = r.action ?? r.action_name ?? '', t = r.target ?? r.node_id ?? '';
      if (a && r.decision) state.decisions.set(actionKey(a, t), String(r.decision));
    }
  } catch (e) { /* decisions history optional — queue still works */ }
}

async function decideAction(nodeId, action, target, decision, btn) {
  if (btn) btn.disabled = true;
  try {
    await apiFetch(EP_DECISIONS, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        node_id: nodeId,
        action, target,
        decision,
        rationale: `analyst ${decision} via dashboard (recommended action, reversible — human gate held)`,
      }),
    });
    state.decisions.set(actionKey(action, target), decision);
    toast(`${decision === 'approved' ? '✓ approved' : '✕ rejected'}: ${action} → ${target}`, decision === 'approved' ? 'ok' : 'warn');
    renderBlastActions(); // refresh row to show the audit badge
  } catch (e) {
    toast('Decision failed: ' + e.message, 'err');
    if (btn) btn.disabled = false;
  }
}

function renderBlastActions() {
  const b = state.blast;
  if (!b) return;
  el.actionsList.innerHTML = b.actions.length
    ? b.actions.map((a) => {
        const key = actionKey(a.text, a.target);
        const decided = state.decisions.get(key);
        const rev = isReversible(a.text);
        const fastLane = a.priority === 'P1' && rev && !decided;
        return `<div class="action">
          <span class="pri ${priClass(a.priority)}">${esc(a.priority)}</span>
          <div style="flex:1;min-width:0">
            <div class="action-text"><b>${esc(a.text)}</b> <span class="muted">→</span> <code>${esc(a.target)}</code>
              ${rev ? '<span class="rev-badge" title="non-destructive — can be rolled back">↩ reversible</span>' : ''}
              ${fastLane ? '<span class="rev-badge" title="P1 + reversible — one click to approve">⚡ fast-lane</span>' : ''}
            </div>
            ${(a.desc || a.rationale) ? `<div class="action-desc">${esc(a.desc || a.rationale)}</div>` : ''}
            <div class="action-foot">
              ${decided
                ? `<span class="dec-badge ${decided === 'approved' ? 'approved' : 'rejected'}">${decided === 'approved' ? '✓ approved' : '✕ rejected'} · recorded</span>`
                : `<button class="btn decide approve" data-k="${esc(key)}" data-d="approved">✓ Approve</button>
                   <button class="btn decide reject" data-k="${esc(key)}" data-d="rejected">✕ Reject</button>
                   <span class="dec-badge pending">recommended · awaits human</span>`}
            </div>
          </div>
        </div>`;
      }).join('')
    : '<p class="muted small">no containment actions returned</p>';
  el.actionsList.querySelectorAll('.btn.decide').forEach((btn) => {
    btn.addEventListener('click', () => {
      const k = btn.dataset.k.split('|');
      decideAction(state.blast.sourceId, k.slice(0, -1).join('|'), k[k.length - 1], btn.dataset.d, btn);
    });
  });
}

function renderBlast() {
  const b = state.blast;
  el.blastSource.textContent =
    `source: ${b.sourceId} · ${b.rows.length} nodes in radius · ${b.exfilCount} exfil-risk · ${state.dpdpRegulatedSet.size} regulated`;
  el.blastRows.innerHTML = b.rows.length
    ? b.rows.map((r) => {
        const width = r.risk === null ? 0 : Math.min(100, Math.max(4, Number(r.risk) <= 1 ? Number(r.risk) * 100 : Number(r.risk)));
        const node = state.nodeById.get(r.id);
        const isExfil = r.exfil === true;
        const dc = ['public', 'internal', 'confidential', 'regulated'].includes(r.dc)
          ? `<span class="dc dc-${r.dc}" title="data classification: ${esc(r.dc)}">${esc(r.dc)}</span>`
          : '';
        return `<tr class="${isExfil ? 'blast-row-exfil' : ''}">
          <td>${esc(r.id)}${String(r.id) === String(b.sourceId) ? ' ◀' : ''}${isExfil ? '<span class="exfil-tag">EXFIL RISK</span>' : ''}${dc}</td>
          <td class="${Number(r.distance) === 0 ? 'dist-0' : ''}">${esc(r.distance)}</td>
          <td><span class="risk-bar" style="width:${width}px"></span>${fmtRisk(r.risk)}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="3" class="muted">no nodes returned</td></tr>';
  renderBlastActions();
  el.blastEmpty.hidden = true;
  el.blastResults.hidden = false;
  draw();
  if (window.UI) {
    UI.blastPulse();
    UI.countUp(document.getElementById('statBlast'), b.rows.length, { dur: 0.7 });
  }
  if (window.Graph3D) {
    const riskById = b.rows.map((r) => [r.id, r.risk]);
    window.Graph3D.setBlast(state.blastSet, riskById);
    if (window.Graph3D.setExfil) window.Graph3D.setExfil(state.exfilSet);
  }
}

/* ================= DPDP regulated-data overlay =================
 * Contract: GET /blast-radius gains:
 *   regulated_datasets: [{dataset_id,name,classification,nodes_exposed,records_exposed_est}]
 *   notification_scope: {dpdp_72h_required, affected_individuals_est, datasets}
 * All optional. Missing fields → explicit "not available in this build" note, never invented.
 */
function renderDpdp() {
  const b = state.blast;
  const card = el.dpdpCard;
  if (!card) return;
  card.hidden = false;
  const ds = Array.isArray(b.regulatedDatasets) ? b.regulatedDatasets : null;
  const ns = (b.notificationScope && typeof b.notificationScope === 'object') ? b.notificationScope : null;
  const anyRegulated = state.dpdpRegulatedSet.size > 0;

  if (ds || ns) {
    const datasetsHtml = ds && ds.length
      ? `<div class="dpdp-datasets">${ds.map((d) => {
          const name = d.name ?? d.dataset_id ?? 'dataset';
          const cls = String(d.classification ?? 'regulated').toLowerCase();
          return `<div class="dpdp-dataset">
            <span class="ds-name">${esc(name)}</span>
            <span class="dc dc-${['public', 'internal', 'confidential', 'regulated'].includes(cls) ? cls : 'regulated'}">${esc(d.classification ?? 'regulated')}</span>
            <span class="ds-stats">${fmtCount(d.nodes_exposed ?? d.nodesExposed)} nodes · ${fmtCount(d.records_exposed_est ?? d.recordsExposedEst)} records est.</span>
          </div>`;
        }).join('')}</div>`
      : '<p class="muted small">regulated_datasets returned empty by the API.</p>';
    const notify72 = ns ? ns.dpdp_72h_required === true : null;
    const affected = ns ? ns.affected_individuals_est ?? ns.affectedIndividualsEst : null;
    card.innerHTML = `
      <div class="dpdp-head"><span class="dpdp-kicker">DPDP Act 2023 · regulated-data exposure</span></div>
      ${notify72 === true
        ? '<p class="dpdp-notice"><b>72h breach notification required</b> — compromised blast radius reaches regulated personal data. Notify the Data Protection Board of India within 72 hours; notify affected individuals as prescribed.</p>'
        : notify72 === false
          ? '<p class="dpdp-notice calm"><b>No 72h notification obligation flagged</b> by the API for this blast radius.</p>'
          : ''}
      <div class="dpdp-metrics">
        <div><span class="sm-num">${anyRegulated ? state.dpdpRegulatedSet.size : '—'}</span><span class="sm-label">regulated nodes in radius</span></div>
        <div><span class="sm-num">${affected !== null && affected !== undefined ? Number(affected).toLocaleString() : '—'}</span><span class="sm-label">affected individuals (est.)</span></div>
      </div>
      ${datasetsHtml}
      <p class="muted small dpdp-foot">Estimates come from the API — verify before any regulatory filing. Containment remains a human decision; nothing auto-executes.</p>`;
    const g = window.gsap;
    if (g) g.from(card, { opacity: 0, y: 8, duration: 0.45, ease: 'power2.out' });
  } else if (anyRegulated) {
    // real regulated nodes, but this backend build publishes no notification-scope fields
    card.innerHTML = `
      <div class="dpdp-head"><span class="dpdp-kicker">DPDP Act 2023 · regulated-data exposure</span></div>
      <p class="dpdp-na">${state.dpdpRegulatedSet.size} node${state.dpdpRegulatedSet.size > 1 ? 's' : ''} in this blast radius hold <b>regulated</b> data, but <b>notification-scope fields are not available in this backend build</b> — the 72h obligation cannot be confirmed from the API.</p>`;
  } else {
    card.innerHTML = `
      <div class="dpdp-head"><span class="dpdp-kicker">DPDP Act 2023 · regulated-data exposure</span></div>
      <p class="dpdp-na">Regulated-data overlay <b>not available in this backend build</b> — no <code>regulated_datasets</code> / <code>notification_scope</code> in the <code>/blast-radius</code> response.</p>`;
  }
}

function fmtCount(v) {
  if (v === null || v === undefined || v === '') return '—';
  const n = Number(v);
  return Number.isFinite(n) ? n.toLocaleString() : esc(v);
}

function flashDpdp() {
  const card = el.dpdpCard;
  if (!card || card.hidden) return;
  if (card.scrollIntoView) card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  const g = window.gsap;
  if (g) {
    g.fromTo(card,
      { boxShadow: '0 0 0 rgba(255,45,85,0)' },
      { boxShadow: '0 0 28px rgba(255,45,85,0.55)', duration: 0.4, yoyo: true, repeat: 1, ease: 'power2.inOut' });
  }
}

/* click a regulated node (2D or 3D) → compute blast radius, then jump to its DPDP card */
async function handleNodeClick(id) {
  await runBlastRadius(id);
  if (state.dpdpRegulatedSet && state.dpdpRegulatedSet.has(id)) flashDpdp();
}

/* camera tour through the blast-radius path (3D); switches to 3D first if needed */
function tourBlastView() {
  if (!state.blast || !state.blast.rows.length) { toast('Compute a blast radius first', 'warn'); return; }
  const w3 = window.Graph3D;
  if (!w3 || typeof w3.tourBlast !== 'function') { toast('3D view unavailable — tour needs WebGL', 'warn'); return; }
  if (window.UI && window.UI.getMode() !== '3d') {
    const ok = window.UI.setView('3d');
    if (ok === false) { toast('3D view unavailable — tour needs WebGL', 'warn'); return; }
    setTimeout(() => w3.tourBlast(state.blast.rows), 600); // let 3D settle after view switch
  } else {
    w3.tourBlast(state.blast.rows);
  }
  toast(`Touring ${Math.min(10, state.blast.rows.length)} blast-radius nodes`, 'info');
}

/* ================= red-team replay (demo scenarios) =================
 * Contract: GET /demo-scenarios → [{id,name,description,severity,steps:[...]}]
 *           POST /demo-scenarios/{id}/run → {detected,mttd_seconds,mttc_seconds,
 *             false_positives,blast_radius_precision,findings}
 * All optional — a 404 renders an explicit "not available in this build" state.
 */
async function loadScenarios() {
  if (!el.scenarioStatus) return;
  el.scenarioStatus.innerHTML = 'Loading scripted scenarios from <code>GET /demo-scenarios</code>…';
  try {
    const data = await apiFetch(EP_DEMO_SCENARIOS);
    const list = Array.isArray(data) ? data : (data.scenarios ?? data.items ?? []);
    state.scenarios = (Array.isArray(list) ? list : [])
      .map((s) => ({
        id: String(s.id ?? ''),
        name: String(s.name ?? s.id ?? ''),
        description: String(s.description ?? ''),
        severity: String(s.severity ?? ''),
        steps: Array.isArray(s.steps) ? s.steps : [],
      }))
      .filter((s) => s.id);
    state.scenariosState = 'ready';
    renderScenarios();
  } catch (e) {
    state.scenariosState = 'unsupported';
    el.scenarioStatus.innerHTML =
      'Red-team replay <b>not available in this backend build</b> — <code>GET /demo-scenarios</code> failed: ' +
      esc(e.message);
    el.scenarioList.innerHTML = '';
  }
}

function renderScenarios() {
  if (state.scenariosState !== 'ready') return;
  el.scenarioStatus.textContent = state.scenarios.length
    ? `${state.scenarios.length} scripted scenario${state.scenarios.length > 1 ? 's' : ''} — one-click replay against the graph. All metrics measured live by the API.`
    : 'The API returned no scenarios.';
  el.scenarioList.innerHTML = state.scenarios.map((s) =>
    `<div class="scenario">
       <div class="scenario-top"><b>${esc(s.name)}</b><span class="sev ${sevClass(s.severity)}">${esc(s.severity || 'n/a')}</span></div>
       ${s.description ? `<p class="muted small">${esc(s.description)}</p>` : ''}
       <div class="scenario-foot">
         <span class="muted small">${s.steps.length} steps</span>
         <button class="btn accent sm" data-run="${esc(s.id)}">▶ Run</button>
       </div>
     </div>`).join('');
  el.scenarioList.querySelectorAll('[data-run]').forEach((btn) =>
    btn.addEventListener('click', () => runScenario(btn.dataset.run)));
}

async function runScenario(id) {
  const s = state.scenarios.find((x) => x.id === id);
  el.scenarioResult.hidden = false;
  el.scenarioResult.innerHTML = `<p class="muted small">running scenario <code>${esc(id)}</code>… (POST /demo-scenarios/{id}/run)</p>`;
  try {
    const r = await apiFetch(EP_DEMO_SCENARIOS + '/' + encodeURIComponent(id) + '/run', { method: 'POST' });
    renderScenarioResult(s, r);
  } catch (e) {
    el.scenarioResult.innerHTML = `<p class="err-text">Scenario run failed: ${esc(e.message)}</p>`;
  }
}

function fmtMetric(v, suffix) {
  if (v === null || v === undefined || v === '') return '—';
  const n = Number(v);
  if (!Number.isFinite(n)) return esc(v);
  return n.toLocaleString(undefined, { maximumFractionDigits: 2 }) + (suffix || '');
}

function renderScenarioResult(s, r) {
  const detected = r.detected === true;
  const mttd = r.mttd_seconds ?? r.mttd ?? null;
  const mttc = r.mttc_seconds ?? r.mttc ?? null;
  const fp = r.false_positives ?? r.falsePositives ?? r.fp ?? null;
  const prec = r.blast_radius_precision ?? r.precision ?? null;
  state.lastScenarioRun = {
    name: s ? s.name : '', id: s ? s.id : '',
    detected, mttd, mttc, fp, prec,
  };
  el.scenarioResult.innerHTML = `
    <div class="scenario-res-top">
      <span class="det ${detected ? 'yes' : 'no'}">${detected ? '✓ DETECTED' : '✕ NOT DETECTED'}</span>
      <b>${esc(s ? s.name : '')}</b>
    </div>
    <div class="scenario-metrics">
      <div><span class="sm-num">${fmtMetric(mttd)}</span><span class="sm-label">MTTD (s)</span></div>
      <div><span class="sm-num">${fmtMetric(mttc)}</span><span class="sm-label">MTTC (s)</span></div>
      <div><span class="sm-num">${fmtMetric(fp)}</span><span class="sm-label">false positives</span></div>
      <div><span class="sm-num">${fmtMetric(prec, '%')}</span><span class="sm-label">blast precision</span></div>
    </div>
    <div class="scenario-res-foot">
      <button class="btn ghost sm" id="btnCopyDemoScript">⧉ copy demo script</button>
      <span class="muted small">measured by the API, not scripted</span>
    </div>`;
  const cb = document.getElementById('btnCopyDemoScript');
  if (cb) cb.addEventListener('click', copyDemoScript);
  const g = window.gsap;
  if (g) g.from(el.scenarioResult, { opacity: 0, y: 8, duration: 0.4, ease: 'power2.out' });
}

/* judge-friendly narration — every number is a real measured value from the run above */
function copyDemoScript() {
  const r = state.lastScenarioRun;
  if (!r) return;
  const verdict = r.detected ? 'detected the campaign' : 'did NOT detect the campaign';
  const mttd = r.mttd !== null && r.mttd !== undefined ? r.mttd + 's' : 'n/a';
  const mttc = r.mttc !== null && r.mttc !== undefined ? r.mttc + 's' : 'n/a';
  const fp = r.fp !== null && r.fp !== undefined ? r.fp : 'n/a';
  const prec = r.prec !== null && r.prec !== undefined ? r.prec + '%' : 'n/a';
  const text =
`GraphOps red-team replay — "${r.name}"
We replayed a scripted attack campaign against the SOC graph and GraphOps ${verdict}.
Measured live: MTTD ${mttd} · MTTC ${mttc} · false positives ${fp} · blast-radius precision ${prec}.
Containment stays human-gated: every action is a recommendation awaiting analyst approval — nothing auto-executes.`;
  if (!navigator.clipboard || !navigator.clipboard.writeText) {
    toast('Clipboard unavailable in this browser context', 'err');
    return;
  }
  navigator.clipboard.writeText(text)
    .then(() => toast('Demo script copied — paste it into the judge walkthrough', 'ok'))
    .catch((e) => toast('Copy failed: ' + (e && e.message ? e.message : e), 'err'));
}

/* ================= evidence-chain drawer ================= */
function bfsPath(a, b) {
  // shortest path over the loaded graph (undirected BFS) between two finding nodes
  if (!a || !b || !state.nodeById.has(a) || !state.nodeById.has(b)) return [];
  if (a === b) return [a];
  const adj = new Map(); // id -> [{to, etype}]
  for (const e of state.edges) {
    const s = e.source.id, t = e.target.id;
    if (!adj.has(s)) adj.set(s, []);
    if (!adj.has(t)) adj.set(t, []);
    adj.get(s).push({ to: t, etype: e.etype });
    adj.get(t).push({ to: s, etype: e.etype });
  }
  const prev = new Map([[a, null]]);
  const q = [a];
  while (q.length) {
    const cur = q.shift();
    if (cur === b) break;
    for (const { to } of adj.get(cur) || []) {
      if (!prev.has(to)) { prev.set(to, cur); q.push(to); }
    }
  }
  if (!prev.has(b)) return [];
  const nodes = [];
  for (let c = b; c !== null; c = prev.get(c)) nodes.unshift(c);
  // annotate edge etypes along the directed path
  const annotated = nodes.map((id, i) => {
    if (i === 0) return { id, edge: null };
    const from = nodes[i - 1];
    let etype = '';
    for (const e of state.edges) {
      if ((e.source.id === from && e.target.id === id) ||
          (e.source.id === id && e.target.id === from)) { etype = e.etype || ''; break; }
    }
    return { id, edge: etype };
  });
  return annotated;
}

function openDrawer(finding) {
  if (!finding) { toast('No finding to inspect', 'warn'); return; }
  state.drawerFinding = finding;
  el.drawerSub.textContent = `${finding.severity} · ${finding.nodes.length} involved node${finding.nodes.length > 1 ? 's' : ''}`;
  const uniq = [...new Set(finding.nodes)];
  const path = uniq.length >= 2 ? bfsPath(uniq[0], uniq[uniq.length - 1]) : uniq.map((id) => ({ id, edge: null }));
  const signals = finding.evidence.length
    ? finding.evidence.map((s, i) =>
        `<div class="signal"><span class="signal-num">${i + 1}</span><span class="signal-text">${esc(s)}</span></div>`).join('')
    : '<p class="path-empty">No evidence strings returned by the hunt query.</p>';
  const chain = path.length
    ? `<div class="path-chain">${path.map((p, i) =>
        `${i > 0 ? `<span class="path-edge">—<b>${esc(p.edge || '?')}</b>→</span>` : ''}` +
        `<button class="path-node" data-node="${esc(p.id)}">${esc(p.id)}</button>`).join('')}</div>`
    : `<p class="path-empty">No path between <code>${esc(uniq[0] || '')}</code> and <code>${esc(uniq[uniq.length - 1] || '')}</code> in the loaded graph (${state.edges.length} edges, truncated by /graph cap).</p>`;
  el.drawerBody.innerHTML = `
    <div class="drawer-sec"><h3>Finding</h3>
      <div class="finding-top" style="margin-bottom:8px">
        <span class="finding-title" style="font-size:14px;font-weight:700">${esc(finding.title)}</span>
        <span class="sev ${sevClass(finding.severity)}">${esc(finding.severity)}</span>
      </div>
    </div>
    <div class="drawer-sec"><h3>Signals fired — ${finding.evidence.length}</h3>${signals}</div>
    <div class="drawer-sec"><h3>Subgraph path — ${path.length} hops</h3>${chain}
      <div class="drawer-actions">
        <button class="btn primary" id="drawerHighlight">⬈ Highlight on graph</button>
        <button class="btn ghost" id="drawerBlast">Blast radius: ${esc(uniq[0] || '')}</button>
      </div>
    </div>`;
  el.drawerBody.querySelectorAll('.path-node').forEach((btn) =>
    btn.addEventListener('click', () => handleNodeClick(btn.dataset.node)));
  const hb = el.drawerBody.querySelector('#drawerHighlight');
  if (hb) hb.addEventListener('click', () => {
    const ids = new Set(path.length ? path.map((p) => p.id) : uniq);
    state.attackPath = ids;
    if (window.Graph3D) window.Graph3D.setAttackPath(ids);
    pulseLoop(); draw();
    toast(`Highlighted ${ids.size} nodes from the evidence chain`, 'ok');
  });
  const db = el.drawerBody.querySelector('#drawerBlast');
  if (db && uniq[0]) db.addEventListener('click', () => { closeDrawer(); handleNodeClick(uniq[0]); });
  el.drawer.hidden = false;
  const g = window.gsap;
  if (g) g.fromTo('.drawer', { x: 430, opacity: 0.6 }, { x: 0, opacity: 1, duration: 0.42, ease: 'power3.out' });
  toast('Evidence chain opened — ' + finding.title.slice(0, 60), 'info');
}

function closeDrawer() {
  if (el.drawer.hidden) return;
  const g = window.gsap;
  const done = () => { el.drawer.hidden = true; };
  if (g) g.to('.drawer', { x: 430, opacity: 0, duration: 0.3, ease: 'power2.in', onComplete: done, overwrite: true });
  else done();
}

/* ================= bridge for ui.js / graph3d.js ================= */
function pushGraphTo3D() {
  if (!window.Graph3D || state.nodes.length === 0) return;
  window.Graph3D.setData(
    state.nodes.map((n) => ({ id: n.id, etype: n.etype, label: n.label, degree: n.degree, dc: n.dc })),
    state.edges.map((e) => ({ a: e.source.id, b: e.target.id, etype: e.etype }))
  );
  window.Graph3D.onNodeClick = (id) => handleNodeClick(id);
  window.Graph3D._wired = true;
  if (window.Graph3D.setExfil) window.Graph3D.setExfil(state.exfilSet);
  if (window.Graph3D.setRegulated) window.Graph3D.setRegulated(state.dpdpRegulatedSet);
}

function clearHighlights() {
  state.attackPath = new Set();
  state.blastSet = new Set();
  state.exfilSet = new Set();
  state.dpdpRegulatedSet = new Set();
  state.blast = null;
  el.blastResults.hidden = true;
  el.blastEmpty.hidden = false;
  el.blastSource.textContent = '';
  if (el.dpdpCard) el.dpdpCard.hidden = true;
  if (el.btnBlastTour) el.btnBlastTour.hidden = true;
  if (window.Graph3D) {
    window.Graph3D.setAttackPath(new Set());
    window.Graph3D.setBlast(new Set(), []);
    if (window.Graph3D.setExfil) window.Graph3D.setExfil(new Set());
    if (window.Graph3D.setRegulated) window.Graph3D.setRegulated(new Set());
  }
  const sb = document.getElementById('statBlast');
  if (sb && window.UI) UI.countUp(sb, 0, { dur: 0.5 });
  draw();
}

function focusFinding(i) {
  const f = state.findings[i];
  if (!f) return;
  state.attackPath = new Set(f.nodes);
  if (window.Graph3D) {
    window.Graph3D.setAttackPath(state.attackPath);
    if (f.nodes[0] && typeof window.Graph3D.flyTo === 'function') window.Graph3D.flyTo(f.nodes[0]);
  }
  pulseLoop();
  draw();
  const cards = el.findingsList.querySelectorAll('.finding');
  if (cards[i] && cards[i].scrollIntoView) cards[i].scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function exposeBridge() {
  window.GraphOps = {
    getGraphData: () => ({
      nodes: state.nodes.map((n) => ({ id: n.id, etype: n.etype, label: n.label, degree: n.degree, dc: n.dc })),
      edges: state.edges.map((e) => ({ a: e.source.id, b: e.target.id, etype: e.etype })),
    }),
    getBlast: () => (state.blast
      ? { set: state.blastSet, risk: state.blast.rows.map((r) => [r.id, r.risk]), exfil: state.exfilSet }
      : null),
    getDpdp: () => (state.blast
      ? { regulated: state.blast.regulatedDatasets, notificationScope: state.blast.notificationScope,
          regulatedNodes: [...state.dpdpRegulatedSet] }
      : null),
    getScenarios: () => state.scenarios,
    runScenario,
    getAttackPath: () => state.attackPath,
    getFindings: () => state.findings,
    runHunt: (opts) => runHunt(opts || {}),
    runDemo: runDemoScenario,
    runBlast: runBlastRadius,
    clickNode: handleNodeClick, // blast radius + DPDP jump for regulated nodes
    clearHighlights,
    focusFinding,
    redraw2d: () => draw(),
    toast,
    openEvidence: openDrawer,
    closeDrawer,
    toggleAutoRefresh: () => setAutoRefresh(!state.autoRefreshOn),
    isAutoRefresh: () => state.autoRefreshOn,
    openDrawerForFinding: (i) => openDrawer(state.findings[i]),
  };
  if (window.Graph3D) {
    window.Graph3D.onNodeClick = (id) => handleNodeClick(id);
    window.Graph3D._wired = true;
  }
}
