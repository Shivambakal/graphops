/* GraphOps SOC dashboard — zero hardcoded data.
 * Everything renders from the API at http://localhost:8000:
 *   GET  /health        -> node/edge counts
 *   GET  /graph         -> {nodes, edges}
 *   POST /hunt          -> {findings}
 *   POST /blast-radius  -> {blast_radius, actions}   (body: {node_id})
 * If the API is down, an explicit offline state is shown — nothing is faked.
 */
'use strict';

/* ================= API contract ================= */
const API_BASE = 'http://localhost:8000';
const EP_HEALTH = API_BASE + '/health';
const EP_HUNT = API_BASE + '/hunt';
const EP_BLAST = API_BASE + '/blast-radius';
const EP_GRAPH = API_BASE + '/graph';
const START_CMD = 'uvicorn graphops.api.server:app';

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
  hovered: null,
  dragged: null,
  layoutDone: false,
  apiUp: false,
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
  footStamp: $('footStamp'),
};

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
  const v = e && (e[key] ?? (key === 'source' ? e.from : e.to));
  return (v && typeof v === 'object') ? nodeIdOf(v) : v;
}

/* ================= boot ================= */
window.addEventListener('DOMContentLoaded', init);

async function init() {
  el.footStamp.textContent = 'loaded ' + new Date().toLocaleString();
  sizeCanvas();
  window.addEventListener('resize', () => { sizeCanvas(); draw(); });
  wireCanvas();
  el.btnRunHunt.addEventListener('click', runHunt);
  el.btnDemo.addEventListener('click', runDemoScenario);

  const up = await checkHealth();
  if (!up) { setOffline(); return; }
  setOnline();
  await loadGraph();
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
        x: 0, y: 0, r: 7, degree: 0,
      }))
      .filter((n) => n.id);
    state.nodeById = new Map(state.nodes.map((n) => [n.id, n]));
    state.edges = rawEdges
      .map((e) => {
        const s = state.nodeById.get(String(edgeEnd(e, 'source') ?? ''));
        const t = state.nodeById.get(String(edgeEnd(e, 'target') ?? ''));
        return (s && t) ? { source: s, target: t } : null;
      })
      .filter(Boolean);
    for (const e of state.edges) { e.source.degree++; e.target.degree++; }
    for (const n of state.nodes) n.r = 6 + Math.min(8, n.degree * 1.6);

    // authoritative counts from /graph itself
    el.healthLine.innerHTML =
      `nodes <b>${state.nodes.length}</b> · edges <b>${state.edges.length}</b> · <span style="color:var(--green)">online</span>`;

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
    const isHover = state.hovered === n;

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
        `<span class="tt-type">${esc(n.etype)} · degree ${n.degree}</span><br>` +
        `<span class="muted">click → blast radius</span>`;
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
    if (n) runBlastRadius(n.id);
  });
}

/* ================= hunt ================= */
async function runHunt() {
  el.btnRunHunt.disabled = true;
  el.huntStatus.textContent = 'hunting… (POST /hunt)';
  try {
    const data = await apiFetch(EP_HUNT, { method: 'POST' });
    const raw = data.findings ?? data.results ?? [];
    state.findings = raw.map(normalizeFinding).filter((f) => f.title);
    renderFindings();
    el.huntStatus.textContent =
      state.findings.length === 0
        ? 'Hunt complete — no findings returned.'
        : `Hunt complete — ${state.findings.length} finding${state.findings.length > 1 ? 's' : ''} · ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    el.huntStatus.textContent = 'Hunt failed: ' + e.message;
    if (!state.apiUp || /Failed to fetch|NetworkError/i.test(e.message)) setOffline();
  } finally {
    el.btnRunHunt.disabled = !state.apiUp;
  }
}

function normalizeFinding(f) {
  const ev = f.evidence ?? f.evidence_strings ?? f.details ?? [];
  const nodes = f.nodes ?? f.involved_nodes ?? f.node_ids ?? f.entities ?? [];
  return {
    title: String(f.title ?? f.name ?? ''),
    severity: String(f.severity ?? f.level ?? 'info'),
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
    card.className = 'finding ' + sevClass(f.severity);
    const evHtml = f.evidence.length
      ? `<ul class="evidence">${f.evidence.map((e) => `<li>${esc(e)}</li>`).join('')}</ul>`
      : '<p class="muted small" style="margin:6px 0 0">no evidence strings returned</p>';
    const chips = f.nodes.length
      ? `<div class="nodes-label">involved nodes — click for blast radius</div>
         <div class="node-chips">${[...new Set(f.nodes)].map((id) =>
           `<button class="node-chip" data-node="${esc(id)}">${esc(id)}</button>`).join('')}</div>`
      : '<p class="muted small" style="margin:6px 0 0">no node ids attached</p>';
    card.innerHTML =
      `<div class="finding-top"><span class="finding-title">${esc(f.title)}</span>` +
      `<span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span></div>` +
      evHtml + chips;
    el.findingsList.appendChild(card);
  }
  el.findingsList.querySelectorAll('.node-chip').forEach((b) =>
    b.addEventListener('click', () => runBlastRadius(b.dataset.node)));
}

/* ---- demo attack scenario: hunt, then highlight finding nodes as the attack path ---- */
async function runDemoScenario() {
  el.btnDemo.disabled = true;
  el.canvasStatus.textContent = 'running demo scenario… (POST /hunt)';
  await runHunt();
  state.attackPath = new Set(state.findings.flatMap((f) => f.nodes));
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

/* keep the pulse animation alive while an attack path is highlighted */
let pulsing = false;
function pulseLoop() {
  if (pulsing) return;
  pulsing = true;
  (function tick() {
    if (state.attackPath.size === 0) { pulsing = false; draw(); return; }
    draw();
    requestAnimationFrame(tick);
  })();
}

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
    const list = Array.isArray(rawBr) ? rawBr : (rawBr.nodes ?? []);
    const rows = list
      .map((r) => ({
        id: String(r.id ?? r.node_id ?? nodeIdOf(r) ?? ''),
        distance: r.distance ?? r.hops ?? r.depth ?? '—',
        risk: r.risk ?? r.score ?? r.risk_score ?? null,
      }))
      .filter((r) => r.id)
      .sort((a, b) => (Number(a.distance) || 0) - (Number(b.distance) || 0));
    const rawActions = data.actions ?? data.recommendations ?? [];
    const actions = (Array.isArray(rawActions) ? rawActions : []).map((a) => ({
      text: String(a.action ?? a.title ?? a.name ?? ''),
      desc: String(a.description ?? a.detail ?? a.why ?? ''),
      priority: String(a.priority ?? a.severity ?? 'P3'),
    })).filter((a) => a.text);

    state.blast = { sourceId: nodeId, rows, actions };
    state.blastSet = new Set(rows.map((r) => r.id));
    renderBlast();
  } catch (e) {
    el.blastSource.textContent = 'blast-radius failed: ' + e.message;
    el.blastEmpty.hidden = false;
    el.blastEmpty.textContent = 'Blast-radius request failed: ' + e.message;
    if (/Failed to fetch|NetworkError/i.test(e.message)) setOffline();
  }
}

function renderBlast() {
  const b = state.blast;
  el.blastSource.textContent = `source: ${b.sourceId} · ${b.rows.length} nodes in radius`;
  el.blastRows.innerHTML = b.rows.length
    ? b.rows.map((r) => {
        const width = r.risk === null ? 0 : Math.min(100, Math.max(4, Number(r.risk) <= 1 ? Number(r.risk) * 100 : Number(r.risk)));
        return `<tr>
          <td>${esc(r.id)}${String(r.id) === String(b.sourceId) ? ' ◀' : ''}</td>
          <td class="${Number(r.distance) === 0 ? 'dist-0' : ''}">${esc(r.distance)}</td>
          <td><span class="risk-bar" style="width:${width}px"></span>${fmtRisk(r.risk)}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="3" class="muted">no nodes returned</td></tr>';
  el.actionsList.innerHTML = b.actions.length
    ? b.actions.map((a) =>
        `<div class="action"><span class="pri ${priClass(a.priority)}">${esc(a.priority)}</span>` +
        `<div><div class="action-text">${esc(a.text)}</div>` +
        (a.desc ? `<div class="action-desc">${esc(a.desc)}</div>` : '') +
        `</div></div>`).join('')
    : '<p class="muted small">no containment actions returned</p>';
  el.blastEmpty.hidden = true;
  el.blastResults.hidden = false;
  draw();
}
