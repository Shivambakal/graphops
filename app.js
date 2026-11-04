// GraphOps App — Incident Decision & Graph Analytics Orchestrator
// Connects data.js, engine.js, 2D Vis-Network, 3D Force Graph, ECharts, and SOC Incident UI.
(function () {
"use strict";

const $ = id => document.getElementById(id);
const esc = s => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;");

// Colors & Styling Tokens
const COLORS = {
  asset:    { background: "#201510", border: "#a06a3c" },
  identity: { background: "#221a0e", border: "#c9973f" },
  network:  { background: "#12211f", border: "#4f7d7a" },
};
const HIT = { background: "#2a1215", border: "#b3273a" };
const ENTRY = { background: "#241c0e", border: "#e3d5b3" };
const GOLD = { background: "#241c0e", border: "#c9973f" };
const CONTAINED = { background: "#16202e", border: "#5b7fa6" };
const DIM = { background: "#0b0a08", border: "#26211a" };

const EDGE_BASE = "#2b251c", EDGE_HIT = "#b3273a", EDGE_GOLD = "#c9973f", EDGE_DIM = "#14110c", EDGE_CONTAINED = "#24344a";

// Application State
const S = {
  nodes: NODES.slice(),
  edges: EDGES.slice(),
  techniques: TECHNIQUES,
  crownJewels: CROWN_JEWELS.slice(),

  blast: null,
  baselineBlast: null,
  layer: 0,
  playing: false,
  playTimer: null,
  speed: 1,

  // Replay
  replaying: false,
  replayTimer: null,
  replayStepIdx: 0,

  // Containment Lab
  containedNodes: new Set(),
  containedEdges: new Set(),
  containmentRanking: null,

  // Navigation & Highlighting
  collapsed: {},
  filters: { asset: true, identity: true, network: true },
  highlightPath: null,
  highlightTechnique: null,
  drawerTarget: null, // { type: 'node', id: '...' } or { type: 'edge', idx: ... }

  scenarios: [],
  crit: {},
  mode3d: false,
  graph3d: null,
  charts: {},

  treeEdgeIdx: {},
  hotTreeIdx: new Set(),
  revealed: new Set(),

  // Live Telemetry
  telemetryActive: true,
  telemetryTimer: null,
  telemetryLastUpdate: Date.now(),
  tickerIndex: 0
};

let nodeById = {};
function refreshNodeMap() {
  nodeById = {};
  S.nodes.forEach(n => nodeById[n.id] = n);
}
refreshNodeMap();

const labelOf = id => (nodeById[id] && nodeById[id].label) || id;
const critOfUI = id => (S.crit[id] != null ? S.crit[id] : (nodeById[id]?.criticality || 3));

// CDN Availability Checks
const HAS_VIS = typeof vis !== "undefined";
const HAS_3D = typeof ForceGraph3D !== "undefined";
const HAS_ECHARTS = typeof echarts !== "undefined";

if (!HAS_VIS) {
  $("cdnError").style.display = "flex";
  return;
}

// 2D Vis-Network Datasets
let visNodes = new vis.DataSet(
  S.nodes.map(n => ({
    id: n.id,
    label: n.label,
    group: n.group,
    color: COLORS[n.group],
    shape: "dot",
    size: 22,
    font: { color: "#ece7db", size: 12.5 }
  }))
);

let visEdges = new vis.DataSet(
  S.edges.map((e, i) => ({
    id: i,
    from: e.from,
    to: e.to,
    label: `${e.rel || e.label} ·${e.weight}`,
    font: { color: "#7d7668", size: 9.5 },
    color: { color: EDGE_BASE },
    width: 1,
    title: `${e.rel || e.label} (${e.confidence || "HIGH"} confidence) — ${e.evidence || ""}`
  }))
);

const network = new vis.Network($("net2d"), { nodes: visNodes, edges: visEdges }, {
  physics: {
    stabilization: true,
    barnesHut: { gravitationalConstant: -2200, springLength: 100 }
  },
  interaction: { hover: true, multiselect: false }
});

function neighborsOf(id) {
  const out = new Set();
  S.edges.forEach(e => {
    if (e.from === id) out.add(e.to);
    if (e.to === id) out.add(e.from);
  });
  return [...out];
}

function isHidden(id) {
  const n = nodeById[id];
  if (!n || !S.filters[n.group]) return true;
  return Object.values(S.collapsed).some(arr => arr.includes(id));
}

function applyVisibility() {
  S.nodes.forEach(n => {
    try { visNodes.update({ id: n.id, hidden: isHidden(n.id) }); } catch (e) {}
  });
  if (S.mode3d && S.graph3d) rebuild3D();
}

// ---------- Simulation & Bounded Propagation ----------
function stopAnim() {
  S.playing = false;
  if (S.playTimer) { clearTimeout(S.playTimer); S.playTimer = null; }
  $("btnPlay").textContent = "Play";
  $("btnStopAnim").disabled = true;
  $("btnPlay").disabled = !S.blast;
  stopReplay();
  if (S.blast) paint2D();
}

function simulate() {
  stopAnim();
  const startId = $("entrySel").value;
  const depth = parseInt($("depthSel").value, 10) || 3;

  // Run bounded weighted path propagation
  S.blast = blastRadius(S.nodes, S.edges, startId, depth, S.crit, S.containedNodes, S.containedEdges);
  if (!S.baselineBlast || S.containedNodes.size === 0) {
    S.baselineBlast = S.blast;
  }

  S.highlightPath = null;
  S.highlightTechnique = null;
  S.collapsed = {};

  // Build attack tree links
  S.treeEdgeIdx = {};
  const key2idx = {};
  S.edges.forEach((e, i) => key2idx[[e.from, e.to].sort().join("|")] = i);
  Object.keys(S.blast.info).forEach(id => {
    const p = S.blast.info[id].parent;
    if (p) S.treeEdgeIdx[id] = key2idx[[id, p].sort().join("|")];
  });

  applyVisibility();
  S.layer = 0;
  S.revealed = new Set([startId]);

  const tl = $("timeline");
  tl.max = Math.max(1, S.blast.layers.length - 1);
  tl.value = 0;
  tl.disabled = false;
  ["btnPlay", "btnStepBack", "btnStepFwd", "speedSel"].forEach(id => $(id).disabled = false);

  // Evaluate containment rankings
  updateContainmentRanking();

  renderAll();
  updateIncidentHeader();
  startPlay();
}

function updateContainmentRanking() {
  if (!S.blast) return;
  const startId = S.blast.startId;
  const depth = S.blast.maxDepth;
  S.containmentRanking = rankContainmentActions(S.nodes, S.edges, startId, depth, null, S.crit, S.crownJewels);

  // Surface Incident Commander Recommendation Banner
  const rec = S.containmentRanking.recommended;
  const banner = $("recBanner");
  if (rec && S.blast && Object.keys(S.blast.info).length > 2 && S.containedNodes.size === 0) {
    banner.style.display = "flex";
    $("recBadge").textContent = `${rec.riskReductionPct}% RISK REDUCTION`;
    $("recReason").textContent = `Isolate ${rec.label} · ${rec.reasons.slice(0, 2).join(" · ")}`;
    $("btnApplyRec").onclick = () => {
      toggleNodeContainment(rec.id);
      banner.style.display = "none";
    };
  } else {
    banner.style.display = "none";
  }
}

// Staggered node ignition animation with shockwaves
function igniteLayer(k, done) {
  const ids = (S.blast.layers[k] || []).filter(id => !S.revealed.has(id));
  if (!ids.length) { if (done) done(); return; }
  ids.forEach((id, i) => {
    setTimeout(() => {
      if (!S.blast) return;
      S.revealed.add(id);
      shockwave(id, S.containedNodes.has(id) ? "contained" : "");
      updateHotEdges();
      paint2D();
      if (S.mode3d && S.graph3d) { try { S.graph3d.refresh(); } catch (e) {} }
      if (i === ids.length - 1 && done) done();
    }, 140 * i);
  });
}

function shockwave(id, customClass) {
  if (S.mode3d) return;
  try {
    const pos = network.getPositions([id])[id];
    if (!pos) return;
    const dom = network.canvasToDOM(pos);
    const el = document.createElement("div");
    el.className = `shockwave ${customClass || ""} ${(S.blast && id === S.blast.startId ? "entry" : "")}`.trim();
    el.style.left = dom.x + "px";
    el.style.top = dom.y + "px";
    $("center").appendChild(el);
    setTimeout(() => el.remove(), 1000);
  } catch (e) {}
}

function startPlay() {
  if (!S.blast || S.playing) return;
  S.playing = true;
  $("btnPlay").textContent = "Pause";
  $("btnStopAnim").disabled = false;

  const step = () => {
    if (!S.playing) return;
    if (S.layer >= S.blast.layers.length - 1) { stopAnim(); return; }
    S.layer++;
    renderLayerChrome();
    igniteLayer(S.layer, () => {
      if (S.playing) S.playTimer = setTimeout(step, Math.round(750 / S.speed));
    });
  };
  step();
}

function renderLayerChrome() {
  const k = S.layer;
  $("timeline").value = k;
  $("timelineLabel").textContent = "hop " + k + " / " + (S.blast.layers.length - 1);
}

function syncRevealed() {
  S.revealed = new Set();
  if (!S.blast) return;
  Object.entries(S.blast.info).forEach(([id, r]) => {
    if (r.depth <= S.layer) S.revealed.add(id);
  });
}

function renderLayer() {
  const k = S.layer;
  $("timeline").value = k;
  $("timelineLabel").textContent = "hop " + k + " / " + (S.blast.layers.length - 1);
  syncRevealed();
  updateHotEdges();
  paint2D();
  if (S.mode3d && S.graph3d) { try { S.graph3d.refresh(); } catch (e) {} }
  if ($("drawer").classList.contains("open") && S.drawerTarget) {
    if (S.drawerTarget.type === "node") showNodeDetail(S.drawerTarget.id);
  }
}

function updateHotEdges() {
  S.hotTreeIdx = new Set();
  if (!S.blast || S.highlightPath) return;
  Object.keys(S.blast.info).forEach(id => {
    const r = S.blast.info[id];
    if (r.depth > 0 && S.revealed.has(id) && S.treeEdgeIdx[id] != null) {
      S.hotTreeIdx.add(S.treeEdgeIdx[id]);
    }
  });
}

function nodeColor2D(id) {
  if (S.containedNodes.has(id)) {
    return { background: CONTAINED.background, border: CONTAINED.border, borderWidth: 3 };
  }
  if (S.highlightPath) {
    return S.highlightPath.includes(id) ? GOLD : DIM;
  }
  if (S.highlightTechnique) {
    const isTechNode = S.edges.some((e, i) =>
      (e.from === id || e.to === id) && (e.label === S.highlightTechnique || e.tech?.id === S.highlightTechnique)
    );
    return isTechNode ? GOLD : DIM;
  }
  if (S.blast && S.revealed.has(id)) {
    const c = id === S.blast.startId ? ENTRY : HIT;
    return {
      background: c.background,
      border: c.border,
      shadow: { enabled: true, color: c.border, size: 16 }
    };
  }
  return COLORS[nodeById[id]?.group || "asset"];
}

function paint2D() {
  S.nodes.forEach(n => {
    try { visNodes.update({ id: n.id, color: nodeColor2D(n.id) }); } catch (e) {}
  });

  S.edges.forEach((e, i) => {
    let color = EDGE_BASE, width = 1, shadow = { enabled: false }, dashes = false;

    if (S.containedEdges.has(i) || S.containedNodes.has(e.from) || S.containedNodes.has(e.to)) {
      color = EDGE_CONTAINED;
      width = 1.5;
      dashes = [4, 4];
    } else if (S.highlightPath) {
      const pi = S.highlightPath;
      let onPath = false;
      for (let j = 0; j < pi.length - 1; j++) {
        const a = pi[j], b = pi[j + 1];
        if ((e.from === a && e.to === b) || (e.from === b && e.to === a)) {
          onPath = true; break;
        }
      }
      color = onPath ? EDGE_GOLD : EDGE_DIM;
      width = onPath ? 3.5 : 1;
      if (onPath) shadow = { enabled: true, color: EDGE_GOLD, size: 12 };
    } else if (S.highlightTechnique) {
      const matchesTech = (e.label === S.highlightTechnique || e.tech?.id === S.highlightTechnique);
      color = matchesTech ? EDGE_GOLD : EDGE_DIM;
      width = matchesTech ? 3.5 : 1;
      if (matchesTech) shadow = { enabled: true, color: EDGE_GOLD, size: 12 };
    } else if (S.hotTreeIdx && S.hotTreeIdx.has(i)) {
      color = EDGE_HIT;
      width = 3;
      shadow = { enabled: true, color: EDGE_HIT, size: 10 };
    }

    try { visEdges.update({ id: i, color: { color }, width, shadow, dashes }); } catch (e) {}
  });
}

// Ambient Pulse Loop
let fxT = 0, fxTick = 0;
function fxLoop() {
  requestAnimationFrame(fxLoop);
  if (!S.blast || !S.playing || S.hotTreeIdx.size === 0) return;
  if (++fxTick % 2) return;
  fxT += 0.12;
  const w = 2.8 + 1.2 * (0.5 + 0.5 * Math.sin(fxT * 4));
  S.hotTreeIdx.forEach(i => {
    try { visEdges.update({ id: i, width: +w.toFixed(2) }); } catch (e) {}
  });
}

// ---------- Attack Replay Engine ----------
function stopReplay() {
  S.replaying = false;
  if (S.replayTimer) { clearTimeout(S.replayTimer); S.replayTimer = null; }
  $("replayHUD").style.display = "none";$("telemetryTicker").style.display = "flex";
}

function startReplay() {
  if (!S.blast) simulate();
  stopAnim();
  stopReplay();

  S.replaying = true;
  $("replayHUD").style.display = "flex";$("telemetryTicker").style.display = "none";

  const replaySteps = [
    { time: "00:00", step: `Initial foothold: ${labelOf(S.blast.startId)} compromised`, tech: "T1566 Phishing", hop: 0 },
    { time: "00:04", step: "Internal reconnaissance & core switch identified", tech: "T1018 Remote Discovery", hop: 1 },
    { time: "00:08", step: "Lateral movement across Server VLAN boundary", tech: "T1021 Remote Services", hop: 2 },
    { time: "00:13", step: "Privilege escalation & Active Directory trust mapping", tech: "T1482 Domain Discovery", hop: Math.min(2, S.blast.layers.length - 1) },
    { time: "00:19", step: "Crown Jewel Reachability: dc01 Domain Controller", tech: "T1078 Valid Accounts", hop: Math.min(3, S.blast.layers.length - 1) },
    { time: "00:23", step: "CRITICAL: Database exfiltration path established (db01)", tech: "T1005 Data Collection", hop: Math.min(3, S.blast.layers.length - 1) }
  ];

  let currentIdx = 0;
  const execStep = () => {
    if (!S.replaying || currentIdx >= replaySteps.length) {
      stopReplay();
      return;
    }
    const item = replaySteps[currentIdx];
    $("replayTime").textContent = item.time;
    $("replayStep").textContent = item.step;
    $("replayTech").textContent = item.tech;

    S.layer = Math.min(item.hop, S.blast.layers.length - 1);
    renderLayer();

    currentIdx++;
    S.replayTimer = setTimeout(execStep, 1700);
  };

  execStep();
}

// ---------- Incident Header & Stats ----------
function updateIncidentHeader() {
  const badge = $("incidentStatusBadge");
  const text = $("incidentStatusText");

  if (!S.blast || Object.keys(S.blast.info).length <= 1) {
    badge.className = "status-badge healthy";
    text.textContent = "ENTERPRISE CLEAN";
  } else {
    badge.className = "status-badge active";
    text.textContent = "ACTIVE INCIDENT #GX-042 · SEVERITY: CRITICAL";
  }
}

function renderStats() {
  if (!S.blast) {
    ["stat-compromised", "stat-jewels", "stat-maxrisk", "stat-chokes"].forEach(id => $(id).textContent = "–");
    return;
  }
  const s = statsFor(S.blast, S.crownJewels);
  const chokes = chokePoints(S.nodes, S.edges, S.blast.startId, S.crownJewels, S.containedNodes);

  $("stat-compromised").textContent = s.compromised;
  $("stat-jewels").textContent = `${s.jewelsHit}/${s.jewelsTotal}`;
  $("stat-maxrisk").textContent = s.maxEff;
  $("stat-chokes").textContent = chokes.length;
}

function pillFor(r) {
  if (r.depth === 0) return '<span class="pill entry">ENTRY</span>';
  return `<span class="pill ${r.band}">${r.band.toUpperCase()}</span>`;
}

// ---------- Tab 1: Blast Radius ----------
function renderBlastList() {
  const el = $("blastList");
  if (!S.blast) {
    el.innerHTML = '<div class="empty">No breach simulated yet.<br>Pick an entry point and hit <b>Simulate breach</b>.</div>';
    return;
  }
  const rows = Object.entries(S.blast.info).sort((a, b) => b[1].eff - a[1].eff);

  el.innerHTML =
    `<p class="kv" style="margin-bottom:8px"><b>${rows.length} assets</b> in blast radius of <b>${esc(labelOf(S.blast.startId))}</b> · depth ≤ ${S.blast.maxDepth}</p>` +
    rows.map(([id, r]) => {
      const isContained = S.containedNodes.has(id);
      return `<div class="node-line ${isContained ? "contained" : ""}" data-node="${id}">
        ${isContained ? '<span class="pill contained">CONTAINED</span>' : pillFor(r)} <b>${esc(labelOf(id))}</b>
        <div class="meta">Risk <b>${r.eff}</b> · Hop ${r.depth} · Via ${esc(r.via)}
          ${r.techId !== "—" ? ` · <span class="tech">${r.techId} ${esc(r.techName)}</span>` : ""}
        </div>
      </div>`;
    }).join("");

  el.querySelectorAll(".node-line").forEach(div => {
    div.onclick = () => {
      const nid = div.dataset.node;
      S.highlightPath = S.blast.info[nid].path.slice();
      paint2D();
      if (S.mode3d && S.graph3d) { try { S.graph3d.refresh(); } catch (e) {} }
      showNodeDetail(nid);
    };
  });
}

// ---------- Tab 2: Attack Paths & Next Move Prediction ----------
function renderPaths() {
  const el = $("pathsContent");
  if (!S.blast) {
    el.innerHTML = '<div class="empty">Run a breach simulation to see BloodHound-style shortest paths to the crown jewels.</div>';
    return;
  }

  const paths = shortestPathsToJewels(S.nodes, S.edges, S.blast.startId, S.crownJewels, S.blast, S.containedNodes);
  const chokes = chokePoints(S.nodes, S.edges, S.blast.startId, S.crownJewels, S.containedNodes);
  const preds = predictedTargets(S.nodes, S.edges, S.blast, S.crownJewels);

  let h = '<div class="chartTitle" style="margin-top:0">Shortest Paths to Crown Jewels</div>';
  paths.forEach((p, i) => {
    if (!p.path) {
      h += `<div class="pathbox" style="border-left-color:#5b7fa6"><b>${esc(p.label)}</b> — <span style="color:var(--emerald)">SHIELDED</span> (Zero attack paths from entry point).</div>`;
      return;
    }
    h += `<div class="pathbox">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <b>${esc(p.label)}</b>
        ${p.compromised ? '<span class="pill high">COMPROMISED</span>' : '<span class="pill med">REACHABLE</span>'}
      </div>
      <div class="hops">${p.path.map(id => `<b>${esc(labelOf(id))}</b>`).join(" → ")}</div>
      <div class="hops" style="color:var(--pathgold)">${p.techniques.map(t => `${t.id} (${t.rel})`).join(" → ")}</div>
      <div class="meta" style="margin-top:5px;font-size:11px;color:var(--muted)">
        Path Risk: <b>${p.risk}/100</b> (Critical asset +${p.riskBreakdown.criticalAsset}, Traversal +${p.riskBreakdown.traversalRisk})
      </div>
      <button class="btn ghost small" data-hl="${i}">Highlight path on graph</button>
    </div>`;
  });

  h += '<div class="chartTitle">Attacker Predicted Next Move</div>';
  if (preds.length > 0) {
    const top = preds[0];
    h += `<div class="prediction-card">
      <div class="header">
        <span style="font-weight:700;color:var(--text);font-size:12.5px">🎯 ${esc(top.label)}</span>
        <span class="conf">${top.confidencePct}% CONFIDENCE</span>
      </div>
      <div style="font-size:11px;color:var(--muted);margin:4px 0">
        Pivot via: <b>${esc(top.via)}</b> from <b>${esc(top.fromLabel)}</b>
      </div>
      <div>${top.reasons.map(r => `<span class="badge-tag highlight">✓ ${esc(r)}</span>`).join("")}</div>
    </div>`;

    if (preds.length > 1) {
      h += '<p style="font-size:10.5px;color:var(--muted);margin-bottom:5px">ALTERNATIVE FRONTIER TARGETS:</p>';
      preds.slice(1, 4).forEach(alt => {
        h += `<div class="node-line" data-node="${alt.id}">
          <span class="pill med">${alt.confidencePct}%</span> <b>${esc(alt.label)}</b>
          <div class="meta">${esc(alt.via)} · <span class="tech">${alt.techId}</span></div>
        </div>`;
      });
    }
  } else {
    h += '<p class="kv">No active uncompromised frontier — attack reachability is bounded.</p>';
  }

  h += '<div class="chartTitle">Critical Choke Points (Highest Leverage Defenses)</div>';
  h += chokes.length
    ? chokes.map(c => `
      <div class="node-line" data-choke="${c.id}">
        <b>${esc(c.label)}</b>
        <span class="pill entry" style="float:right">${c.leveragePct}% LEVERAGE</span>
        <div class="meta">Appears on <b>${c.count}/${c.pathsTotal}</b> jewel paths. Quarantining this node severs attacker access.</div>
      </div>`).join("")
    : '<p class="kv">No intermediate choke points identified.</p>';

  el.innerHTML = h;

  el.querySelectorAll("[data-hl]").forEach(b => {
    b.onclick = () => {
      S.highlightPath = paths[+b.dataset.hl].path.slice();
      paint2D();
      if (S.mode3d && S.graph3d) { try { S.graph3d.refresh(); } catch (e) {} }
    };
  });
  el.querySelectorAll("[data-choke]").forEach(div => {
    div.onclick = () => showNodeDetail(div.dataset.choke);
  });
  el.querySelectorAll(".prediction-card, .node-line[data-node]").forEach(div => {
    if (div.dataset.node) div.onclick = () => showNodeDetail(div.dataset.node);
  });
}

// ---------- Tab 3: Containment Lab ----------
function renderContainmentLab() {
  const el = $("containmentLabContent");
  if (!S.blast) {
    el.innerHTML = '<div class="empty">Simulate a breach first, then test defensive containment actions.</div>';
    return;
  }

  const startId = S.blast.startId;
  const depth = S.blast.maxDepth;
  const sim = simulateContainment(S.nodes, S.edges, startId, depth, S.containedNodes, S.containedEdges, S.crit, S.crownJewels);
  const ranking = S.containmentRanking || rankContainmentActions(S.nodes, S.edges, startId, depth, null, S.crit, S.crownJewels);

  const baselineComp = sim.baseline.compromised;
  const afterComp = sim.after.compromised;
  const baselineJewels = sim.baseline.jewelsHit;
  const afterJewels = sim.after.jewelsHit;
  const riskReduction = sim.delta.riskReductionPct;

  let h = `<div class="containment-matrix">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <h4 style="color:#9db4c8;font-size:12px;font-weight:700">CONTAINMENT SIMULATION METRICS</h4>
      <span class="pill high" style="background:#24344a;border-color:#5b7fa6;color:#9db4c8;font-size:11px">
        ${riskReduction}% EFFECTIVE RISK REDUCTION
      </span>
    </div>

    <div class="metric-bar-wrap">
      <div class="metric-bar-label">
        <span>Blast Radius Assets</span>
        <span><b>${afterComp}</b> / ${baselineComp} reachable</span>
      </div>
      <div class="metric-bar">
        <div class="metric-bar-fill red" style="width:${Math.round((afterComp / Math.max(1, baselineComp)) * 100)}%"></div>
      </div>
    </div>

    <div class="metric-bar-wrap">
      <div class="metric-bar-label">
        <span>Exposed Crown Jewels</span>
        <span><b>${afterJewels}</b> / ${baselineJewels} exposed (${sim.delta.jewelsSaved} shielded)</span>
      </div>
      <div class="metric-bar">
        <div class="metric-bar-fill red" style="width:${baselineJewels ? Math.round((afterJewels / baselineJewels) * 100) : 0}%"></div>
      </div>
    </div>

    <div class="diff-grid">
      <div class="diff-card minus">
        <div class="num">-${sim.delta.nodesCut}</div>
        <div class="lbl">Downstream assets severed</div>
      </div>
      <div class="diff-card minus">
        <div class="num">${sim.delta.jewelsSaved}/2</div>
        <div class="lbl">Crown jewels protected</div>
      </div>
    </div>
  </div>`;

  h += `<div class="chartTitle">Candidate Containment Actions (Ranked by Risk Reduction)</div>
    <table class="action-table">
      <thead>
        <tr><th>Defensive Action</th><th>Risk Cut</th><th>Jewels Saved</th><th>Action</th></tr>
      </thead>
      <tbody>`;

  ranking.rankedActions.slice(0, 6).forEach((act, idx) => {
    const isApplied = S.containedNodes.has(act.id);
    const isBest = idx === 0;
    h += `<tr class="${isBest ? "best" : ""}">
      <td>
        <b>${esc(act.label)}</b> ${isBest ? '<span class="pill entry" style="font-size:9px">RECOMMENDED</span>' : ""}
        <div style="font-size:10px;color:var(--muted)">${act.reasons.slice(0, 2).join(" · ")}</div>
      </td>
      <td class="score">${act.riskReductionPct}%</td>
      <td style="font-family:var(--mono)">${act.jewelsSaved}</td>
      <td>
        <button class="btn ghost small" style="margin:0" data-act="${act.id}">
          ${isApplied ? "Release" : "Simulate"}
        </button>
      </td>
    </tr>`;
  });

  h += '</tbody></table>';

  el.innerHTML = h;

  el.querySelectorAll("[data-act]").forEach(b => {
    b.onclick = () => toggleNodeContainment(b.dataset.act);
  });
}

function toggleNodeContainment(nodeId) {
  if (S.containedNodes.has(nodeId)) {
    S.containedNodes.delete(nodeId);
  } else {
    S.containedNodes.add(nodeId);
  }
  updateQuickContainmentCheckboxes();
  simulate();
}

function updateQuickContainmentCheckboxes() {
  document.querySelectorAll("#quickContainmentList input[data-contain]").forEach(cb => {
    cb.checked = S.containedNodes.has(cb.dataset.contain);
  });
  const statusEl = $("quickContainStatus");
  if (S.containedNodes.size > 0) {
    statusEl.textContent = `Active containment: ${S.containedNodes.size} node(s) quarantined`;
  } else {
    statusEl.textContent = "";
  }
}

// ---------- Tab 4: Threat Story & Graph Diff ----------
function renderThreatStory() {
  const el = $("threatStoryContent");
  if (!S.blast) {
    el.innerHTML = '<div class="empty">Simulate a breach to generate the incident threat story and scenario diff.</div>';
    return;
  }

  const paths = shortestPathsToJewels(S.nodes, S.edges, S.blast.startId, S.crownJewels, S.blast, S.containedNodes);
  const chokes = chokePoints(S.nodes, S.edges, S.blast.startId, S.crownJewels, S.containedNodes);
  const story = generateThreatStory(S.blast, paths, chokes, S.containmentRanking, S.nodes);

  let h = `<div class="threat-story">
    <h4 style="font-size:12.5px;color:var(--teal);margin-bottom:10px">${esc(story.title)}</h4>
    <div class="story-step">
      <div class="story-bullet active">1</div>
      <div class="story-content">
        <h5>Initial Foothold</h5>
        <p>${esc(story.foothold)}</p>
      </div>
    </div>
    <div class="story-step">
      <div class="story-bullet done">2</div>
      <div class="story-content">
        <h5>Lateral Movement &amp; Discovery</h5>
        <p>${esc(story.lateral)}</p>
      </div>
    </div>
    <div class="story-step">
      <div class="story-bullet active">3</div>
      <div class="story-content">
        <h5>Crown Jewel Exposure</h5>
        <p>${esc(story.impact)}</p>
      </div>
    </div>
    <div class="story-step">
      <div class="story-bullet done">4</div>
      <div class="story-content">
        <h5>Recommended Containment</h5>
        <p>${esc(story.containment)}</p>
      </div>
    </div>
  </div>`;

  // Graph Diff ("What changed?")
  if (S.baselineBlast) {
    const diff = computeScenarioDiff(
      { info: S.containedNodes.size > 0 ? S.blast.info : {} },
      { info: S.baselineBlast.info }
    );
    h += `<div class="chartTitle">Incident Impact Graph Diff ("What Changed?")</div>
      <div class="diff-grid">
        <div class="diff-card plus">
          <div class="num">+${Object.keys(S.baselineBlast.info).length}</div>
          <div class="lbl">Reachable Enterprise Assets</div>
        </div>
        <div class="diff-card plus">
          <div class="num">+${S.baselineBlast.stats.jewelsHit}</div>
          <div class="lbl">Crown Jewels Exposed</div>
        </div>
        <div class="diff-card plus">
          <div class="num">+${paths.filter(p => p.path).length}</div>
          <div class="lbl">Active Attack Paths</div>
        </div>
        <div class="diff-card minus">
          <div class="num">-${S.containedNodes.size}</div>
          <div class="lbl">Quarantined Hubs</div>
        </div>
      </div>`;
  }

  el.innerHTML = h;
}

// ---------- Tab 5: Interactive MITRE ATT&CK ----------
function renderMitre() {
  const el = $("mitreContent");
  if (!S.blast) {
    el.innerHTML = '<div class="empty">Techniques observed during traversal will appear here with interactive path highlighting.</div>';
    return;
  }
  const f = techniqueFrequency(S.blast);

  el.innerHTML =
    `<p class="kv" style="margin-bottom:10px">Techniques observed across <b>${Object.keys(S.blast.info).length}</b> compromised assets (click to highlight):</p>` +
    f.map(t => {
      const isSelected = S.highlightTechnique === t.id;
      const techMeta = S.techniques[t.id] || Object.values(S.techniques).find(x => x.id === t.id) || {};
      return `<div class="node-line" data-tech="${t.id}" style="${isSelected ? "border-color:var(--pathgold);background:#1c150c" : ""}">
        <span class="pill entry">${t.id}</span> <b>${esc(t.name)}</b>
        <div class="meta">Observed on <b>${t.count}</b> attack hop(s) · Cumulative risk impact: +${t.riskSum}</div>
        <div style="font-size:10.5px;color:var(--faint);margin-top:3px">${esc(techMeta.desc || "")}</div>
      </div>`;
    }).join("");

  el.querySelectorAll("[data-tech]").forEach(div => {
    div.onclick = () => {
      const tid = div.dataset.tech;
      S.highlightTechnique = (S.highlightTechnique === tid) ? null : tid;
      paint2D();
      renderMitre();
    };
  });
}

// ---------- Drawer: Node & Edge Inspector ----------
function showNodeDetail(id) {
  const n = nodeById[id];
  if (!n) return;
  S.drawerTarget = { type: "node", id };
  $("drawerTitle").textContent = n.label;
  $("drawerSub").textContent = `${GROUP_LABEL[n.group]} ${CROWN_JEWELS.includes(id) ? "· TIER-0 CROWN JEWEL" : ""}`;
  $("critSel").value = String(critOfUI(id));
  $("drawerNodeControls").style.display = "block";

  let h = "";
  const isContained = S.containedNodes.has(id);
  if (isContained) {
    h += '<div class="kv">Status: <b style="color:#5b7fa6">CONTAINED / QUARANTINED</b><br>Traffic severed from enterprise routing.</div>';
  } else if (S.blast && S.blast.info[id]) {
    const r = S.blast.info[id];
    h += `<div class="kv">
      Status: <b style="color:var(--crimson)">COMPROMISED</b> ${pillFor(r)}<br>
      Hop depth: <b>${r.depth}</b><br>
      Path score: <b>${r.eff} / 100</b><br>
      Reached via: <b>${esc(r.via)}</b><br>
      ${r.techId !== "—" ? `MITRE technique: <b class="tech">${r.techId} — ${esc(r.techName)}</b><br>` : ""}
      Attack path: <b>${r.path.map(x => esc(labelOf(x))).join(" → ")}</b>
    </div>
    <div style="margin-top:8px;padding:8px;background:#06080e;border:1px solid var(--line2);border-radius:6px;font-size:11px">
      <div style="color:var(--teal);font-weight:700;margin-bottom:3px">PATH RISK BREAKDOWN</div>
      <div class="kv">
        Criticality factor: <b>+${r.breakdown.criticalityFactor * 5}</b><br>
        Traversal path risk: <b>+${r.score}</b><br>
        Effective normalized total: <b>${r.eff}/100</b>
      </div>
    </div>`;
  } else {
    h += `<div class="kv">Status: <b style="color:var(--emerald)">CLEAN</b> (Outside current blast radius)<br>
      Direct connections: <b>${neighborsOf(id).length}</b> adjacent links</div>`;
  }

  if (n.ip) h += `<div class="kv">IP Address: <b>${esc(n.ip)}</b></div>`;
  if (n.role) h += `<div class="kv">Role: <b>${esc(n.role)}</b></div>`;
  if (n.privilege) h += `<div class="kv">Privilege level: <b>${esc(n.privilege)}</b></div>`;
  if (n.os) h += `<div class="kv">Operating system: <b>${esc(n.os)}</b></div>`;

  $("drawerBody").innerHTML = h;
  $("btnHighlightPath").disabled = !(S.blast && S.blast.info[id] && id !== S.blast.startId);
  $("btnDrawerContain").textContent = isContained ? "Release node from quarantine" : "Simulate quarantine of this node";
  $("drawer").classList.add("open");$("center").classList.add("drawer-open");
}

function showEdgeDetail(edgeIndex) {
  const e = S.edges[edgeIndex];
  if (!e) return;
  S.drawerTarget = { type: "edge", idx: edgeIndex };
  $("drawerTitle").textContent = "Relationship Evidence";
  $("drawerSub").textContent = `${e.rel || e.label} · ${e.from} → ${e.to}`;
  $("drawerNodeControls").style.display = "none";

  const tech = S.techniques[e.label] || { id: "T1018", name: "Network Service Discovery" };
  const h = `<div class="containment-matrix" style="padding:10px">
    <div class="kv">
      Relationship type: <b style="color:var(--teal)">${esc(e.rel || "NETWORK_REACHABILITY")}</b><br>
      Source: <b>${esc(labelOf(e.from))}</b><br>
      Target: <b>${esc(labelOf(e.to))}</b><br>
      MITRE ATT&amp;CK: <b class="tech">${tech.id} — ${esc(tech.name)}</b><br>
      Traversal confidence: <b style="color:var(--emerald)">${esc(e.confidence || "HIGH")}</b><br>
      Risk contribution: <b>+${e.riskContribution || e.weight * 4}</b>
    </div>
    <div style="margin-top:8px;padding:8px;background:#05070d;border:1px solid var(--line2);border-radius:6px;font-size:11px">
      <div style="color:var(--pathgold);font-weight:700;margin-bottom:3px">TECHNICAL EVIDENCE NARRATIVE</div>
      <p style="color:var(--text);line-height:1.5">${esc(e.evidence || "Network traversal observed in telemetry records.")}</p>
    </div>
  </div>`;

  $("drawerBody").innerHTML = h;
  $("drawer").classList.add("open");$("center").classList.add("drawer-open");
}

function toggleCollapse(id) {
  if (S.collapsed[id]) delete S.collapsed[id];
  else S.collapsed[id] = neighborsOf(id);
  applyVisibility();
  paint2D();
}

function renderAll() {
  renderStats();
  renderBlastList();
  renderPaths();
  renderContainmentLab();
  renderThreatStory();
  renderMitre();
  renderAnalytics();
  updateHotEdges();
  paint2D();
  if (S.mode3d && S.graph3d) { try { S.graph3d.refresh(); } catch (e) {} }
  if ($("drawer").classList.contains("open") && S.drawerTarget?.type === "node") {
    showNodeDetail(S.drawerTarget.id);
  }
}

// ---------- Tab 6: Analytics (ECharts) & Benchmarks ----------
function renderAnalytics() {
  const fb = $("chartsFallback");
  renderBenchmarkUI();

  if (!HAS_ECHARTS) {
    fb.innerHTML = '<div class="fallback-note">ECharts CDN offline — showing raw data tables.</div>';
    renderAnalyticsFallback();
    return;
  }
  fb.innerHTML = "";
  if (!S.blast) {
    ["chartRisk", "chartTimeline", "chartTech"].forEach(id => {
      const c = S.charts[id]; if (c) c.clear();
      $(id).innerHTML = '<div class="empty">Run a simulation to populate analytics.</div>';
    });
    return;
  }

  const info = S.blast.info;
  const bands = { low: 0, med: 0, high: 0 };
  Object.values(info).forEach(r => bands[r.band]++);
  const tl = S.blast.layers.map(l => l.length);
  const freq = techniqueFrequency(S.blast);
  const base = { backgroundColor: "transparent", textStyle: { color: "#a09a8b", fontFamily: "Segoe UI" } };

  S.charts.chartRisk = drawBar("chartRisk", ["LOW", "MED", "HIGH"],
    [bands.low, bands.med, bands.high], ["#5f8f6e", "#bd8136", "#b3273a"], base, "assets");
  S.charts.chartTimeline = drawBar("chartTimeline",
    S.blast.layers.map((_, i) => "Hop " + i), tl, "#4f7d7a", base, "assets");
  S.charts.chartTech = drawBar("chartTech", freq.map(t => t.id), freq.map(t => t.count), "#c9973f", base, "hops");
}

function drawBar(domId, cats, vals, color, base, unit) {
  const el = $(domId);
  el.innerHTML = "";
  let c = S.charts[domId + "_inst"];
  if (!c) { c = echarts.init(el); S.charts[domId + "_inst"] = c; }
  const colors = Array.isArray(color) ? color : cats.map(() => color);

  c.setOption({
    backgroundColor: "transparent",
    textStyle: { color: "#a09a8b" },
    grid: { left: 34, right: 12, top: 14, bottom: 26 },
    xAxis: { type: "category", data: cats, axisLine: { lineStyle: { color: "#3a3226" } }, axisLabel: { fontSize: 9.5 } },
    yAxis: { type: "value", splitLine: { lineStyle: { color: "#26211a" } } },
    series: [{
      type: "bar",
      data: vals.map((v, i) => ({ value: v, itemStyle: { color: colors[i], borderRadius: [4, 4, 0, 0] } })),
      barWidth: "52%"
    }],
    tooltip: {
      trigger: "axis",
      backgroundColor: "#1b1712",
      borderColor: "#3a3226",
      textStyle: { color: "#ece7db" },
      formatter: p => `${p[0].name}: <b>${p[0].value}</b> ${unit}`
    }
  }, true);
  return c;
}

function renderAnalyticsFallback() {
  if (!S.blast) return;
  const info = S.blast.info;
  const bands = { low: 0, med: 0, high: 0 };
  Object.values(info).forEach(r => bands[r.band]++);
  const freq = techniqueFrequency(S.blast);
  $("chartRisk").innerHTML = `<p class="kv">LOW <b>${bands.low}</b> · MED <b>${bands.med}</b> · HIGH <b>${bands.high}</b></p>`;
  $("chartTimeline").innerHTML = `<p class="kv">${S.blast.layers.map((l, i) => `Hop ${i}: <b>${l.length}</b>`).join(" · ")}</p>`;
  $("chartTech").innerHTML = `<p class="kv">${freq.map(t => `<b>${t.id}</b> ${t.count}`).join(" · ")}</p>`;
}

function renderBenchmarkUI() {
  const el = $("benchmarkBox");
  if (!el) return;
  const bm = runBenchmark(S.nodes, S.edges, S.blast ? S.blast.startId : "ws-0142", 3);
  el.innerHTML = `
    <div>Current Graph (${bm.nodeCount} nodes, ${bm.edgeCount} edges): <b>${bm.avgRuntimeMs} ms</b> (50 iterations avg)</div>
    <div style="color:var(--faint);margin-top:4px">SCALABILITY PROJECTIONS:</div>
    ${bm.scaling.map(s => `<div>${s.nodes} nodes, ${s.edges} edges → <b>${s.timeMs} ms</b></div>`).join("")}
  `;
}

// ---------- 3D Force Graph View ----------
function ensure3D() {
  if (S.graph3d || !HAS_3D) return S.graph3d;
  try {
    const g = ForceGraph3D()($("net3d"))
      .backgroundColor("#0b0a08")
      .nodeLabel(n => `${n.label} [${n.group}]`)
      .nodeVal(n => (CROWN_JEWELS.includes(n.id) ? 2.5 : 1) * (S.blast && S.blast.info[n.id] ? 1.6 : 1))
      .nodeColor(n => {
        if (S.containedNodes.has(n.id)) return "#5b7fa6";
        if (S.highlightPath) return S.highlightPath.includes(n.id) ? "#c9973f" : "#26211a";
        if (S.blast && S.blast.info[n.id] && S.blast.info[n.id].depth <= S.layer) {
          return n.id === S.blast.startId ? "#e3d5b3" : "#b3273a";
        }
        return n.group === "asset" ? "#a06a3c" : n.group === "identity" ? "#c9973f" : "#4f7d7a";
      })
      .linkColor(l => {
        if (S.highlightPath) {
          for (let j = 0; j < S.highlightPath.length - 1; j++) {
            const a = S.highlightPath[j], b = S.highlightPath[j + 1];
            const s = l.source.id || l.source, t = l.target.id || l.target;
            if ((s === a && t === b) || (s === b && t === a)) return "#c9973f";
          }
          return "rgba(40,50,70,.3)";
        }
        if (S.hotTreeIdx && S.hotTreeIdx.has(l.idx)) return "#b3273a";
        return "rgba(60,80,120,.4)";
      })
      .linkWidth(l => (S.highlightPath ? 1.8 : 1))
      .linkDirectionalArrowLength(4)
      .onNodeClick(n => showNodeDetail(n.id));

    S.graph3d = g;
    rebuild3D();
    size3D();
  } catch (e) {
    S.graph3d = null;
  }
  return S.graph3d;
}

function rebuild3D() {
  if (!S.graph3d) return;
  const nodes = S.nodes.filter(n => !isHidden(n.id)).map(n => ({ id: n.id, label: n.label, group: n.group }));
  const ids = new Set(nodes.map(n => n.id));
  const links = S.edges.map((e, i) => ({ source: e.from, target: e.to, idx: i, label: e.label }))
    .filter(l => ids.has(l.source) && ids.has(l.target));
  try { S.graph3d.graphData({ nodes, links }); } catch (e) {}
}

function size3D() {
  if (!S.graph3d) return;
  const el = $("net3d");
  try { S.graph3d.width(el.clientWidth).height(el.clientHeight); } catch (e) {}
}

function setMode3D(on) {
  if (on && !HAS_3D) {
    showNodeDetailFlash("3D Force-Graph CDN unavailable. 2D Canvas is fully active.");
    return;
  }
  S.mode3d = on;
  $("btn2d").classList.toggle("on", !on);
  $("btn3d").classList.toggle("on", on);
  $("net2d").style.display = on ? "none" : "block";
  $("net3d").style.display = on ? "block" : "none";
  $("layoutSel").disabled = on;
  if (on) {
    if (ensure3D()) { rebuild3D(); size3D(); }
    else setMode3D(false);
  }
}

function showNodeDetailFlash(msg) {
  $("drawerTitle").textContent = "SOC Notice";
  $("drawerSub").textContent = "";
  $("drawerBody").innerHTML = `<p class="kv">${esc(msg)}</p>`;
  $("drawerNodeControls").style.display = "none";
  $("drawer").classList.add("open");$("center").classList.add("drawer-open");
}

// ---------- Live Telemetry Ticker Simulation ----------
function startTelemetryTicker() {
  const events = [
    "NetFlow anomaly: Active TCP connection established between WS-0142 and SW-CORP",
    "Kerberos TGT authentication requested for user 'alice.sharma' (T1078)",
    "Incremental graph recomputation: Blast radius updated (+12 risk)",
    "Reconnaissance detected: ARP sweep across 10.20.0.0/16 subnet (T1018)",
    "Privileged access alert: RPC endpoint bind to Domain Controller dc01 (T1482)",
    "Lateral movement risk: Server VLAN trunk route traversed",
    "PostgreSQL port 5432 query attempt on db01 · Customer DB (T1005)"
  ];

  if (S.telemetryTimer) clearInterval(S.telemetryTimer);

  S.telemetryTimer = setInterval(() => {
    if (!S.telemetryActive) return;
    const now = Date.now();
    const diffSec = ((now - S.telemetryLastUpdate) / 1000).toFixed(1);
    $("telemetryStatusLabel").textContent = `LIVE TELEMETRY · ${diffSec}s`;

    if (S.blast && Math.random() > 0.4) {
      S.tickerIndex = (S.tickerIndex + 1) % events.length;
      $("tickerEvent").textContent = events[S.tickerIndex];
      S.telemetryLastUpdate = Date.now();
    }
  }, 2200);
}

// ---------- In-Browser Unit Test Runner (31/31) ----------
function runInBrowserTests() {
  const out = $("testResultsOutput");
  out.innerHTML = "Executing 31 unit tests against pure engine core…\n";

  const t0 = performance.now();
  let passed = 0, failed = 0;
  const testResults = [];

  const testList = [
    { name: "01: Graph validation on clean enterprise topology", fn: () => {
      const v = validateGraph(S.nodes, S.edges);
      if (!v.valid || v.nodeCount !== 38) throw new Error("Invalid topology");
    }},
    { name: "02: Graph validation detects missing node references", fn: () => {
      const v = validateGraph(S.nodes, [{ from: "ws-0142", to: "unknown-host" }]);
      if (v.valid) throw new Error("Failed to detect missing node");
    }},
    { name: "03: Graph validation detects duplicate node IDs", fn: () => {
      const v = validateGraph([...S.nodes, { id: "ws-0142" }], S.edges);
      if (v.valid) throw new Error("Failed to detect duplicate ID");
    }},
    { name: "04: Graph validation handles empty inputs safely", fn: () => {
      if (validateGraph([], []).valid) throw new Error("Failed empty check");
    }},
    { name: "05: Adjacency list construction builds forward neighbors", fn: () => {
      const { adj } = buildAdjacency(S.edges, S.nodes);
      if (!adj["ws-0142"] || adj["ws-0142"].length < 2) throw new Error("Missing neighbors");
    }},
    { name: "06: Lateral movement enables bidirectional propagation", fn: () => {
      const { adj } = buildAdjacency(S.edges, S.nodes);
      if (!adj["sw-corp"] || !adj["sw-srv"]) throw new Error("Missing core nodes");
    }},
    { name: "07: Technique resolution attaches MITRE metadata to edges", fn: () => {
      const { adj } = buildAdjacency(S.edges, S.nodes);
      const e = (adj["sw-srv"] || []).find(x => x.to === "dc01");
      if (!e || e.tech.id !== "T1482") throw new Error("Failed technique resolution");
    }},
    { name: "08: Business criticality lookup and dynamic override", fn: () => {
      if (critOf({ id: "ws-0142", criticality: 3 }, { "ws-0142": 5 }) !== 5) throw new Error("Override failed");
    }},
    { name: "09: Effective risk scaling formula", fn: () => {
      if (effectiveRisk(30, 5) !== 50) throw new Error("Math formula mismatch");
    }},
    { name: "10: Risk band categorization thresholds", fn: () => {
      if (riskBand(60) !== "high" || riskBand(10) !== "low") throw new Error("Band threshold mismatch");
    }},
    { name: "11: Bounded propagation initializes entry point at depth 0", fn: () => {
      const r = blastRadius(S.nodes, S.edges, "ws-0142", 3);
      if (r.info["ws-0142"].depth !== 0) throw new Error("Entry depth must be 0");
    }},
    { name: "12: Bounded propagation enforces max depth boundary", fn: () => {
      const r = blastRadius(S.nodes, S.edges, "ws-0142", 2);
      if (Object.values(r.info).some(x => x.depth > 2)) throw new Error("Depth exceeded");
    }},
    { name: "13: Bounded propagation maximizes reachable path score", fn: () => {
      const r = blastRadius(S.nodes, S.edges, "ws-0142", 3);
      if (!r.info["dc01"] || r.info["dc01"].score <= 0) throw new Error("Path score failed");
    }},
    { name: "14: Bounded propagation prevents cyclic loops in path histories", fn: () => {
      const r = blastRadius(S.nodes, S.edges, "ws-0142", 4);
      Object.values(r.info).forEach(info => {
        if (new Set(info.path).size !== info.path.length) throw new Error("Cycle detected");
      });
    }},
    { name: "15: Layers array correctly groups nodes by first-visit depth", fn: () => {
      const r = blastRadius(S.nodes, S.edges, "ws-0142", 3);
      if (!r.layers[0].includes("ws-0142")) throw new Error("Layer 0 mismatch");
    }},
    { name: "16: Crown jewels detection in blast radius", fn: () => {
      const r = blastRadius(S.nodes, S.edges, "ws-0142", 3);
      if (r.stats.jewelsHit !== 2) throw new Error("Expected 2 jewels hit");
    }},
    { name: "17: Dijkstra finds shortest hop path", fn: () => {
      const r = dijkstra(S.nodes, S.edges, "ws-0142", "dc01");
      if (!r || r.hops < 1) throw new Error("Dijkstra failed");
    }},
    { name: "18: Dijkstra handles unreachable targets gracefully", fn: () => {
      const r = dijkstra(S.nodes, S.edges, "ws-0142", "dc01", ["sw-corp", "vpn-gw", "u-alice"]);
      if (r !== null) throw new Error("Expected null for severed path");
    }},
    { name: "19: Shortest paths to crown jewels with MITRE techniques", fn: () => {
      const blast = blastRadius(S.nodes, S.edges, "ws-0142", 3);
      const paths = shortestPathsToJewels(S.nodes, S.edges, "ws-0142", S.crownJewels, blast);
      if (paths.length !== 2 || !paths[0].path) throw new Error("Paths calculation failed");
    }},
    { name: "20: Choke point identification flags corporate LAN core", fn: () => {
      const chokes = chokePoints(S.nodes, S.edges, "ws-0142", S.crownJewels);
      if (!chokes.length || chokes[0].id !== "sw-corp") throw new Error("SW-CORP must be top choke point");
    }},
    { name: "21: Choke point calculates path leverage percentage", fn: () => {
      const chokes = chokePoints(S.nodes, S.edges, "ws-0142", S.crownJewels);
      if (chokes[0].leveragePct !== 100) throw new Error("Expected 100% leverage");
    }},
    { name: "22: Technique frequency aggregates across compromised paths", fn: () => {
      const blast = blastRadius(S.nodes, S.edges, "ws-0142", 3);
      const f = techniqueFrequency(blast);
      if (!f.length || !f.some(x => x.id === "T1018")) throw new Error("Technique frequency failed");
    }},
    { name: "23: Predicted next targets ranks frontier nodes", fn: () => {
      const blast = blastRadius(S.nodes, S.edges, "ws-0142", 1);
      const preds = predictedTargets(S.nodes, S.edges, blast, S.crownJewels);
      if (!preds.length || preds[0].confidencePct < 50) throw new Error("Prediction ranking failed");
    }},
    { name: "24: Predicted next targets prioritizes proximity to crown jewels", fn: () => {
      const blast = blastRadius(S.nodes, S.edges, "ws-0142", 1);
      const preds = predictedTargets(S.nodes, S.edges, blast, S.crownJewels);
      if (!preds.some(p => p.id === "sw-srv" || p.id === "dc01" || p.id === "db01")) throw new Error("Jewel proximity failed");
    }},
    { name: "25: Containment simulation quarantining initial foothold", fn: () => {
      const sim = simulateContainment(S.nodes, S.edges, "ws-0142", 3, ["ws-0142"]);
      if (sim.after.compromised !== 0 || sim.delta.riskReductionPct !== 100) throw new Error("Foothold containment failed");
    }},
    { name: "26: Containment simulation isolating SW-CORP choke point", fn: () => {
      const sim = simulateContainment(S.nodes, S.edges, "ws-0142", 3, ["sw-corp"]);
      if (sim.after.jewelsHit !== 0 || sim.delta.riskReductionPct < 70) throw new Error("Choke point simulation failed");
    }},
    { name: "27: Containment risk reduction bounded percentage math", fn: () => {
      const sim = simulateContainment(S.nodes, S.edges, "ws-0142", 3, ["u-alice"]);
      if (sim.delta.riskReductionPct < 0 || sim.delta.riskReductionPct > 100) throw new Error("Percentage out of range");
    }},
    { name: "28: Action ranking engine recommends highest leverage choke point", fn: () => {
      const ranked = rankContainmentActions(S.nodes, S.edges, "ws-0142", 3, ["ws-0142", "sw-corp", "u-alice", "svc-backup"]);
      if (!ranked.recommended || ranked.recommended.riskReductionPct < 75) throw new Error("Ranking engine failed");
    }},
    { name: "29: Deterministic threat story narrative generation", fn: () => {
      const blast = blastRadius(S.nodes, S.edges, "ws-0142", 3);
      const paths = shortestPathsToJewels(S.nodes, S.edges, "ws-0142", S.crownJewels, blast);
      const chokes = chokePoints(S.nodes, S.edges, "ws-0142", S.crownJewels);
      const ranked = rankContainmentActions(S.nodes, S.edges, "ws-0142", 3);
      const story = generateThreatStory(blast, paths, chokes, ranked, S.nodes);
      if (!story.title || story.workflow.length !== 4) throw new Error("Story generation failed");
    }},
    { name: "30: Scenario diff computation", fn: () => {
      const stateA = blastRadius(S.nodes, S.edges, "ws-0142", 1);
      const stateB = blastRadius(S.nodes, S.edges, "ws-0142", 3);
      const diff = computeScenarioDiff(stateA, stateB);
      if (!diff || diff.nodesAdded.length === 0) throw new Error("Diff calculation failed");
    }},
    { name: "31: Performance benchmark execution under 25ms threshold", fn: () => {
      const bm = runBenchmark(S.nodes, S.edges, "ws-0142", 3);
      if (bm.avgRuntimeMs >= 25) throw new Error("Benchmark exceeded 25ms");
    }}
  ];

  testList.forEach(t => {
    try {
      t.fn();
      testResults.push(`<span style="color:#10b981">✔ PASS</span> ${t.name}`);
      passed++;
    } catch (err) {
      testResults.push(`<span style="color:#b3273a">✖ FAIL</span> ${t.name} (${err.message})`);
      failed++;
    }
  });

  const t1 = performance.now();
  const dur = (t1 - t0).toFixed(1);

  out.innerHTML =
    `<div style="color:var(--teal);font-weight:700;margin-bottom:8px">TEST RESULTS: ${passed}/${testList.length} PASS (${failed} failures) in ${dur}ms</div>` +
    testResults.join("\n");
}

// ---------- Data Ingestion (JSON / CSV) ----------
function parseCSVGraph(csvText) {
  const lines = csvText.trim().split(/\r?\n/);
  const nodes = [];
  const edges = [];
  const nodeMap = new Set();

  lines.forEach(line => {
    const parts = line.split(",").map(p => p.trim());
    if (parts.length >= 2) {
      const [from, to, label, weight, rel, confidence] = parts;
      if (!nodeMap.has(from)) {
        nodes.push({ id: from, label: from, group: "asset", criticality: 3 });
        nodeMap.add(from);
      }
      if (!nodeMap.has(to)) {
        nodes.push({ id: to, label: to, group: "asset", criticality: 3 });
        nodeMap.add(to);
      }
      edges.push({
        from,
        to,
        label: label || "lan",
        weight: parseInt(weight, 10) || 3,
        rel: rel || "NETWORK_REACHABILITY",
        confidence: confidence || "HIGH",
        riskContribution: (parseInt(weight, 10) || 3) * 4,
        evidence: "Imported telemetry edge"
      });
    }
  });

  return { nodes, edges };
}

function executeImport() {
  const valEl = $("importValidationStatus");
  const raw = $("importInput").value.trim();
  if (!raw) {
    valEl.innerHTML = '<span style="color:var(--crimson)">Error: Input is empty.</span>';
    return;
  }

  let parsed = null;
  if (raw.startsWith("{") || raw.startsWith("[")) {
    try {
      parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) parsed = { nodes: S.nodes, edges: parsed };
    } catch (e) {
      valEl.innerHTML = `<span style="color:var(--crimson)">JSON Syntax Error: ${e.message}</span>`;
      return;
    }
  } else {
    parsed = parseCSVGraph(raw);
  }

  const v = validateGraph(parsed.nodes, parsed.edges);
  if (!v.valid) {
    valEl.innerHTML = `<span style="color:var(--crimson)">Validation Failed: ${v.errors.slice(0, 3).join("; ")}</span>`;
    return;
  }

  // Apply new graph
  S.nodes = parsed.nodes;
  S.edges = parsed.edges;
  refreshNodeMap();

  visNodes.clear();
  visNodes.add(S.nodes.map(n => ({
    id: n.id,
    label: n.label,
    group: n.group || "asset",
    color: COLORS[n.group || "asset"] || COLORS.asset,
    shape: "dot",
    size: 22,
    font: { color: "#ece7db", size: 12.5 }
  })));

  visEdges.clear();
  visEdges.add(S.edges.map((e, i) => ({
    id: i,
    from: e.from,
    to: e.to,
    label: `${e.rel || e.label} ·${e.weight || 3}`,
    font: { color: "#7d7668", size: 9.5 },
    color: { color: EDGE_BASE },
    width: 1
  })));

  populateDropdowns();
  $("entrySel").value = S.nodes[0]?.id || "";
  valEl.innerHTML = `<span style="color:var(--emerald)">✔ Successfully imported ${S.nodes.length} nodes &amp; ${S.edges.length} edges!</span>`;
  setTimeout(() => {
    $("modalImport").classList.remove("open");
    simulate();
  }, 900);
}

// ---------- Export & Print ----------
function exportJSON() {
  if (!S.blast) {
    showNodeDetailFlash("Run a breach simulation first — there is no report to export yet.");
    return;
  }
  const report = {
    tool: "GraphOps",
    track: "General Track — Cybersecurity",
    competition: "hackFront India",
    timestamp: new Date().toISOString(),
    entryPoint: { id: S.blast.startId, label: labelOf(S.blast.startId) },
    maxDepth: S.blast.maxDepth,
    stats: statsFor(S.blast, S.crownJewels),
    containedNodes: [...S.containedNodes],
    containmentRanking: S.containmentRanking,
    shortestPathsToCrownJewels: shortestPathsToJewels(S.nodes, S.edges, S.blast.startId, S.crownJewels, S.blast, S.containedNodes),
    chokePoints: chokePoints(S.nodes, S.edges, S.blast.startId, S.crownJewels, S.containedNodes),
    predictedNextTargets: predictedTargets(S.nodes, S.edges, S.blast, S.crownJewels),
    threatStory: generateThreatStory(S.blast, null, null, S.containmentRanking, S.nodes),
    nodesInBlastRadius: Object.entries(S.blast.info).map(([id, r]) => ({
      id,
      label: labelOf(id),
      group: nodeById[id]?.group,
      depth: r.depth,
      riskScore: r.eff,
      reachedVia: r.via,
      technique: `${r.techId} ${r.techName}`,
      path: r.path.map(labelOf)
    }))
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `graphops-incident-${S.blast.startId}.json`;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

function printSummary() {
  if (!S.blast) {
    showNodeDetailFlash("Run a breach simulation first.");
    return;
  }
  const s = statsFor(S.blast, S.crownJewels);
  const rows = Object.entries(S.blast.info).sort((a, b) => b[1].eff - a[1].eff);

  $("printSummary").innerHTML = `
    <h1>GraphOps — Incident Brief &amp; Blast Radius Report</h1>
    <p>Foothold: <b>${esc(labelOf(S.blast.startId))}</b> · Max Depth: <b>${S.blast.maxDepth} hops</b> · Timestamp: ${new Date().toLocaleString()}</p>
    <p>Reachable Assets: <b>${s.compromised}</b> · Crown Jewels Exposed: <b>${s.jewelsHit}/${s.jewelsTotal}</b> · Max Path Risk: <b>${s.maxEff}</b></p>
    <table>
      <thead>
        <tr><th>Asset</th><th>Type</th><th>Risk</th><th>Hop</th><th>Via</th><th>Technique</th><th>Path</th></tr>
      </thead>
      <tbody>
        ${rows.map(([id, r]) => `
          <tr>
            <td>${esc(labelOf(id))}</td>
            <td>${nodeById[id]?.group}</td>
            <td>${r.eff} (${r.band})</td>
            <td>${r.depth}</td>
            <td>${esc(r.via)}</td>
            <td>${r.techId}</td>
            <td>${r.path.map(labelOf).join(" → ")}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
  window.print();
}

// ---------- Search & Path Finder ----------
function doSearch() {
  const q = $("nodeSearch").value.trim().toLowerCase();
  const msg = $("searchMsg");
  if (!q) { msg.textContent = ""; return; }

  const hits = S.nodes.filter(n => n.label.toLowerCase().includes(q) || n.id.includes(q));
  if (!hits.length) { msg.textContent = `No node matches "${q}".`; return; }

  msg.textContent = `${hits.length} match(es) — focused: ${hits[0].label}`;
  const id = hits[0].id;
  if (!S.mode3d) {
    try {
      network.focus(id, { scale: 1.3, animation: { duration: 600 } });
      network.selectNodes([id]);
    } catch (e) {}
  }
  showNodeDetail(id);
}

function findPathUI() {
  const a = $("pathFrom").value, b = $("pathTo").value;
  if (a === b) {
    S.highlightPath = [a];
  } else {
    const r = dijkstra(S.nodes, S.edges, a, b, S.containedNodes);
    if (!r) {
      showNodeDetailFlash(`Zero paths exist between ${labelOf(a)} and ${labelOf(b)} (Path severed by containment or air-gap).`);
      return;
    }
    S.highlightPath = r.path;
  }
  updateHotEdges();
  paint2D();
  if (S.mode3d && S.graph3d) { try { S.graph3d.refresh(); } catch (e) {} }
  try { network.fit({ animation: { duration: 400 } }); } catch (e) {}
}

function clearPathUI() {
  S.highlightPath = null;
  S.highlightTechnique = null;
  updateHotEdges();
  paint2D();
  if (S.mode3d && S.graph3d) { try { S.graph3d.refresh(); } catch (e) {} }
}

// ---------- Layouts & Tabs ----------
function setLayout(kind) {
  if (kind === "hier") {
    network.setOptions({
      layout: { hierarchical: { enabled: true, direction: "UD", sortMethod: "hubsize", levelSeparation: 110 } },
      physics: { enabled: false }
    });
  } else {
    network.setOptions({
      layout: { hierarchical: { enabled: false } },
      physics: { enabled: true, stabilization: true, barnesHut: { gravitationalConstant: -2200 } }
    });
  }
}

const TABS = ["blast", "paths", "lab", "story", "mitre", "analytics", "guide"];
function switchTab(name) {
  TABS.forEach(t => {
    $("tab-" + t)?.classList.toggle("on", t === name);
    $("panel-" + t)?.classList.toggle("on", t === name);
  });
  if (name === "analytics") {
    renderAnalytics();
    if (HAS_ECHARTS) {
      ["chartRisk", "chartTimeline", "chartTech"].forEach(id => {
        const c = S.charts[id + "_inst"];
        if (c) { try { c.resize(); } catch (e) {} }
      });
    }
  }
}

// ---------- Reset & Preset Scenarios ----------
function resetAll() {
  stopAnim();
  S.blast = null;
  S.baselineBlast = null;
  S.layer = 0;
  S.highlightPath = null;
  S.highlightTechnique = null;
  S.collapsed = {};
  S.containedNodes.clear();
  S.containedEdges.clear();
  S.hotTreeIdx = new Set();
  S.revealed = new Set();

  const tl = $("timeline");
  tl.value = 0;
  tl.max = 3;
  tl.disabled = true;
  ["btnPlay", "btnStepBack", "btnStepFwd", "speedSel", "btnStopAnim"].forEach(id => $(id).disabled = true);
  $("btnPlay").textContent = "Play";
  $("timelineLabel").textContent = "hop 0";
  $("drawer").classList.remove("open");$("center").classList.remove("drawer-open");
  $("recBanner").style.display = "none";
  updateQuickContainmentCheckboxes();
  updateIncidentHeader();

  applyVisibility();
  renderAll();
  try { network.fit(); } catch (e) {}
}

function loadPresetScenario(presetId) {
  const preset = PRESET_SCENARIOS.find(p => p.id === presetId);
  if (!preset) return;
  $("entrySel").value = preset.entryId;
  $("depthSel").value = String(preset.depth);
  S.containedNodes.clear();
  updateQuickContainmentCheckboxes();
  simulate();
}

function populateDropdowns() {
  const entrySel = $("entrySel"), pathFrom = $("pathFrom"), pathTo = $("pathTo");
  [entrySel, pathFrom, pathTo].forEach(sel => { if (sel) sel.innerHTML = ""; });

  S.nodes.forEach(n => {
    const o = document.createElement("option");
    o.value = n.id;
    o.textContent = `${n.label}  [${GROUP_LABEL[n.group] || "Asset"}]`;
    if (entrySel) entrySel.appendChild(o.cloneNode(true));
    if (pathFrom) pathFrom.appendChild(o.cloneNode(true));
    if (pathTo) pathTo.appendChild(o.cloneNode(true));
  });

  const presetSel = $("presetSel");
  if (presetSel) {
    presetSel.innerHTML = PRESET_SCENARIOS.map(p =>
      `<option value="${p.id}">${esc(p.name)}</option>`
    ).join("");
  }
}

// ---------- Initialization ----------
function init() {
  populateDropdowns();
  $("entrySel").value = "ws-0142";
  $("pathTo").value = "db01";

  if (!HAS_3D) {
    $("btn3d").disabled = true;
    $("btn3d").title = "3D library offline (CDN unreachable)";
  }

  // Network Event Listeners
  network.on("click", p => {
    if (p.nodes.length) {
      showNodeDetail(p.nodes[0]);
    } else if (p.edges.length) {
      showEdgeDetail(p.edges[0]);
    } else {
      $("drawer").classList.remove("open");$("center").classList.remove("drawer-open");
    }
  });

  network.on("doubleClick", p => {
    if (p.nodes.length) toggleCollapse(p.nodes[0]);
  });

  // Buttons
  $("btnBreach").onclick = simulate;
  $("btnReplay").onclick = startReplay;
  $("btnStopAnim").onclick = stopAnim;
  $("btnReset").onclick = resetAll;

  $("btnPlay").onclick = () => (S.playing ? stopAnim() : startPlay());
  $("btnStepBack").onclick = () => { if (S.blast && S.layer > 0) { stopAnim(); S.layer--; renderLayer(); } };
  $("btnStepFwd").onclick = () => { if (S.blast && S.layer < S.blast.layers.length - 1) { stopAnim(); S.layer++; renderLayer(); } };
  $("timeline").oninput = e => { if (S.blast) { stopAnim(); S.layer = +e.target.value; renderLayer(); } };
  $("speedSel").onchange = e => {
    S.speed = parseFloat(e.target.value);
    if (S.playing) { stopAnim(); startPlay(); }
  };

  $("presetSel").onchange = e => loadPresetScenario(e.target.value);

  $("nodeSearch").addEventListener("keydown", e => { if (e.key === "Enter") doSearch(); });
  $("nodeSearch").addEventListener("input", () => { $("searchMsg").textContent = ""; });

  [["flt-asset", "asset"], ["flt-identity", "identity"], ["flt-network", "network"]].forEach(([id, g]) => {
    $(id).onchange = e => { S.filters[g] = e.target.checked; applyVisibility(); paint2D(); };
  });

  $("btnFindPath").onclick = findPathUI;
  $("btnClearPath").onclick = clearPathUI;

  $("btn2d").onclick = () => setMode3D(false);
  $("btn3d").onclick = () => setMode3D(true);
  $("layoutSel").onchange = e => setLayout(e.target.value);

  // Quick Containment Panel
  $("btnApplyQuickContain").onclick = () => {
    document.querySelectorAll("#quickContainmentList input[data-contain]").forEach(cb => {
      if (cb.checked) S.containedNodes.add(cb.dataset.contain);
      else S.containedNodes.delete(cb.dataset.contain);
    });
    updateQuickContainmentCheckboxes();
    simulate();
  };

  $("btnClearContain").onclick = () => {
    S.containedNodes.clear();
    updateQuickContainmentCheckboxes();
    simulate();
  };

  $("btnDrawerContain").onclick = () => {
    if (S.drawerTarget?.type === "node") {
      toggleNodeContainment(S.drawerTarget.id);
    }
  };

  $("critSel").onchange = e => {
    if (S.drawerTarget?.type !== "node") return;
    const id = S.drawerTarget.id;
    S.crit[id] = parseInt(e.target.value, 10);
    if (S.blast) simulate();
    else showNodeDetail(id);
  };

  $("btnHighlightPath").onclick = () => {
    if (S.drawerTarget?.type === "node") {
      const id = S.drawerTarget.id;
      if (S.blast && S.blast.info[id]) {
        S.highlightPath = S.blast.info[id].path.slice();
        updateHotEdges();
        paint2D();
        if (S.mode3d && S.graph3d) { try { S.graph3d.refresh(); } catch (e) {} }
      }
    }
  };

  $("btnIsolate").onclick = () => {
    if (S.drawerTarget?.type === "node") toggleCollapse(S.drawerTarget.id);
  };

  $("drawerClose").onclick = () => $("drawer").classList.remove("open");$("center").classList.remove("drawer-open");

  // Tabs
  TABS.forEach(t => {
    const btn = $("tab-" + t);
    if (btn) btn.onclick = () => switchTab(t);
  });
  $("btnOpenContainment").onclick = () => switchTab("lab");

  // Tests Modal
  $("btnOpenTests").onclick = () => {
    $("modalTests").classList.add("open");
    runInBrowserTests();
  };
  $("btnCloseTests").onclick = () => $("modalTests").classList.remove("open");
  $("btnRerunTests").onclick = runInBrowserTests;

  // Import Modal
  $("btnOpenImport").onclick = () => $("modalImport").classList.add("open");
  $("btnCloseImport").onclick = () => $("modalImport").classList.remove("open");
  $("btnExecuteImport").onclick = executeImport;

  $("btnLoadSampleJSON").onclick = () => {
    $("importInput").value = JSON.stringify({
      nodes: S.nodes.slice(0, 10),
      edges: S.edges.slice(0, 12)
    }, null, 2);
  };
  $("btnLoadSampleCSV").onclick = () => {
    $("importInput").value = [
      "internet, vpn-gw, vpn, 4, EXTERNAL_INGRESS, HIGH",
      "vpn-gw, core-switch, vpn, 4, NETWORK_REACHABILITY, HIGH",
      "core-switch, admin-pc, lan, 2, NETWORK_REACHABILITY, HIGH",
      "admin-pc, domain-controller, ad, 5, DOMAIN_TRUST, HIGH",
      "core-switch, db-server, db, 5, CAN_ACCESS, HIGH"
    ].join("\n");
  };
  $("btnResetToDefaultGraph").onclick = () => {
    S.nodes = NODES.slice();
    S.edges = EDGES.slice();
    refreshNodeMap();
    init();
    $("modalImport").classList.remove("open");
    simulate();
  };

  $("btnExportJSON").onclick = exportJSON;
  $("btnPrint").onclick = printSummary;

  // Telemetry Toggle
  $("chkLiveTelemetry").onchange = e => {
    S.telemetryActive = e.target.checked;
    $("liveTelemetryBadge").style.opacity = S.telemetryActive ? "1" : "0.3";
  };

  window.addEventListener("resize", () => { if (S.mode3d) size3D(); });

  // Initial Paint & Live Telemetry
  applyVisibility();
  paint2D();
  renderAll();
  fxLoop();
  startTelemetryTicker();
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();

})();
