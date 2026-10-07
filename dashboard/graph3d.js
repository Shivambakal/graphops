/* GraphOps 3D threat graph — Three.js force-directed visualization.
 * Data comes ONLY from the API (via app.js -> setData). No hardcoded nodes.
 * Exposes window.Graph3D. Lazy init: call init(container) then setData().
 */
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/OrbitControls.js';

const ETYPE_HEX = {
  host: 0x38bdf8,
  user: 0xa78bfa,
  ip: 0xfbbf24,
  process: 0x34d399,
  alert: 0xf87171,
};
const ETYPE_DEFAULT = 0x94a3b8;
const RISK_HEX = new THREE.Color(0xff2d55);
const REGULATED_HEX = new THREE.Color(0xff2d55); // crimson — DPDP regulated-data halo
// data-classification color mode (mirror of dashboard DC_COLORS, 2D↔3D sync)
const DC_HEX = {
  regulated: 0xff2d55,
  confidential: 0xfbbf24,
  internal: 0x38bdf8,
  public: 0x5b6b82, // dim
};

const G = {
  inited: false,
  visible: false,
  renderer: null, scene: null, camera: null, controls: null,
  nodeGroup: null, edgeLines: null, stars: null, grid: null,
  meshes: [],          // THREE.Mesh per node, parallel to data.nodes
  meshById: new Map(),
  nodes: [], edges: [],
  blastSet: new Set(), blastRisk: new Map(), attackSet: new Set(),
  exfilSet: new Set(),
  regulatedSet: new Set(), // blast nodes holding regulated data (DPDP overlay, crimson halos)
  regHalos: [],            // wireframe halo meshes for regulated nodes
  hovered: null,
  layout: null,        // {iter, total} while settling
  shockwaves: [],
  tooltip: null, container: null,
  onNodeClick: null,
  colorMode: 'etype',  // 'etype' | 'dc' — synced from app.js toggle
  raf: 0, clock: new THREE.Clock(),
  sphereGeo: null,
};

function etypeColorHex(etype) {
  return ETYPE_HEX[String(etype || '').toLowerCase()] ?? ETYPE_DEFAULT;
}

function init(container) {
  if (G.inited) return true;
  if (!window.WebGLRenderingContext) return false;
  G.container = container;
  G.tooltip = document.getElementById('tooltip3d');

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  } catch (e) { return false; }
  G.renderer = renderer;
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x05080f, 0.0011);
  G.scene = scene;

  const camera = new THREE.PerspectiveCamera(
    55,
    container.clientWidth / Math.max(1, container.clientHeight),
    0.1, 4000
  );
  camera.position.set(0, 90, 230);
  G.camera = camera;

  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.06;
  controls.minDistance = 40;
  controls.maxDistance = 900;
  controls.autoRotate = true;
  controls.autoRotateSpeed = 0.7;
  controls.addEventListener('start', () => { controls.autoRotate = false; });
  G.controls = controls;

  // lights
  scene.add(new THREE.AmbientLight(0x8aa0c8, 0.85));
  const key = new THREE.PointLight(0x22d3ee, 90000, 0, 1.8);
  key.position.set(120, 160, 80);
  scene.add(key);
  const rim = new THREE.PointLight(0xa78bfa, 60000, 0, 1.8);
  rim.position.set(-140, -60, -120);
  scene.add(rim);

  // reference grid + starfield backdrop
  const grid = new THREE.GridHelper(520, 52, 0x1e2c4d, 0x0e1628);
  grid.material.transparent = true;
  grid.material.opacity = 0.5;
  grid.position.y = -95;
  scene.add(grid);
  G.grid = grid;

  const starGeo = new THREE.BufferGeometry();
  const starPos = new Float32Array(900 * 3);
  for (let i = 0; i < 900; i++) {
    const r = 700 + Math.random() * 900;
    const th = Math.random() * Math.PI * 2;
    const ph = Math.acos(2 * Math.random() - 1);
    starPos[i * 3] = r * Math.sin(ph) * Math.cos(th);
    starPos[i * 3 + 1] = r * Math.cos(ph);
    starPos[i * 3 + 2] = r * Math.sin(ph) * Math.sin(th);
  }
  starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
  G.stars = new THREE.Points(starGeo, new THREE.PointsMaterial({
    color: 0x3b5a8a, size: 2.2, sizeAttenuation: true,
    transparent: true, opacity: 0.75,
  }));
  scene.add(G.stars);

  G.nodeGroup = new THREE.Group();
  scene.add(G.nodeGroup);
  G.sphereGeo = new THREE.SphereGeometry(1, 20, 14);

  container.appendChild(renderer.domElement);
  renderer.domElement.className = 'graph3d-canvas';

  wirePointer();
  new ResizeObserver(resize).observe(container);
  resize();

  G.inited = true;
  G.raf = requestAnimationFrame(tick);
  return true;
}

function resize() {
  if (!G.inited || !G.container) return;
  const w = G.container.clientWidth, h = G.container.clientHeight;
  if (w < 2 || h < 2) return;
  G.camera.aspect = w / h;
  G.camera.updateProjectionMatrix();
  G.renderer.setSize(w, h);
}

/* ---------- data ---------- */
function clearGraph() {
  for (const m of G.meshes) {
    G.nodeGroup.remove(m);
    m.material.dispose();
  }
  G.meshes = [];
  G.meshById.clear();
  if (G.edgeLines) {
    G.nodeGroup.remove(G.edgeLines);
    G.edgeLines.geometry.dispose();
    G.edgeLines.material.dispose();
    G.edgeLines = null;
  }
  for (const s of G.shockwaves) G.scene.remove(s.mesh);
  G.shockwaves = [];
  for (const h of G.regHalos) { h.parent && h.parent.remove(h); h.geometry.dispose(); h.material.dispose(); }
  G.regHalos = [];
}

function setData(nodes, edges) {
  if (!G.inited) return;
  clearGraph();
  G.nodes = nodes;
  G.edges = edges;
  const R = 95;

  for (const n of nodes) {
    const color = new THREE.Color(etypeColorHex(n.etype));
    const mat = new THREE.MeshStandardMaterial({
      color, roughness: 0.32, metalness: 0.55,
      emissive: color.clone().multiplyScalar(0.25),
    });
    const mesh = new THREE.Mesh(G.sphereGeo, mat);
    const size = 1.6 + Math.min(4.2, (n.degree || 0) * 0.35);
    mesh.scale.setScalar(size);
    // contract: nodes may carry data_classification (public/internal/confidential/regulated)
    mesh.userData = { id: n.id, label: n.label, etype: n.etype, baseSize: size, baseColor: color.clone(), dc: String(n.dc || '').toLowerCase() };
    // random point in sphere
    const th = Math.random() * Math.PI * 2;
    const ph = Math.acos(2 * Math.random() - 1);
    const rr = R * Math.cbrt(Math.random());
    mesh.position.set(
      rr * Math.sin(ph) * Math.cos(th),
      rr * Math.cos(ph) * 0.7,
      rr * Math.sin(ph) * Math.sin(th)
    );
    G.nodeGroup.add(mesh);
    G.meshes.push(mesh);
    G.meshById.set(n.id, mesh);
  }

  // edges as one LineSegments (positions refreshed each layout frame)
  const pos = new Float32Array(edges.length * 6);
  const col = new Float32Array(edges.length * 6);
  const eg = new THREE.BufferGeometry();
  eg.setAttribute('position', new THREE.BufferAttribute(pos, 3));
  eg.setAttribute('color', new THREE.BufferAttribute(col, 3));
  G.edgeLines = new THREE.LineSegments(eg, new THREE.LineBasicMaterial({
    vertexColors: true, transparent: true, opacity: 0.22,
    blending: THREE.AdditiveBlending, depthWrite: false,
  }));
  G.edgeLines.userData.edgePairs = edges
    .map((e) => [G.meshById.get(e.a), G.meshById.get(e.b), String(e.etype || '')])
    .filter(([a, b]) => a && b);
  const meshIndex = new Map(G.meshes.map((m, i) => [m, i]));
  G.edgeLines.userData.edgeIdx = G.edgeLines.userData.edgePairs
    .map(([a, b]) => [meshIndex.get(a), meshIndex.get(b)]);
  G.nodeGroup.add(G.edgeLines);

  // start progressive 3D layout
  G.layout = { iter: 0, total: 110 };
  applyRegulatedHalos(); // rebuild halos after clearGraph wiped them (setRegulated may predate setData)
  applyBlastColors();
}

function refreshEdgeGeometry() {
  if (!G.edgeLines) return;
  const pairs = G.edgeLines.userData.edgePairs;
  const p = G.edgeLines.geometry.attributes.position.array;
  const c = G.edgeLines.geometry.attributes.color.array;
  const dim = new THREE.Color(0x2a3a5c);
  const lateral = new THREE.Color(0x7a4b2a); // lateral-movement etypes: smb/winrm/rdp/ssh/lateral
  const hot = new THREE.Color(0xf87171);     // attack-path edges
  const LATERAL_RE = /smb|winrm|rdp|ssh|wmi|rpc|lateral|network/i;
  let k = 0;
  for (const [a, b, etype] of pairs) {
    p[k * 3] = a.position.x; p[k * 3 + 1] = a.position.y; p[k * 3 + 2] = a.position.z;
    p[k * 3 + 3] = b.position.x; p[k * 3 + 4] = b.position.y; p[k * 3 + 5] = b.position.z;
    const col = (G.attackSet.has(a.userData.id) && G.attackSet.has(b.userData.id)) ? hot
      : (LATERAL_RE.test(etype) ? lateral : dim);
    c[k * 3] = col.r; c[k * 3 + 1] = col.g; c[k * 3 + 2] = col.b;
    c[k * 3 + 3] = col.r; c[k * 3 + 4] = col.g; c[k * 3 + 5] = col.b;
    k++;
  }
  G.edgeLines.geometry.setDrawRange(0, pairs.length * 2);
  G.edgeLines.geometry.attributes.position.needsUpdate = true;
  G.edgeLines.geometry.attributes.color.needsUpdate = true;
}

/* 3D force layout: repulsion + springs + weak centering, progressive. */
function layoutStep() {
  const L = G.layout;
  if (!L || L.iter >= L.total) return;
  const PER = 4;
  const nodes = G.meshes;
  const n = nodes.length;
  if (n === 0) { L.iter = L.total; return; }
  const k = 34;
  const rest = 26;

  for (let s = 0; s < PER && L.iter < L.total; s++, L.iter++) {
    const temp = 1 - L.iter / L.total;
    const disp = new Float32Array(n * 3);
    // repulsion (all pairs)
    for (let i = 0; i < n; i++) {
      const a = nodes[i].position;
      for (let j = i + 1; j < n; j++) {
        const b = nodes[j].position;
        let dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
        let d2 = dx * dx + dy * dy + dz * dz;
        if (d2 < 1) { dx = Math.random() - .5; dy = Math.random() - .5; dz = Math.random() - .5; d2 = 1; }
        const d = Math.sqrt(d2);
        const f = Math.min(60, (k * k) / d) / d;
        disp[i * 3] += dx * f; disp[i * 3 + 1] += dy * f; disp[i * 3 + 2] += dz * f;
        disp[j * 3] -= dx * f; disp[j * 3 + 1] -= dy * f; disp[j * 3 + 2] -= dz * f;
      }
    }
    // springs (index pairs precomputed in setData)
    for (const [ia, ib] of (G.edgeLines ? G.edgeLines.userData.edgeIdx : [])) {
      const a = nodes[ia], b = nodes[ib];
      const pa = a.position, pb = b.position;
      const dx = pb.x - pa.x, dy = pb.y - pa.y, dz = pb.z - pa.z;
      const d = Math.sqrt(dx * dx + dy * dy + dz * dz) || 1;
      const f = ((d - rest) * 0.02) / d;
      disp[ia * 3] += dx * f; disp[ia * 3 + 1] += dy * f; disp[ia * 3 + 2] += dz * f;
      disp[ib * 3] -= dx * f; disp[ib * 3 + 1] -= dy * f; disp[ib * 3 + 2] -= dz * f;
    }
    // apply with cooling + centering
    const maxD = 9 * temp + 0.6;
    for (let i = 0; i < n; i++) {
      const p = nodes[i].position;
      let dx = disp[i * 3] - p.x * 0.004;
      let dy = disp[i * 3 + 1] - p.y * 0.004;
      let dz = disp[i * 3 + 2] - p.z * 0.004;
      const m = Math.sqrt(dx * dx + dy * dy + dz * dz);
      if (m > maxD) { const sc = maxD / m; dx *= sc; dy *= sc; dz *= sc; }
      p.x += dx; p.y += dy; p.z += dz;
    }
  }
  refreshEdgeGeometry();
  if (L.iter >= L.total) {
    const st = document.getElementById('canvasStatus');
    if (st && G.visible) st.textContent = `${G.nodes.length} nodes · ${G.edgeLines.userData.edgePairs.length} edges · 3D`;
  }
}

/* ---------- highlights ---------- */
function isRegulatedMesh(u) {
  return G.regulatedSet.has(u.id) || u.dc === 'regulated';
}

function applyRegulatedHalos() {
  for (const h of G.regHalos) { h.parent && h.parent.remove(h); h.geometry.dispose(); h.material.dispose(); }
  G.regHalos = [];
  for (const mesh of G.meshes) {
    if (!isRegulatedMesh(mesh.userData)) continue;
    const halo = new THREE.Mesh(
      new THREE.SphereGeometry(1.28, 18, 12),
      new THREE.MeshBasicMaterial({ color: 0xff2d55, transparent: true, opacity: 0.5, wireframe: true })
    );
    halo.userData.isRegHalo = true;
    mesh.add(halo); // follows the node automatically
    G.regHalos.push(halo);
  }
}

function applyBlastColors() {
  for (const mesh of G.meshes) {
    const u = mesh.userData;
    const risk = G.blastRisk.get(u.id);
    const regulated = isRegulatedMesh(u);
    // color-mode tint: node base color comes from data classification when enabled
    const dcTint = (G.colorMode === 'dc' && u.dc && DC_HEX[u.dc] !== undefined)
      ? new THREE.Color(DC_HEX[u.dc]) : null;
    const base = dcTint || u.baseColor;
    if (G.exfilSet.has(u.id)) {
      // exfil-risk overlay wins: suspected C2/exfil endpoint, hot amber
      mesh.material.color.copy(EXFIL_HEX);
      mesh.material.emissive.copy(EXFIL_HEX).multiplyScalar(0.7);
    } else if (regulated) {
      // DPDP regulated-data overlay: crimson tint, halo marks it in any blast state
      mesh.material.color.copy(u.baseColor).lerp(REGULATED_HEX, 0.72);
      mesh.material.emissive.copy(REGULATED_HEX).multiplyScalar(0.55);
    } else if (risk !== undefined && risk !== null && Number.isFinite(Number(risk))) {
      const rn = Math.max(0, Math.min(1, Number(risk) <= 1 ? Number(risk) : Number(risk) / 100));
      mesh.material.color.copy(base).lerp(RISK_HEX, 0.25 + rn * 0.65);
      mesh.material.emissive.copy(mesh.material.color).multiplyScalar(0.55);
    } else if (G.blastSet.has(u.id)) {
      mesh.material.color.set(0x22d3ee);
      mesh.material.emissive.set(0x22d3ee).multiplyScalar(0.6);
    } else if (u.etype === 'alert') {
      // alert nodes: always a touch hotter so they stand out pre-blast
      mesh.material.color.copy(u.baseColor);
      mesh.material.emissive.copy(u.baseColor).multiplyScalar(0.55);
    } else {
      mesh.material.color.copy(base);
      mesh.material.emissive.copy(base).multiplyScalar(0.25);
    }
  }
}

/* ---------- node color mode: entity type <-> data classification ---------- */
function setColorMode(m) {
  G.colorMode = m === 'dc' ? 'dc' : 'etype';
  if (!G.inited) return;
  applyBlastColors();
}

function setBlast(idSet, riskById) {
  G.blastSet = new Set(idSet || []);
  G.blastRisk = new Map(riskById || []);
  if (!G.inited) return;
  applyBlastColors();
  // shockwave burst on up to 40 blast nodes
  const ids = [...G.blastSet].slice(0, 40);
  for (const id of ids) {
    const mesh = G.meshById.get(id);
    if (!mesh) continue;
    const sm = new THREE.Mesh(
      new THREE.SphereGeometry(1, 18, 12),
      new THREE.MeshBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.55, wireframe: true })
    );
    sm.position.copy(mesh.position);
    sm.scale.setScalar(mesh.userData.baseSize);
    G.scene.add(sm);
    G.shockwaves.push({ mesh: sm, t: 0 });
  }
}

function setAttackPath(idSet) {
  G.attackSet = new Set(idSet || []);
  if (G.inited && G.edgeLines) refreshEdgeGeometry(); // hot edges on the attack path
}

/* ---------- exfil-risk overlay: external IPs near the compromised source ---------- */
const EXFIL_HEX = new THREE.Color(0xff7847);
function setExfil(idSet) {
  G.exfilSet = new Set(idSet || []);
  if (!G.inited) return;
  applyBlastColors();
}

/* ---------- DPDP overlay: crimson halos on nodes holding regulated data ---------- */
function setRegulated(idSet) {
  G.regulatedSet = new Set(idSet || []);
  if (!G.inited) return;
  applyRegulatedHalos();
  applyBlastColors();
}

/* ---------- camera tour through the blast-radius path (GSAP timeline) ---------- */
function tourBlast(rows) {
  if (!G.inited) return false;
  const seq = (rows || [])
    .slice(0, 10) // keep the tour tight: nearest 10 nodes by distance
    .map((r) => G.meshById.get(r.id ?? r))
    .filter(Boolean);
  if (!seq.length) return false;
  const g = window.gsap;
  if (G.controls) G.controls.autoRotate = false;
  if (!g) { flyTo(seq[0].userData.id); return true; }
  const tl = g.timeline({ defaults: { duration: 1.15, ease: 'power2.inOut' } });
  for (const mesh of seq) {
    const target = mesh.position.clone();
    const dir = G.camera.position.clone().sub(target);
    if (dir.length() < 1e-3) dir.set(0.4, 0.35, 1);
    dir.normalize().multiplyScalar(95);
    const camTo = target.clone().add(dir);
    tl.to(G.camera.position, {
      x: camTo.x, y: camTo.y, z: camTo.z,
      onUpdate: () => { if (G.controls) G.controls.update(); },
    }, '>');
    tl.to(G.controls ? G.controls.target : {}, {
      x: target.x, y: target.y, z: target.z,
      onUpdate: () => { if (G.controls) G.controls.update(); },
    }, '<');
    // attention ping as the tour reaches each node
    tl.add(() => {
      const sm = new THREE.Mesh(
        new THREE.SphereGeometry(1, 18, 12),
        new THREE.MeshBasicMaterial({ color: 0xff2d55, transparent: true, opacity: 0.6, wireframe: true })
      );
      sm.position.copy(target);
      sm.scale.setScalar(mesh.userData.baseSize);
      G.scene.add(sm);
      G.shockwaves.push({ mesh: sm, t: 0 });
    }, '-=0.35');
  }
  return true;
}

/* ---------- camera fly-to on selection ---------- */
function flyTo(id) {
  if (!G.inited) return;
  const mesh = G.meshById.get(id);
  if (!mesh) return;
  const target = mesh.position.clone();
  const dir = G.camera.position.clone().sub(target);
  if (dir.length() < 1e-3) dir.set(0.4, 0.35, 1);
  dir.normalize().multiplyScalar(85); // cinematic close-up distance
  const camTo = target.clone().add(dir);
  const g = window.gsap;
  if (G.controls) G.controls.autoRotate = false;
  if (g) {
    g.to(G.camera.position, {
      x: camTo.x, y: camTo.y, z: camTo.z,
      duration: 1.25, ease: 'power3.inOut', overwrite: true,
    });
    g.to(G.controls.target, {
      x: target.x, y: target.y, z: target.z,
      duration: 1.25, ease: 'power3.inOut', overwrite: true,
      onUpdate: () => G.controls.update(),
    });
  } else {
    G.camera.position.copy(camTo);
    G.controls.target.copy(target);
    G.controls.update();
  }
  // attention ping on the selected node
  const sm = new THREE.Mesh(
    new THREE.SphereGeometry(1, 18, 12),
    new THREE.MeshBasicMaterial({ color: 0xf87171, transparent: true, opacity: 0.6, wireframe: true })
  );
  sm.position.copy(target);
  sm.scale.setScalar(mesh.userData.baseSize);
  G.scene.add(sm);
  G.shockwaves.push({ mesh: sm, t: 0 });
}

/* ---------- pointer ---------- */
const raycaster = new THREE.Raycaster();
const pointerNDC = new THREE.Vector2();
let downPos = null;

function pick(ev) {
  const r = G.renderer.domElement.getBoundingClientRect();
  pointerNDC.x = ((ev.clientX - r.left) / r.width) * 2 - 1;
  pointerNDC.y = -((ev.clientY - r.top) / r.height) * 2 + 1;
  raycaster.setFromCamera(pointerNDC, G.camera);
  // grow raycast targets slightly for easier hover
  const hits = raycaster.intersectObjects(G.meshes, false);
  return hits.length ? hits[0].object : null;
}

function wirePointer() {
  const el = G.renderer.domElement;
  el.addEventListener('pointermove', (ev) => {
    if (!G.visible) return;
    const mesh = pick(ev);
    G.hovered = mesh;
    el.style.cursor = mesh ? 'pointer' : 'grab';
    const tt = G.tooltip;
    if (mesh && tt) {
      const u = mesh.userData;
      const v = mesh.position.clone().project(G.camera);
      const r = G.container.getBoundingClientRect();
      tt.hidden = false;
      tt.style.left = Math.min(((v.x + 1) / 2) * r.width + 18, r.width - 250) + 'px';
      tt.style.top = Math.max(((-v.y + 1) / 2) * r.height - 12, 8) + 'px';
      tt.innerHTML =
        `<span class="tt-id">${escapeHtml(u.label)}</span><br>` +
        `<span class="tt-type">${escapeHtml(u.etype)}${u.dc ? ` · ${escapeHtml(u.dc)}` : ''}</span><br>` +
        `<span class="muted">${isRegulatedMesh(u) ? 'regulated data — click → DPDP' : 'click → blast radius'}</span>`;
    } else if (tt) {
      tt.hidden = true;
    }
  });
  el.addEventListener('pointerleave', () => {
    G.hovered = null;
    if (G.tooltip) G.tooltip.hidden = true;
  });
  el.addEventListener('pointerdown', (ev) => { downPos = [ev.clientX, ev.clientY]; });
  el.addEventListener('pointerup', (ev) => {
    if (!downPos) return;
    const moved = Math.hypot(ev.clientX - downPos[0], ev.clientY - downPos[1]);
    downPos = null;
    if (moved > 6 || !G.visible) return;
    const mesh = pick(ev);
    if (mesh && typeof G.onNodeClick === 'function') G.onNodeClick(mesh.userData.id);
  });
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ---------- frame ---------- */
function tick() {
  G.raf = requestAnimationFrame(tick);
  if (!G.visible || !G.inited) return;
  const t = G.clock.getElapsedTime();

  layoutStep();

  // pulses
  for (const mesh of G.meshes) {
    const u = mesh.userData;
    const id = u.id;
    let s = u.baseSize;
    if (G.attackSet.has(id)) {
      s *= 1 + 0.28 * Math.sin(t * 6);
      mesh.material.emissive.setHex(0xf87171).multiplyScalar(0.55 + 0.3 * Math.sin(t * 6));
    } else if (G.exfilSet.has(id)) {
      s *= 1 + 0.22 * Math.sin(t * 5 + 0.6); // exfil-risk pulse (suspected C2)
    } else if (G.regulatedSet.has(id) || u.dc === 'regulated') {
      s *= 1 + 0.18 * Math.sin(t * 4.5 + 0.9); // regulated-data pulse (DPDP overlay)
    } else if (G.blastSet.has(id)) {
      s *= 1 + 0.16 * Math.sin(t * 4 + 1);
    } else if (G.hovered === mesh) {
      s *= 1.35;
    }
    mesh.scale.setScalar(s);
  }

  // shockwaves expand + fade
  for (let i = G.shockwaves.length - 1; i >= 0; i--) {
    const sh = G.shockwaves[i];
    sh.t += 1 / 60;
    const k = sh.t / 1.4;
    if (k >= 1) {
      G.scene.remove(sh.mesh);
      sh.mesh.geometry.dispose(); sh.mesh.material.dispose();
      G.shockwaves.splice(i, 1);
      continue;
    }
    sh.mesh.scale.setScalar(sh.mesh.scale.x + 42 * (1 / 60));
    sh.mesh.material.opacity = 0.55 * (1 - k);
  }

  G.stars.rotation.y = t * 0.004;
  G.controls.update();
  G.renderer.render(G.scene, G.camera);
}

function setVisible(v) {
  G.visible = !!v;
  if (G.inited) {
    G.renderer.domElement.style.display = v ? 'block' : 'none';
    if (v) { resize(); refreshEdgeGeometry(); }
  }
}

window.Graph3D = {
  init, setData, setBlast, setExfil, setAttackPath, setVisible, resize, flyTo,
  setRegulated, tourBlast, setColorMode,
  // read-only debug surface for automated verification (no state mutation)
  debug: () => ({
    nodes: G.meshes.length,
    regulated: G.regulatedSet.size,
    halos: G.regHalos.length,
    colorMode: G.colorMode,
    tourCapable: typeof tourBlast === 'function',
  }),
};
