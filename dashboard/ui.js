/* GraphOps UI layer — GSAP motion, command palette (Cmd+K), animated
 * counters, 2D/3D view toggle, boot overlay. Classic script; needs gsap
 * (guarded). Talks to app.js through window.GraphOps bridge.
 */
'use strict';

const UI = (() => {
  const $ = (id) => document.getElementById(id);
  const hasGsap = () => typeof window.gsap !== 'undefined';
  const OPS = () => window.GraphOps || {};

  /* ---------- boot overlay ---------- */
  let booted = false;
  function bootDone() {
    if (booted) return;
    booted = true;
    const boot = $('boot');
    if (!boot) return;
    if (hasGsap()) {
      window.gsap.to(boot, {
        opacity: 0, duration: 0.6, ease: 'power2.inOut', delay: 0.25,
        onComplete: () => boot.remove(),
      });
    } else {
      boot.remove();
    }
  }
  // safety: never trap the user behind the boot screen
  setTimeout(bootDone, 7000);

  /* ---------- entrance motion ---------- */
  function entrance() {
    if (!hasGsap()) return;
    const g = window.gsap;
    g.from('.topbar', { y: -26, opacity: 0, duration: 0.7, ease: 'power3.out' });
    g.from('.statsbar .stat', { y: 14, opacity: 0, duration: 0.55, stagger: 0.07, ease: 'power2.out', delay: 0.15 });
    g.from('main.grid .panel', { y: 30, opacity: 0, duration: 0.75, stagger: 0.1, ease: 'power3.out', delay: 0.25 });
    g.from('.foot', { opacity: 0, duration: 0.8, delay: 0.6 });
  }

  /* ---------- animated counters ---------- */
  function countUp(elm, to, { dur = 1.1 } = {}) {
    if (!elm) return;
    const target = Number(to);
    if (!Number.isFinite(target)) { elm.textContent = String(to ?? '—'); return; }
    if (!hasGsap()) { elm.textContent = target.toLocaleString(); return; }
    const obj = { v: 0 };
    window.gsap.to(obj, {
      v: target, duration: dur, ease: 'power2.out',
      onUpdate: () => { elm.textContent = Math.round(obj.v).toLocaleString(); },
    });
  }

  /* ---------- findings stagger ---------- */
  function animateFindings() {
    if (!hasGsap()) return;
    const cards = document.querySelectorAll('#findingsList .finding');
    if (!cards.length) return;
    window.gsap.fromTo(cards,
      { x: -18, opacity: 0 },
      { x: 0, opacity: 1, duration: 0.45, stagger: 0.07, ease: 'power2.out', overwrite: true });
  }

  /* ---------- blast shockwave flash (view-agnostic) ---------- */
  function blastPulse() {
    const sh = $('shock');
    if (!sh || !hasGsap()) return;
    window.gsap.fromTo(sh,
      { opacity: 0.55 },
      { opacity: 0, duration: 0.9, ease: 'power2.out', overwrite: true });
  }

  /* ---------- 2D / 3D view toggle ---------- */
  let mode = '2d';
  let threeFailed = false;

  function setView(next) {
    const ops = OPS();
    if (next === '3d') {
      if (threeFailed || !window.Graph3D) { threeFailed = true; return false; }
    }
    mode = next;
    const b2 = $('btnView2d'), b3 = $('btnView3d');
    if (b2) b2.classList.toggle('active', next === '2d');
    if (b3) b3.classList.toggle('active', next === '3d');
    const canvas = $('graphCanvas'), wrap3d = $('graph3dWrap'), tip = $('tooltip');
    const is3d = next === '3d';

    if (is3d) {
      const ok = window.Graph3D.init(wrap3d);
      if (!ok) {
        threeFailed = true;
        const cs = $('canvasStatus');
        if (cs) cs.textContent = 'WebGL unavailable — staying in 2D';
        setView('2d');
        return false;
      }
      if (canvas) canvas.style.display = 'none';
      if (tip) tip.hidden = true;
      wrap3d.hidden = false;
      // feed current normalized data (app.js owns it)
      const d = ops.getGraphData ? ops.getGraphData() : null;
      if (d) {
        window.Graph3D.setData(d.nodes, d.edges);
        const b = ops.getBlast ? ops.getBlast() : null;
        if (b) window.Graph3D.setBlast(b.set, b.risk);
        const p = ops.getAttackPath ? ops.getAttackPath() : null;
        if (p) window.Graph3D.setAttackPath(p);
      }
      window.Graph3D.setVisible(true);
      const cs = $('canvasStatus');
      if (cs) cs.textContent = '3D · drag to orbit · scroll to zoom · click node → blast radius';
      if (hasGsap()) window.gsap.from(wrap3d, { opacity: 0, scale: 0.985, duration: 0.5, ease: 'power2.out' });
    } else {
      if (window.Graph3D) window.Graph3D.setVisible(false);
      wrap3d.hidden = true;
      if (canvas) canvas.style.display = '';
      if (ops.redraw2d) ops.redraw2d();
    }
    return true;
  }
  function getMode() { return mode; }

  /* ---------- command palette ---------- */
  const paletteCommands = () => {
    const ops = OPS();
    const cmds = [
      { title: 'Run hunt', hint: 'POST /hunt', run: () => ops.runHunt && ops.runHunt() },
      { title: 'Run demo attack scenario', hint: 'hunt + highlight', run: () => ops.runDemo && ops.runDemo() },
      { title: mode === '2d' ? 'Switch to 3D graph' : 'Switch to 2D graph', hint: 'toggle view', run: () => setView(mode === '2d' ? '3d' : '2d') },
      { title: 'Clear highlights', hint: 'attack path + blast', run: () => ops.clearHighlights && ops.clearHighlights() },
    ];
    const findings = ops.getFindings ? ops.getFindings() : [];
    findings.forEach((f, i) => {
      cmds.push({
        title: `Finding ${i + 1}: ${f.title}`,
        hint: `${f.severity} · ${f.nodes.length} nodes`,
        run: () => ops.focusFinding && ops.focusFinding(i),
      });
    });
    return cmds;
  };

  let palOpen = false, palSel = 0, palItems = [];
  function openPalette() {
    const p = $('palette');
    if (!p || palOpen) return;
    palOpen = true; palSel = 0;
    p.hidden = false;
    const inp = $('paletteInput');
    inp.value = '';
    renderPalette('');
    if (hasGsap()) {
      window.gsap.fromTo('#paletteBox', { y: -14, opacity: 0, scale: 0.99 },
        { y: 0, opacity: 1, scale: 1, duration: 0.22, ease: 'power2.out' });
    }
    setTimeout(() => inp.focus(), 0);
  }
  function closePalette() {
    const p = $('palette');
    if (!p || !palOpen) return;
    palOpen = false;
    p.hidden = true;
  }
  function renderPalette(q) {
    const list = $('paletteList');
    if (!list) return;
    const query = q.trim().toLowerCase();
    palItems = paletteCommands().filter((c) =>
      !query || c.title.toLowerCase().includes(query) || (c.hint || '').toLowerCase().includes(query));
    palSel = Math.min(palSel, Math.max(0, palItems.length - 1));
    list.innerHTML = palItems.length
      ? palItems.map((c, i) =>
          `<div class="pal-item${i === palSel ? ' sel' : ''}" data-i="${i}">` +
          `<span class="pal-title">${escHtml(c.title)}</span>` +
          `<span class="pal-hint">${escHtml(c.hint || '')}</span></div>`).join('')
      : '<div class="pal-empty">no matching command</div>';
    list.querySelectorAll('.pal-item').forEach((n) => {
      n.addEventListener('click', () => { palSel = Number(n.dataset.i); execPalette(); });
      n.addEventListener('mousemove', () => {
        palSel = Number(n.dataset.i);
        list.querySelectorAll('.pal-item').forEach((m, j) => m.classList.toggle('sel', j === palSel));
      });
    });
  }
  function execPalette() {
    const c = palItems[palSel];
    closePalette();
    if (c && typeof c.run === 'function') {
      try { c.run(); } catch (e) { /* command failed; dashboard stays up */ }
    }
  }
  function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function wirePalette() {
    const inp = $('paletteInput'), pal = $('palette');
    if (!inp || !pal) return;
    inp.addEventListener('input', () => { palSel = 0; renderPalette(inp.value); });
    inp.addEventListener('keydown', (ev) => {
      if (ev.key === 'ArrowDown') { ev.preventDefault(); palSel = Math.min(palSel + 1, palItems.length - 1); renderPalette(inp.value); }
      else if (ev.key === 'ArrowUp') { ev.preventDefault(); palSel = Math.max(palSel - 1, 0); renderPalette(inp.value); }
      else if (ev.key === 'Enter') { ev.preventDefault(); execPalette(); }
      else if (ev.key === 'Escape') { closePalette(); }
    });
    pal.addEventListener('click', (ev) => { if (ev.target === pal) closePalette(); });
    document.addEventListener('keydown', (ev) => {
      const mod = ev.metaKey || ev.ctrlKey;
      if (mod && ev.key.toLowerCase() === 'k') { ev.preventDefault(); palOpen ? closePalette() : openPalette(); }
      else if (ev.key === 'Escape' && palOpen) { closePalette(); }
    });
    const btn = $('btnPalette');
    if (btn) btn.addEventListener('click', openPalette);
  }

  function wireToggle() {
    const b2 = $('btnView2d'), b3 = $('btnView3d');
    if (b2) b2.addEventListener('click', () => setView('2d'));
    if (b3) b3.addEventListener('click', () => setView('3d'));
  }

  window.addEventListener('DOMContentLoaded', () => {
    entrance();
    wirePalette();
    wireToggle();
  });

  return { bootDone, countUp, animateFindings, blastPulse, setView, getMode, openPalette };
})();

window.UI = UI;
