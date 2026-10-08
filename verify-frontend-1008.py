"""Headless Playwright verification for the GraphOps frontend (build/frontend-1008).

Phase A: real backend (uvicorn graphops.api.server:app) — verifies the six
2026-10-08 frontend features against the LIVE API:
  1. run history + MTTD/MTTC trend + side-by-side comparison (real run records)
  2. per-method hunt metrics panel (real findings; honest /metrics-unavailable note)
  3. approval queue: cost/reversibility summary, impact-tier rows, approve flow,
     queue-depth indicator (real GET /decisions + GET /health)
  4. keyboard shortcuts (?, R, G, A) + Cmd+K documentation + shortcuts overlay
  5. bugfix: method-filter options no longer duplicate on re-hunt
  6. bugfix: 2D drag-release no longer fires blast-radius (6px guard like 3D)
  + DPDP card: regulated-datasets metric cell when the API ships it, honest
  "not available" note otherwise.
Phase B: API down (?api=dead port) — every new panel shows an explicit
offline/unavailable state; nothing is faked.
"""
import sys
from playwright.sync_api import sync_playwright

API = "http://127.0.0.1:8010"
FE = "http://127.0.0.1:8010"  # API serves the dashboard at / (same origin)

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, detail)


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1600, "height": 950})
        page = ctx.new_page()
        page.goto(f"{FE}/?api={API}", wait_until="networkidle")
        page.evaluate("() => localStorage.clear()")
        page.reload(wait_until="networkidle")
        page.wait_for_timeout(3000)

        # ---------- boot / online ----------
        check("A0 API online", "online" in page.locator("#healthLine").inner_text().lower())
        check("A1 graph loaded", page.evaluate("() => window.GraphOps.getGraphData().nodes.length") > 100)

        # ---------- hunt + method metrics ----------
        page.click("#btnRunHunt")
        page.wait_for_selector("#findingsList .finding", timeout=20000)
        page.wait_for_timeout(800)
        n_find = page.evaluate("() => window.GraphOps.getFindings().length")
        mm_rows = page.locator("#methodMetrics .mm-row").count()
        check("A2 hunt returns findings", n_find > 0, f"{n_find} findings")
        check("A3 method-metrics rows rendered from real findings", mm_rows > 0, f"{mm_rows} rows")
        mm_text = page.locator("#methodMetricsBody").inner_text()
        check("A4 honest /metrics-unavailable note (backend has no /metrics)",
              "not in this backend build" in mm_text, mm_text[:120])
        src = page.locator("#metricsSrc").inner_text()
        check("A5 metrics source label honest", "hunt findings" in src.lower(), src)

        # ---------- bugfix 5: no duplicate method options on re-hunt ----------
        opts1 = page.eval_on_selector("#huntMethod", "s => [...s.options].map(o => o.value)")
        page.click("#btnRunHunt")
        page.wait_for_timeout(1500)
        opts2 = page.eval_on_selector("#huntMethod", "s => [...s.options].map(o => o.value)")
        dupes = len(opts2) != len(set(opts2))
        check("A6 method filter has no duplicate options after re-hunt", not dupes and opts1 == opts2,
              f"{len(opts1)} -> {len(opts2)} options")

        # ---------- approval queue ----------
        qrows = page.locator("#approvalQueue .qrow").count()
        check("A7 approval queue renders real queue rows", qrows > 0, f"{qrows} rows")
        qsum = page.locator("#queueSummary").inner_text()
        check("A8 summary bar shows real cost + reversibility",
              "est. business cost" in qsum and "avg reversibility" in qsum, qsum[:110])
        check("A9 impact-tier badges on rows", page.locator("#approvalQueue .tier").count() > 0)
        qd = page.locator("#queueDepth").inner_text()
        check("A10 queue-depth indicator from /health", "awaiting" in qd.lower(), qd)
        # approve the first queued item -> audit badge + toast
        first = page.locator("#approvalQueue .qrow").first
        first.locator("button.approve").click()
        page.wait_for_timeout(1200)
        badge = first.locator(".qrow-foot").inner_text()
        check("A11 queue approve records audit badge", "approved" in badge.lower() and "recorded" in badge.lower(), badge[:60])

        # ---------- red-team scenario run -> history ----------
        page.wait_for_selector("#scenarioList .scenario", timeout=15000)
        scen_id = page.eval_on_selector("#scenarioList [data-run]", "b => b.dataset.run")
        page.eval_on_selector("#scenarioList [data-run]",
                              "(b) => b.click()")  # first scenario
        page.wait_for_selector("#scenarioResult .scenario-metrics", timeout=20000)
        page.wait_for_timeout(600)
        hist_n = page.locator("#runHistory .hist-row").count()
        check("A12 run recorded to history (real API response)", hist_n == 1, f"{hist_n} rows")
        hc = page.locator("#historyCount").inner_text()
        check("A13 history count label", "1 recorded" in hc.lower(), hc)
        # run the SAME scenario again -> trend chart needs >=2 runs
        page.eval_on_selector("#scenarioList [data-run]", "(b) => b.click()")
        page.wait_for_timeout(2500)
        hist_n2 = page.locator("#runHistory .hist-row").count()
        check("A14 second run recorded", hist_n2 == 2, f"{hist_n2} rows")
        trend = page.locator("#runHistory .trend svg").count()
        trend_note = page.locator("#runHistory").inner_text()
        check("A15 MTTD/MTTC trend chart from real values",
              trend > 0 or "recorded runs" in trend_note, trend_note[:100])
        # comparison: tick both
        boxes = page.locator("#runHistory [data-cmp]")
        boxes.nth(0).check()
        boxes.nth(1).check()
        page.wait_for_timeout(600)
        cmp = page.locator("#histCompare .cmp-table")
        check("A16 side-by-side comparison table", cmp.count() == 1)
        if cmp.count():
            rows = page.locator("#histCompare .cmp-table tbody tr").count()
            check("A17 comparison has 7 metric rows", rows == 7, f"{rows} rows")

        # ---------- blast radius + DPDP ----------
        page.evaluate("(id => window.GraphOps.runBlast(id))('user:u-0042')")
        page.wait_for_selector("#blastRows tr", timeout=20000)
        page.wait_for_timeout(800)
        dpdp = page.locator("#dpdpCard").inner_text()
        check("A18 DPDP card visible after blast", page.locator("#dpdpCard").is_visible())
        has_contract = "regulated datasets in radius" in dpdp and "72h" in dpdp
        has_note = "not available in this backend build" in dpdp
        check("A19 DPDP: contract fields OR honest unavailable note", has_contract or has_note,
              dpdp[:110])

        # ---------- bugfix 6: drag-release must not fire blast-radius ----------
        # find a canvas point that hits a node (deterministic baseline).
        # NOTE: clearHighlights() first — otherwise the loop would mistake the
        # earlier A18 blast's "source: ..." line for a fresh hit.
        page.evaluate("() => window.GraphOps.clearHighlights()")
        page.wait_for_timeout(300)
        page.evaluate("() => document.getElementById('canvasWrap').scrollIntoView({block: 'center'})")
        page.wait_for_timeout(400)
        box = page.locator("#graphCanvas").bounding_box()
        tgt = page.evaluate("(box) => {"
            "  const ns = window.GraphOps.getGraphData().nodes;"
            "  const cx = box.width / 2, cy = box.height / 2;"
            "  let best = null, bd = 1e18;"
            "  for (const n of ns) {"
            "    const d = (n.x - cx) ** 2 + (n.y - cy) ** 2;"
            "    if (d < bd) { bd = d; best = n; }"
            "  }"
            "  return { id: best.id, vx: box.x + best.x, vy: box.y + best.y };"
            "}", box)
        hit = (tgt["vx"], tgt["vy"])
        page.mouse.click(*hit)
        page.wait_for_timeout(1000)
        ok = page.locator("#blastSource").inner_text().startswith("source:")
        check("A20 baseline click hits a real node", ok, tgt["id"])
        blasts = []
        page.on("request", lambda r: blasts.append(r.url) if "/blast-radius" in r.url else None)
        if hit:
            hx, hy = hit
            s1 = page.locator("#blastSource").inner_text()
            page.mouse.move(hx, hy)
            page.mouse.down()
            page.mouse.move(hx + 10, hy, steps=5)  # 10px drag: > 6px guard, within node hit radius
            page.mouse.up()  # browser fires click on release -> must be ignored
            page.wait_for_timeout(1500)
            s2 = page.locator("#blastSource").inner_text()
            check("A21 drag-release fires no new blast-radius request",
                  len(blasts) == 0 and s2 == s1, f"requests={len(blasts)}")
            # and a REAL click still works afterwards
            page.mouse.click(hx + 3, hy + 3)
            page.wait_for_timeout(1200)
            check("A22 genuine click still fires blast-radius", len(blasts) >= 1,
                  f"requests={len(blasts)}")

        # ---------- keyboard shortcuts ----------
        page.keyboard.press("?")
        page.wait_for_timeout(400)
        check("A23 '?' opens shortcuts overlay", page.locator("#shortcutsOverlay").is_visible())
        check("A24 overlay lists new keys",
              "R" in page.locator("#shortcutsOverlay").inner_text() and "approval queue" in
              page.locator("#shortcutsOverlay").inner_text().lower())
        page.keyboard.press("Escape")
        page.keyboard.press("a")
        page.wait_for_timeout(800)
        check("A25 'a' jumps to + refreshes approval queue",
              page.locator("#approvalQueue .qrow").count() > 0)
        page.keyboard.press("g")  # 2d -> 3d
        page.wait_for_timeout(1500)
        check("A26 'g' toggles to 3D view", page.locator("#btnView3d").evaluate(
            "b => b.classList.contains('active')"))
        page.keyboard.press("g")  # back to 2d
        # Cmd+K documents the new commands
        page.keyboard.press("Control+k")
        page.wait_for_timeout(400)
        page.fill("#paletteInput", "approval queue")
        page.wait_for_timeout(300)
        pal = page.locator("#paletteList").inner_text()
        check("A27 palette documents approval-queue commands", "approval queue" in pal.lower(), pal[:100])
        page.keyboard.press("Escape")

        # ---------- Phase B: API down ----------
        page2 = ctx.new_page()
        page2.goto(f"{FE}/?api=http://127.0.0.1:8999", wait_until="domcontentloaded")
        page2.wait_for_timeout(3000)
        check("B1 offline banner shown", page2.locator("#offlineBanner").is_visible())
        mm_off = page2.locator("#methodMetricsBody").inner_text()
        check("B2 method metrics shows explicit offline state", "offline" in mm_off.lower(), mm_off[:90])
        q_off = page2.locator("#queueSummary").inner_text()
        check("B3 approval queue shows explicit offline state", "offline" in q_off.lower(), q_off[:90])
        h_off = page2.locator("#runHistory").inner_text()
        h_rows_off = page2.locator("#runHistory .hist-row").count()
        check("B4 history keeps the browser's own run records while API is down",
              h_rows_off == 2 and "No runs recorded yet" not in h_off,
              f"{h_rows_off} rows kept offline")

        browser.close()

    fails = [r for r in results if not r[1]]
    print(f"\n{len(results)-len(fails)}/{len(results)} checks passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
