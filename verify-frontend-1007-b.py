"""Frontend verification round B (build/frontend-1007b) — GraphOps dashboard.

Covers the 2026-10-07 frontend features (dual-contract red-team runner,
decision-queue persistence badge, data-classification color toggle,
offline retry, queue empty state, 3D empty guard, new shortcuts/palette):
  C1 offline states: banner + retry button, queue empty state, scenario offline line
  C2 color-mode toggle (button + keyboard X), 2D canvasStatus updates
  C3 persistence badge: persisted -> Supabase (stub true) and in-memory only (stub false)
  C4 queue empty state before any blast
  C5 redteam contract preferred: scenarios from GET /redteam/scenarios, run via POST /redteam/run/{id}
  C5b legacy fallback: /redteam/scenarios 404 -> GET /demo-scenarios used, run via legacy run URL
  C6 both contracts 404 -> explicit "not available in this backend build"
  C7 keyboard: X flips color mode; T with no blast toasts the guidance
  C8 3D empty guard: setView('3d') returns false on empty graph, stays in 2D
  C9 palette exposes tour / color-toggle / retry commands
Spawns its own uvicorn on 8011 from build/.venv; kills it at the end.
"""
import json, subprocess, sys, time, urllib.request

BUILD = "/home/hatch/workspace/hackfront-india/build"
VENV_PY = BUILD + "/.venv/bin/python"
API = "http://127.0.0.1:8011"

CONTRACT_SCENARIOS = [
    {"id": "token-theft-escalation", "name": "Token theft → lateral movement",
     "description": "Stolen OAuth token creeps scopes, moves laterally, stages data.",
     "severity": "critical", "steps": ["phish token", "scope creep", "lateral smb", "stage", "exfil"]},
    {"id": "impossible-travel", "name": "Impossible travel login",
     "description": "Same identity, two continents in 8 minutes.",
     "severity": "high", "steps": ["login US", "login IN"]},
]
CONTRACT_RUN = {
    "detected": True, "mttd_seconds": 41.3, "mttc_seconds": 182.0,
    "false_positives": 2, "blast_radius_precision": 91.7,
}

results = []
def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, detail)

def wait_api():
    for _ in range(60):
        try:
            urllib.request.urlopen(API + "/health", timeout=2)
            return True
        except Exception:
            time.sleep(0.5)
    return False

def main():
    srv = subprocess.Popen(
        [VENV_PY, "-m", "uvicorn", "graphops.api.server:app",
         "--host", "127.0.0.1", "--port", "8011", "--log-level", "warning"],
        cwd=BUILD, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_api():
            print("FAIL server did not boot"); sys.exit(1)
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])

            # ---------- C1: offline states ----------
            ctx1 = browser.new_context(viewport={"width": 1500, "height": 900})
            pg = ctx1.new_page()
            pg.goto(f"{API}/?api=http://127.0.0.1:9", wait_until="networkidle")
            pg.wait_for_timeout(2200)
            check("C1a offline banner visible", pg.locator("#offlineBanner").is_visible())
            check("C1b retry button present", pg.locator("#btnRetryApi").is_visible())
            check("C1c run-hunt disabled offline", pg.locator("#btnRunHunt").is_disabled())
            check("C1d queue empty state (pre-blast)", "containment queue appears" in pg.locator("#actionsList").inner_text())
            check("C1e scenario offline line", "offline" in pg.locator("#scenarioStatus").inner_text().lower())
            check("C1f hunt offline line", "offline" in pg.locator("#huntStatus").inner_text().lower())
            ctx1.close()

            # ---------- C2: color-mode toggle ----------
            ctx2 = browser.new_context(viewport={"width": 1500, "height": 900})
            pg = ctx2.new_page()
            pg.goto(f"{API}/?api={API}", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            check("C2a online boot", "online" in pg.locator("#healthLine").inner_text().lower())
            check("C2b toggle button present", pg.locator("#btnColorMode").count() == 1)
            check("C2c initial mode etype", pg.evaluate("() => window.GraphOps.getColorMode()") == "etype")
            pg.click("#btnColorMode")
            pg.wait_for_timeout(400)
            check("C2d click -> dc mode", pg.evaluate("() => window.GraphOps.getColorMode()") == "dc")
            check("C2e button label flips", "type color" in pg.locator("#btnColorMode").inner_text())
            check("C2f canvasStatus names data classification",
                  "data classification" in pg.locator("#canvasStatus").inner_text())
            check("C2g button active class", "active" in (pg.locator("#btnColorMode").get_attribute("class") or ""))
            pg.click("#btnColorMode")
            pg.wait_for_timeout(400)
            check("C2h click -> back to etype", pg.evaluate("() => window.GraphOps.getColorMode()") == "etype")
            pg.keyboard.press("x")
            pg.wait_for_timeout(400)
            check("C2i keyboard X -> dc", pg.evaluate("() => window.GraphOps.getColorMode()") == "dc")
            pg.keyboard.press("x")  # restore
            pg.wait_for_timeout(300)

            # ---------- C3: persistence badge ----------
            def decisions_route(persisted):
                def h(route):
                    route.fulfill(status=200, content_type="application/json",
                                  body=json.dumps({"decisions": [], "queue": [],
                                                   "persisted": persisted, "queue_persisted": False}))
                return h
            pg.route(f"{API}/decisions*", decisions_route(True))
            node = pg.evaluate("() => window.GraphOps.getGraphData().nodes[0].id")
            pg.evaluate(f"(id => window.GraphOps.runBlast(id))({json.dumps(node)})")
            pg.wait_for_timeout(2500)
            badge = pg.locator("#actionsList .persist-badge.ok")
            check("C3a persisted badge when store configured", badge.count() == 1,
                  badge.inner_text() if badge.count() else "(none)")
            check("C3b bridge getPersisted true", pg.evaluate("() => window.GraphOps.getPersisted()") is True)
            pg.unroute(f"{API}/decisions*")
            pg.route(f"{API}/decisions*", decisions_route(False))
            pg.reload(wait_until="networkidle")
            pg.wait_for_timeout(2500)
            node = pg.evaluate("() => window.GraphOps.getGraphData().nodes[0].id")
            pg.evaluate(f"(id => window.GraphOps.runBlast(id))({json.dumps(node)})")
            pg.wait_for_timeout(2500)
            warn = pg.locator("#actionsList .persist-badge.warn")
            check("C3c in-memory badge when store absent", warn.count() == 1,
                  warn.inner_text() if warn.count() else "(none)")
            pg.unroute(f"{API}/decisions*")

            # ---------- C4: queue empty state (fresh load, no blast) ----------
            pg.reload(wait_until="networkidle")
            pg.wait_for_timeout(2500)
            check("C4 queue empty before blast",
                  "containment queue appears" in pg.locator("#actionsList").inner_text())

            # ---------- C5: redteam contract preferred ----------
            def rt_scen(route):
                route.fulfill(status=200, content_type="application/json",
                              body=json.dumps({"scenarios": CONTRACT_SCENARIOS}))
            def rt_run(route):
                route.fulfill(status=200, content_type="application/json",
                              body=json.dumps(CONTRACT_RUN))
            pg.route(f"{API}/redteam/scenarios", rt_scen)
            pg.route(f"{API}/redteam/run/*", rt_run)
            pg.reload(wait_until="networkidle")
            pg.wait_for_timeout(2500)
            check("C5a scenarios from redteam contract",
                  pg.locator("#scenarioList .scenario").count() == 2)
            check("C5b contract label names redteam",
                  "GET /redteam/scenarios" in pg.locator("#scenarioStatus").inner_text())
            check("C5c bridge contract = redteam",
                  pg.evaluate("() => window.GraphOps.getScenarioContract()") == "redteam")
            pg.locator("#scenarioList [data-run]").first.click()
            pg.wait_for_timeout(2000)
            res = pg.locator("#scenarioResult").inner_text()
            check("C5d DETECTED + measured metrics", "DETECTED" in res and "41.3" in res and "91.7" in res,
                  res[:90].replace("\n", " "))
            check("C5e run URL footnote is /redteam/run", "/redteam/run/" in res)
            check("C5f copy-demo-script present", pg.locator("#btnCopyDemoScript").count() == 1)
            ctx2.close()

            # ---------- C5b: legacy fallback ----------
            ctx3 = browser.new_context(viewport={"width": 1500, "height": 900})
            pg = ctx3.new_page()
            def rt_404(route):
                route.fulfill(status=404, content_type="text/plain", body="not found")
            def demo_scen(route):
                route.fulfill(status=200, content_type="application/json",
                              body=json.dumps({"scenarios": CONTRACT_SCENARIOS}))
            def demo_run(route):
                route.fulfill(status=200, content_type="application/json",
                              body=json.dumps(CONTRACT_RUN))
            pg.route(f"{API}/redteam/scenarios", rt_404)
            pg.route(f"{API}/redteam/run/*", rt_404)
            pg.route(f"{API}/demo-scenarios", demo_scen)
            pg.route(f"{API}/demo-scenarios/*/run", demo_run)
            pg.goto(f"{API}/?api={API}", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            check("C5b-a falls back to demo contract",
                  pg.evaluate("() => window.GraphOps.getScenarioContract()") == "demo")
            check("C5b-b contract label names demo",
                  "GET /demo-scenarios" in pg.locator("#scenarioStatus").inner_text())
            check("C5b-c scenarios listed via fallback", pg.locator("#scenarioList .scenario").count() == 2)
            pg.locator("#scenarioList [data-run]").first.click()
            pg.wait_for_timeout(2000)
            res2 = pg.locator("#scenarioResult").inner_text()
            check("C5b-d legacy run renders metrics", "DETECTED" in res2 and "41.3" in res2)
            check("C5b-e legacy run URL footnote", "/demo-scenarios/" in res2)
            ctx3.close()

            # ---------- C6: both contracts unavailable ----------
            ctx4 = browser.new_context(viewport={"width": 1500, "height": 900})
            pg = ctx4.new_page()
            pg.route(f"{API}/redteam/scenarios", rt_404)
            pg.route(f"{API}/demo-scenarios", rt_404)
            pg.goto(f"{API}/?api={API}", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            st = pg.locator("#scenarioStatus").inner_text()
            check("C6 explicit not-available state", "not available in this backend build" in st, st[:80])
            check("C6b scenario list empty", pg.locator("#scenarioList .scenario").count() == 0)
            ctx4.close()

            # ---------- C7: keyboard shortcuts ----------
            ctx5 = browser.new_context(viewport={"width": 1500, "height": 900})
            pg = ctx5.new_page()
            pg.goto(f"{API}/?api={API}", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            pg.keyboard.press("t")  # no blast computed yet -> guidance toast
            pg.wait_for_timeout(600)
            check("C7a T with no blast -> toast guidance",
                  "Compute a blast radius first" in pg.locator("#toasts").inner_text())
            ctx5.close()

            # ---------- C8: 3D empty guard ----------
            ctx6 = browser.new_context(viewport={"width": 1500, "height": 900})
            pg = ctx6.new_page()
            def empty_graph(route):
                route.fulfill(status=200, content_type="application/json",
                              body=json.dumps({"nodes": [], "edges": []}))
            pg.route(f"{API}/graph", empty_graph)
            pg.goto(f"{API}/?api={API}", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            r3 = pg.evaluate("() => window.UI.setView('3d')")
            check("C8a setView('3d') refuses empty graph", r3 is False)
            check("C8b stays in 2D", "active" in (pg.locator("#btnView2d").get_attribute("class") or ""))
            check("C8c canvasStatus explains", "no graph data" in pg.locator("#canvasStatus").inner_text().lower())
            ctx6.close()

            # ---------- C9: palette commands ----------
            ctx7 = browser.new_context(viewport={"width": 1500, "height": 900})
            pg = ctx7.new_page()
            pg.goto(f"{API}/?api={API}", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            pg.keyboard.press("Control+k")
            pg.wait_for_timeout(600)
            pg.fill("#paletteInput", "tour")
            pg.wait_for_timeout(400)
            check("C9a palette has blast tour", "Blast-radius camera tour" in pg.locator("#paletteList").inner_text())
            pg.fill("#paletteInput", "color")
            pg.wait_for_timeout(400)
            check("C9b palette has color toggle",
                  "data classification" in pg.locator("#paletteList").inner_text())
            pg.fill("#paletteInput", "retry")
            pg.wait_for_timeout(400)
            check("C9c palette has retry", "Retry API connection" in pg.locator("#paletteList").inner_text())
            ctx7.close()

            browser.close()
    finally:
        srv.terminate()

    fails = [r for r in results if not r[1]]
    print(f"\n{len(results)-len(fails)}/{len(results)} checks passed")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
