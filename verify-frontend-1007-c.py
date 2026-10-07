"""Frontend verification round C — REAL backend contract checks (no stubs).

Assumes a uvicorn server with the NEW backend (GET /redteam/scenarios,
POST /redteam/run/{id}) is already running at 8010.

  D1 real scenarios listed from GET /redteam/scenarios (contract label names it)
  D2 real scenario run: verdict "DETECTED 5/7 stages" + MTTD/MTTC/blast-precision
  D3 stage timeline renders: 7 stage chips, hit+miss classes present
  D4 copy-demo-script clipboard carries the real measured numbers
  D5 method filter: options populated from evidence_chain.detection_method;
       selecting oauth_scope_creep narrows the feed to that method only
"""
import json, sys

API = "http://127.0.0.1:8010"
results = []
def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, detail)

def main():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        ctx = browser.new_context(viewport={"width": 1600, "height": 950},
                                  permissions=["clipboard-read", "clipboard-write"])
        pg = ctx.new_page()
        pg.goto(f"{API}/?api={API}", wait_until="networkidle")
        pg.wait_for_timeout(2800)

        check("D1a online", "online" in pg.locator("#healthLine").inner_text().lower())
        nsc = pg.locator("#scenarioList .scenario").count()
        check("D1b real scenarios listed", nsc >= 1, f"{nsc} scenarios")
        check("D1c contract label = redteam",
              "GET /redteam/scenarios" in pg.locator("#scenarioStatus").inner_text())
        check("D1d bridge contract = redteam",
              pg.evaluate("() => window.GraphOps.getScenarioContract()") == "redteam")

        rid = pg.evaluate("() => window.GraphOps.getScenarios()[0].id")
        pg.evaluate(f"(id => window.GraphOps.runScenario(id))({json.dumps(rid)})")
        pg.wait_for_timeout(3000)
        res = pg.locator("#scenarioResult").inner_text()
        check("D2a real verdict with coverage", "DETECTED" in res and "5/7" in res,
              res[:110].replace("\n", " "))
        nums = [n for n in ["1,800", "2.4"] if n in res]
        check("D2b real metrics (MTTC 1800, precision 2.4%)", len(nums) == 2, res[:110].replace("\n", " "))
        chips = pg.locator("#scenarioResult .stage-timeline .stage").count()
        hits = pg.locator("#scenarioResult .stage-timeline .stage.hit").count()
        miss = pg.locator("#scenarioResult .stage-timeline .stage.miss").count()
        check("D3a stage timeline renders 7 chips", chips == 7, f"{chips} chips")
        check("D3b hit+miss classes", hits >= 1 and miss >= 1, f"hit={hits} miss={miss}")

        pg.click("#btnCopyDemoScript")
        pg.wait_for_timeout(800)
        clip = pg.evaluate("() => navigator.clipboard.readText()")
        check("D4 clipboard has real numbers + human gate",
              "5/7" in clip and "2.4%" in clip and "nothing auto-executes" in clip, clip[:100])

        # D5: method filter fed by evidence_chain.detection_method
        pg.click("#btnRunHunt")
        pg.wait_for_timeout(2500)
        mopts = pg.locator("#huntMethod option").count()
        check("D5a method options populated", mopts > 1, f"{mopts} options")
        vals = pg.locator("#huntMethod option").evaluate_all("els => els.map(e => e.value)")
        check("D5b oauth_scope_creep option present", "oauth_scope_creep" in vals)
        pg.select_option("#huntMethod", "oauth_scope_creep")
        pg.wait_for_timeout(2000)
        n = pg.locator("#findingsList .finding").count()
        meths = pg.evaluate("() => window.GraphOps.getFindings().map(f => f.method)")
        check("D5c method filter narrows feed", n >= 1 and all(m == "oauth_scope_creep" for m in meths),
              f"{n} card(s), methods={meths}")
        browser.close()

    fails = [r for r in results if not r[1]]
    print(f"\n{len(results)-len(fails)}/{len(results)} checks passed")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
