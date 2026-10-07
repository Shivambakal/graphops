"""Headless Playwright verification for the GraphOps frontend (build/frontend-1007).

Phase A: real backend (uvicorn graphops.api.server:app) — verifies online boot,
hunt feed, filters, pagination, blast radius with DPDP fallback note, and the
demo-scenarios 'not available in this build' state (endpoint not yet shipped).
Phase B: Playwright route interception stubs the NEW contract fields
(regulated_datasets, notification_scope, data_classification, GET /demo-scenarios,
POST /demo-scenarios/{id}/run) — verifies the DPDP card, regulated badges,
3D regulated halos, scenario run metrics, and copy-demo-script text.
"""
import sys, time, json
from playwright.sync_api import sync_playwright

API = "http://127.0.0.1:8010"
FE = "http://127.0.0.1:8010"  # API serves the dashboard at / (same origin, no CORS)

CONTRACT_BLAST = {
    "blast_radius": {
        "host:ws-001": {"distance": 0, "risk_score": 100.0, "data_classification": "confidential"},
        "dataset:customer-pii": {"distance": 1, "risk_score": 85.0, "data_classification": "regulated", "regulated_reachable": True},
        "dataset:finance-ledger": {"distance": 2, "risk_score": 60.0, "data_classification": "regulated", "regulated_reachable": True},
        "ip:203.0.113.22": {"distance": 1, "risk_score": 60.0, "data_classification": "public"},
    },
    "actions": [],
    "regulated_datasets": [
        {"dataset_id": "customer-pii", "name": "customer-pii", "classification": "regulated",
         "nodes_exposed": 3, "records_exposed_est": 48210},
        {"dataset_id": "finance-ledger", "name": "finance-ledger", "classification": "regulated",
         "nodes_exposed": 1, "records_exposed_est": 8120},
    ],
    "notification_scope": {
        "dpdp_72h_required": True,
        "affected_individuals_est": 48210,
        "datasets": ["customer-pii", "finance-ledger"],
    },
}
CONTRACT_SCENARIOS = [
    {"id": "token-theft-escalation", "name": "Token theft → lateral movement", "description": "Stolen OAuth token creeps scopes, moves laterally, stages data.", "severity": "critical", "steps": ["phish token", "scope creep", "lateral smb", "stage", "exfil"]},
    {"id": "impossible-travel", "name": "Impossible travel login", "description": "Same identity, two continents in 8 minutes.", "severity": "high", "steps": ["login US", "login IN"]},
]
CONTRACT_RUN = {
    "detected": True, "mttd_seconds": 41.3, "mttc_seconds": 182.0,
    "false_positives": 2, "blast_radius_precision": 91.7,
    "findings": [{"title": "OAuth scope creep", "severity": "critical", "nodes": ["dataset:customer-pii"]}],
}

results = []
def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, detail)

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1600, "height": 950},
                                  permissions=["clipboard-read", "clipboard-write"])
        page = ctx.new_page()
        page.goto(f"{FE}/?api={API}", wait_until="networkidle")
        page.wait_for_timeout(2500)

        # ---- Phase A: real backend ----
        check("A1 boot: no boot overlay trap", page.locator("#boot").count() == 0 or not page.locator("#boot").is_visible(), "")
        check("A2 api online", "online" in page.locator("#healthLine").inner_text().lower())
        check("A3 offline banner hidden", page.locator("#offlineBanner").is_hidden())

        page.click("#btnRunHunt")
        page.wait_for_timeout(2500)
        n = page.locator("#findingsList .finding").count()
        check("A4 hunt renders findings (real API)", n > 0, f"{n} cards")

        page.select_option("#huntSeverity", "critical")
        page.wait_for_timeout(2000)
        n2 = page.locator("#findingsList .finding").count()
        all_crit = all("critical" in (page.locator("#findingsList .finding").nth(i).get_attribute("class") or "")
                       for i in range(n2)) if n2 else True
        check("A5 severity filter applies (fallback mode)", n2 > 0 and all_crit, f"{n2} critical cards")
        page.select_option("#huntSeverity", "")  # reset
        page.wait_for_timeout(2000)

        mopts = page.locator("#huntMethod option").count()
        check("A6 method options populated from real detection_methods", mopts > 1, f"{mopts} options")
        page.select_option("#huntMethod", "oauth_scope_creep")
        page.wait_for_timeout(2000)
        n3 = page.locator("#findingsList .finding").count()
        check("A6b method filter narrows feed (fallback mode)", n3 == 1, f"{n3} card(s)")
        page.select_option("#huntMethod", "")
        page.wait_for_timeout(2000)

        page.select_option("#huntLimit", "3")
        page.wait_for_timeout(1500)
        pb_visible = page.locator("#pageBar").is_visible()
        check("A7 pagination bar appears when total > limit", pb_visible,
              page.locator("#pageInfo").inner_text() if pb_visible else "(hidden)")
        if pb_visible:
            info1 = page.locator("#pageInfo").inner_text()
            page.click("#btnNextPage")
            page.wait_for_timeout(1500)
            info2 = page.locator("#pageInfo").inner_text()
            check("A8 next page advances offset", info1 != info2, f"{info1} -> {info2}")
            page.click("#btnPrevPage")
            page.wait_for_timeout(1500)

        # blast radius on a real node (via bridge to avoid canvas pixel picking)
        node = page.evaluate("() => window.GraphOps.getGraphData().nodes[0].id")
        page.evaluate(f"(id => window.GraphOps.runBlast(id))({json.dumps(node)})")
        page.wait_for_timeout(3000)
        check("A9 blast table renders (real API)", page.locator("#blastRows tr").count() > 0)
        dpdp_txt = page.locator("#dpdpCard").inner_text()
        dpdp_known_state = (
            "72h breach notification required" in dpdp_txt
            or "No 72h notification obligation flagged" in dpdp_txt
            or "not available in this backend build" in dpdp_txt
        )
        check("A10 DPDP card renders a real API state (never invented)", 
              page.locator("#dpdpCard").is_visible() and dpdp_known_state,
              dpdp_txt[:100].replace("\n", " "))
        nsc_real = page.locator("#scenarioList .scenario").count()
        check("A11 scenarios listed from REAL new backend (GET /demo-scenarios)",
              nsc_real >= 1, f"{nsc_real} scenarios")
        if nsc_real:
            real_id = page.evaluate("() => window.GraphOps.getScenarios()[0].id")
            page.evaluate(f"(id => window.GraphOps.runScenario(id))({json.dumps(real_id)})")
            page.wait_for_timeout(3000)
            real_res = page.locator("#scenarioResult").inner_text()
            has_verdict = "DETECTED" in real_res
            import re as _re
            nums = _re.findall(r"\d+\.?\d*", real_res)
            check("A12 real scenario run: verdict + measured numbers",
                  has_verdict and len(nums) >= 2, real_res[:110].replace("\n", " "))
        check("A13 tour button visible after blast", page.locator("#btnBlastTour").is_visible())

        # ---- Phase B: stubbed contract responses ----
        def blast_route(route):
            route.fulfill(status=200, content_type="application/json", body=json.dumps(CONTRACT_BLAST))
        def scen_route(route):
            route.fulfill(status=200, content_type="application/json", body=json.dumps({"scenarios": CONTRACT_SCENARIOS}))
        def run_route(route):
            route.fulfill(status=200, content_type="application/json", body=json.dumps(CONTRACT_RUN))
        page.route(f"{API}/blast-radius", blast_route)
        page.route(f"{API}/demo-scenarios", scen_route)
        page.route(f"{API}/demo-scenarios/*/run", run_route)

        page.reload(wait_until="networkidle")
        page.wait_for_timeout(2500)
        nsc = page.locator("#scenarioList .scenario").count()
        check("B1 scenarios listed from contract", nsc == 2, f"{nsc} scenarios")

        page.locator("#scenarioList [data-run]").first.click()
        page.wait_for_timeout(2000)
        res_txt = page.locator("#scenarioResult").inner_text()
        check("B2 detected badge renders", "DETECTED" in res_txt)
        for needle in ["41.3", "182", "91.7"]:
            check(f"B3 metric {needle} from API", needle in res_txt, res_txt[:160])
        check("B4 copy-demo-script button present", page.locator("#btnCopyDemoScript").count() == 1)
        page.click("#btnCopyDemoScript")
        page.wait_for_timeout(800)
        clip = page.evaluate("() => navigator.clipboard.readText()")
        check("B5 clipboard has judge narration with real numbers",
              "Token theft" in clip and "41.3s" in clip and "91.7%" in clip and "nothing auto-executes" in clip,
              clip[:90])

        page.evaluate("(id => window.GraphOps.runBlast(id))('host:ws-001')")
        page.wait_for_timeout(3000)
        dpdp2 = page.locator("#dpdpCard").inner_text()
        check("B6 DPDP 72h notice card (contract)", "72h breach notification required" in dpdp2, dpdp2[:90])
        check("B7 affected individuals estimate", "48,210" in dpdp2)
        check("B8 regulated dataset badges", page.locator("#dpdpCard .dpdp-dataset").count() == 2)
        check("B9 regulated row badges in blast table", page.locator("#blastRows .dc-regulated").count() == 2,
              f"{page.locator('#blastRows .dc-regulated').count()} badges")
        check("B10 blast source line counts regulated", "2 regulated" in page.locator("#blastSource").inner_text())

        # 3D: init, regulated halos
        page.evaluate("() => window.UI.setView('3d')")
        page.wait_for_timeout(2500)
        dbg = page.evaluate("() => window.Graph3D.debug()")
        check("B11 3D regulated halos exist (contract set)", dbg.get("halos", 0) >= 2, str(dbg))

        # 3D tour capability exists (WebGL may be software-rendered headless; just verify the function runs)
        tour_ok = page.evaluate("() => window.Graph3D.tourBlast([{id: 'host:ws-001'}])")
        check("B12 tourBlast returns true with contract rows", tour_ok is True)

        # regulated node click -> blast + DPDP jump (stubbed contract data)
        page.evaluate("(id => window.GraphOps.clickNode(id))('dataset:customer-pii')")
        page.wait_for_timeout(2500)
        in_reg = page.evaluate("() => (window.GraphOps.getDpdp().regulatedNodes || []).includes('dataset:customer-pii')")
        check("B13 regulated click lands in DPDP regulated set", in_reg is True)
        check("B14 DPDP card visible after regulated click", page.locator("#dpdpCard").is_visible())

        browser.close()

    fails = [r for r in results if not r[1]]
    print(f"\n{len(results)-len(fails)}/{len(results)} checks passed")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
