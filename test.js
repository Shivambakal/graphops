// GraphOps Automated Test Suite — 31 Defensible Unit Tests
// Covers: Graph validation, bounded path propagation, Dijkstra, choke points,
// next-target prediction, containment simulation, action ranking, threat stories, and benchmarks.
// Runnable in Node.js (`node test.js`) and in the browser.

const { NODES, EDGES, TECHNIQUES, CROWN_JEWELS } = require("./data.js");
const {
  validateGraph,
  buildAdjacency,
  critOf,
  effectiveRisk,
  riskBand,
  blastRadius,
  dijkstra,
  shortestPathsToJewels,
  chokePoints,
  techniqueFrequency,
  predictedTargets,
  simulateContainment,
  rankContainmentActions,
  generateThreatStory,
  computeScenarioDiff,
  runBenchmark,
  statsFor
} = require("./engine.js");

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }
function assert(cond, msg) { if (!cond) throw new Error(msg || "Assertion failed"); }
function assertEqual(actual, expected, msg) {
  if (actual !== expected) throw new Error(`${msg || "Equality failed"}: expected ${expected}, got ${actual}`);
}

// 1. Graph validation on clean dataset
test("01: Graph validation on clean enterprise topology", () => {
  const v = validateGraph(NODES, EDGES);
  assert(v.valid === true, "Acme dataset should validate cleanly");
  assertEqual(v.nodeCount, 38, "Should find 38 nodes");
  assertEqual(v.edgeCount, 60, "Should find 60 edges");
  assertEqual(v.errors.length, 0, "Should have 0 errors");
});

// 2. Graph validation detects missing node reference
test("02: Graph validation detects missing node references", () => {
  const badEdges = [{ from: "ws-0142", to: "non-existent-host", label: "lan" }];
  const v = validateGraph(NODES, badEdges);
  assert(v.valid === false, "Must fail validation when node is missing");
  assert(v.errors.some(e => e.includes("non-existent-host")), "Error must cite missing node");
});

// 3. Graph validation detects duplicate node ID
test("03: Graph validation detects duplicate node IDs", () => {
  const dupNodes = [...NODES, { id: "ws-0142", label: "Duplicate" }];
  const v = validateGraph(dupNodes, EDGES);
  assert(v.valid === false, "Must detect duplicate node ID");
  assert(v.errors.some(e => e.includes("Duplicate node id")), "Must cite duplicate ID");
});

// 4. Graph validation handles empty or malformed inputs
test("04: Graph validation handles empty or malformed inputs safely", () => {
  const v1 = validateGraph([], []);
  assert(v1.valid === false, "Empty node array is invalid");
  const v2 = validateGraph(null, null);
  assert(v2.valid === false, "Null graph input is handled gracefully");
});

// 5. Adjacency construction
test("05: Adjacency list construction builds forward neighbors", () => {
  const { adj } = buildAdjacency(EDGES, NODES);
  assert(Array.isArray(adj["ws-0142"]), "WS-0142 must have neighbor list");
  assert(adj["ws-0142"].length >= 2, "WS-0142 should connect to sw-corp, u-alice, vpn-gw");
});

// 6. Lateral movement bidirectional symmetry
test("06: Lateral movement enables bidirectional propagation", () => {
  const { adj } = buildAdjacency(EDGES, NODES);
  const forward = (adj["sw-corp"] || []).some(x => x.to === "sw-srv");
  const reverse = (adj["sw-srv"] || []).some(x => x.to === "sw-corp");
  assert(forward && reverse, "Network core links must allow lateral movement both ways");
});

// 7. MITRE technique resolution on edges
test("07: Technique resolution attaches MITRE metadata to edges", () => {
  const { adj } = buildAdjacency(EDGES, NODES);
  const adEdge = (adj["sw-srv"] || []).find(x => x.to === "dc01");
  assert(adEdge != null, "Must find edge to DC01");
  assertEqual(adEdge.tech.id, "T1482", "AD edge must resolve to T1482 Domain Trust Discovery");
});

// 8. Business criticality lookup and override
test("08: Business criticality lookup and dynamic override", () => {
  const ws = NODES.find(n => n.id === "ws-0142");
  assertEqual(critOf(ws), 3, "Default criticality should be 3");
  assertEqual(critOf(ws, { "ws-0142": 5 }), 5, "Override should return 5");
});

// 9. Effective risk scaling math
test("09: Effective risk scaling formula", () => {
  assertEqual(effectiveRisk(30, 3), 30, "Crit 3 is baseline 1x");
  assertEqual(effectiveRisk(30, 5), 50, "Crit 5 scales up");
  assertEqual(effectiveRisk(30, 1), 10, "Crit 1 scales down");
});

// 10. Risk band categorization
test("10: Risk band categorization thresholds", () => {
  assertEqual(riskBand(60), "high", "Risk >= 45 is high");
  assertEqual(riskBand(30), "med", "Risk between 20 and 44 is med");
  assertEqual(riskBand(10), "low", "Risk < 20 is low");
});

// 11. Bounded propagation depth 0 entry state
test("11: Bounded propagation initializes entry point at depth 0", () => {
  const res = blastRadius(NODES, EDGES, "ws-0142", 3);
  const entry = res.info["ws-0142"];
  assert(entry != null, "Entry node must exist in blast radius");
  assertEqual(entry.depth, 0, "Entry node depth must be 0");
  assertEqual(entry.score, 0, "Entry node initial score must be 0");
  assertEqual(entry.parent, null, "Entry node has no parent");
});

// 12. Bounded propagation enforces max depth boundary
test("12: Bounded propagation enforces max depth boundary", () => {
  const res = blastRadius(NODES, EDGES, "ws-0142", 2);
  Object.values(res.info).forEach(info => {
    assert(info.depth <= 2, `Node depth ${info.depth} exceeds maxDepth 2`);
  });
});

// 13. Bounded propagation monotonic score maximization
test("13: Bounded propagation maximizes reachable path score", () => {
  const res = blastRadius(NODES, EDGES, "ws-0142", 3);
  const dc01 = res.info["dc01"];
  assert(dc01 != null, "DC01 should be reached within 3 hops");
  assert(dc01.score > 0, "DC01 path score must be greater than 0");
  assert(dc01.eff > 0, "DC01 effective risk must be calculated");
});

// 14. Bounded propagation cycle safety
test("14: Bounded propagation prevents cyclic loops in path histories", () => {
  const res = blastRadius(NODES, EDGES, "ws-0142", 4);
  Object.values(res.info).forEach(info => {
    const seen = new Set();
    info.path.forEach(nodeId => {
      assert(!seen.has(nodeId), `Cycle detected in path: ${info.path.join(" -> ")}`);
      seen.add(nodeId);
    });
  });
});

// 15. First-visit layer depth consistency
test("15: Layers array correctly groups nodes by first-visit depth", () => {
  const res = blastRadius(NODES, EDGES, "ws-0142", 3);
  assert(res.layers[0].includes("ws-0142"), "Layer 0 must contain entry node");
  res.layers.forEach((layerNodes, depth) => {
    layerNodes.forEach(id => {
      assertEqual(res.info[id].depth, depth, `Node ${id} layer mismatch`);
    });
  });
});

// 16. Crown jewels detection in blast radius
test("16: Crown jewels detection in blast radius", () => {
  const res = blastRadius(NODES, EDGES, "ws-0142", 3);
  assert(res.info["dc01"] != null, "DC01 (Domain Controller) must be compromised");
  assert(res.info["db01"] != null, "DB01 (Customer DB) must be compromised");
  assertEqual(res.stats.jewelsHit, 2, "Both crown jewels hit at depth 3");
});

// 17. Dijkstra shortest path computation
test("17: Dijkstra finds shortest hop path", () => {
  const res = dijkstra(NODES, EDGES, "ws-0142", "dc01");
  assert(res != null, "Dijkstra must find path to DC01");
  assert(res.hops >= 1, "Hops must be >= 1");
  assertEqual(res.path[0], "ws-0142", "Path starts at ws-0142");
  assertEqual(res.path[res.path.length - 1], "dc01", "Path ends at dc01");
});

// 18. Dijkstra unreachable handling
test("18: Dijkstra handles unreachable targets gracefully", () => {
  // Isolate ws-0142 by excluding its immediate egress vectors (sw-corp, vpn-gw, u-alice)
  const res = dijkstra(NODES, EDGES, "ws-0142", "dc01", ["sw-corp", "vpn-gw", "u-alice"]);
  assert(res === null, "Dijkstra must return null when all egress paths are severed");
  const res2 = dijkstra(NODES, EDGES, "ws-0142", "non-existent-node");
  assert(res2 === null, "Dijkstra must return null for non-existent target");
});

// 19. Shortest paths to crown jewels includes techniques and risk
test("19: Shortest paths to crown jewels with MITRE techniques", () => {
  const blast = blastRadius(NODES, EDGES, "ws-0142", 3);
  const paths = shortestPathsToJewels(NODES, EDGES, "ws-0142", CROWN_JEWELS, blast);
  assertEqual(paths.length, 2, "Must evaluate both crown jewels");
  paths.forEach(p => {
    assert(p.path != null, `Path to ${p.jewel} must exist`);
    assert(p.techniques.length > 0, `Techniques must be attached along path to ${p.jewel}`);
    assert(p.risk > 0, "Risk score must be positive");
  });
});

// 20. Choke point identification
test("20: Choke point identification flags corporate LAN core", () => {
  const chokes = chokePoints(NODES, EDGES, "ws-0142", CROWN_JEWELS);
  assert(chokes.length > 0, "Must identify intermediate choke points");
  assertEqual(chokes[0].id, "sw-corp", "SW-CORP must be the top choke point");
  assertEqual(chokes[0].count, 2, "SW-CORP must be on both crown jewel paths");
});

// 21. Choke point leverage percentage
test("21: Choke point calculates path leverage percentage", () => {
  const chokes = chokePoints(NODES, EDGES, "ws-0142", CROWN_JEWELS);
  const topChoke = chokes[0];
  assertEqual(topChoke.leveragePct, 100, "Top choke point covers 100% of discovered jewel paths");
});

// 22. Technique frequency aggregation
test("22: Technique frequency aggregates across compromised paths", () => {
  const blast = blastRadius(NODES, EDGES, "ws-0142", 3);
  const freqs = techniqueFrequency(blast);
  assert(freqs.length >= 2, "Must aggregate multiple MITRE techniques");
  assert(freqs.some(f => f.id === "T1018"), "Must include T1018 Discovery");
});

// 23. Predicted next targets multi-factor scoring
test("23: Predicted next targets ranks frontier nodes", () => {
  // Depth 1 blast radius has plenty of uncompromised frontier
  const blast = blastRadius(NODES, EDGES, "ws-0142", 1);
  const preds = predictedTargets(NODES, EDGES, blast, CROWN_JEWELS);
  assert(preds.length > 0, "Must predict next reachable targets");
  assert(preds[0].confidencePct >= 50, "Predicted confidence must be >= 50%");
  assert(preds[0].reasons.length >= 2, "Prediction must provide structured explainable reasons");
});

// 24. Predicted next targets crown jewel proximity bonus
test("24: Predicted next targets prioritizes proximity to crown jewels", () => {
  const blast = blastRadius(NODES, EDGES, "ws-0142", 1);
  const preds = predictedTargets(NODES, EDGES, blast, CROWN_JEWELS);
  const highValue = preds.find(p => p.id === "sw-srv" || p.id === "dc01" || p.id === "db01");
  assert(highValue != null, "Frontier prediction must flag high-value route nodes");
});

// 25. Containment simulation isolating single node
test("25: Containment simulation quarantining initial foothold", () => {
  const sim = simulateContainment(NODES, EDGES, "ws-0142", 3, ["ws-0142"]);
  assertEqual(sim.after.compromised, 0, "Isolating foothold eliminates blast radius");
  assertEqual(sim.after.jewelsHit, 0, "Crown jewels are completely shielded");
  assertEqual(sim.delta.riskReductionPct, 100, "100% risk reduction when isolating entry point");
});

// 26. Containment simulation isolating choke point
test("26: Containment simulation isolating SW-CORP choke point", () => {
  const sim = simulateContainment(NODES, EDGES, "ws-0142", 3, ["sw-corp"]);
  assertEqual(sim.after.jewelsHit, 0, "Blocking SW-CORP prevents reaching DC01 and DB01");
  assert(sim.delta.riskReductionPct >= 70, `Expected >= 70% risk reduction, got ${sim.delta.riskReductionPct}%`);
  assertEqual(sim.delta.jewelsSaved, 2, "Protects 2 crown jewels");
});

// 27. Containment risk reduction percentage math
test("27: Containment risk reduction bounded percentage math", () => {
  const sim = simulateContainment(NODES, EDGES, "ws-0142", 3, ["u-alice"]);
  assert(sim.delta.riskReductionPct >= 0 && sim.delta.riskReductionPct <= 100, "Risk reduction must be between 0% and 100%");
});

// 28. Action ranking engine recommends optimal containment
test("28: Action ranking engine recommends highest leverage choke point", () => {
  const ranked = rankContainmentActions(NODES, EDGES, "ws-0142", 3, ["ws-0142", "sw-corp", "u-alice", "svc-backup"]);
  assert(ranked.recommended != null, "Must provide recommended action");
  assert(ranked.rankedActions.length >= 4, "Must rank all evaluated candidate actions");
  // SW-CORP or WS-0142 should have highest risk reduction
  assert(ranked.recommended.riskReductionPct >= 80, "Top action must provide >= 80% risk reduction");
  assert(ranked.recommended.reasons.length >= 2, "Recommended action must have structured explainable rationale");
});

// 29. Threat story deterministic narrative generation
test("29: Deterministic threat story narrative generation", () => {
  const blast = blastRadius(NODES, EDGES, "ws-0142", 3);
  const paths = shortestPathsToJewels(NODES, EDGES, "ws-0142", CROWN_JEWELS, blast);
  const chokes = chokePoints(NODES, EDGES, "ws-0142", CROWN_JEWELS);
  const ranked = rankContainmentActions(NODES, EDGES, "ws-0142", 3);
  const story = generateThreatStory(blast, paths, chokes, ranked, NODES);

  assert(story.title.includes("WS-0142"), "Title cites compromised foothold");
  assert(story.foothold.includes("breach established"), "Narrative describes initial foothold");
  assert(story.impact.includes("Crown Jewel"), "Narrative describes crown jewel impact");
  assert(story.containment.includes("risk reduction"), "Narrative includes recommended containment");
  assertEqual(story.workflow.length, 4, "Workflow has 4 progression stages");
});

// 30. Scenario diff computation
test("30: Scenario diff computation", () => {
  const stateA = blastRadius(NODES, EDGES, "ws-0142", 1);
  const stateB = blastRadius(NODES, EDGES, "ws-0142", 3);
  const diff = computeScenarioDiff(stateA, stateB);
  assert(diff.nodesAdded.length > 0, "Diff identifies newly reachable nodes as depth increases");
  assert(diff.countDelta > 0, "Count delta must be positive");
});

// 31. Live performance benchmark execution under threshold
test("31: Performance benchmark execution under 25ms threshold", () => {
  const bm = runBenchmark(NODES, EDGES, "ws-0142", 3);
  assert(bm.avgRuntimeMs < 25, `Engine runtime must be under 25ms, got ${bm.avgRuntimeMs}ms`);
  assertEqual(bm.scaling.length, 4, "Scaling projections cover 38, 100, 500, 1000 nodes");
});

// Run all tests
console.log("=================================================");
console.log("GRAPHOPS ENGINE TEST SUITE (31 TESTS)");
console.log("=================================================");
let passed = 0;
let failed = 0;
const tStart = Date.now();

tests.forEach((t, i) => {
  try {
    t.fn();
    console.log(`  ✔ PASS [${String(i + 1).padStart(2, "0")}/31] ${t.name}`);
    passed++;
  } catch (err) {
    console.error(`  ✖ FAIL [${String(i + 1).padStart(2, "0")}/31] ${t.name}`);
    console.error(`     Error: ${err.message}`);
    failed++;
  }
});

const tEnd = Date.now();
console.log("=================================================");
console.log(`RESULTS: ${passed}/${tests.length} PASS (${failed} failures) in ${tEnd - tStart}ms`);
console.log("=================================================");

if (typeof module !== "undefined" && module.exports) {
  module.exports = { tests, runAll: () => ({ passed, failed, total: tests.length }) };
}
if (failed > 0) process.exit(1);
