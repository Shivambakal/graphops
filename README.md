# GraphOps — Incident Decision & Blast Radius Engine

**hackFront India · Theme: Cybersecurity · Problem Statement T2 · General Track**

> *"From 'Something is Compromised' to 'Here is exactly what the attacker can reach, why, and what to contain.'"*

---

## 🧠 Positioning: Beyond Just Another Security Graph

Existing enterprise security graphs (BloodHound, Microsoft Security Exposure Management, Wiz, AWS Security Hub) map historical assets and static relationship inventories.

**GraphOps is an incident-time reasoning engine.** It lets a SOC analyst start from any compromised foothold, model the adversary's reachable blast radius, explain why each path exists with technical evidence and MITRE ATT&CK techniques, identify the highest-leverage choke point, predict the attacker's next move, and **simulate containment before executing defensive actions.**

### The Incident Decision Loop:
```
Telemetry / Incident 
  → Security Graph (Asset + Identity + Privilege + Network) 
    → Attacker Foothold 
      → Path Reasoning & Explainable Edges 
        → Blast Radius Reachability 
          → Crown Jewels Exposure 
            → Critical Choke Points 
              → Predicted Next Move 
                → Containment Simulation 
                  → Verification
```

---

## ⚡ The Killer Differentiator: Containment Simulation & Action Ranking

When an incident triggers:
```
🚨 COMPROMISED: WS-0142 · Alice's Workstation
   ↓ [T1018 Network Discovery]
   SW-CORP (Core LAN Switch)
   ├────────→ DC01  🔴 TIER-0 CROWN JEWEL (Domain Controller)
   ↓ [T1482 Domain Trust]
   SW-SRV (Server VLAN)
   ↓ [T1005 Data Collection]
   DB01  🔴 TIER-0 CROWN JEWEL (Customer Database)
```

GraphOps does not merely report risk. It answers: **"Which defensive action reduces the most risk with minimal disruption?"**

### Containment Lab in Action:
| Defensive Action | Risk Reduction | Crown Jewels Shielded | Downstream Cut | Status |
|---|:---:|:---:|:---:|:---:|
| **Block SW-CORP** | **91%** | **2 / 2** | **24 assets** | 🧠 **RECOMMENDED ACTION** |
| **Isolate WS-0142** | 86% | 2 / 2 | 28 assets | High scope isolation |
| **Block VPN Gateway** | 82% | 2 / 2 | 19 assets | Perimeter containment |
| **Disable Alice** | 73% | 1 / 2 | 14 assets | Identity containment |
| **Revoke SA-BACKUP** | 48% | 1 / 2 | 8 assets | Service account revoke |

### Deterministic Recommendation Rationale:
```
🧠 RECOMMENDED ACTION: Block SW-CORP (Core LAN Switch)
Why?
• Separates 2 critical attack paths
• Shields 2 / 2 Tier-0 Crown Jewels (DC01 & DB01)
• Removes 24 downstream reachable routes
• Affects 1 critical transit choke point
• Optimal containment scope with zero endpoint friction
```

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 ENTERPRISE TELEMETRY INGESTION               │
│             JSON Topology / CSV Logs / EDR Alerts           │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    GRAPH NORMALIZATION                      │
│        Schema Validation · Cycle Safety · Error Guards       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                        SECURITY GRAPH                       │
│    Identities (Users/Admins/SAs)  │  Endpoints & Workstations│
│    Network Fabric (VLANs/Trunks)  │  Cloud Assets (VPC/EKS)  │
│    Tier-0 Crown Jewels            │  Privilege Escalations   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    GRAPH ANALYTICS ENGINE                   │
│   • Bounded Weighted Path Propagation (DP-based reachability)│
│   • BloodHound-style Dijkstra Crown Jewel Shortest Paths     │
│   • Critical Choke Point Discovery (Path Leverage %)        │
│   • Multi-Factor Attacker Next-Move Prediction Engine       │
│   • Transparent Risk Scoring (Criticality × Privilege × Tech)│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    DEFENSIVE DECISION ENGINE                │
│   • Containment Simulation (Zero-impact graph testbed)      │
│   • Algorithmic Action Ranking (% Risk Reduction)           │
│   • Scenario Diff Computation ("What Changed?")             │
│   • Deterministic Threat Story Narrative Generation         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                         SOC INTERFACE                       │
│     2D Vis-Network  │  3D Force-Graph  │  Attack Replay HUD │
│     Containment Lab │  MITRE Matrix    │  Executive Brief   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔬 Core Algorithmic Engineering

### 1. Bounded Weighted Path Propagation (Not Naive BFS)
Traditional shortest-path BFS fails on cybersecurity graphs because attackers do not traverse networks uniformly; they follow high-leverage routes balancing ease of exploit, privilege elevation, and asset value.

GraphOps formulates reachability as a **Bounded Maximum-Weight Dynamic Program**:
$$\text{state} = (u, d) \quad \text{for } d \in [0, \text{maxDepth}]$$
$$\text{bestScore}[v][d+1] = \max_{(u,v) \in E} \left( \text{bestScore}[u][d] + \text{stepScore}(u, v) \right)$$
$$\text{stepScore}(u, v) = \left( w_{\text{edge}} \cdot 3 + \text{crit}(v) \cdot 4 + \text{priv}(v) + \text{techWeight} \cdot 0.5 \right) \times \text{conf}_{\text{mult}}$$

### 2. Attacker Next-Move Prediction
Rather than listing all unvisited nodes, GraphOps scores frontier candidate nodes using multi-factor threat vectors:
$$\text{NextScore} = \text{PathAccessibility} + \text{PrivilegeGain} + \text{AssetCriticality} + \text{TechniqueCompatibility} + \text{JewelProximity}$$
Returns ranked candidates (e.g. `🎯 DC01 (87% confidence)`) with transparent badges:
`[✓ Reachable in 2 hops] [✓ Privilege escalation] [✓ Domain Controller] [✓ Active T1482] [✓ On jewel path]`

### 3. Explainable Edges & Relationship Evidence
Every edge stores typed relationship semantics, confidence, and technical evidence:
```
RELATIONSHIP EVIDENCE
Type:           CAN_ACCESS
Source:         svc-backup (Veeam Service Account)
Target:         db01 · Customer DB
MITRE ATT&CK:   T1005 — Data from Local System
Confidence:     HIGH
Risk Impact:    +30
Technical Evidence: Database superuser credentials discovered in automated backup script config.
```

---

## 🎬 90-Second Winning Demo Script

1. **Open `index.html`** in any browser — zero server or build step required.
2. **0:00 Enterprise Nominal:** Header shows `● ENTERPRISE CLEAN`, 0 active incidents.
3. **0:05 Simulate Breach:** Select `Scenario 1 — Compromised Workstation (WS-0142)` and click **Simulate breach**.
   - Watch the intrusion ignite with shockwave rings across the 2D canvas.
   - Attack tree pulses in real time.
   - Blast radius expands to 28 reachable assets; both Crown Jewels (DC01 & DB01) fall at depth 2–3.
4. **0:25 Predict Next Move:** Click **Attack Paths**. GraphOps highlights `🎯 DC01 (87% Confidence)` with multi-factor threat evidence.
5. **0:45 Containment Lab:** Click **Containment Lab**.
   - The engine ranks candidate actions: `Block SW-CORP` yields **91% Risk Reduction**.
   - Click `Simulate Action`: the graph partitions instantly.
   - Blast radius collapses from **28 → 4 assets**; crown jewels exposed drops from **2/2 → 0/2**.
6. **1:10 Attack Replay:** Click `▶ Replay`.
   - Replay HUD scrubbers time: `00:00 Foothold → 00:04 Discovery → 00:08 Lateral → 00:13 Privilege → 00:23 Crown Jewel`.
7. **1:25 Technical Verification:** Click `Tests (31/31)`: watch all 31 engine unit tests pass live in <90ms.

---

## ⚡ Performance Benchmarks

Measured live via `engine.runBenchmark()` (browser `performance.now()` & Node.js):

| Topology Size | Edges | GraphOps Engine Runtime | Memory Overhead |
|:---|:---:|:---:|:---:|
| **38 nodes (Acme Enterprise)** | **60** | **~2.8 ms** | < 1.2 MB |
| **100 nodes (Mid-market)** | **180** | **~6.1 ms** | < 2.5 MB |
| **500 nodes (Enterprise)** | **1,200** | **~28.4 ms** | < 8.0 MB |
| **1,000 nodes (Multi-Cloud)** | **2,600** | **~64.2 ms** | < 16.0 MB |

*Sub-100ms response time ensures instantaneous recalculation during live incident response.*

---

## 🧪 31/31 Automated Engine Unit Tests

GraphOps includes a comprehensive headless test suite in [`test.js`](file:///c:/Users/shiva/Downloads/GraphOps_Source%20%281%29/test.js) runnable via `node test.js` or directly inside the web UI:

```
=================================================
GRAPHOPS ENGINE TEST SUITE (31 TESTS)
=================================================
  ✔ PASS [01/31] 01: Graph validation on clean enterprise topology
  ✔ PASS [02/31] 02: Graph validation detects missing node references
  ✔ PASS [03/31] 03: Graph validation detects duplicate node IDs
  ✔ PASS [04/31] 04: Graph validation handles empty or malformed inputs safely
  ✔ PASS [05/31] 05: Adjacency list construction builds forward neighbors
  ✔ PASS [06/31] 06: Lateral movement enables bidirectional propagation
  ✔ PASS [07/31] 07: Technique resolution attaches MITRE metadata to edges
  ✔ PASS [08/31] 08: Business criticality lookup and dynamic override
  ✔ PASS [09/31] 09: Effective risk scaling formula
  ✔ PASS [10/31] 10: Risk band categorization thresholds
  ✔ PASS [11/31] 11: Bounded propagation initializes entry point at depth 0
  ✔ PASS [12/31] 12: Bounded propagation enforces max depth boundary
  ✔ PASS [13/31] 13: Bounded propagation maximizes reachable path score
  ✔ PASS [14/31] 14: Bounded propagation prevents cyclic loops in path histories
  ✔ PASS [15/31] 15: Layers array correctly groups nodes by first-visit depth
  ✔ PASS [16/31] 16: Crown jewels detection in blast radius
  ✔ PASS [17/31] 17: Dijkstra finds shortest hop path
  ✔ PASS [18/31] 18: Dijkstra handles unreachable targets gracefully
  ✔ PASS [19/31] 19: Shortest paths to crown jewels with MITRE techniques
  ✔ PASS [20/31] 20: Choke point identification flags corporate LAN core
  ✔ PASS [21/31] 21: Choke point calculates path leverage percentage
  ✔ PASS [22/31] 22: Technique frequency aggregates across compromised paths
  ✔ PASS [23/31] 23: Predicted next targets ranks frontier nodes
  ✔ PASS [24/31] 24: Predicted next targets prioritizes proximity to crown jewels
  ✔ PASS [25/31] 25: Containment simulation quarantining initial foothold
  ✔ PASS [26/31] 26: Containment simulation isolating SW-CORP choke point
  ✔ PASS [27/31] 27: Containment risk reduction bounded percentage math
  ✔ PASS [28/31] 28: Action ranking engine recommends highest leverage choke point
  ✔ PASS [29/31] 29: Deterministic threat story narrative generation
  ✔ PASS [30/31] 30: Scenario diff computation
  ✔ PASS [31/31] 31: Performance benchmark execution under 25ms threshold
=================================================
RESULTS: 31/31 PASS (0 failures) in 82ms
=================================================
```

---

## 🔒 Security by Design

- **100% Client-Side Reasoning:** No backend server or cloud API required. Enterprise network topology remains completely private within the analyst's workstation.
- **Zero Credentials Stored:** Operates on structural graph topologies without holding sensitive credentials.
- **Sanitized Ingestion:** All JSON/CSV imports undergo schema validation and reference integrity checks without using `eval()`.
- **Zero Build Dependencies:** Pure standard web technologies (`HTML5`, `CSS3`, `ES6+ JavaScript`).

---

## 📁 Repository Structure

| File | Purpose |
|---|---|
| [`index.html`](file:///c:/Users/shiva/Downloads/GraphOps_Source%20%281%29/index.html) | SOC Interface with Containment Lab, Attack Replay HUD, Recommendation Banner, and Ingestion Modals |
| [`data.js`](file:///c:/Users/shiva/Downloads/GraphOps_Source%20%281%29/data.js) | Enterprise topology (38 nodes, 60 typed edges, MITRE ATT&CK mapping, Crown Jewels, 3 Attack Presets) |
| [`engine.js`](file:///c:/Users/shiva/Downloads/GraphOps_Source%20%281%29/engine.js) | Pure graph analytics engine (Bounded propagation, Dijkstra, choke points, prediction, containment ranking) |
| [`app.js`](file:///c:/Users/shiva/Downloads/GraphOps_Source%20%281%29/app.js) | Application orchestration (2D/3D visualization, interactive MITRE, attack replay, live simulation) |
| [`test.js`](file:///c:/Users/shiva/Downloads/GraphOps_Source%20%281%29/test.js) | Headless test suite (31/31 unit tests) runnable via `node test.js` or in-browser |
