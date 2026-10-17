# Final technical report — GNN-based distributed-attack detection & correlation

## 1. Objective and outcome
Build a reproducible, experimentally validated prototype that detects and
correlates distributed attacks against a Kubernetes microservices application by
combining network flows, workload metrics and IDS alerts into temporal
communication graphs and running Graph Neural Networks over them.

**Outcome.** A single-node lab was stood up and verified at runtime; real,
authorized, rate-capped attack and baseline traffic was captured; the telemetry
was turned into labelled temporal graphs; a GAT and a GraphSAGE model were trained
and compared against non-GNN baselines on **real** data with capture-level splits;
and a correlation engine fuses the model's verdicts with Hubble/Prometheus/Suricata
into incident records. The GNNs beat the baselines on real data and are the only
methods that also classify attack type and identify the target. All claims below
are backed by artifacts in the repository.

## 2. Methodology
### 2.1 Lab (Phase 2)
Kind (v1.32.2) single node; Cilium 1.18.15 CNI + Hubble; Online Boutique v0.10.2
(11 services) in `boutique`; Prometheus 27.52.0 + Grafana 8.15.0; Suricata 7.0.8
as a two-probe DaemonSet (edge af-packet on eth0; internal libpcap on "any");
generators in an isolated `generators` namespace behind default-deny egress.
Verified: app serves `GET /product` (200); Hubble returns live flows with
identities/ports/flags/verdicts; Prometheus scrapes cadvisor (per-container
cpu/mem/net) + kube-state; Suricata fired sid 9000001 on a live SYN burst;
isolation check blocks internet egress while allowing in-cluster.

### 2.2 Telemetry → graphs (Phases 3-4)
`collect/` records a capture (raw Hubble json-lines, Suricata EVE per probe,
Prometheus range, pod metadata), aligns everything into UTC sliding windows
(10 s / 5 s step), and writes a manifest with per-source status and errors.
`graph/build.py` turns each aligned window into the common schema (nodes =
services + external /24 subnets; edges = aggregated Hubble flows + static
dependencies). Node identity is unified to `namespace/workload` across sources;
CPU/mem are normalised to pod-spec limits; unobserved features stay `None`
(latency is not exported, Hubble carries no byte/entropy counters) rather than
being faked. Construction is idempotent and schema-validated.

### 2.3 Dataset and labels (Phase 5)
Twelve captures (3 each of healthy / legitimate-peak / HTTP-flood / SYN-flood)
driven by a rate-capped in-cluster generator; generator pods tagged with a
`sim-subnet` label (exposed by Hubble) model many distinct external sources
converging on the target. Windows are labelled from the scenario timeline (the
label source of truth), never from model output. **309 windows**; split **by
capture**, stratified so every class and both attack types appear in train and
test (no window shared across splits).

### 2.4 Models (Phase 6)
Graph-level window classification with a shared GAT/GraphSAGE encoder and heads
for verdict, attack type, attacking source and target/impacted node. Focal loss
with class handling; validation-based selection; reproducible seeds; feature
normalisation fit on training normals only. Baselines: tuned threshold rules,
Logistic Regression and Random Forest over flow features. Metrics: detection
precision/recall/F1, attack-type macro-F1, source P/R, target top-k, PR-AUC, FPR,
3-class confusion, inference latency; GNNs over 3 seeds (mean ± std).

### 2.5 Correlation (Phase 7)
`correlate/engine.py` groups consecutive attack windows into incidents and, for
each, records model **inference** (category, confidence, ranked targets/sources,
impacted services) and **observed facts** (measured flow convergence, dropped
flows, Suricata signatures, sensor availability) separately, plus evidence
limitations and recommended investigation steps. It also runs the two-probe
Suricata correlation (`ids/`) over the same interval. Correlation is never
presented as causation.

## 3. Results
### Real lab captures (headline)
| Method | detection F1 | type macro-F1 | target top-1 | source R | peak FA |
| --- | --- | --- | --- | --- | --- |
| Threshold rules | 0.00 | 0.00 | 0.00 | 0.54 | 0.00 |
| Logistic Regression | 0.588 | 0.00 | 0.47 | 0.96 | 0.00 |
| Random Forest | 0.114 | 0.00 | 0.06 | 0.10 | 0.00 |
| GraphSAGE | 0.815 ± 0.043 | 0.58 | 0.78 | 0.55 | 0.00 |
| **GAT** | **0.818 ± 0.013** | **0.61** | 0.84 | 0.83 | 0.00 |

GAT PR-AUC 0.88, FPR 0.09, ~1.8 ms/window; GraphSAGE ~4 ms. No false alarm on
legitimate peaks. (`reports/phase6/phase6.json`, plots in `reports/phase6/`.)

### Synthetic (development only — NOT real-world performance)
Detection is trivial for every method (F1 = 1.0); only attack-type classification
separates the GNN (GraphSAGE 0.72 / GAT 0.67 macro-F1) from LR/RF (0.02).

### Correlation
`real-http-flood` → 1 incident, `ddos_http_flood` (conf 0.67), target
`boutique/frontend` (0.88), sources = the simulated attacker subnets, corroborated
by 532 Suricata HTTP-flood alerts. `real-syn-flood` → incident + 13 IDS incidents
(complementary sensors). `real-peak` and `real-healthy` → 0 incidents.

## 4. Limitations
- **Scale.** Four training captures and two attack families; this is a validated
  prototype, not a production detector. Detection F1 ≈ 0.82 with honest variance
  (GAT 0.818 ± 0.013 over 3 seeds); GAT and GraphSAGE are comparable on detection,
  GAT ahead on target identification (top-1 0.84 vs 0.78).
- **Single-node IDS.** The two probes share one host; "two observation points"
  is realised by capture interface, weaker than two physical taps.
- **SYN-flood attribution.** Hubble under-enriches RST-storm connections, so SYN
  source attribution comes from the Suricata probe, not Hubble (documented).
- **Missing app metrics.** Online Boutique exports no HTTP latency/error rate, so
  `latence_p95`/`taux_erreurs` are absent (a Hubble drop-ratio proxy is used).
- **Sandbox fixes.** Kernel without IPv6 / `CAP_SYS_RESOURCE`; both handled
  reproducibly (`lab/sandbox/`, `lab/k8s/boutique/render.py`) and are no-ops on a
  normal host.

## 5. Future work
More captures per class and more attack families (UDP/ICMP flood, slowloris,
distributed brute force/scan — the generator and schema already support them);
two physically separate IDS taps on a multi-node cluster; an app with real
latency/error metrics (or a service mesh) to populate the health features;
confidence calibration and per-capture cross-validation; online/streaming
inference wired to the live Hubble/Prometheus/Suricata feeds instead of captures.

## 6. Reproduce
`docs/ARCHITECTURE.md` (design), `reports/PHASE1-2.md`, `reports/PHASE3-4.md`,
`reports/PHASE5-7.md` (per-phase acceptance), and `README.md` (commands). The
offline path is exercised by CI; the full path by the lab scripts on a host with
Docker/Kind.
