# Phase 5, 6 & 7 report — real labelled captures, models, correlation

## Phase 5 — authorized captures, labels, leakage-resistant splits
Twelve real captures were recorded on the live lab (3 per class), driven by a
rate-capped, in-cluster-only generator (`lab/generators/attacker.py`) from the
isolated `generators` namespace (default-deny egress). Each scenario runs
warmup → event → cooldown; the scenario timeline is the label source of truth
(`collect/label.py` labels each window by the phase its midpoint falls in).
Distributed sources are modelled by tagging generator pods with a
`gnn-lab/sim-subnet` label that Hubble exposes, so many pods converge on the
target as distinct external /24 subnets.

Scenarios (`lab/scenarios/`): `healthy` (normal), `peak` (legitimate flash crowd,
`pic_legitime`), `http_flood` (`ddos_http_flood`), `syn_flood` (`ddos_syn_flood`).
Safety: only the in-cluster `frontend` is targeted, always rate-capped, no
spoofing/persistence/destruction; isolation is re-checked before sessions.

**Dataset** (`reports/dataset_real.json`, `data_prep/dataset_report.py`):
- 12 captures, **309 windows**; verdicts normal 171 / attaque 92 / pic_legitime 46
  (class imbalance 3.72); attack types http_flood 46, syn_flood 46.
- nodes/window 11–20 (mean 16.4), edges/window 15–69 (mean 54.1), ext sources
  mean 4.6; **0 duplicate windows**.
- Honest missing-feature rates: `latence_p95` 100 % (Online Boutique exports no
  app latency), `entropie_*`/`taille_moy_paquets` 100 % (not in Hubble L3/L4),
  `paquets_s`/`connexions_ouvertes` 72 % (external-only features).
- **Split is by capture** (stratified so every class and both attack types appear
  in train and test); no window is shared across splits → no leakage.

## Phase 6 — baseline vs GAT vs GraphSAGE (honest, real data)
`python -m model.phase6 --real "data/windows/real-*" --synth data/windows/synth`
Graph-level window classification; GNNs over 3 seeds (mean ± std); metrics include
PR-AUC, FPR, confusion matrix and inference latency.

**REAL lab captures** (test = held-out captures, both attack types present):

| Method | detection F1 | type macro-F1 | target top-1 | peak false-alarm |
| --- | --- | --- | --- | --- |
| Threshold rules | 0.00 | 0.00 | 0.00 | 0.00 |
| Logistic Regression | 0.59 | 0.00 | 0.47 | 0.00 |
| Random Forest | 0.11 | 0.00 | 0.06 | 0.00 |
| GraphSAGE | 0.815 ± 0.043 | 0.58 | 0.78 | 0.00 |
| **GAT (ours)** | **0.818 ± 0.013** | **0.61** | 0.84 | 0.00 |

GAT PR-AUC 0.88, FPR 0.09, inference ~1.8 ms/window; GraphSAGE ~4 ms. The GNNs
clearly beat the flow baselines on detection and are the only methods that do
attack-type classification and target identification. No method raised a false
alarm on a legitimate traffic peak (`fp_rate_peaks` 0). Numbers are modest and
honest: four training captures, two attack families; this is a validated
prototype, not a production detector. Synthetic results are reported **separately**
in `reports/phase6/phase6.json` and are development-only, never presented as
real-world performance.

Known modelling limitation found and documented: **SYN-flood source attribution
from Hubble is weak** (SYN→RST storm connections are poorly enriched), so SYN
sources come from the Suricata probe instead (which fired sid 9000001 and 13
incidents on the syn capture). HTTP-flood windows attribute sources 100 %.

## Phase 7 — distributed-attack correlation engine
`correlate/engine.py` + `correlate/run.py` fuse, per capture: the GNN's per-window
verdict/type/target/sources, Hubble flow convergence, Prometheus workload state,
and the two-probe Suricata incidents (`ids/correlation_ids.py`). Consecutive
attack windows (small gaps bridged) form one **incident** (`correlate/schema.py`)
that separates **observed facts** (measured flows, dropped flows, IDS signatures,
sensor availability) from **model inference** (predicted category/confidence,
ranked targets and source subnets), lists **evidence limitations** (sources are
indicators not attribution; correlation ≠ causation; missing sensors) and
**recommended investigation steps**.

Result on the real captures:
- `real-http-flood`: 1 incident, category `ddos_http_flood` (conf 0.67),
  target `boutique/frontend` (0.88), sources = the simulated attacker subnets,
  119 519 flows + 532 Suricata HTTP-flood alerts as corroborating facts.
- `real-syn-flood`: incident formed; GNN under-detected windows but 13 IDS
  incidents corroborate (complementary sensors).
- `real-peak`, `real-healthy`: **0 incidents** (no false incident on benign load).

**Acceptance criteria (met):** real authorized captures with reliable labels;
capture-level leakage-resistant splits; full dataset statistics; baseline/GAT/
GraphSAGE trained and compared with uncertainty and proper metrics; GNN superiority
shown only against a fair baseline; correlation engine emits structured incidents
separating fact from inference with limitations — all on real data, synthetic kept
separate.
