# GNN-based distributed-attack detection & correlation

Detects and correlates distributed attacks (HTTP flood, SYN flood, and — by the
same pipeline — other volumetric/slow/scan families) against a Kubernetes
microservices app, by turning **Cilium/Hubble flows + Prometheus metrics +
Suricata IDS alerts** into **temporal communication graphs** and running Graph
Neural Networks (GAT, GraphSAGE) over them, then fusing model verdicts with the
telemetry into **incident records** that separate observed facts from inference.

It distinguishes normal behaviour, benign load peaks and confirmed attacks, and
**does not report detection performance that is not backed by evaluation on
labelled data** (synthetic and real results are kept strictly separate).

> Built and validated on a live single-node lab. See `docs/ARCHITECTURE.md` and
> the per-phase reports in `reports/`.

## Repository layout
| Path | What |
| --- | --- |
| `schema/` | the common window format, JSON Schema, validator, feature contract |
| `lab/` | Kind cluster + Cilium/Hubble + Online Boutique + Prometheus/Grafana + Suricata; scripts, scenarios, rate-capped generator |
| `collect/` | live telemetry collectors (Hubble/Prometheus/Suricata/k8s), UTC alignment, capture manifest, labeler |
| `graph/` | temporal graph builder (aligned capture → schema window) |
| `data_prep/` | synthetic data, window→graph, capture-level splits, dataset report, metrics |
| `model/` | GAT/GraphSAGE + heads, losses, training, baselines (threshold/LR/RF), the Phase-6 driver, plots, explainability |
| `correlate/` | incident schema + correlation engine (GNN + Hubble + Prometheus + Suricata) |
| `ids/` | two-probe Suricata correlation (rules + AI) |
| `deploy/` | FastAPI service, Dockerfiles, docker-compose, Kubernetes manifests |
| `demo/` | Streamlit dashboard |
| `reports/` | per-phase reports, dataset stats, Phase-6 evaluation + plots |

## Quick start (offline — no cluster)
```bash
make install                 # or: pip install -r requirements.txt (+ CPU torch, torch_geometric)
make synth-data              # synthetic DEV dataset  -> data/windows/synth
make train-synth             # quick model            -> model/artifacts_synth
make test                    # full test suite (25 tests)
```

## Full pipeline (with the lab)
Requires Docker + Kind + kubectl + helm + hubble on the PATH (pinned versions in
`lab/versions.env`). On a restricted host (no `CAP_SYS_RESOURCE`) the scripts
auto-select `lab/sandbox/` — see `docs/ARCHITECTURE.md §3`.
```bash
make lab-up                                   # Phase 2: bring up + verify the whole lab (~15-25 min first run)
make scenario SCN=lab/scenarios/http_flood.yaml   # Phase 3-5: authorized, rate-capped, in-cluster capture
make process  CAP=data/captures/real-http-flood   # Phase 3-4: raw -> validated windows
make dataset-report                           # Phase 5: dataset statistics -> reports/dataset_real.json
make train                                    # Phase 6: train the GNN on REAL captures -> model/artifacts
make phase6                                   # Phase 6: baseline vs GAT vs GraphSAGE (real + synth, separate)
make plots                                    # Phase 6: evaluation plots
make correlate CAP=data/captures/real-http-flood  # Phase 7: incident records -> incidents.json
make api                                      # Phase 8: FastAPI on :8000
make demo                                     # Phase 8: Streamlit dashboard
make lab-down                                 # tear the cluster down (captures on disk are kept)
```

## The deliverable functions
```python
from model.correlation import correlation_attaque_distribuee
res = correlation_attaque_distribuee(flux, metriques, alertes, fenetre="10s")
# -> {verdict, type, confiance, p_attack, cibles, sources, impactes, explication, ...}

from ids.correlation_ids import correlation_ids_suricata
incidents = correlation_ids_suricata(eve_ids1, eve_ids2, mode="regles")  # or "ia"
```

## API (Phase 8)
```
GET  /health
POST /correlation/attaque      GNN inference on a window of signals
POST /correlation/ids          two-probe Suricata correlation
GET  /captures                 processed captures + incident counts
GET  /incidents[?capture=ID]   stored incident records (Phase 7)
GET  /metrics/evaluation       the Phase-6 report (real + synthetic, separate)
```

## Results (honest summary)
On **real** lab captures (12 captures, 309 windows, capture-level split):

| Method | detection F1 | type macro-F1 | target top-1 | peak false-alarm |
| --- | --- | --- | --- | --- |
| Logistic Regression | 0.588 | 0.00 | 0.47 | 0.00 |
| Random Forest | 0.114 | 0.00 | 0.06 | 0.00 |
| GraphSAGE | 0.815 ± 0.043 | 0.58 | 0.78 | 0.00 |
| **GAT** | **0.818 ± 0.013** | **0.61** | **0.84** | 0.00 |

The GNNs clearly beat the flow baselines on real data and are the only methods
that classify attack type and identify the target; no method false-alarmed on a
legitimate peak (GAT PR-AUC 0.88, FPR 0.09, ~1.8 ms/window). On **synthetic**
data detection is trivial for every method (F1=1.0) and only attack-type
classification separates the GNN (SAGE 0.72) from the
baselines (0.02) — which is exactly why synthetic numbers are never presented as
real-world performance. Full numbers + plots in `reports/phase6/`.

## Reproducing the real dataset
`data/windows/` (processed graph windows), per-capture `manifest.json`,
`scenario.json` and `incidents.json` are included. The raw packet/flow captures
(~3.4 GB) are not shipped; re-run `make scenario` + `make process` to regenerate
them. Everything is seeded and idempotent; outputs are never overwritten.

## Safety
Every attack is generated **only inside the isolated lab**: in-cluster targets
only, always rate-capped, from the `generators` namespace behind a default-deny
egress policy (verified by `lab/scripts/60-isolation.sh --check`). No spoofing,
persistence, stealth or destructive actions. Attacking source subnets are
reported as **indicators, not attribution**.

## Troubleshooting
- **Cilium/pods crash with `oom_score_adj` / `apply caps` errors** → restricted
  host; the scripts use `lab/sandbox/` automatically (see its header).
- **Node services crashloop (`server must be bound`)** → host without an IPv6
  stack; `lab/k8s/boutique/render.py` injects an IPv4-bind patch.
- **Docker Hub 429 / image pulls fail** → images are pre-loaded into the node
  (`lab/scripts/lib.sh preload`); re-run the step or use a mirror.
- **Prometheus metrics empty** → the rate window must span ≥ 2 scrapes
  (`collect/prometheus.py` uses ≥ 4× the step).

## Limitations (see docs/ARCHITECTURE.md §6 and reports/PHASE5-7.md)
Single-node two-probe IDS visibility; SYN-flood source attribution comes from the
IDS (Hubble under-enriches RST storms); no app-latency metric from Online
Boutique; small real dataset (a validated prototype, not a production detector).
