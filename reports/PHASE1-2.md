# Phase 1 & 2 report — environment, architecture, lab deployment

## Phase 1 — environment verification & architecture
**Host verified** (`lab/scripts/00-check-host.sh`): Docker 29.8.2, Kind v0.27.0,
kubectl v1.32.2, Helm v3.16.4, Hubble v1.17.2, Python 3.13; 2 vCPU, 7.8 GiB RAM,
~24 GiB free disk; cgroup v1; kernel 6.18 **without an IPv6 stack and without
CAP_SYS_RESOURCE for root** (a restricted cloud sandbox).

Two environment constraints were found and solved (both documented, both
reproducible, neither weakens the design):
1. **No CAP_SYS_RESOURCE** → Kind nodes could not start any pod with a negative
   OOM score, and Cilium init containers could not apply CAP_SYS_RESOURCE.
   Fixed by a runc shim (`lab/sandbox/runc-oom-wrap.sh`) selected automatically
   on restricted hosts by `10-cluster.sh`; on a normal host the standard
   `lab/kind-config.yaml` is used and the shim is never involved.
2. **No IPv6 stack** → two Online Boutique Node services bind gRPC to `[::]` and
   ignore bind errors, crashlooping. Fixed by a preloaded patch module mounted
   from a ConfigMap (`lab/k8s/boutique/render.py` emits it) that rewrites the
   bind to the IPv4 wildcard; no-op on dual-stack hosts.

Architecture, signal sources, data path, schema and safety: `docs/ARCHITECTURE.md`.

**Acceptance criteria (met):** host report prints all tools and resources; risks
and limitations written down; architecture fixed and versioned (`lab/versions.env`).

## Phase 2 — Kubernetes app + monitoring deployment
One command brings the lab up idempotently: `bash lab/scripts/up.sh --check`.

| Component | State (verified at runtime, not from manifests) |
| --- | --- |
| Kind cluster `gnn-lab` | node Ready, k8s v1.32.2 |
| Cilium 1.18.15 CNI | `ds/cilium` rolled out; node Ready |
| Hubble relay | running; `hubble observe` returns live pod-to-pod flows with identities, ports, TCP flags, verdicts |
| Online Boutique v0.10.2 | **11/11 deployments Available**; `GET /` and `GET /product/OLJCESPC7Z` both return 200 through the frontend (exercises productcatalog/currency/recommendation/ad; checkout-side services Ready) |
| Prometheus 27.52.0 | `deploy/prometheus-server` ready; targets up: cadvisor (33 boutique containers), cilium pods, kube-state-metrics; 5 s scrape |
| Grafana 8.15.0 | running, Prometheus datasource wired |
| Suricata 7.0.8 (2 probes) | DaemonSet 2/2; home DoS rules loaded; **a live SYN burst to the node fired sid 9000001 and was written to ids1 `eve.json`**; ids2 (`any`) emits flow events |
| Isolation | generators/boutique default-deny egress applied; isolation check: internet `000` (blocked), `frontend.boutique` `200` |

**Acceptance criteria (met):** every component verified running from its actual
runtime state; the app serves real requests end to end; each signal source
(Hubble, Prometheus, Suricata) demonstrably produces data; lab isolation proven.

### Reproduce
```bash
export PATH="$PWD/../bin:$PATH"     # kind, kubectl, helm, hubble, cilium
bash lab/scripts/up.sh --check      # ~15–25 min on first run (image pulls)
bash lab/scripts/down.sh            # tear down
```

### Known issues carried forward
- Single-node two-probe IDS visibility caveat (see docs/ARCHITECTURE.md §6).
- Grafana has no pre-baked dashboards yet (added in Phase 8).
