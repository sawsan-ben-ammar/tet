# Architecture — GNN-based distributed-attack detection & correlation

## 1. Goal and scope
Detect and correlate distributed attacks (volumetric DDoS, SYN/UDP/ICMP floods,
HTTP floods, slow attacks, distributed brute force, distributed scans) against a
Kubernetes microservices application, by combining **network flows**, **workload
metrics** and **IDS alerts** into **temporal communication graphs** and running
Graph Neural Networks over them. The system must separate normal behaviour,
benign load peaks, recovery/fault behaviour and confirmed attacks, and must never
claim detection that is not supported by reproducible evaluation on labelled data.

## 2. Signal sources (what observes what)
| Signal | Source | Visibility | Limitation |
| --- | --- | --- | --- |
| L3/L4 flows (who→whom, bytes, packets, verdict, flags) | **Cilium Hubble** | every pod-to-pod + pod-to-world flow on the node | identities are Cilium's; sampled under very high rates |
| Per-container CPU/mem/network, restarts, readiness | **Prometheus** (cadvisor + kube-state-metrics) | all boutique pods | 5 s scrape; gauges are point-in-time |
| IDS alerts (signatures, severity, XFF) | **Suricata** two probes (ids1 edge/af-packet eth0, ids2 internal/libpcap any) | ids1 sees node-edge with real external IPs; ids2 sees all pod veths | single node: both probes on one host; see §6 |
| Pod metadata, service identity, dependencies | **Kubernetes API** + Hubble | authoritative | — |
| Experiment metadata, labels, capture config | **scenario YAML** (label source of truth) | — | labels are only as good as the scenario |

## 3. Infrastructure (pinned — see lab/versions.env)
- Ubuntu/Linux host, Docker, **Kind** single node `kindest/node:v1.32.2`.
- **Cilium 1.18.15** as CNI (kube-proxy replacement) + **Hubble** relay.
- **Online Boutique v0.10.2** in namespace `boutique` (11 services).
- **Prometheus 27.52.0** + **Grafana 8.15.0** in `monitoring`.
- **Suricata 7.0.8** DaemonSet (two probes) in `security`.
- Traffic/attack generators in `generators`, behind default-deny egress.

A single all-in-one node is used because the reference host is 2 vCPU / 8 GiB;
generator isolation is enforced by **Cilium NetworkPolicies**, not node placement
(lab/k8s/network-policies.yaml). A restricted host (no CAP_SYS_RESOURCE, as in
some cloud sandboxes) is handled by lab/sandbox/ (documented there).

## 4. Data path
```
Hubble flows ┐
Prometheus   ┤→ collectors (Phase 3, UTC-aligned) → common window JSON (schema/)
Suricata EVE ┘        │                                   │
k8s metadata ─────────┘                                   ▼
                                     temporal graph builder (Phase 4, versioned schema)
                                                          │
                              capture-level split + labels (Phase 5, leakage-resistant)
                                                          │
            ┌──────────────── baseline (LR/RF) ──────────┤
            ├──────────────── GAT (graph-level) ─────────┤  training + evaluation (Phase 6)
            └──────────────── GraphSAGE ─────────────────┘
                                                          │
                                    correlation engine (Phase 7): GNN window verdicts
                                    + Hubble topology + Prometheus + Suricata → incidents
                                                          │
                                      FastAPI + Streamlit + Docker + K8s (Phase 8)
```

## 5. Graph schema (summary; full contract in schema/)
- **Nodes** = pods/microservices (internal) and external source subnets.
- **Directed edges** = observed communication (Hubble `flux`) and service
  dependencies (`dependance`).
- **Node features**: volume, connections, diversity, health (internal only),
  alerts, context. **Edge features**: counts, protocol/verdict, direction.
- Missing values stay `None` (never silently 0); a per-role "present" flag keeps
  "missing" distinct from "zero". Schema is versioned; outputs are idempotent and
  never overwrite existing captures.

## 6. Known limitations (honest)
- Single-node kind: the two IDS probes sit on one host; "two logically distinct
  observation points" is realised by capture interface (edge vs all-veth), which
  is weaker than two physically separate taps. Documented in lab/README.
- Attacking source addresses are reported as **indicators**, not attribution
  (volumetric attacks spoof addresses).
- Synthetic data (data_prep/synth.py) is for development/CI only and is never
  reported as real-world detection performance (Phase 5/6 keep them separate).

## 7. Safety
Only in-cluster targets are ever attacked, always rate-capped, from the isolated
`generators` namespace behind default-deny egress. No flooding of third parties,
no persistence/stealth/destructive actions. Isolation is checked before every
session (scripts/60-isolation.sh --check).
