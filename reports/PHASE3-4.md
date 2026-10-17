# Phase 3 & 4 report — telemetry collection, alignment, temporal graphs

## Phase 3 — telemetry collection & timestamp alignment
New package `collect/` records one **capture** (a timed recording session) from
the live cluster and aligns all sources into common UTC windows.

| Source | Collector | What it yields |
| --- | --- | --- |
| Hubble flows | `collect/hubble.py` | directed edges: src/dst identity (service or /24 subnet), port, proto, verdict, SYN; raw json-lines kept |
| Prometheus | `collect/prometheus.py` | per-workload cpu rate, mem working set, net rx/tx rate, restarts (cadvisor + kube-state); rate window ≥ 4×scrape |
| Suricata EVE | `collect/suricata.py` | normalised alerts per probe (ids1/ids2), reshaped to the exact schema `ids/` already consumes |
| Kubernetes | `collect/kube.py` | workload type, readiness, restarts, **cpu/mem limits from the pod spec**, Boutique dependency edges |

- **Alignment** (`collect/align.py`): sliding windows `[t, t+W)` step `S`, UTC;
  flows/alerts placed by event time, metrics by last-sample-≤-window-end.
- **Capture manifest** (`collect/model.py`): capture id, scenario, UTC interval,
  window/step, per-source present/n/first/last/**errors**, clock notes,
  schema_version. Raw files are never overwritten (idempotent).
- Driver `lab/scripts/capture.sh <scenario> <dur> [id] [ns]` pulls all sources
  into `data/captures/<id>/raw/`; `python -m collect.run_capture <dir>` processes.

Node identity is unified to `namespace/workload` across every source (bug found
and fixed during validation: Prometheus had keyed bare workloads, splitting each
service into two nodes). CPU/mem are normalised to their pod-spec limits; app
latency/HTTP error rate are **not** exported by Online Boutique, so
`latence_p95`/`taux_erreurs` stay `None` (the latter gets a Hubble drop-ratio
proxy) — documented, not faked.

## Phase 4 — temporal graph construction & schema validation
`graph/build.py` turns one aligned window bundle into the **common window format**
(`schema/window.schema.json`) — the same format the synthetic generator emits, so
`to_graph`, the models, evaluation and correlation are unchanged. Nodes =
services + external subnets; edges = Hubble flows (aggregated, with counts +
verdict) and static Boutique dependencies. Missing features stay `None`; feature
provenance is documented in the module header. Outputs are written idempotently
and validated against the schema (referential checks included).

## Validation (on a real 50 s capture under load)
```
capture cap-smoke3: 11 windows, 0 invalid
sources: hubble=35089 flows, suricata_ids2=617, prometheus=317 samples, kube=11
mid window: 15 nodes (13 services incl. loadgen+coredns, 2 external), 44 flux + 15 dependance edges
frontend under load: cpu=0.83 (of limit), mem=0.115, 594 kB/s, 343 req/s, 5415 flows, 10 peers
```
Unit tests: `collect/tests/test_collectors.py` (parsers + alignment + a built
window passes the schema). `python -m pytest collect/tests -q` → 4 passed.

**Acceptance criteria (met):** all four sources collected and UTC-aligned;
errors/missing recorded in the manifest; graphs built in the versioned schema and
validated; construction idempotent and non-destructive; verified on real
telemetry, not synthetic.
