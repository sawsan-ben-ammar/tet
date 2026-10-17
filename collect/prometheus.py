"""Prometheus metric collection (Phase 3).

Range queries over the capture interval give per-pod workload/infra metrics:
CPU seconds rate, memory working set, network rx/tx rate and container restarts
(from cadvisor + kube-state-metrics, scraped every 5 s). Values are returned per
(workload, timestamp) so Phase 4 can place them in the right window.

Honest limitations: Online Boutique does not export app-level HTTP latency or
error rate, so `latence_p95` and `taux_erreurs` are NOT available from Prometheus
here and are left missing (None) in the window; a drop-based error proxy comes
from Hubble instead. If a service mesh / OTel is added, wire its histogram here.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections import defaultdict

from collect.hubble import workload_of

# metric -> PromQL template (%(w)s = window step for rate, %(ns)s = namespace)
QUERIES = {
    "cpu_seconds_rate": 'sum by (pod) (rate(container_cpu_usage_seconds_total{namespace="%(ns)s",container!="",container!="POD"}[%(w)s]))',
    "mem_working_bytes": 'sum by (pod) (container_memory_working_set_bytes{namespace="%(ns)s",container!="",container!="POD"})',
    "net_rx_rate": 'sum by (pod) (rate(container_network_receive_bytes_total{namespace="%(ns)s"}[%(w)s]))',
    "net_tx_rate": 'sum by (pod) (rate(container_network_transmit_bytes_total{namespace="%(ns)s"}[%(w)s]))',
    "restarts": 'max by (pod) (kube_pod_container_status_restarts_total{namespace="%(ns)s"})',
}
# cpu/mem *limits* are static and always present in the pod spec, so they come
# from pods.json (collect.kube), not from kube-state-metrics - one less dependency.


def query_range(base_url, promql, start, end, step=5.0, timeout=30):
    q = urllib.parse.urlencode({"query": promql, "start": f"{start:.3f}",
                                "end": f"{end:.3f}", "step": f"{step:g}"})
    url = f"{base_url.rstrip('/')}/api/v1/query_range?{q}"
    # localhost (port-forward) is in NO_PROXY; build an opener with no proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as resp:
        obj = json.load(resp)
    if obj.get("status") != "success":
        raise RuntimeError(f"prometheus error: {obj.get('error')}")
    return obj["data"]["result"]


def collect(base_url, namespace, start, end, step=5.0, rate_window=None):
    """Return {workload: {metric: [(ts, value), ...]}} plus any per-metric errors.
    rate_window: PromQL window for rate() metrics; must span >= 2 scrapes, so it
    defaults to max(4*step, 20s) (a 5s window over a 5s scrape yields nothing)."""
    rw = rate_window or max(4 * step, 20.0)
    out = defaultdict(lambda: defaultdict(list))
    errors = []
    for metric, tmpl in QUERIES.items():
        promql = tmpl % {"ns": namespace, "w": f"{int(rw)}s"}
        try:
            series = query_range(base_url, promql, start, end, step)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{metric}: {exc}")
            continue
        for s in series:
            pod = s["metric"].get("pod", "")
            wl = f"{namespace}/{workload_of(pod)}"   # unify with Hubble/kube node ids
            for ts, val in s["values"]:
                try:
                    out[wl][metric].append((float(ts), float(val)))
                except (TypeError, ValueError):
                    pass
    return out, errors
