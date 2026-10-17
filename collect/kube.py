"""Kubernetes metadata (Phase 3): workload -> {type, ready, restarts, replicas,
dependencies}. Parsed from `kubectl get pods -o json` output (snapshot) and a
static dependency map of Online Boutique (A calls B). Service 'type' maps k8s
workloads to the schema node types (gateway/service/database/cache)."""
from __future__ import annotations

import json
from collect.hubble import workload_of


def _cpu_to_cores(q):
    if not q: return None
    q=str(q)
    try:
        if q.endswith("m"): return float(q[:-1])/1000.0
        if q.endswith("n"): return float(q[:-1])/1e9
        return float(q)
    except ValueError: return None


def _mem_to_bytes(q):
    if not q: return None
    q=str(q); units={"Ki":1024,"Mi":1024**2,"Gi":1024**3,"K":1e3,"M":1e6,"G":1e9}
    for u,f in units.items():
        if q.endswith(u):
            try: return float(q[:-len(u)])*f
            except ValueError: return None
    try: return float(q)
    except ValueError: return None

# Online Boutique dependency edges (caller -> callee), from its architecture.
BOUTIQUE_DEPENDS = {
    "frontend": ["productcatalogservice", "currencyservice", "cartservice",
                 "recommendationservice", "shippingservice", "checkoutservice", "adservice"],
    "checkoutservice": ["productcatalogservice", "shippingservice", "paymentservice",
                        "emailservice", "currencyservice", "cartservice"],
    "recommendationservice": ["productcatalogservice"],
    "cartservice": ["redis-cart"],
}
NODE_TYPE = {
    "frontend": "gateway", "redis-cart": "cache",
}
DB_LIKE = {"redis-cart"}


def node_type(workload: str) -> str:
    if workload in NODE_TYPE:
        return NODE_TYPE[workload]
    if workload in DB_LIKE:
        return "cache"
    return "service"


def parse_pods(pods_json: dict) -> dict:
    """kubectl get pods -o json -> {workload: meta}."""
    out = {}
    for item in pods_json.get("items", []):
        md = item.get("metadata", {})
        wl = workload_of(md.get("name", ""))
        st = item.get("status", {})
        conds = {c["type"]: c["status"] for c in st.get("conditions", [])}
        restarts = sum(cs.get("restartCount", 0)
                       for cs in st.get("containerStatuses", []) or [])
        ns = md.get("namespace", "")
        key = f"{ns}/{wl}"
        meta = out.setdefault(key, {"workload": wl, "namespace": ns,
                                    "type": node_type(wl), "replicas": 0,
                                    "ready": True, "restarts": 0,
                                    "cpu_limit": None, "mem_limit": None})
        meta["replicas"] += 1
        meta["restarts"] += restarts
        meta["ready"] = meta["ready"] and (conds.get("Ready") == "True")
        cl = mlim = None
        for c in item.get("spec", {}).get("containers", []):
            lim = (c.get("resources", {}) or {}).get("limits", {}) or {}
            cc = _cpu_to_cores(lim.get("cpu")); mm = _mem_to_bytes(lim.get("memory"))
            if cc: cl = (cl or 0) + cc
            if mm: mlim = (mlim or 0) + mm
        if cl: meta["cpu_limit"] = cl
        if mlim: meta["mem_limit"] = mlim
    return out


def dependency_edges(workloads, namespace="boutique"):
    """Return [(caller_node, callee_node)] for workloads present in the capture."""
    present = set(workloads)
    edges = []
    for a, bs in BOUTIQUE_DEPENDS.items():
        an = f"{namespace}/{a}"
        if an not in present:
            continue
        for b in bs:
            bn = f"{namespace}/{b}"
            if bn in present:
                edges.append((an, bn))
    return edges
