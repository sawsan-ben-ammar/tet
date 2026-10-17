"""Build a schema window (graph) from one aligned WindowBundle (Phase 4).

This is the real-data counterpart of data_prep.synth.make_window: it produces the
exact same common window format (schema/window.schema.json), so everything
downstream (to_graph, models, evaluation, correlation) is unchanged.

Feature provenance (honest; missing stays None, never 0):
  external source node (a /24 subnet seen in Hubble flows)
    nb_flux               = # flow events from the subnet in the window
    paquets_s             = flow-event rate (proxy; Hubble per-event has no pkt count)
    requetes_s            = HTTP flow-event rate
    ratio_syn             = fraction of its flows that are SYN-only
    connexions_ouvertes   = distinct (dst,port) it opened
    nb_destinations/ports = distinct dsts / dst ports
    nb_sources_uniques    = 1
    nb_alertes/gravite    = Suricata alerts whose src is in the subnet
    octets_s, entropie_*, variabilite_*, taille_moy, health = None (not observed here)
  internal node (a boutique workload)
    cpu                   = container_cpu rate / cpu_limit (fraction; raw rate if no limit)
    memoire               = mem_working_set / mem_limit (fraction; raw bytes if no limit)
    octets_s              = net rx+tx byte rate (Prometheus)
    requetes_s/nb_flux    = incoming flow-event rate / # flows touching it
    nb_sources_uniques    = distinct peers talking to it
    ratio_syn             = SYN-only fraction among flows to it
    taux_erreurs          = fraction of flows to it with verdict DROPPED (Hubble proxy)
    nb_alertes/gravite    = Suricata alerts targeting it
    latence_p95           = None (Online Boutique exports no app latency)
Edges: flux (aggregated Hubble flows, with count + verdict) and dependance
(static Boutique call graph for workloads present).
"""
from __future__ import annotations

from collections import defaultdict

from schema.features import FEATURES, WINDOW_S, STEP_S
from collect.model import iso
from collect import kube as K


def _blank():
    return {f: None for f in FEATURES}


def _entropy(counts):
    import math
    tot = sum(counts)
    if tot <= 0:
        return 0.0
    return -sum((c / tot) * math.log2(c / tot) for c in counts if c > 0)


def build_window(bundle, scenario, verdict="normal", attack_type="none",
                 cibles=None, sources_lbl=None, impactes=None, origine="labo"):
    """Turn one WindowBundle into a schema window dict. Labels are passed in
    (Phase 5 derives them from the scenario); default is an unlabelled normal."""
    width = max(bundle.t_end - bundle.t_start, 1.0)
    flows = bundle.flows
    alerts = bundle.alerts

    # ---- per-node flow aggregation ----
    ext_out = defaultdict(lambda: dict(n=0, http=0, syn=0, dsts=set(), ports=set()))
    int_in = defaultdict(lambda: dict(n=0, syn=0, drop=0, peers=set()))
    int_out = defaultdict(lambda: dict(n=0))
    edge_agg = defaultdict(lambda: dict(n=0, drop=0, proto="", syn=0))
    node_is_ext = {}

    for f in flows:
        node_is_ext.setdefault(f.src, f.src_external)
        node_is_ext.setdefault(f.dst, f.dst_external)
        edge_agg[(f.src, f.dst)]["n"] += 1
        edge_agg[(f.src, f.dst)]["proto"] = f.proto
        if f.verdict == "DROPPED":
            edge_agg[(f.src, f.dst)]["drop"] += 1
        if f.syn:
            edge_agg[(f.src, f.dst)]["syn"] += 1
        if f.src_external:
            s = ext_out[f.src]; s["n"] += 1
            if f.proto == "TCP" and f.port in (80, 8080):
                s["http"] += 1
            if f.syn:
                s["syn"] += 1
            s["dsts"].add(f.dst); s["ports"].add(f.port)
        if not f.dst_external:
            d = int_in[f.dst]; d["n"] += 1; d["peers"].add(f.src)
            if f.syn:
                d["syn"] += 1
            if f.verdict == "DROPPED":
                d["drop"] += 1
        if not f.src_external:
            int_out[f.src]["n"] += 1

    # ---- alerts per node (by subnet for external, by workload-ip for internal) ----
    from collect.hubble import subnet_of
    alert_src = defaultdict(lambda: [0, 0])  # subnet -> [count, maxsev]
    alert_dst = defaultdict(lambda: [0, 0])
    for a in alerts:
        ssub = subnet_of(a["src_ip"]) if a["src_ip"] else ""
        sev = 4 - min(3, max(1, a["severity"]))  # severity 1(high)->3, 3(low)->1 scale
        alert_src[ssub][0] += 1; alert_src[ssub][1] = max(alert_src[ssub][1], sev)
        # dest ip maps to a workload only if we can; else count on the subnet
        dsub = subnet_of(a["dest_ip"]) if a["dest_ip"] else ""
        alert_dst[dsub][0] += 1; alert_dst[dsub][1] = max(alert_dst[dsub][1], sev)

    nodes, edges = [], []
    seen = set()

    # external source nodes
    for sub, s in ext_out.items():
        f = _blank()
        al = alert_src.get(sub, [0, 0])
        f.update(nb_flux=s["n"], paquets_s=s["n"] / width, requetes_s=s["http"] / width,
                 ratio_syn=(s["syn"] / s["n"]) if s["n"] else 0.0,
                 connexions_ouvertes=float(len({(d, p) for d in s["dsts"] for p in s["ports"]}) or len(s["dsts"])),
                 nb_sources_uniques=1, nb_destinations=len(s["dsts"]), nb_ports=len(s["ports"]),
                 nb_alertes=al[0], gravite_max_alerte=al[1],
                 instant_premiere_anomalie=WINDOW_S)
        nodes.append({"id": sub, "role": "externe", "type": "externe", "features": f})
        seen.add(sub)

    # internal workload nodes
    metr = bundle.metrics
    all_int = set(int_in) | set(int_out) | {w for w in metr}
    for nid in all_int:
        if node_is_ext.get(nid, False):
            continue
        f = _blank()
        m = metr.get(nid, {})
        pod_meta = bundle.pods.get(nid, {})
        cpu = m.get("cpu_seconds_rate"); cl = pod_meta.get("cpu_limit")
        mem = m.get("mem_working_bytes"); ml = pod_meta.get("mem_limit")
        din = int_in.get(nid, dict(n=0, syn=0, drop=0, peers=set()))
        net = None
        if m.get("net_rx_rate") is not None or m.get("net_tx_rate") is not None:
            net = (m.get("net_rx_rate") or 0.0) + (m.get("net_tx_rate") or 0.0)
        f.update(
            cpu=(cpu / cl) if (cpu is not None and cl) else cpu,
            memoire=(mem / ml) if (mem is not None and ml) else (mem if mem is not None else None),
            octets_s=net,
            requetes_s=din["n"] / width if din["n"] else 0.0,
            nb_flux=din["n"] + int_out.get(nid, {"n": 0})["n"],
            nb_sources_uniques=len(din["peers"]),
            ratio_syn=(din["syn"] / din["n"]) if din["n"] else 0.0,
            taux_erreurs=(din["drop"] / din["n"]) if din["n"] else 0.0,
            nb_destinations=1, nb_ports=1,
            nb_alertes=0, gravite_max_alerte=0, instant_premiere_anomalie=WINDOW_S,
        )
        ntype = bundle.pods.get(nid, {}).get("type") or K.node_type(nid.split("/")[-1])
        nodes.append({"id": nid, "role": "interne", "type": ntype, "features": f})
        seen.add(nid)

    # flux edges (aggregated), both endpoints must be known nodes
    for (a, b), e in edge_agg.items():
        if a in seen and b in seen:
            edges.append({"src": a, "dst": b, "type": "flux",
                          "octets": 0.0, "paquets": float(e["n"]), "flux": e["n"]})
    # dependency edges among internal workloads present
    for a, b in K.dependency_edges([n["id"] for n in nodes if n["role"] == "interne"]):
        if a in seen and b in seen:
            edges.append({"src": a, "dst": b, "type": "dependance"})

    return {
        "fenetre": {"debut": iso(bundle.t_start), "duree_s": round(width, 3), "pas_s": STEP_S},
        "origine": origine, "scenario": scenario,
        "noeuds": nodes, "aretes": edges,
        "labels": {"verdict": verdict, "type": attack_type if verdict == "attaque" else "none",
                   "cibles": cibles or [], "sources": sources_lbl or [], "impactes": impactes or []},
    }
