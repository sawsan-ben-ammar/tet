"""Build a window dict from raw signals (flows, metrics, alerts).

This is the production counterpart of the lab exporter: the final function calls it
to turn one window of live signals into the common format, then into a graph.

    flux:      list of {src_ip, dst, octets, paquets, flux, syn, http, requetes}
    metriques: {node_id: {cpu, memoire, latence_p95, taux_erreurs, type}}
    alertes:   list of {node, gravite}
"""
from __future__ import annotations

import ipaddress

from schema.features import FEATURES, WINDOW_S, STEP_S


def _subnet(ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return ip


def _blank():
    return {f: None for f in FEATURES}


def build_window(flux, metriques=None, alertes=None, fenetre_s=WINDOW_S,
                 debut="1970-01-01T00:00:00Z", scenario="live", origine="labo") -> dict:
    metriques = metriques or {}
    alertes = alertes or []
    span = max(fenetre_s, 1.0)

    alert_by_node = {}
    for a in alertes:
        node = a.get("node")
        g = float(a.get("gravite", 1))
        cur = alert_by_node.setdefault(node, [0, 0.0])
        cur[0] += 1
        cur[1] = max(cur[1], g)

    nodes, edges = {}, []
    # aggregate flows per source subnet and per destination
    agg_src, agg_dst = {}, {}
    for e in flux:
        src = _subnet(e["src_ip"])
        dst = e["dst"]
        s = agg_src.setdefault(src, dict(octets=0.0, paquets=0.0, flux=0, syn=0.0, http=0,
                                         requetes=0.0, dsts=set(), ports=set()))
        s["octets"] += e.get("octets", 0.0); s["paquets"] += e.get("paquets", 0.0)
        s["flux"] += e.get("flux", 1); s["syn"] += e.get("syn", 0.0)
        s["http"] += 1 if e.get("http") else 0; s["requetes"] += e.get("requetes", 0.0)
        s["dsts"].add(dst); s["ports"].add(e.get("port", 0))
        agg_dst.setdefault(dst, dict(octets=0.0, paquets=0.0, flux=0, srcs=set()))
        agg_dst[dst]["octets"] += e.get("octets", 0.0)
        agg_dst[dst]["paquets"] += e.get("paquets", 0.0)
        agg_dst[dst]["flux"] += e.get("flux", 1)
        agg_dst[dst]["srcs"].add(src)
        edges.append({"src": src, "dst": dst, "type": "flux",
                      "octets": e.get("octets", 0.0), "paquets": e.get("paquets", 0.0),
                      "flux": e.get("flux", 1)})

    for src, s in agg_src.items():
        f = _blank()
        na = alert_by_node.get(src, [0, 0.0])
        f.update(paquets_s=s["paquets"] / span, octets_s=s["octets"] / span,
                 requetes_s=s["requetes"] / span, nb_flux=s["flux"],
                 connexions_ouvertes=float(s["flux"]),
                 ratio_syn=s["syn"] / max(1.0, s["paquets"]),
                 duree_moy_connexion=0.0, nb_sources_uniques=1,
                 nb_destinations=len(s["dsts"]), nb_ports=len(s["ports"]),
                 entropie_url=0.0, entropie_ua=0.0, variabilite_intervalles=0.0,
                 taille_moy_paquets=s["octets"] / max(1.0, s["paquets"]),
                 nb_alertes=na[0], gravite_max_alerte=na[1], instant_premiere_anomalie=WINDOW_S)
        nodes[src] = {"id": src, "role": "externe", "type": "externe", "features": f}

    all_dst = set(agg_dst) | set(metriques)
    for dst in all_dst:
        m = metriques.get(dst, {})
        d = agg_dst.get(dst, dict(octets=0.0, paquets=0.0, flux=0, srcs=set()))
        na = alert_by_node.get(dst, [0, 0.0])
        f = _blank()
        f.update(paquets_s=d["paquets"] / span, octets_s=d["octets"] / span,
                 requetes_s=d["flux"] / span, nb_flux=d["flux"],
                 connexions_ouvertes=float(d["flux"]), ratio_syn=0.0, duree_moy_connexion=0.0,
                 nb_sources_uniques=len(d["srcs"]), nb_destinations=1, nb_ports=1,
                 entropie_url=0.0, entropie_ua=0.0,
                 cpu=m.get("cpu"), memoire=m.get("memoire"),
                 latence_p95=m.get("latence_p95"), taux_erreurs=m.get("taux_erreurs"),
                 nb_alertes=na[0], gravite_max_alerte=na[1], instant_premiere_anomalie=WINDOW_S)
        nodes[dst] = {"id": dst, "role": "interne", "type": m.get("type", "service"), "features": f}

    # dependency edges supplied via metriques[node]["depend_sur"]
    for node, m in metriques.items():
        for dep in m.get("depend_sur", []):
            if node in nodes and dep in nodes:
                edges.append({"src": node, "dst": dep, "type": "dependance"})

    return {
        "fenetre": {"debut": debut, "duree_s": fenetre_s, "pas_s": STEP_S},
        "origine": origine, "scenario": scenario,
        "noeuds": list(nodes.values()), "aretes": edges,
        "labels": {"verdict": "normal", "type": "none", "cibles": [], "sources": [], "impactes": []},
    }
