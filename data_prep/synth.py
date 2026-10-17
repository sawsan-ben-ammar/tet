"""Synthetic labelled windows.

This models the *statistics* each situation leaves in a window (how many sources,
how much they converge, how the internal services react) and emits windows in the
common format. It is the reproducible stand-in for the isolated lab: it produces
the labelled dataset the model trains and tests on, with no live traffic. The lab
(Phase 1 of the guide) produces windows in the exact same format, so the model and
the evaluation code do not change when real captures replace these.

The numbers here are feature *distributions*, not an attack tool: a volumetric
flood is "many external nodes, high packets/s each, converging on one target",
a legitimate peak is "many external nodes, moderate rate, high URL diversity".
"""
from __future__ import annotations

import ipaddress
import random
from typing import Optional

from schema.features import FEATURES, WINDOW_S, STEP_S

# The fixed internal topology of the Online Boutique, with its dependency edges.
INTERNAL = {
    "ingress": "gateway",
    "frontend": "service",
    "cart": "service",
    "productcatalog": "service",
    "checkout": "service",
    "payment": "service",
    "shipping": "service",
    "currency": "service",
    "recommendation": "service",
    "redis": "cache",
    "catalogdb": "database",
}
# "A depends on B": A calls B. Used to propagate impact along the chain.
DEPENDENCIES = [
    ("frontend", "ingress"),
    ("cart", "frontend"),
    ("productcatalog", "frontend"),
    ("checkout", "frontend"),
    ("payment", "checkout"),
    ("shipping", "checkout"),
    ("currency", "frontend"),
    ("recommendation", "frontend"),
    ("redis", "cart"),
    ("catalogdb", "productcatalog"),
]
# Targets an attack can pick and the services downstream of each (impact path).
DOWNSTREAM = {
    "ingress": ["frontend", "cart", "productcatalog", "checkout", "payment", "redis"],
    "frontend": ["cart", "productcatalog", "checkout", "redis"],
    "checkout": ["payment", "shipping"],
}

ATTACK_PROFILES = {
    # type -> (packets/s per bot, requests/s per bot, syn ratio, uses http)
    "ddos_udp_flood": dict(pps=(800, 4000), rps=(0, 0), syn=(0.0, 0.05), http=False),
    "ddos_icmp_flood": dict(pps=(600, 3000), rps=(0, 0), syn=(0.0, 0.02), http=False),
    "ddos_syn_flood": dict(pps=(400, 2000), rps=(0, 0), syn=(0.85, 0.99), http=False),
    "ddos_http_flood": dict(pps=(20, 120), rps=(15, 80), syn=(0.1, 0.3), http=True),
    "slowloris": dict(pps=(1, 6), rps=(0, 2), syn=(0.2, 0.5), http=True),
    "slow_post": dict(pps=(1, 8), rps=(0, 2), syn=(0.2, 0.5), http=True),
    "bruteforce_distribue": dict(pps=(5, 30), rps=(3, 15), syn=(0.2, 0.4), http=True),
    "scan_distribue": dict(pps=(2, 20), rps=(0, 1), syn=(0.3, 0.6), http=False),
}


def _blank_features() -> dict:
    return {f: None for f in FEATURES}


def _subnet(rng: random.Random) -> str:
    a, b, c = rng.randint(1, 223), rng.randint(0, 255), rng.randint(0, 255)
    if a in (10, 127) or (a == 192 and b == 168):
        a = 11
    return str(ipaddress.ip_network(f"{a}.{b}.{c}.0/24"))


def _external_node(node_id, pps, rps, syn, http, n_ports, regular, rng):
    f = _blank_features()
    f.update(
        paquets_s=pps,
        octets_s=pps * rng.uniform(60, 800),
        requetes_s=rps,
        nb_flux=max(1, int(rng.uniform(1, 5))),
        connexions_ouvertes=rng.uniform(1, 50) if http else rng.uniform(0, 5),
        ratio_syn=syn,
        duree_moy_connexion=rng.uniform(30, 120) if "slow" in str(node_id) else rng.uniform(0.1, 5),
        nb_sources_uniques=1,
        nb_destinations=rng.randint(1, 3),
        nb_ports=n_ports,
        entropie_url=rng.uniform(0.0, 0.8) if http else 0.0,
        entropie_ua=rng.uniform(0.0, 0.5) if http else 0.0,
        variabilite_intervalles=rng.uniform(0.0, 0.2) if regular else rng.uniform(0.5, 1.0),
        taille_moy_paquets=rng.uniform(40, 1400),
        nb_alertes=0,
        gravite_max_alerte=0,
        instant_premiere_anomalie=rng.uniform(0, WINDOW_S),
    )
    return {"id": node_id, "role": "externe", "type": "externe", "features": f}


def _internal_node(node_id, ntype, stress, rng):
    """stress in [0,1]: 0 healthy, 1 overloaded (target or impacted)."""
    f = _blank_features()
    base_lat = {"gateway": 20, "service": 40, "database": 15, "cache": 2}.get(ntype, 30)
    f.update(
        paquets_s=rng.uniform(50, 500) * (1 + 8 * stress),
        octets_s=rng.uniform(5e3, 5e4) * (1 + 6 * stress),
        requetes_s=rng.uniform(10, 200) * (1 + 6 * stress),
        nb_flux=int(rng.uniform(5, 40) * (1 + 10 * stress)),
        connexions_ouvertes=rng.uniform(10, 100) * (1 + 15 * stress),
        ratio_syn=rng.uniform(0.0, 0.1) + 0.4 * stress,
        duree_moy_connexion=rng.uniform(0.5, 5),
        nb_sources_uniques=int(rng.uniform(5, 50) * (1 + 20 * stress)),
        nb_destinations=rng.randint(1, 6),
        nb_ports=rng.randint(1, 4),
        entropie_url=rng.uniform(0.5, 1.0) * (1 - 0.5 * stress),
        entropie_ua=rng.uniform(0.4, 1.0) * (1 - 0.5 * stress),
        cpu=min(1.0, rng.uniform(0.1, 0.4) + 0.7 * stress),
        memoire=min(1.0, rng.uniform(0.2, 0.5) + 0.5 * stress),
        latence_p95=base_lat * (1 + 25 * stress),
        taux_erreurs=min(1.0, rng.uniform(0.0, 0.02) + 0.6 * stress),
        nb_alertes=int(rng.uniform(0, 2) + 6 * stress),
        gravite_max_alerte=min(3, int(3 * stress + rng.uniform(0, 0.5))),
        instant_premiere_anomalie=rng.uniform(0, WINDOW_S) if stress > 0.3 else WINDOW_S,
    )
    return {"id": node_id, "role": "interne", "type": ntype, "features": f}


def _dependency_edges(ids: set) -> list:
    out = []
    for a, b in DEPENDENCIES:
        if a in ids and b in ids:
            out.append({"src": a, "dst": b, "type": "dependance"})
    return out


def make_window(verdict: str, attack_type: str = "none", scenario: str = "s",
                debut: str = "2026-01-01T00:00:00Z", seed: Optional[int] = None) -> dict:
    """Build one labelled window. verdict in {normal, pic_legitime, attaque}."""
    rng = random.Random(seed)
    nodes, edges = [], []
    sources, cibles, impactes = [], [], []

    # --- internal nodes, stressed only under attack or peak ---
    if verdict == "attaque":
        target = rng.choice(list(DOWNSTREAM))
        impacted = DOWNSTREAM[target]
    elif verdict == "pic_legitime":
        target, impacted = "ingress", ["frontend", "cart", "productcatalog"]
    else:
        target, impacted = None, []

    for name, ntype in INTERNAL.items():
        if verdict == "attaque":
            stress = 1.0 if name == target else (rng.uniform(0.4, 0.8) if name in impacted else rng.uniform(0, 0.1))
        elif verdict == "pic_legitime":
            stress = rng.uniform(0.3, 0.6) if name in impacted + ["ingress"] else rng.uniform(0, 0.15)
        else:
            stress = rng.uniform(0.0, 0.12)
        nodes.append(_internal_node(name, ntype, stress, rng))
    if verdict == "attaque":
        cibles = [target]
        impactes = [n for n in impacted if rng.random() < 0.7]

    # --- external sources ---
    if verdict == "attaque":
        prof = ATTACK_PROFILES[attack_type]
        n_sub = rng.choice([1, 4, 8, 16, 32, 64])
        bots_per_sub = rng.randint(2, 12)
        n_ports = rng.randint(50, 500) if attack_type == "scan_distribue" else rng.randint(1, 3)
        for _ in range(n_sub):
            sub = _subnet(rng)
            sources.append(sub)
            pps = rng.uniform(*prof["pps"]) * bots_per_sub
            rps = rng.uniform(*prof["rps"]) * bots_per_sub
            syn = rng.uniform(*prof["syn"])
            node = _external_node(sub + ("#slow" if "slow" in attack_type else ""),
                                  pps, rps, syn, prof["http"], n_ports, regular=True, rng=rng)
            node["id"] = sub
            node["features"]["nb_alertes"] = rng.randint(0, 3)
            node["features"]["gravite_max_alerte"] = rng.randint(0, 2)
            nodes.append(node)
            edges.append({"src": sub, "dst": target, "type": "flux",
                          "octets": node["features"]["octets_s"] * WINDOW_S,
                          "paquets": pps * WINDOW_S, "flux": node["features"]["nb_flux"]})
        # a few legitimate clients in the background
        for _ in range(rng.randint(2, 6)):
            sub = _subnet(rng)
            node = _external_node(sub, rng.uniform(5, 40), rng.uniform(2, 20),
                                  rng.uniform(0.0, 0.1), True, rng.randint(1, 2), regular=False, rng=rng)
            nodes.append(node)
            edges.append({"src": sub, "dst": "ingress", "type": "flux",
                          "octets": node["features"]["octets_s"] * WINDOW_S,
                          "paquets": node["features"]["paquets_s"] * WINDOW_S, "flux": node["features"]["nb_flux"]})
    else:
        n_clients = rng.randint(30, 120) if verdict == "pic_legitime" else rng.randint(5, 40)
        rate_scale = rng.uniform(2.0, 5.0) if verdict == "pic_legitime" else 1.0
        for _ in range(n_clients):
            sub = _subnet(rng)
            node = _external_node(sub, rng.uniform(5, 40) * rate_scale, rng.uniform(2, 25) * rate_scale,
                                  rng.uniform(0.0, 0.1), True, rng.randint(1, 2), regular=False, rng=rng)
            nodes.append(node)
            edges.append({"src": sub, "dst": "ingress", "type": "flux",
                          "octets": node["features"]["octets_s"] * WINDOW_S,
                          "paquets": node["features"]["paquets_s"] * WINDOW_S, "flux": node["features"]["nb_flux"]})

    ids = {n["id"] for n in nodes}
    edges.extend(_dependency_edges(ids))
    # keep only unique source subnets actually present
    sources = [s for s in dict.fromkeys(sources) if s in ids]

    return {
        "fenetre": {"debut": debut, "duree_s": WINDOW_S, "pas_s": STEP_S},
        "origine": "labo",
        "scenario": scenario,
        "noeuds": nodes,
        "aretes": edges,
        "labels": {
            "verdict": verdict,
            "type": attack_type if verdict == "attaque" else "none",
            "cibles": cibles,
            "sources": sources,
            "impactes": impactes,
        },
    }
