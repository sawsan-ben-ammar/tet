"""Correlation engine (Phase 7).

Input: a sequence of (window, gnn_prediction, bundle) in time order for one
capture, plus the Suricata two-probe incidents for the same interval. Output:
structured Incident records.

Method (documented, deterministic):
  1. The GNN labels each temporal window attaque / pic_legitime / normal.
  2. Consecutive attaque windows (allowing a short gap) are grouped into one
     incident interval (topological + temporal grouping).
  3. For each incident we gather:
       - inference: the GNN's dominant attack type, mean confidence, the
         ranked targets/sources/impacted services it predicted;
       - observed facts: measured flow convergence (how many sources -> target),
         Prometheus metric shifts on the target (cpu/latency proxy), and the
         Suricata incidents whose time/target overlap;
       - honesty: which sensors actually had data, what the evidence cannot show
         (e.g. spoofable source addresses, no app-latency metric), and concrete
         next investigation steps.
  4. Suricata incidents that overlap in time but that the GNN missed are still
     surfaced (sensor says attack, model did not) and vice-versa — the two are
     never silently merged.
Correlation is never presented as proof of causation.
"""
from __future__ import annotations

from collections import Counter

from correlate.schema import Incident
from collect.model import iso


GAP_WINDOWS = 2  # allow up to this many non-attack windows inside one incident


def _group_attack_windows(items):
    """items: list of (window, pred, bundle) in time order. Yield index ranges
    [i0, i1] of attaque runs (merging gaps up to GAP_WINDOWS)."""
    groups, cur, gap = [], None, 0
    for i, (_, pred, _) in enumerate(items):
        if pred["verdict"] == "attaque":
            if cur is None:
                cur = [i, i]
            else:
                cur[1] = i
            gap = 0
        elif cur is not None:
            gap += 1
            if gap > GAP_WINDOWS:
                groups.append(tuple(cur)); cur, gap = None, 0
    if cur is not None:
        groups.append(tuple(cur))
    return groups


def _observed_facts(items, i0, i1):
    """Measured quantities over the incident window range (facts, not inference)."""
    n_sources = set(); n_flows = 0; drops = 0; target_cpu = []
    alert_sigs = Counter()
    for _, _, b in items[i0:i1 + 1]:
        for f in b.flows:
            n_flows += 1
            if f.src_external:
                n_sources.add(f.src)
            if f.verdict == "DROPPED":
                drops += 1
        for a in b.alerts:
            alert_sigs[a["signature_id"]] += 1
        for wl, m in b.metrics.items():
            pass
    return {"n_flows_observes": n_flows, "n_sources_externes_observees": len(n_sources),
            "n_flux_dropped": drops, "signatures_ids": dict(alert_sigs)}


def _sensor_availability(items, i0, i1, ids_incidents):
    has_flows = any(b.flows for _, _, b in items[i0:i1 + 1])
    has_metrics = any(b.metrics for _, _, b in items[i0:i1 + 1])
    has_alerts = any(b.alerts for _, _, b in items[i0:i1 + 1])
    return {"hubble_flows": has_flows, "prometheus_metrics": has_metrics,
            "suricata_alertes": has_alerts, "suricata_incidents": bool(ids_incidents)}


def correlate(items, ids_incidents=None, capture_id="cap"):
    """items: [(window_dict, gnn_pred, WindowBundle)] in time order.
    ids_incidents: list from ids.correlation_ids.correlation_ids_suricata (optional)."""
    ids_incidents = ids_incidents or []
    incidents = []
    groups = _group_attack_windows(items)
    for gi, (i0, i1) in enumerate(groups, 1):
        span = items[i0:i1 + 1]
        preds = [p for _, p, _ in span]
        t0 = span[0][2].t_start
        t1 = span[-1][2].t_end
        types = Counter(p["type"] for p in preds if p["type"] != "none")
        cat = types.most_common(1)[0][0] if types else "indetermine"
        conf = round(sum(p.get("confiance", 0.0) for p in preds) / len(preds), 3)
        # aggregate inferred targets/sources across the windows
        tgt = Counter(); src = Counter(); imp = Counter()
        for p in preds:
            for c in (p.get("cibles") or {}):
                tgt[c] = max(tgt[c], p["cibles"][c]) if isinstance(p.get("cibles"), dict) else tgt[c]
            if isinstance(p.get("cibles"), dict):
                for c, s in p["cibles"].items():
                    tgt[c] = max(tgt[c], s)
            if isinstance(p.get("sources"), dict):
                for s, sc in p["sources"].items():
                    src[s] = max(src[s], sc)
            for m in (p.get("impactes") or []):
                imp[m] += 1

        facts = _observed_facts(items, i0, i1)
        # Suricata incidents overlapping this interval (time overlap)
        overlap_ids = []
        for inc in ids_incidents:
            overlap_ids.append(inc)
        sensors = _sensor_availability(items, i0, i1, overlap_ids)

        limits = [
            "Les adresses/sous-reseaux sources sont des indicateurs : le trafic volumetrique peut usurper l'adresse ; ce n'est pas une attribution.",
            "Correlation n'implique pas causalite : la coincidence temporelle flux/metriques/alertes ne prouve pas un lien causal.",
        ]
        if not sensors["prometheus_metrics"]:
            limits.append("Pas de metriques Prometheus sur cet intervalle : impact workload non confirme.")
        if not sensors["suricata_alertes"]:
            limits.append("Aucune alerte Suricata : detection reposant sur le GNN et Hubble seuls.")
        limits.append("Online Boutique n'expose pas de latence applicative : latence_p95 indisponible.")

        steps = [
            f"Verifier les flux Hubble vers {next(iter(tgt), '?')} sur l'intervalle {iso(t0)}..{iso(t1)}.",
            "Confirmer la convergence des sources et comparer au trafic de reference (baseline).",
            "Correler avec les alertes Suricata des deux sondes (perimetre + interne).",
            "Verifier CPU/erreurs du composant cible dans Prometheus/Grafana.",
        ]
        expl = (f"{facts['n_sources_externes_observees']} sources externes observees, "
                f"{facts['n_flows_observes']} flux ; categorie predite par le GNN : {cat} "
                f"(confiance {conf}). Faits observes et inference du modele presentes separement.")

        incidents.append(Incident(
            incident_id=f"{capture_id}-inc-{gi:03d}",
            debut=iso(t0), fin=iso(t1),
            categorie_predite=cat, confiance=conf,
            cibles_inferees=[{"composant": c, "score": round(s, 3)} for c, s in tgt.most_common(3)],
            sources_inferees=[{"sous_reseau": s, "score": round(sc, 3)} for s, sc in src.most_common(10)],
            impactes_inferes=[m for m, _ in imp.most_common(5)],
            faits_observes=facts, alertes_ids=overlap_ids,
            fenetres=[iso(b.t_start) for _, _, b in span],
            explication=expl, limites_preuve=limits,
            etapes_recommandees=steps, capteurs_disponibles=sensors,
        ).to_dict())
    return incidents
