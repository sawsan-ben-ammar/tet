"""Metrics specific to the two-probe correlation (Section 14.7)."""
from __future__ import annotations


def compression(n_alerts_in: int, n_incidents_out: int) -> float:
    return n_alerts_in / max(1, n_incidents_out)


def incident_purity(incident_sources, truth_sources) -> float:
    """Share of an incident's sources that belong to the matching true scenario."""
    inc = set(incident_sources)
    if not inc:
        return 0.0
    return len(inc & set(truth_sources)) / len(inc)


def detection_delay(incident_debut_ts: float, truth_debut_ts: float) -> float:
    return max(0.0, incident_debut_ts - truth_debut_ts)


def summarise(incidents, n_alerts_in, truths) -> dict:
    """truths: list of scenario truth dicts. Match each incident to the truth with the
    most source overlap, then average purity."""
    purities = []
    for inc in incidents:
        best = max(truths, key=lambda tr: len(set(inc["sources"]) & set(tr["sources"])), default=None)
        if best:
            purities.append(incident_purity(inc["sources"], best["sources"]))
    return {
        "taux_compression": round(compression(n_alerts_in, len(incidents)), 1),
        "n_incidents": len(incidents),
        "purete_moyenne": round(sum(purities) / len(purities), 3) if purities else 0.0,
    }
