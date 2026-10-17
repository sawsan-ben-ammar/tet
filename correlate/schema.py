"""Incident record schema (Phase 7).

An incident separates OBSERVED FACTS (flows, alerts, metrics that were measured)
from MODEL INFERENCE (the GNN's verdict/type/sources/targets). It never presents
correlation as proof of causation, and always lists evidence limitations.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class Incident:
    incident_id: str
    debut: str                      # ISO UTC
    fin: str
    # --- model inference (from the GNN over temporal windows) ---
    categorie_predite: str          # attack type or "indetermine"
    confiance: float                # mean window confidence
    cibles_inferees: list = field(default_factory=list)      # [{composant, score}]
    sources_inferees: list = field(default_factory=list)     # [{sous_reseau, score}] (indicators, not attribution)
    impactes_inferes: list = field(default_factory=list)
    # --- observed facts (measured, not inferred) ---
    faits_observes: dict = field(default_factory=dict)       # flows, alerts, metric shifts
    alertes_ids: list = field(default_factory=list)          # correlated Suricata incidents
    # --- provenance / honesty ---
    fenetres: list = field(default_factory=list)             # window timestamps in the incident
    explication: str = ""
    limites_preuve: list = field(default_factory=list)       # what the evidence cannot show
    etapes_recommandees: list = field(default_factory=list)  # investigation steps
    capteurs_disponibles: dict = field(default_factory=dict) # which sensors had data

    def to_dict(self):
        return asdict(self)
