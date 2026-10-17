"""The deliverable function: correlation_attaque_distribuee.

Loads the trained model once, then for each window of signals returns the correlated
event: verdict, type, targets, attacking sources, impacted components, a confidence
score and an explanation.
"""
from __future__ import annotations

import json
import os
import re

import torch

from schema.features import WINDOW_S
from data_prep.to_graph import Stats, window_to_data
from model.gnn import CorrelationGNN
from model.predict import predict_window
from model.explain import build_explanation

_ARTIFACTS = os.environ.get("GNN_ARTIFACTS", os.path.join(os.path.dirname(__file__), "artifacts"))
_STATE = {"model": None, "stats": None, "conv": "gat", "version": None}


def load_model(artifacts: str = _ARTIFACTS):
    with open(os.path.join(artifacts, "features.json")) as fh:
        conv = json.load(fh).get("conv", "gat")
    model = CorrelationGNN(conv=conv)
    model.load_state_dict(torch.load(os.path.join(artifacts, "model.pt"), map_location="cpu", weights_only=True))
    model.eval()
    stats = Stats.from_json(os.path.join(artifacts, "stats.json"))
    _STATE.update(model=model, stats=stats, conv=conv, version=os.path.basename(artifacts.rstrip("/")))
    return model, stats


def _parse_fenetre(fenetre) -> float:
    if isinstance(fenetre, (int, float)):
        return float(fenetre)
    m = re.match(r"(\d+(?:\.\d+)?)\s*s?", str(fenetre))
    return float(m.group(1)) if m else WINDOW_S


def correlation_attaque_distribuee(flux, metriques=None, alertes=None, fenetre="10s") -> dict:
    """Analyse one window of signals and return the correlated event.

    flux:      list of flow records (see model.window_builder)
    metriques: {node_id: {cpu, memoire, latence_p95, taux_erreurs, type, depend_sur}}
    alertes:   list of {node, gravite}
    """
    from model.window_builder import build_window

    if _STATE["model"] is None:
        load_model()
    model, stats = _STATE["model"], _STATE["stats"]

    fen_s = _parse_fenetre(fenetre)
    window = build_window(flux, metriques, alertes, fenetre_s=fen_s)
    if not window["noeuds"]:
        return {"verdict": "normal", "type": "none", "confiance": 1.0,
                "cibles": [], "sources": [], "impactes": [], "explication": "",
                "modele": _STATE["version"]}
    data = window_to_data(window, stats)
    res, out = predict_window(model, data)

    res["modele"] = _STATE["version"]
    if res["verdict"] != "attaque":
        res["explication"] = ""
        res["cibles"] = []
        return res

    # format cibles as a ranked list of {composant, score}
    ranked = sorted(res["cibles"].items(), key=lambda kv: -kv[1])[:3]
    res["explication"] = build_explanation(window, res, data, out)
    res["cibles"] = [{"composant": k, "score": v} for k, v in ranked]
    res["sources"] = [{"sous_reseau": k, "score": v}
                      for k, v in sorted(res["sources"].items(), key=lambda kv: -kv[1])]
    return res
