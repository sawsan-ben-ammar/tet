"""FastAPI service exposing both correlation functions.

    uvicorn deploy.api:app --host 0.0.0.0 --port 8000

Endpoints:
    GET  /health
    POST /correlation/attaque      -> correlation_attaque_distribuee (GNN inference on signals)
    POST /correlation/ids          -> correlation_ids_suricata (two-probe IDS correlation)
    GET  /captures                 -> list processed captures and their incident counts
    GET  /incidents[?capture=ID]   -> retrieve stored incident records (Phase 7)
    GET  /metrics/evaluation       -> the Phase 6 evaluation report (real + synthetic, separate)
"""
from __future__ import annotations

import glob
import json
import os
from typing import Any, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from model.correlation import correlation_attaque_distribuee, load_model, _STATE
from ids.correlation_ids import correlation_ids_suricata

app = FastAPI(title="Correlation d'attaques distribuees", version="1.0")
_IA_MODEL = {"m": None}


@app.on_event("startup")
def _startup():
    try:
        load_model()
    except Exception as exc:  # noqa: BLE001 - service still starts, /health reports
        print("model load failed:", exc)
    ia_path = os.environ.get("IDS_IA_MODEL", "ids/artifacts/ia.json")
    if os.path.exists(ia_path):
        try:
            from xgboost import XGBClassifier
            m = XGBClassifier()
            m.load_model(ia_path)
            _IA_MODEL["m"] = m
        except Exception as exc:  # noqa: BLE001
            print("ia model load failed:", exc)


class AttaqueRequest(BaseModel):
    flux: list
    metriques: Optional[dict] = None
    alertes: Optional[list] = None
    fenetre: str = "10s"


class IdsRequest(BaseModel):
    alertes_ids1: list
    alertes_ids2: list
    metriques: Optional[dict] = None
    fenetre: str = "10s"
    mode: str = "regles"


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "model": _STATE.get("version"),
            "ia_model_loaded": _IA_MODEL["m"] is not None}


@app.post("/correlation/attaque")
def attaque(req: AttaqueRequest) -> dict:
    return correlation_attaque_distribuee(req.flux, req.metriques, req.alertes, req.fenetre)


@app.post("/correlation/ids")
def ids(req: IdsRequest) -> dict:
    model = _IA_MODEL["m"] if req.mode == "ia" else None
    incidents = correlation_ids_suricata(req.alertes_ids1, req.alertes_ids2,
                                         req.metriques, req.fenetre, req.mode, model)
    return {"incidents": incidents, "n": len(incidents)}


# --------------------------- incident retrieval --------------------------- #
# Incidents produced offline by the Phase-7 engine are stored per capture at
# data/captures/<id>/incidents.json. These endpoints expose them for the
# dashboard and investigation (the brief's "incident retrieval").
_CAPTURES_DIR = os.environ.get("GNN_CAPTURES", "data/captures")
_REPORTS_DIR = os.environ.get("GNN_REPORTS", "reports")


@app.get("/captures")
def captures() -> dict:
    import glob
    out = []
    for inc in sorted(glob.glob(os.path.join(_CAPTURES_DIR, "*", "incidents.json"))):
        try:
            with open(inc) as fh:
                d = json.load(fh)
            out.append({"capture": d.get("capture"), "n_windows": d.get("n_windows"),
                        "n_attack_windows": d.get("n_attack_windows"),
                        "n_incidents": d.get("n_incidents")})
        except Exception:  # noqa: BLE001
            continue
    return {"captures": out, "n": len(out)}


@app.get("/incidents")
def incidents(capture: Optional[str] = None) -> dict:
    import glob
    paths = ([os.path.join(_CAPTURES_DIR, capture, "incidents.json")] if capture
             else sorted(glob.glob(os.path.join(_CAPTURES_DIR, "*", "incidents.json"))))
    all_inc = []
    for p in paths:
        if not os.path.exists(p):
            continue
        with open(p) as fh:
            all_inc.extend(json.load(fh).get("incidents", []))
    return {"incidents": all_inc, "n": len(all_inc)}


@app.get("/metrics/evaluation")
def evaluation_metrics() -> dict:
    """Serve the Phase-6 evaluation report if present (real + synthetic, separate)."""
    p = os.path.join(_REPORTS_DIR, "phase6", "phase6.json")
    if os.path.exists(p):
        with open(p) as fh:
            return json.load(fh)
    return {"status": "no evaluation report yet", "path": p}
