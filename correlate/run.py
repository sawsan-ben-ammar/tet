"""Run the correlation engine over one processed capture (Phase 7).

Loads the trained GNN, rebuilds the capture's aligned bundles + windows, runs the
GNN per window, runs the two-probe Suricata correlation over the capture's EVE,
then fuses everything into incident records.

    python -m correlate.run data/captures/<id> [--artifacts model/artifacts] [--out ...]
"""
from __future__ import annotations

import argparse
import json
import os

from collect.model import CaptureManifest
from collect.capture import build_capture
from collect import suricata as S
from graph.build import build_window
from data_prep.to_graph import window_to_data, Stats
from model.gnn import CorrelationGNN
from model.predict import predict_window
from correlate.engine import correlate
from ids.correlation_ids import correlation_ids_suricata


def _load_model(artifacts):
    with open(os.path.join(artifacts, "features.json")) as fh:
        conv = json.load(fh).get("conv", "gat")
    import torch
    m = CorrelationGNN(conv=conv)
    m.load_state_dict(torch.load(os.path.join(artifacts, "model.pt"), map_location="cpu", weights_only=True))
    m.eval()
    return m, Stats.from_json(os.path.join(artifacts, "stats.json"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cap_dir")
    ap.add_argument("--artifacts", default="model/artifacts")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    seed = os.path.join(args.cap_dir, "manifest.seed.json")
    s = json.load(open(seed)) if os.path.exists(seed) else {"capture_id": os.path.basename(args.cap_dir)}
    m = CaptureManifest(capture_id=s.get("capture_id", "cap"), scenario=s.get("scenario", "cap"),
                        t_start=s.get("t_start", 0.0), t_end=s.get("t_end", 0.0),
                        window_s=s.get("window_s", 10.0), step_s=s.get("step_s", 5.0))
    bundles = build_capture(args.cap_dir, m)

    model, stats = _load_model(args.artifacts)
    items = []
    for b in bundles:
        w = build_window(b, scenario=m.capture_id)
        data = window_to_data(w, stats)
        pred, _ = predict_window(model, data)
        items.append((w, pred, b))

    # two-probe Suricata incidents over the raw EVE of THIS capture only. The EVE
    # file on the node accumulates across sessions, so alerts are windowed to the
    # capture interval [t_start, t_end] before correlation (otherwise stale alerts
    # from earlier scenarios would leak in).
    raw = os.path.join(args.cap_dir, "raw")
    t0, t1 = m.t_start, m.t_end

    def _window_eve(path, probe):
        if not os.path.exists(path):
            return []
        out = []
        for a in S.read_eve(path, probe):
            if not (t0 and t1) or (t0 <= a["ts"] <= t1):
                out.append(S.to_eve_record(a))
        return out

    eve1 = _window_eve(os.path.join(raw, "eve.ids1.jsonl"), "ids1")
    eve2 = _window_eve(os.path.join(raw, "eve.ids2.jsonl"), "ids2")
    ids_incidents = correlation_ids_suricata(eve1, eve2, mode="regles")

    incidents = correlate(items, ids_incidents, capture_id=m.capture_id)
    out = args.out or os.path.join(args.cap_dir, "incidents.json")
    with open(out, "w") as fh:
        json.dump({"capture": m.capture_id, "n_windows": len(items),
                   "n_attack_windows": sum(p["verdict"] == "attaque" for _, p, _ in items),
                   "n_incidents": len(incidents), "incidents": incidents}, fh, indent=2)
    print(f"{m.capture_id}: {len(items)} windows, "
          f"{sum(p['verdict']=='attaque' for _,p,_ in items)} attack windows, "
          f"{len(incidents)} incidents, {len(ids_incidents)} IDS incidents -> {out}")


if __name__ == "__main__":
    main()
