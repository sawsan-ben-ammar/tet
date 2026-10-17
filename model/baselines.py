"""The two reference methods the GNN must beat (Section 10 of the brief).

Both produce the SAME prediction shape as the GNN, so evaluate.py scores them
identically.
"""
from __future__ import annotations

import numpy as np

from schema.features import FEATURES


# --------------------------------------------------------------------------- #
# Baseline 1: threshold rules (what a simple firewall does)
# --------------------------------------------------------------------------- #
class ThresholdRules:
    def __init__(self, t_src_rate=300.0, t_dst_rate=3000.0):
        self.t_src = t_src_rate
        self.t_dst = t_dst_rate

    def fit(self, windows):
        """Grid-search the two thresholds on training windows (maximise detection F1)."""
        from data_prep.evaluate import evaluate
        best, best_f1 = (self.t_src, self.t_dst), -1.0
        for ts in (50, 100, 200, 400, 800, 1600):
            for td in (500, 1000, 2000, 4000, 8000):
                self.t_src, self.t_dst = ts, td
                preds = [self.predict(w) for w in windows]
                f1 = evaluate(preds, windows)["detection_F1"]
                if f1 > best_f1:
                    best_f1, best = f1, (ts, td)
        self.t_src, self.t_dst = best
        return self

    def predict(self, w):
        # incoming rate per destination
        incoming = {}
        for e in w["aretes"]:
            if e["type"] == "flux":
                incoming[e["dst"]] = incoming.get(e["dst"], 0.0) + e.get("paquets", 0.0)
        cibles = {k: v for k, v in incoming.items() if v / 10.0 > self.t_dst}
        sources = {}
        for n in w["noeuds"]:
            if n["role"] == "externe":
                rate = (n["features"].get("paquets_s") or 0.0) + (n["features"].get("requetes_s") or 0.0)
                if rate > self.t_src:
                    sources[n["id"]] = rate
        verdict = "attaque" if cibles and sources else "normal"
        return {"verdict": verdict, "type": "ddos_udp_flood" if verdict == "attaque" else "none",
                "sources": sources, "cibles": cibles}


# --------------------------------------------------------------------------- #
# Baseline 2: Random Forest / XGBoost per flow (the classic ML approach)
# --------------------------------------------------------------------------- #
class FlowClassifier:
    def __init__(self, kind="rf", tau=0.1):  # kind in {"rf","xgb","lr"}
        self.kind = kind
        self.tau = tau  # share of attack flows to call the window an attack
        self.model = None

    def _rows(self, windows, labelled=True):
        """One row per flux edge: source features + the edge volume."""
        X, y, meta = [], [], []
        for wi, w in enumerate(windows):
            feats = {n["id"]: n["features"] for n in windows[wi]["noeuds"]}
            srcset = set(w["labels"].get("sources", []))
            for e in w["aretes"]:
                if e["type"] != "flux":
                    continue
                sf = feats.get(e["src"], {})
                row = [sf.get(f) if sf.get(f) is not None else 0.0 for f in FEATURES]
                row += [e.get("octets", 0.0), e.get("paquets", 0.0)]
                X.append(row)
                y.append(1 if (labelled and e["src"] in srcset) else 0)
                meta.append((wi, e["src"], e["dst"]))
        return np.array(X, dtype=float), np.array(y), meta

    def fit(self, windows):
        X, y, _ = self._rows(windows)
        if self.kind == "xgb":
            from xgboost import XGBClassifier
            self.model = XGBClassifier(n_estimators=120, max_depth=6, n_jobs=2,
                                       eval_metric="logloss", verbosity=0)
        elif self.kind == "lr":
            from sklearn.pipeline import make_pipeline
            from sklearn.preprocessing import StandardScaler
            from sklearn.linear_model import LogisticRegression
            self.model = make_pipeline(StandardScaler(),
                                       LogisticRegression(max_iter=1000, class_weight="balanced"))
        else:
            from sklearn.ensemble import RandomForestClassifier
            self.model = RandomForestClassifier(n_estimators=120, max_depth=12,
                                                n_jobs=2, class_weight="balanced")
        if len(set(y)) < 2:  # guard: all one class
            y[0] = 1 - y[0]
        self.model.fit(X, y)
        return self

    def predict_batch(self, windows):
        X, _, meta = self._rows(windows, labelled=False)
        if len(X) == 0:
            return [{"verdict": "normal", "type": "none", "sources": {}, "cibles": {}} for _ in windows]
        proba = self.model.predict_proba(X)[:, 1]
        per_win = [dict(sources={}, cibles={}, n=0, atk=0) for _ in windows]
        for (wi, src, dst), p in zip(meta, proba):
            pw = per_win[wi]
            pw["n"] += 1
            if p > 0.5:
                pw["atk"] += 1
                pw["sources"][src] = max(pw["sources"].get(src, 0.0), float(p))
                pw["cibles"][dst] = pw["cibles"].get(dst, 0.0) + float(p)
        preds = []
        for pw in per_win:
            share = pw["atk"] / pw["n"] if pw["n"] else 0.0
            verdict = "attaque" if share > self.tau else "normal"
            preds.append({"verdict": verdict, "p_attack": round(float(share), 4),
                          "type": "ddos_udp_flood" if verdict == "attaque" else "none",
                          "sources": pw["sources"] if verdict == "attaque" else {},
                          "cibles": pw["cibles"] if verdict == "attaque" else {}})
        return preds
