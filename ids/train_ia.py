"""Train the IA-mode window classifier (XGBoost, level 1 of Section 14.4).

Builds labelled (target, window) feature rows from synthetic scenarios and fits an
XGBoost classifier that the correlation uses in mode="ia".

    python -m ids.train_ia --out ids/artifacts/ia.json
"""
from __future__ import annotations

import argparse
import os
import random

from ids.common import pipeline, windows
from ids.correlation_ids import window_features
from ids.synth_eve import scenario_alerts, noise_alerts
from schema.features import ATTACK_TYPES

ATTACKS = [a for a in ATTACK_TYPES if a != "none"]


def build_rows(n_scenarios=120, seed=0):
    rng = random.Random(seed)
    X, y = [], []
    for i in range(n_scenarios):
        if rng.random() < 0.55:
            # positive: a real distributed attack (many sources)
            kind = rng.choice(ATTACKS)
            i1, i2, _ = scenario_alerts(kind, n_src=rng.choice([40, 80, 160]),
                                        duration=rng.uniform(20, 50), seed=seed + i)
            i1 += noise_alerts(seed=seed + 1000 + i)
            label = 1
        else:
            # negative: a sub-threshold DoS burst from few sources (false-positive case)
            kind = rng.choice(ATTACKS)
            i1, i2, _ = scenario_alerts(kind, n_src=rng.choice([1, 2, 3, 5]),
                                        duration=rng.uniform(10, 25), seed=seed + i)
            i1 += noise_alerts(seed=seed + 2000 + i)
            label = 0
        alerts = pipeline(i1, i2)
        for _, chunk in windows(alerts):
            by_target = {}
            for a in chunk:
                by_target.setdefault(a.cible, []).append(a)
            for al in by_target.values():
                X.append(window_features(al))
                y.append(label)
    return X, y


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="ids/artifacts/ia.json")
    ap.add_argument("--scenarios", type=int, default=120)
    args = ap.parse_args()

    from xgboost import XGBClassifier
    X, y = build_rows(args.scenarios)
    if len(set(y)) < 2:
        raise SystemExit("need both classes")
    model = XGBClassifier(n_estimators=150, max_depth=5, n_jobs=2,
                          eval_metric="logloss", verbosity=0)
    model.fit(X, y)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    model.save_model(args.out)
    acc = (model.predict(X) == y).mean()
    print(f"trained on {len(X)} rows, train acc {acc:.3f} -> {args.out}")


if __name__ == "__main__":
    main()
