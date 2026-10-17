"""Phase 6 evaluation driver: baseline (LR/RF) vs GAT vs GraphSAGE.

Runs the full comparison on a window set, with capture-level splits (no leakage),
multiple seeds for the GNNs (mean ± std), confusion matrices, PR-AUC, FPR and
inference latency. Real and synthetic datasets are evaluated and reported
SEPARATELY and never mixed in a single headline number.

    python -m model.phase6 --real "data/windows/real-*" --out reports/phase6
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import time

from data_prep.dataset import load_windows, make_split, stratified_capture_split, to_data_list
from data_prep.evaluate import evaluate, format_table
from model.baselines import ThresholdRules, FlowClassifier
from model.train import train, run_eval
from model.predict import predict_window


def _latency_ms(model, windows, stats):
    data = to_data_list(windows[: min(len(windows), 50)], stats)
    if not data:
        return None
    t0 = time.time()
    for d in data:
        predict_window(model, d)
    return round(1000.0 * (time.time() - t0) / len(data), 2)


def evaluate_dataset(windows, name, seeds=(0, 1, 2), epochs=25):
    sp = stratified_capture_split(windows, n_test=1, n_val=1, seed=0)
    out = {"name": name, "n_windows": len(windows),
           "split": {"train": len(sp.train), "val": len(sp.val), "test": len(sp.test)}}
    rows = {}

    # baselines (deterministic)
    tr = ThresholdRules().fit(sp.train)
    rows["Threshold rules"] = evaluate([tr.predict(w) for w in sp.test], sp.test)
    for kind, label in [("lr", "Logistic Regression"), ("rf", "Random Forest")]:
        try:
            clf = FlowClassifier(kind).fit(sp.train)
            rows[label] = evaluate(clf.predict_batch(sp.test), sp.test)
        except Exception as exc:  # noqa: BLE001
            rows[label] = {"error": str(exc)}

    # GNNs: multiple seeds -> mean/std of detection F1 and type macro F1
    for conv, label in [("sage", "GraphSAGE"), ("gat", "GAT (ours)")]:
        per_seed, last = [], None
        lat = None
        for sd in seeds:
            m = train(sp.train, sp.stats, epochs=epochs, conv=conv, val=sp.val, seed=sd, log=False)
            met = run_eval(m, sp.test, sp.stats)
            per_seed.append(met)
            last = m
        def agg(key):
            vals = [p[key] for p in per_seed if isinstance(p.get(key), (int, float))]
            return (round(statistics.mean(vals), 3),
                    round(statistics.pstdev(vals), 3) if len(vals) > 1 else 0.0) if vals else (None, None)
        base = dict(per_seed[-1])
        base["detection_F1_mean"], base["detection_F1_std"] = agg("detection_F1")
        base["macro_F1_type_mean"], base["macro_F1_type_std"] = agg("macro_F1_type")
        base["inference_latency_ms"] = _latency_ms(last, sp.test, sp.stats)
        base["seeds"] = list(seeds)
        rows[label] = base

    out["results"] = rows
    out["table"] = format_table({k: v for k, v in rows.items() if "error" not in v})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", default="data/windows/real-*")
    ap.add_argument("--synth", default=None, help="synthetic windows dir (optional)")
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    ap.add_argument("--out", default="reports/phase6")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    report = {}
    real = load_windows(args.real)
    if real:
        r = evaluate_dataset(real, "real (lab captures)", seeds=args.seeds, epochs=args.epochs)
        report["real"] = r
        print("\n===== REAL (lab captures) =====")
        print(f"windows={r['n_windows']} split={r['split']}")
        print(r["table"])
    else:
        print("no real windows found at", args.real)

    if args.synth:
        syn = load_windows(args.synth)
        if syn:
            s = evaluate_dataset(syn, "synthetic (development only)", seeds=args.seeds, epochs=args.epochs)
            report["synth"] = s
            print("\n===== SYNTHETIC (development only; NOT real-world performance) =====")
            print(f"windows={s['n_windows']} split={s['split']}")
            print(s["table"])

    with open(os.path.join(args.out, "phase6.json"), "w") as fh:
        json.dump(report, fh, indent=2)
    print("\nwrote", os.path.join(args.out, "phase6.json"))


if __name__ == "__main__":
    main()
