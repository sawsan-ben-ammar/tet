"""Train GAT and GraphSAGE and tabulate all four methods on the same test split.

    python -m model.compare --windows data/windows/labo --epochs 20
"""
from __future__ import annotations

import argparse

from data_prep.dataset import load_dir, load_windows, make_split, to_data_list
from data_prep.evaluate import evaluate, format_table
from model.baselines import ThresholdRules, FlowClassifier
from model.gnn import CorrelationGNN  # noqa: F401 (imported for side effects / clarity)
from model.train import train, run_eval


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--windows", default="data/windows/labo")
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--hold-out-type", default=None,
                    help="attack type reserved for test (generalisation)")
    args = ap.parse_args()

    W = load_windows(args.windows)
    sp = make_split(W, seed=args.seed,
                    hold_out_types=[args.hold_out_type] if args.hold_out_type else None)

    rows = {}
    tr = ThresholdRules().fit(sp.train)
    rows["Threshold rules"] = evaluate([tr.predict(w) for w in sp.test], sp.test)

    rf = FlowClassifier("rf").fit(sp.train)
    rows["Random Forest"] = evaluate(rf.predict_batch(sp.test), sp.test)

    sage = train(sp.train, sp.stats, epochs=args.epochs, conv="sage", val=sp.val, seed=args.seed, log=False)
    rows["GraphSAGE"] = run_eval(sage, sp.test, sp.stats)

    gat = train(sp.train, sp.stats, epochs=args.epochs, conv="gat", val=sp.val, seed=args.seed, log=False)
    rows["GAT (ours)"] = run_eval(gat, sp.test, sp.stats)

    print(format_table(rows))


if __name__ == "__main__":
    main()
