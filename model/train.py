"""Train the correlation GNN and save weights + stats + feature list.

    python -m model.train --windows data/windows/labo --epochs 30 --out model/artifacts
"""
from __future__ import annotations

import argparse
import json
import os

import torch
from torch_geometric.loader import DataLoader

from schema.features import FEATURES
from data_prep.dataset import load_dir, load_windows, make_split, to_data_list
from data_prep.evaluate import evaluate
from model.gnn import CorrelationGNN
from model.losses import total_loss
from model.predict import predict_window


def run_eval(model, windows, stats):
    data_list = to_data_list(windows, stats)
    preds = [predict_window(model, d)[0] for d in data_list]
    return evaluate(preds, windows)


def train(windows, stats, epochs=30, hid=64, layers=3, heads=4, lr=1e-3, conv="gat",
          gamma=2.0, lam=(1.0, 0.5, 1.0, 1.0), val=None, seed=0, log=True):
    torch.manual_seed(seed)
    model = CorrelationGNN(hid=hid, layers=layers, heads=heads, conv=conv)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    train_list = to_data_list(windows, stats)
    loader = DataLoader(train_list, batch_size=32, shuffle=True)

    best_f1, best_state = -1.0, None
    for ep in range(epochs):
        model.train()
        tot = 0.0
        for batch in loader:
            opt.zero_grad()
            out = model(batch)
            loss = total_loss(out, batch, lam=lam, gamma=gamma)
            loss.backward()
            opt.step()
            tot += float(loss)
        if val is not None:
            m = run_eval(model, val, stats)
            if m["detection_F1"] >= best_f1:
                best_f1, best_state = m["detection_F1"], {k: v.clone() for k, v in model.state_dict().items()}
            if log:
                print(f"ep {ep:02d} loss {tot/len(loader):.3f} val_F1 {m['detection_F1']:.3f} "
                      f"type_F1 {m['macro_F1_type']:.3f} fp_peaks {m['fp_rate_peaks']:.3f}")
        elif log:
            print(f"ep {ep:02d} loss {tot/len(loader):.3f}")
    if best_state is not None:
        model.load_state_dict(best_state)
    return model


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--windows", default="data/windows/labo")
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--conv", default="gat", choices=["gat", "sage"])
    ap.add_argument("--out", default="model/artifacts")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    W = load_windows(args.windows)
    scenarios = sorted({w["scenario"] for w in W})
    print(f"loaded {len(W)} windows from {len(scenarios)} capture(s) matching {args.windows!r}")
    if len(scenarios) < 3:
        raise SystemExit(
            f"ERROR: need at least 3 captures (train/val/test are split by capture), "
            f"found {len(scenarios)}: {scenarios}\n"
            f"  cwd = {os.getcwd()}\n"
            f"  Check that data/windows/<capture>/*.json exists here "
            f"(note: data/ is in .gitignore, so it is not copied by git clone/pull).")
    sp = make_split(W, seed=args.seed)
    print(f"split: train={len(sp.train)} val={len(sp.val)} test={len(sp.test)} windows")
    if not sp.train or not sp.val or not sp.test:
        raise SystemExit("ERROR: a split is empty; add more captures.")
    model = train(sp.train, sp.stats, epochs=args.epochs, conv=args.conv, val=sp.val, seed=args.seed)

    test_m = run_eval(model, sp.test, sp.stats)
    print("TEST", json.dumps(test_m, indent=2))

    os.makedirs(args.out, exist_ok=True)
    torch.save(model.state_dict(), os.path.join(args.out, "model.pt"))
    sp.stats.to_json(os.path.join(args.out, "stats.json"))
    with open(os.path.join(args.out, "features.json"), "w") as fh:
        json.dump({"features": FEATURES, "conv": args.conv}, fh)
    with open(os.path.join(args.out, "test_metrics.json"), "w") as fh:
        json.dump(test_m, fh, indent=2)
    print(f"saved -> {args.out}")


if __name__ == "__main__":
    main()
