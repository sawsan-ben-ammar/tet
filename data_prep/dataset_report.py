"""Dataset statistics report (Phase 5).

Scans one or more window directories (each a capture/scenario) and reports
everything the brief asks for: number of captures and windows, label
distribution, node/edge statistics, missing features and timestamp coverage,
duplicate windows and capture overlap, class imbalance, and the split
methodology. Real and synthetic captures are reported separately (origine).

    python -m data_prep.dataset_report data/windows/real-* --out reports/dataset.json
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
from collections import Counter, defaultdict

from schema.features import FEATURES
from data_prep.dataset import load_dir, make_split


def _window_hash(w):
    key = (w["scenario"], w["fenetre"]["debut"], len(w["noeuds"]), len(w["aretes"]))
    return hashlib.sha1(repr(key).encode()).hexdigest()[:12]


def report(dirs):
    captures = {}
    all_windows = []
    for d in dirs:
        ws = load_dir(d)
        if not ws:
            continue
        cap = os.path.basename(d.rstrip("/"))
        captures[cap] = ws
        all_windows.extend(ws)

    verdicts = Counter(w["labels"]["verdict"] for w in all_windows)
    types = Counter(w["labels"]["type"] for w in all_windows if w["labels"]["verdict"] == "attaque")
    origines = Counter(w["origine"] for w in all_windows)

    n_nodes = [len(w["noeuds"]) for w in all_windows]
    n_edges = [len(w["aretes"]) for w in all_windows]
    ext = [sum(n["role"] == "externe" for n in w["noeuds"]) for w in all_windows]

    # missing-feature coverage per feature (share of nodes where it is None)
    miss = {f: [0, 0] for f in FEATURES}   # [missing, total]
    for w in all_windows:
        for n in w["noeuds"]:
            for f in FEATURES:
                miss[f][1] += 1
                if n["features"].get(f) is None:
                    miss[f][0] += 1
    missing = {f: round(m / t, 3) if t else 0.0 for f, (m, t) in miss.items()}

    # duplicate windows / overlap
    hashes = Counter(_window_hash(w) for w in all_windows)
    dups = sum(c - 1 for c in hashes.values() if c > 1)

    per_capture = {}
    for cap, ws in captures.items():
        vc = Counter(w["labels"]["verdict"] for w in ws)
        per_capture[cap] = {"windows": len(ws), "verdicts": dict(vc),
                            "origine": ws[0]["origine"] if ws else None,
                            "t_first": ws[0]["fenetre"]["debut"] if ws else None,
                            "t_last": ws[-1]["fenetre"]["debut"] if ws else None}

    # split preview (by capture/scenario; no window leakage)
    split = None
    if all_windows:
        sp = make_split(all_windows, seed=0)
        split = {"train_windows": len(sp.train), "val_windows": len(sp.val),
                 "test_windows": len(sp.test),
                 "method": "grouped by capture/scenario id (no window shared across splits)"}

    imbalance = None
    if verdicts:
        mx, mn = max(verdicts.values()), min(verdicts.values())
        imbalance = round(mx / mn, 2) if mn else None

    return {
        "n_captures": len(captures),
        "n_windows": len(all_windows),
        "origine_distribution": dict(origines),
        "verdict_distribution": dict(verdicts),
        "attack_type_distribution": dict(types),
        "class_imbalance_ratio_max_min": imbalance,
        "nodes_per_window": {"min": min(n_nodes, default=0), "max": max(n_nodes, default=0),
                              "mean": round(sum(n_nodes) / len(n_nodes), 1) if n_nodes else 0},
        "edges_per_window": {"min": min(n_edges, default=0), "max": max(n_edges, default=0),
                              "mean": round(sum(n_edges) / len(n_edges), 1) if n_edges else 0},
        "external_nodes_per_window_mean": round(sum(ext) / len(ext), 1) if ext else 0,
        "duplicate_windows": dups,
        "missing_feature_rate": missing,
        "per_capture": per_capture,
        "split_preview": split,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    dirs = []
    for pat in args.dirs:
        dirs.extend(sorted(glob.glob(pat)))
    rep = report([d for d in dirs if os.path.isdir(d)])
    txt = json.dumps(rep, indent=2)
    print(txt)
    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as fh:
            fh.write(txt)


if __name__ == "__main__":
    main()
