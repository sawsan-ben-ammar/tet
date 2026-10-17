"""Generate evaluation plots from the Phase-6 report (Phase 6/8 deliverable).

    python -m model.plots --report reports/phase6/phase6.json --out reports/phase6
Produces, for each dataset present (real, synth): a detection-F1 bar chart across
methods and a verdict confusion-matrix heatmap for the GAT model.
"""
from __future__ import annotations
import argparse, json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def _bar(results, title, path):
    methods = [m for m in results if "error" not in results[m]]
    f1 = [results[m].get("detection_F1_mean", results[m].get("detection_F1", 0)) for m in methods]
    typ = [results[m].get("macro_F1_type_mean", results[m].get("macro_F1_type", 0)) for m in methods]
    x = range(len(methods)); w = 0.38
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([i - w/2 for i in x], f1, w, label="detection F1", color="#2b6cb0")
    ax.bar([i + w/2 for i in x], typ, w, label="attack-type macro-F1", color="#dd6b20")
    ax.set_xticks(list(x)); ax.set_xticklabels(methods, rotation=20, ha="right")
    ax.set_ylim(0, 1.05); ax.set_ylabel("score"); ax.set_title(title); ax.legend()
    fig.tight_layout(); fig.savefig(path, dpi=120); plt.close(fig)


def _cm(results, title, path):
    gat = results.get("GAT (ours)", {})
    cm = gat.get("confusion_verdict")
    if not cm:
        return
    import numpy as np
    M = np.array(cm["matrix"], float); order = cm["order"]
    Mn = M / M.sum(1, keepdims=True).clip(min=1)
    fig, ax = plt.subplots(figsize=(5, 4.2))
    im = ax.imshow(Mn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(order))); ax.set_xticklabels(order, rotation=20, ha="right")
    ax.set_yticks(range(len(order))); ax.set_yticklabels(order)
    ax.set_xlabel("predicted"); ax.set_ylabel("true"); ax.set_title(title)
    for i in range(len(order)):
        for j in range(len(order)):
            ax.text(j, i, f"{int(M[i,j])}", ha="center", va="center",
                    color="white" if Mn[i, j] > 0.5 else "black")
    fig.colorbar(im, fraction=0.046); fig.tight_layout(); fig.savefig(path, dpi=120); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="reports/phase6/phase6.json")
    ap.add_argument("--out", default="reports/phase6")
    a = ap.parse_args()
    d = json.load(open(a.report)); os.makedirs(a.out, exist_ok=True)
    made = []
    for key in ("real", "synth"):
        if key in d:
            r = d[key]["results"]; nm = d[key]["name"]
            p1 = os.path.join(a.out, f"detection_{key}.png"); _bar(r, f"Detection & type — {nm}", p1); made.append(p1)
            p2 = os.path.join(a.out, f"confusion_{key}.png"); _cm(r, f"Verdict confusion (GAT) — {nm}", p2)
            if os.path.exists(p2): made.append(p2)
    print("wrote:", *made)


if __name__ == "__main__":
    main()
