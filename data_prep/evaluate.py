"""Metrics shared by every method, so the GNN, the baselines and the rules all
report the same numbers (Section 10 of the brief). Never plain accuracy.

A prediction for one window is a dict:
    {"verdict": "attaque", "type": "ddos_syn_flood",
     "sources": {subnet: score,...}, "cibles": {node: score,...}}
A ground-truth window is the raw window dict.
"""
from __future__ import annotations

from collections import defaultdict

from schema.features import VERDICTS


def _pr_auc(scores, labels):
    """Average precision (area under PR curve) for binary labels. No sklearn dep."""
    pairs = sorted(zip(scores, labels), key=lambda x: -x[0])
    P = sum(labels)
    if P == 0:
        return 0.0
    tp = fp = 0; ap = 0.0; prev_r = 0.0
    for _, y in pairs:
        if y: tp += 1
        else: fp += 1
        prec = tp / (tp + fp); rec = tp / P
        ap += prec * (rec - prev_r); prev_r = rec
    return ap


def _prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f1


def evaluate(preds: list, windows: list) -> dict:
    """preds[i] corresponds to windows[i]."""
    assert len(preds) == len(windows)
    # detection (attaque vs not)
    tp = fp = fn = tn = 0
    peak_total = peak_fp = 0
    # type (attack windows only)
    type_tp = defaultdict(int); type_fp = defaultdict(int); type_fn = defaultdict(int)
    # sources
    s_tp = s_fp = s_fn = 0
    # target top-k
    top1 = top3 = tgt_total = 0

    for pred, w in zip(preds, windows):
        gt = w["labels"]
        is_atk = gt["verdict"] == "attaque"
        pred_atk = pred["verdict"] == "attaque"
        tp += is_atk and pred_atk
        fp += (not is_atk) and pred_atk
        fn += is_atk and (not pred_atk)
        tn += (not is_atk) and (not pred_atk)
        if gt["verdict"] == "pic_legitime":
            peak_total += 1
            peak_fp += pred_atk

        if is_atk:
            gt_t, pr_t = gt["type"], pred.get("type", "none")
            if gt_t == pr_t:
                type_tp[gt_t] += 1
            else:
                type_fn[gt_t] += 1
                type_fp[pr_t] += 1

            gt_src = set(gt.get("sources", []))
            pr_src = set(pred.get("sources", {}))
            s_tp += len(gt_src & pr_src)
            s_fp += len(pr_src - gt_src)
            s_fn += len(gt_src - pr_src)

            gt_tgt = set(gt.get("cibles", []))
            if gt_tgt:
                tgt_total += 1
                ranked = sorted(pred.get("cibles", {}), key=lambda k: -pred["cibles"][k])
                if ranked[:1] and ranked[0] in gt_tgt:
                    top1 += 1
                if gt_tgt & set(ranked[:3]):
                    top3 += 1

    det_p, det_r, det_f1 = _prf(tp, fp, fn)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    # 3-class confusion over verdicts
    vi = {v: i for i, v in enumerate(VERDICTS)}
    cm = [[0, 0, 0] for _ in VERDICTS]
    for pred, w in zip(preds, windows):
        cm[vi[w["labels"]["verdict"]]][vi.get(pred["verdict"], 0)] += 1
    # detection PR-AUC if scores are present
    scores = [pred.get("p_attack") for pred in preds]
    pr_auc = None
    if all(sc is not None for sc in scores):
        labels = [1 if w["labels"]["verdict"] == "attaque" else 0 for w in windows]
        pr_auc = round(_pr_auc(scores, labels), 4)
    types = set(type_tp) | set(type_fp) | set(type_fn)
    macro = sum(_prf(type_tp[t], type_fp[t], type_fn[t])[2] for t in types) / len(types) if types else 0.0
    src_p, src_r, _ = _prf(s_tp, s_fp, s_fn)
    return {
        "detection_P": det_p, "detection_R": det_r, "detection_F1": det_f1,
        "fp_rate_peaks": peak_fp / peak_total if peak_total else 0.0,
        "macro_F1_type": macro,
        "detection_FPR": round(fpr, 4),
        "detection_PR_AUC": pr_auc,
        "confusion_verdict": {"order": VERDICTS, "matrix": cm},
        "source_P": src_p, "source_R": src_r,
        "target_top1": top1 / tgt_total if tgt_total else 0.0,
        "target_top3": top3 / tgt_total if tgt_total else 0.0,
        "n_windows": len(windows),
    }


def format_table(rows: dict) -> str:
    """rows: {method_name: metrics_dict} -> a markdown table."""
    cols = ["detection_F1", "fp_rate_peaks", "macro_F1_type", "source_P", "source_R",
            "target_top1", "target_top3"]
    head = "| Method | " + " | ".join(cols) + " |"
    sep = "| --- " * (len(cols) + 1) + "|"
    lines = [head, sep]
    for name, m in rows.items():
        cells = " | ".join(f"{m.get(c, 0.0):.3f}" for c in cols)
        lines.append(f"| {name} | {cells} |")
    return "\n".join(lines)
