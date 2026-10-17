"""Multi-task focal loss. The internal-node head only trains on lab windows."""
from __future__ import annotations

import torch
import torch.nn.functional as F


def focal_ce(logits, target, gamma=2.0, weight=None):
    ce = F.cross_entropy(logits, target, reduction="none", weight=weight)
    pt = torch.exp(-ce)
    return ((1 - pt) ** gamma * ce).mean()


def focal_bce(logits, target, gamma=2.0, pos_weight=None):
    bce = F.binary_cross_entropy_with_logits(logits, target, reduction="none", pos_weight=pos_weight)
    pt = torch.exp(-bce)
    return ((1 - pt) ** gamma * bce).mean()


def total_loss(out, data, lam=(1.0, 0.5, 1.0, 1.0), gamma=2.0):
    """Sum of the four task losses, each masked to where it applies."""
    loss = lam[0] * focal_ce(out["verdict"], data.y_verdict, gamma)

    atk = data.y_verdict == 2  # graph-level mask over the batch
    if atk.any():
        loss = loss + lam[1] * focal_ce(out["type"][atk], data.y_type[atk], gamma)

    if data.is_ext.any():
        loss = loss + lam[2] * focal_bce(out["ext"][data.is_ext], data.y_ext[data.is_ext], gamma)

    # internal nodes, only on lab graphs (has_int is per-graph -> expand to nodes)
    batch = data.batch if hasattr(data, "batch") and data.batch is not None \
        else torch.zeros(data.x.size(0), dtype=torch.long)
    node_has_int = data.has_int[batch]
    mask = (~data.is_ext) & node_has_int
    if mask.any():
        loss = loss + lam[3] * focal_ce(out["int"][mask], data.y_int[mask], gamma)
    return loss
