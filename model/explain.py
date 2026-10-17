"""Explanation: which flows and which features drove the verdict.

Two sources: the GAT's own attention (free, always available) and GNNExplainer
(on demand, a few seconds). build_explanation writes one plain sentence an operator
can act on.
"""
from __future__ import annotations

import torch

from schema.features import FEATURES


def top_attention_edges(data, out, k=10):
    """Return [(src_id, dst_id, weight), ...] for the highest-attention flows."""
    att = out.get("att")
    if att is None:
        return []
    edge_index, alpha = att
    alpha = alpha.mean(-1) if alpha.dim() > 1 else alpha
    k = min(k, alpha.numel())
    top = torch.topk(alpha, k).indices
    ids = data.node_ids
    res = []
    for e in top.tolist():
        a, b = int(edge_index[0, e]), int(edge_index[1, e])
        if a < len(ids) and b < len(ids):
            res.append((ids[a], ids[b], float(alpha[e])))
    return res


def gnn_explainer(model, data, epochs=120):
    """Top edges and features from GNNExplainer on the verdict head."""
    import torch.nn as nn
    from torch_geometric.data import Data
    from torch_geometric.explain import Explainer, GNNExplainer

    class VerdictOnly(nn.Module):
        def __init__(self, m):
            super().__init__()
            self.m = m

        def forward(self, x, edge_index, edge_attr=None, batch=None):
            d = Data(x=x, edge_index=edge_index,
                     edge_attr=edge_attr if edge_attr is not None else data.edge_attr)
            d.batch = batch if batch is not None else torch.zeros(x.size(0), dtype=torch.long)
            return self.m(d)["verdict"]

    explainer = Explainer(
        model=VerdictOnly(model), algorithm=GNNExplainer(epochs=epochs),
        explanation_type="model", node_mask_type="attributes", edge_mask_type="object",
        model_config=dict(mode="multiclass_classification", task_level="graph", return_type="raw"))
    e = explainer(data.x, data.edge_index, edge_attr=data.edge_attr,
                  batch=torch.zeros(data.x.size(0), dtype=torch.long))
    top_feats = e.node_mask.abs().sum(0)
    feat_idx = torch.topk(top_feats, min(5, top_feats.numel())).indices.tolist()
    return [FEATURES[i] for i in feat_idx if i < len(FEATURES)]


def build_explanation(window, res, data, out) -> str:
    """One sentence: convergence, target, path, standout features."""
    sources = res.get("sources", {})
    n_src = len(sources)
    n_sub = len({s.split("#")[0] for s in sources})
    target = max(res.get("cibles", {}), key=lambda k: res["cibles"][k]) if res.get("cibles") else "?"
    impacted = res.get("impactes", [])
    path = " -> ".join([target] + impacted[:3]) if impacted else target

    # standout features on the target node
    standout = []
    ids = window and [n["id"] for n in window["noeuds"]]
    if ids and target in ids:
        tf = window["noeuds"][ids.index(target)]["features"]
        for name in ("latence_p95", "taux_erreurs", "ratio_syn", "paquets_s"):
            v = tf.get(name)
            if v is not None and v > 0:
                standout.append(name)
    feats = ", ".join(standout[:3]) if standout else "volume et connexions"

    return (f"{n_src} sources ({n_sub} sous-reseaux) convergent vers {target} ; "
            f"propagation {path} ; indicateurs saillants : {feats}. "
            f"Sources presentees comme indicateurs (adresses possiblement usurpees), non comme attribution.")
