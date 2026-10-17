"""Turn a model's raw output on one graph into the common prediction dict."""
from __future__ import annotations

import torch

from schema.features import VERDICTS, ATTACK_TYPES


@torch.no_grad()
def predict_window(model, data, src_threshold=0.5):
    model.eval()
    out = model(data)
    p_verdict = out["verdict"].softmax(-1)[0]
    verdict = VERDICTS[int(p_verdict.argmax())]
    res = {"verdict": verdict, "type": "none", "confiance": round(float(p_verdict.max()), 3),
           "p_attack": round(float(p_verdict[VERDICTS.index("attaque")]), 4),
           "sources": {}, "cibles": {}, "impactes": []}
    if verdict != "attaque":
        return res, out

    res["type"] = ATTACK_TYPES[int(out["type"][0].argmax())]
    p_ext = out["ext"].sigmoid()
    p_int = out["int"].softmax(-1)
    ids = data.node_ids
    is_ext = data.is_ext
    for i, nid in enumerate(ids):
        if is_ext[i]:
            if float(p_ext[i]) > src_threshold:
                res["sources"][nid] = round(float(p_ext[i]), 3)
        else:
            res["cibles"][nid] = round(float(p_int[i, 0]), 3)  # P(target)
            if int(p_int[i].argmax()) == 1:
                res["impactes"].append(nid)
    return res, out
