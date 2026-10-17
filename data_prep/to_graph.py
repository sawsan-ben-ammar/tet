"""Window (JSON) -> PyTorch Geometric Data, and the normalisation stats.

Features are log-compressed then z-scored against *normal* behaviour, per internal
component and per node type for external sources. A binary "present" flag per
role-specific feature group keeps "missing" distinct from "zero" so lab and public
graphs can share one feature vector.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import torch
from torch_geometric.data import Data

from schema.features import (FEATURES, NODE_TYPES, VERDICTS, ATTACK_TYPES,
                             EXTERNAL_ONLY, INTERNAL_ONLY)

N_FEAT = len(FEATURES)
EDGE_DIM = 4  # [is_flux, is_dependance, log_octets, direction]
# input dim = features + present-flags(2) + node-type one-hot
IN_DIM = N_FEAT + 2 + len(NODE_TYPES)


def _logc(x: float) -> float:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return 0.0
    return math.copysign(math.log1p(abs(x)), x)


@dataclass
class Stats:
    """Mean/std of log-features, keyed by node type (external sources share 'externe')."""
    mean: dict = field(default_factory=dict)
    std: dict = field(default_factory=dict)

    def key(self, node) -> str:
        return node.get("type", "externe")

    def norm(self, node) -> np.ndarray:
        k = self.key(node)
        mean = self.mean.get(k, np.zeros(N_FEAT))
        std = self.std.get(k, np.ones(N_FEAT))
        raw = np.array([_logc(node["features"].get(f)) for f in FEATURES])
        return np.clip((raw - mean) / (std + 1e-6), -10, 10)

    def to_json(self, path):
        obj = {"mean": {k: v.tolist() for k, v in self.mean.items()},
               "std": {k: v.tolist() for k, v in self.std.items()}}
        with open(path, "w") as fh:
            json.dump(obj, fh)

    @classmethod
    def from_json(cls, path):
        with open(path) as fh:
            obj = json.load(fh)
        s = cls()
        s.mean = {k: np.array(v) for k, v in obj["mean"].items()}
        s.std = {k: np.array(v) for k, v in obj["std"].items()}
        return s


def fit_stats(windows) -> Stats:
    """Fit on NORMAL windows only. windows: iterable of dicts."""
    buckets: dict = {}
    for w in windows:
        if w["labels"]["verdict"] != "normal":
            continue
        for n in w["noeuds"]:
            k = n.get("type", "externe")
            buckets.setdefault(k, []).append([_logc(n["features"].get(f)) for f in FEATURES])
    s = Stats()
    for k, rows in buckets.items():
        arr = np.array(rows)
        s.mean[k] = arr.mean(0)
        s.std[k] = arr.std(0)
    return s


def _present_flags(node) -> list:
    ext = 1.0 if any(node["features"].get(f) is not None for f in EXTERNAL_ONLY) else 0.0
    inte = 1.0 if any(node["features"].get(f) is not None for f in INTERNAL_ONLY) else 0.0
    return [ext, inte]


def window_to_data(w: dict, stats: Stats) -> Data:
    nodes = w["noeuds"]
    ids = [n["id"] for n in nodes]
    idx = {k: i for i, k in enumerate(ids)}

    X = []
    for n in nodes:
        z = stats.norm(n)
        onehot = np.zeros(len(NODE_TYPES))
        onehot[NODE_TYPES.index(n.get("type", "externe"))] = 1.0
        X.append(np.concatenate([z, _present_flags(n), onehot]))

    src, dst, attr = [], [], []
    for e in w["aretes"]:
        a, b = idx[e["src"]], idx[e["dst"]]
        if e["type"] == "flux":
            base = [1.0, 0.0, _logc(e.get("octets", 0.0))]
        else:
            base = [0.0, 1.0, 0.0]
        src += [a, b]
        dst += [b, a]
        attr += [base + [1.0], base + [-1.0]]
    if not src:  # isolated graph guard
        src, dst = [0], [0]
        attr = [[0.0, 0.0, 0.0, 0.0]]

    L = w["labels"]
    is_ext = torch.tensor([n["role"] == "externe" for n in nodes])
    y_ext = torch.tensor([1.0 if i in set(L.get("sources", [])) else 0.0 for i in ids])
    # internal node class: 0 cible, 1 impacte, 2 sain
    cibles, impactes = set(L.get("cibles", [])), set(L.get("impactes", []))
    y_int = torch.tensor([0 if i in cibles else 1 if i in impactes else 2 for i in ids], dtype=torch.long)

    return Data(
        x=torch.tensor(np.array(X), dtype=torch.float),
        edge_index=torch.tensor([src, dst], dtype=torch.long),
        edge_attr=torch.tensor(np.array(attr), dtype=torch.float),
        is_ext=is_ext,
        y_ext=y_ext,
        y_int=y_int,
        has_int=torch.tensor([w["origine"] == "labo"]),
        y_verdict=torch.tensor([VERDICTS.index(L["verdict"])], dtype=torch.long),
        y_type=torch.tensor([ATTACK_TYPES.index(L.get("type", "none"))], dtype=torch.long),
        scenario=w["scenario"],
        node_ids=ids,
    )


def load_window(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)
