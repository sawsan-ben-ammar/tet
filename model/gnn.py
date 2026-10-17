"""The multi-task GNN: a shared GAT encoder and three heads.

- graph head:    verdict (normal / pic_legitime / attaque) + attack type
- external head: is this source an attacker?
- internal head: is this component the target / impacted / healthy?

GraphSAGE is available for comparison by passing conv="sage".
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, SAGEConv, global_mean_pool, global_max_pool

from schema.features import VERDICTS, ATTACK_TYPES
from data_prep.to_graph import IN_DIM, EDGE_DIM


class Encoder(nn.Module):
    def __init__(self, in_dim=IN_DIM, hid=64, layers=3, heads=4, dropout=0.2, conv="gat"):
        super().__init__()
        self.inp = nn.Linear(in_dim, hid)
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()
        self.conv = conv
        for _ in range(layers):
            if conv == "gat":
                self.convs.append(GATConv(hid, hid // heads, heads=heads,
                                          edge_dim=EDGE_DIM, dropout=dropout))
            else:
                self.convs.append(SAGEConv(hid, hid, aggr="max"))
            self.norms.append(nn.LayerNorm(hid))
        self.dropout = dropout
        self._last_att = None

    def forward(self, x, edge_index, edge_attr):
        h = self.inp(x)
        atts = []
        for conv, norm in zip(self.convs, self.norms):
            if self.conv == "gat":
                out, att = conv(h, edge_index, edge_attr, return_attention_weights=True)
                atts.append(att)
            else:
                out = conv(h, edge_index)
            h = norm(h + F.dropout(F.elu(out), self.dropout, self.training))
        self._last_att = atts[-1] if atts else None
        return h


class CorrelationGNN(nn.Module):
    def __init__(self, in_dim=IN_DIM, hid=64, layers=3, heads=4, dropout=0.2, conv="gat"):
        super().__init__()
        self.enc = Encoder(in_dim, hid, layers, heads, dropout, conv)
        self.verdict_head = nn.Sequential(nn.Linear(2 * hid, hid), nn.ReLU(), nn.Linear(hid, len(VERDICTS)))
        self.type_head = nn.Sequential(nn.Linear(2 * hid, hid), nn.ReLU(), nn.Linear(hid, len(ATTACK_TYPES)))
        self.ext_head = nn.Linear(hid, 1)
        self.int_head = nn.Linear(hid, 3)

    def forward(self, data):
        h = self.enc(data.x, data.edge_index, data.edge_attr)
        batch = data.batch if hasattr(data, "batch") and data.batch is not None \
            else torch.zeros(data.x.size(0), dtype=torch.long, device=data.x.device)
        g = torch.cat([global_mean_pool(h, batch), global_max_pool(h, batch)], dim=-1)
        return {
            "verdict": self.verdict_head(g),
            "type": self.type_head(g),
            "ext": self.ext_head(h).squeeze(-1),
            "int": self.int_head(h),
            "att": self.enc._last_att,
            "h": h,
        }
