"""Per-window labelling from a scenario timeline (Phase 5).

The scenario YAML/JSON is the label source of truth. A window is labelled by
which phase its midpoint falls in: warmup/cooldown -> normal; the event phase ->
the scenario's verdict/type. Targets come from the scenario; attacking sources
are the simulated subnets; impacted services are the target's direct dependants
(reported as inference, see the correlation engine). Labels are assigned by time,
never by looking at the model's output.
"""
from __future__ import annotations
import json

from collect.kube import BOUTIQUE_DEPENDS


def _downstream(target):
    """Direct dependants of the target workload (who calls it) -> impacted."""
    wl = target.split("/")[-1]
    ns = target.split("/")[0] if "/" in target else "boutique"
    out = []
    for caller, callees in BOUTIQUE_DEPENDS.items():
        if wl in callees:
            out.append(f"{ns}/{caller}")
    return out


def load_scenario(path):
    with open(path) as fh:
        return json.load(fh)


def label_window(mid_ts, scn, present_ids):
    """Return (verdict, type, cibles, sources, impactes) for a window midpoint."""
    ph = scn["phases"]
    verdict, atype = "normal", "none"
    a0, a1 = ph["attack"]
    if a0 <= mid_ts < a1:
        verdict = scn.get("verdict", "normal")
        atype = scn.get("type", "none") if verdict == "attaque" else "none"
    if verdict == "normal":
        return "normal", "none", [], [], []
    target = scn["target"]
    cibles = [target] if target in present_ids else []
    sources = [s.replace("-", ".") + "/24" for s in scn.get("sim_subnets", [])]
    sources = [s for s in sources if s in present_ids]
    impactes = [d for d in _downstream(target) if d in present_ids]
    return verdict, atype, cibles, sources, impactes
