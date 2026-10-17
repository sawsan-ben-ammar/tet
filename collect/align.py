"""Time alignment (Phase 3).

Cut the raw per-source streams into common sliding windows [t, t+W) stepping by S,
all in UTC. Every window gets the flows, alerts and metric samples whose event
time falls inside it. Metrics (sampled every step) use the last sample at or
before the window end (last-observation-carried-forward within one step). The
output is a list of WindowBundle; Phase 4 turns each into a schema graph window.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass
class WindowBundle:
    t_start: float
    t_end: float
    flows: list = field(default_factory=list)       # collect.hubble.Flow
    alerts: list = field(default_factory=list)       # normalised suricata dicts
    metrics: dict = field(default_factory=dict)      # workload -> {metric: value}
    pods: dict = field(default_factory=dict)         # workload -> meta dict


def _grid(t0, t1, width, step):
    t = math.floor(t0 / step) * step
    while t < t1:
        yield t, t + width
        t += step


def _metric_at(samples, t_end):
    """Last (ts,val) at or before t_end; None if none."""
    best = None
    for ts, val in samples:
        if ts <= t_end and (best is None or ts > best[0]):
            best = (ts, val)
    return best[1] if best else None


def align(flows, alerts, prom, pods, t_start, t_end, width=10.0, step=5.0):
    """Build the aligned window bundles. Inputs:
       flows: iterable of Flow; alerts: iterable of normalised dicts;
       prom: {workload: {metric: [(ts,val)]}}; pods: {workload: meta}."""
    flows = sorted(flows, key=lambda f: f.ts)
    alerts = sorted(alerts, key=lambda a: a["ts"])
    bundles = []
    for ws, we in _grid(t_start, t_end, width, step):
        b = WindowBundle(t_start=ws, t_end=we)
        b.flows = [f for f in flows if ws <= f.ts < we]
        b.alerts = [a for a in alerts if ws <= a["ts"] < we]
        for wl, series in prom.items():
            vals = {m: _metric_at(s, we) for m, s in series.items()}
            if any(v is not None for v in vals.values()):
                b.metrics[wl] = vals
        b.pods = dict(pods)
        # keep only non-empty windows (some signal present)
        if b.flows or b.alerts or b.metrics:
            bundles.append(b)
    return bundles
