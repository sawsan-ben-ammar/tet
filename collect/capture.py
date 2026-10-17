"""Capture orchestration (Phase 3).

A capture reads the raw source files already written to disk (hubble.jsonl,
eve.ids1.jsonl, eve.ids2.jsonl, prometheus.json, pods.json), aligns them into
UTC windows, fills a manifest with per-source status/errors, and returns the
aligned WindowBundles. Raw files are the originals; nothing here overwrites them.

The live wiring (port-forwards, `hubble observe`, copying EVE off the node) is in
collect/run_capture.py so this module stays pure and unit-testable.
"""
from __future__ import annotations

import json
import os

from collect.model import CaptureManifest, SourceStatus
from collect import hubble as H
from collect import suricata as S
from collect import kube as K
from collect.align import align


def _status_from(name, records, tsfn):
    st = SourceStatus(name=name, present=bool(records), n_records=len(records))
    if records:
        ts = [tsfn(r) for r in records if tsfn(r)]
        if ts:
            st.t_first, st.t_last = min(ts), max(ts)
    return st


def build_capture(cap_dir, manifest: CaptureManifest):
    """Read raw files under cap_dir/raw, align, update manifest, return bundles."""
    raw = os.path.join(cap_dir, "raw")

    flows = list(H.read_flows(os.path.join(raw, "hubble.jsonl"))) \
        if os.path.exists(os.path.join(raw, "hubble.jsonl")) else []
    manifest.add_source(_status_from("hubble", flows, lambda f: f.ts))

    alerts = []
    for probe in ("ids1", "ids2"):
        p = os.path.join(raw, f"eve.{probe}.jsonl")
        got = list(S.read_eve(p, probe)) if os.path.exists(p) else []
        alerts += got
        manifest.add_source(_status_from(f"suricata_{probe}", got, lambda a: a["ts"]))

    prom, pods = {}, {}
    pj = os.path.join(raw, "prometheus.json")
    if os.path.exists(pj):
        with open(pj) as fh:
            prom = {k: {m: [tuple(x) for x in v] for m, v in series.items()}
                    for k, series in json.load(fh).items()}
    ppods = os.path.join(raw, "pods.json")
    if os.path.exists(ppods):
        with open(ppods) as fh:
            pods = K.parse_pods(json.load(fh))
    ps = SourceStatus(name="prometheus", present=bool(prom),
                      n_records=sum(len(s) for series in prom.values() for s in series.values()))
    manifest.add_source(ps)
    manifest.add_source(SourceStatus(name="kube_meta", present=bool(pods), n_records=len(pods)))

    # capture interval: prefer the manifest's, else infer from data
    t0, t1 = manifest.t_start, manifest.t_end
    if not (t0 and t1):
        allts = [f.ts for f in flows] + [a["ts"] for a in alerts]
        if allts:
            t0, t1 = min(allts), max(allts)
            manifest.t_start, manifest.t_end = t0, t1
    bundles = align(flows, alerts, prom, pods, t0, t1,
                    width=manifest.window_s, step=manifest.step_s)
    return bundles
