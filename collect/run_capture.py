"""Process a raw capture into schema windows (Phases 3->4).

    python -m collect.run_capture data/captures/<id> \
        [--verdict normal|pic_legitime|attaque] [--attack-type ddos_syn_flood] \
        [--out data/windows/<id>]

Reads raw/ + manifest.seed.json, aligns to UTC windows, builds graph windows,
validates each against the schema, and writes them idempotently (never
overwrites an existing window file). Finalises manifest.json with per-source
status and prints a short capture summary.
"""
from __future__ import annotations

import argparse
import json
import os

from collect.model import CaptureManifest
from collect.capture import build_capture
from graph.build import build_window
from schema.validate import check


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cap_dir")
    ap.add_argument("--verdict", default="normal",
                    choices=["normal", "pic_legitime", "attaque"])
    ap.add_argument("--attack-type", default="none")
    ap.add_argument("--out", default=None)
    ap.add_argument("--scenario-json", default=None, help="label windows from a scenario timeline")
    args = ap.parse_args()

    seed = os.path.join(args.cap_dir, "manifest.seed.json")
    if os.path.exists(seed):
        with open(seed) as fh:
            s = json.load(fh)
        m = CaptureManifest(capture_id=s["capture_id"], scenario=s["scenario"],
                            window_s=s.get("window_s", 10.0), step_s=s.get("step_s", 5.0),
                            t_start=s.get("t_start", 0.0), t_end=s.get("t_end", 0.0),
                            config=s.get("config", {}))
    else:
        cid = os.path.basename(args.cap_dir.rstrip("/"))
        m = CaptureManifest(capture_id=cid, scenario=cid)

    bundles = build_capture(args.cap_dir, m)

    scn = None
    sj = args.scenario_json or os.path.join(args.cap_dir, "scenario.json")
    if os.path.exists(sj):
        from collect.label import load_scenario
        scn = load_scenario(sj)

    out = args.out or os.path.join("data", "windows", m.capture_id)
    os.makedirs(out, exist_ok=True)
    n_written, n_skipped, n_invalid = 0, 0, 0
    for i, b in enumerate(bundles):
        if scn is not None:
            from collect.label import label_window
            present = {n for bb in [b] for n in
                       [f.src for f in bb.flows] + [f.dst for f in bb.flows]} | set(b.metrics)
            v, at, cib, src, imp = label_window((b.t_start + b.t_end) / 2, scn, present)
            w = build_window(b, scenario=m.capture_id, verdict=v, attack_type=at,
                             cibles=cib, sources_lbl=src, impactes=imp, origine=m.origine)
        else:
            w = build_window(b, scenario=m.capture_id, verdict=args.verdict,
                             attack_type=args.attack_type, origine=m.origine)
        try:
            check(w)
        except Exception as exc:  # noqa: BLE001
            n_invalid += 1
            m.sources.setdefault("graph", __import__("collect.model", fromlist=["SourceStatus"]).SourceStatus("graph"))
            continue
        path = os.path.join(out, f"{m.capture_id}_{i:04d}.json")
        if os.path.exists(path):          # idempotent: never overwrite
            n_skipped += 1
            continue
        with open(path, "w") as fh:
            json.dump(w, fh)
        n_written += 1

    m.to_json(os.path.join(args.cap_dir, "manifest.json"))
    summary = {"capture": m.capture_id, "windows_built": len(bundles),
               "written": n_written, "skipped_existing": n_skipped, "invalid": n_invalid,
               "out": out,
               "sources": {k: {"present": v.present, "n": v.n_records, "errors": v.errors[:3]}
                           for k, v in m.sources.items()}}
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
