"""Generate a labelled dataset of scenarios and write it under data/windows/labo/.

A scenario is a short time series of windows: warmup (normal) -> event -> cooldown.
Splitting is done by scenario later, so every window carries its scenario id.

    python -m data_prep.generate_dataset --scenarios 400 --out data/windows/labo
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random

from schema.features import ATTACK_TYPES, STEP_S
from schema.validate import check
from data_prep.synth import make_window

ATTACKS = [a for a in ATTACK_TYPES if a != "none"]


def scenario_windows(kind: str, scn_id: str, rng: random.Random, start: dt.datetime):
    """Yield the windows of one scenario in time order."""
    if kind == "normal":
        verdict, atype, n_event = "normal", "none", rng.randint(4, 8)
    elif kind == "pic_legitime":
        verdict, atype, n_event = "pic_legitime", "none", rng.randint(3, 6)
    else:
        verdict, atype, n_event = "attaque", kind, rng.randint(4, 10)

    n_warm, n_cool = rng.randint(2, 4), rng.randint(1, 3)
    t = start
    plan = [("normal", "none")] * n_warm + [(verdict, atype)] * n_event + [("normal", "none")] * n_cool
    for i, (v, a) in enumerate(plan):
        debut = t.strftime("%Y-%m-%dT%H:%M:%SZ")
        w = make_window(v, a, scenario=scn_id, debut=debut, seed=rng.randint(0, 2**31))
        yield w
        t += dt.timedelta(seconds=STEP_S)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", type=int, default=400)
    ap.add_argument("--out", default="data/windows/labo")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(args.out, exist_ok=True)
    # Mix: ~40% attacks (spread over types), ~30% normal, ~30% legitimate peaks.
    kinds = []
    for _ in range(args.scenarios):
        r = rng.random()
        if r < 0.40:
            kinds.append(rng.choice(ATTACKS))
        elif r < 0.70:
            kinds.append("normal")
        else:
            kinds.append("pic_legitime")

    counts, n_win = {}, 0
    base = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    for idx, kind in enumerate(kinds):
        scn_id = f"scn{idx:04d}"
        start = base + dt.timedelta(minutes=idx * 5)
        for wi, w in enumerate(scenario_windows(kind, scn_id, rng, start)):
            check(w)  # fail fast if the generator ever emits something invalid
            with open(os.path.join(args.out, f"{scn_id}_{wi:03d}.json"), "w") as fh:
                json.dump(w, fh)
            n_win += 1
        counts[kind] = counts.get(kind, 0) + 1

    print(f"{args.scenarios} scenarios, {n_win} windows -> {args.out}")
    for k in sorted(counts):
        print(f"  {k:24s} {counts[k]}")


if __name__ == "__main__":
    main()
