"""Load windows, split by scenario, fit stats on the training normals.

Splitting by scenario (not by window) is the rule that stops the model from
"recognising" a scenario it also trained on.
"""
from __future__ import annotations

import glob
import os
import random
from dataclasses import dataclass

from data_prep.to_graph import Stats, fit_stats, window_to_data, load_window


@dataclass
class Split:
    train: list
    val: list
    test: list
    stats: Stats


def _group_split(scenarios, ratios, seed):
    rng = random.Random(seed)
    scns = sorted(scenarios)
    rng.shuffle(scns)
    n = len(scns)
    n_tr = int(ratios[0] * n)
    n_va = int(ratios[1] * n)
    return set(scns[:n_tr]), set(scns[n_tr:n_tr + n_va]), set(scns[n_tr + n_va:])


def load_dir(path: str) -> list:
    return [load_window(p) for p in sorted(glob.glob(os.path.join(path, "*.json")))]


def load_windows(spec) -> list:
    """Load windows from a dir, a glob, a comma-separated list, or a parent dir
    that contains per-capture subdirs. Each window keeps its scenario id, so
    splitting by scenario (= capture) stays leakage-free across all of them."""
    import itertools
    if isinstance(spec, str):
        parts = spec.split(",")
    else:
        parts = list(spec)
    paths = []
    for part in parts:
        part = part.strip()
        matched = sorted(glob.glob(part))
        if not matched and os.path.isdir(part):
            matched = [part]
        for m in matched:
            if os.path.isdir(m):
                direct = glob.glob(os.path.join(m, "*.json"))
                if direct:
                    paths.append(m)
                else:  # parent of capture subdirs
                    for sub in sorted(glob.glob(os.path.join(m, "*"))):
                        if os.path.isdir(sub) and glob.glob(os.path.join(sub, "*.json")):
                            paths.append(sub)
    windows = list(itertools.chain.from_iterable(load_dir(p) for p in dict.fromkeys(paths)))
    return windows


def make_split(windows, ratios=(0.7, 0.15, 0.15), seed=0,
               hold_out_types=None, hold_out_scenarios=None) -> Split:
    """Group windows by scenario into train/val/test.

    hold_out_types: attack types whose scenarios go only to test (generalisation).
    hold_out_scenarios: explicit scenario ids forced into test.
    """
    hold_out_types = set(hold_out_types or [])
    forced_test = set(hold_out_scenarios or [])

    scn_type = {}
    for w in windows:
        scn_type.setdefault(w["scenario"], set()).add(w["labels"]["type"])

    pool = [s for s in scn_type if s not in forced_test
            and not (scn_type[s] & hold_out_types)]
    tr, va, te = _group_split(pool, ratios, seed)
    te |= forced_test | {s for s in scn_type if scn_type[s] & hold_out_types}

    train = [w for w in windows if w["scenario"] in tr]
    val = [w for w in windows if w["scenario"] in va]
    test = [w for w in windows if w["scenario"] in te]
    stats = fit_stats(train) if train else fit_stats(windows)
    return Split(train, val, test, stats)




def stratified_capture_split(windows, n_test=1, n_val=1, seed=0):
    """Capture-level split that guarantees each class (and attack type) appears in
    train and test. Captures are grouped by their dominant (verdict,type) label;
    from each group, n_test go to test, n_val to val, the rest to train. No window
    is shared across splits (grouping is by scenario/capture id)."""
    rng = random.Random(seed)
    cap_label, cap_of = {}, {}
    for w in windows:
        cap = w["scenario"]
        cap_of.setdefault(cap, []).append(w)
        lab = w["labels"]
        key = (lab["verdict"], lab["type"])
        # dominant non-normal label defines the capture's class
        cur = cap_label.get(cap)
        if cur is None or (cur[0] == "normal" and key[0] != "normal"):
            cap_label[cap] = key
    groups = {}
    for cap, key in cap_label.items():
        groups.setdefault(key, []).append(cap)
    test_caps, val_caps, train_caps = set(), set(), set()
    for key, caps in groups.items():
        caps = sorted(caps); rng.shuffle(caps)
        test_caps |= set(caps[:n_test])
        val_caps |= set(caps[n_test:n_test + n_val])
        train_caps |= set(caps[n_test + n_val:])
    def pick(capset):
        return [w for w in windows if w["scenario"] in capset]
    train, val, test = pick(train_caps), pick(val_caps), pick(test_caps)
    stats = fit_stats(train) if train else fit_stats(windows)
    return Split(train, val, test, stats)


def to_data_list(windows, stats):
    return [window_to_data(w, stats) for w in windows]
