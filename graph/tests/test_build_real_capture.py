"""Integration test: build + validate windows from a real processed capture if
one exists (skips cleanly in CI where no capture is present)."""
import glob
import json
import os

import pytest

from schema.validate import check

REAL = sorted(glob.glob("data/windows/real-*"))


@pytest.mark.skipif(not REAL, reason="no real capture windows present")
def test_real_windows_validate_and_have_signal():
    total, attack = 0, 0
    http_attack, http_with_src = 0, 0
    for d in REAL:
        for f in glob.glob(os.path.join(d, "*.json")):
            w = json.load(open(f))
            check(w)                       # schema + referential rules
            total += 1
            lab = w["labels"]
            if lab["verdict"] == "attaque":
                attack += 1
                assert lab["cibles"], "attack window must name a target"
                if lab["type"] == "ddos_http_flood":
                    http_attack += 1
                    if lab["sources"]:
                        http_with_src += 1
    assert total > 0 and attack > 0
    # HTTP-flood traffic is well enriched by Hubble -> source attribution works.
    # (SYN-flood RST storms are poorly enriched; their sources come from the IDS
    # probe instead - a documented sensor-visibility limitation, see reports/.)
    if http_attack:
        assert http_with_src >= 0.8 * http_attack, \
            f"only {http_with_src}/{http_attack} HTTP-flood windows had sources"
