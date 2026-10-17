"""Tests for the deliverable function and the model quality. Run: pytest -q

Two groups:
- plumbing: correlation_attaque_distribuee runs on raw signals (shape, empty, scale,
  determinism). It must never crash and always return the full output.
- quality: the trained model on proper windows (normal not flagged, peaks not flagged,
  floods detected). Judged on windows, not on lossy signal round-trips.
"""
import time

import pytest

from data_prep.synth import make_window
from data_prep.to_graph import window_to_data, Stats
from model.correlation import correlation_attaque_distribuee, load_model, _ARTIFACTS
from model.predict import predict_window

REQUIRED_KEYS = {"verdict", "type", "confiance", "cibles", "sources", "impactes", "explication"}


@pytest.fixture(scope="module")
def model_stats():
    """A synthetic-trained model, for the architecture-quality tests below.

    These tests validate the GNN *architecture* on synthetic data and must not
    depend on which model is deployed in model/artifacts (that artifact is trained
    on the real lab captures; see reports/PHASE5-7.md). So we train a small model
    on freshly generated synthetic windows here. Real-data performance is reported
    separately by model.phase6, never by these synthetic tests.
    """
    from data_prep.dataset import make_split
    from data_prep.synth import make_window
    from model.train import train
    W = []
    attacks = ["ddos_syn_flood", "ddos_http_flood", "ddos_udp_flood", "scan_distribue"]
    for s in range(120):
        W.append(make_window("normal", scenario=f"n{s}", seed=s))
        W.append(make_window("pic_legitime", scenario=f"p{s}", seed=500 + s))
        W.append(make_window("attaque", attacks[s % len(attacks)], scenario=f"a{s}", seed=1000 + s))
    sp = make_split(W, seed=0)
    model = train(sp.train, sp.stats, epochs=20, conv="gat", val=sp.val, seed=0, log=False)
    return model, sp.stats


# --------------------------- plumbing --------------------------- #
def _simple_signals(n_src, pps, http, target="ingress"):
    flux = [dict(src_ip=f"45.{i//256%256}.{i%256}.7", dst=target, octets=pps * 60,
                 paquets=pps, flux=3, http=http, requetes=pps if http else 0,
                 syn=0 if http else pps) for i in range(n_src)]
    metriques = {target: dict(cpu=0.9, memoire=0.8, latence_p95=500, taux_erreurs=0.5,
                              type="gateway", depend_sur=[])}
    return flux, metriques, [{"node": target, "gravite": 3}]


def test_output_shape_and_types():
    flux, met, al = _simple_signals(50, 2000, http=False)
    r = correlation_attaque_distribuee(flux, met, al)
    assert REQUIRED_KEYS <= set(r)
    assert r["verdict"] in ("normal", "pic_legitime", "attaque")
    assert 0.0 <= r["confiance"] <= 1.0
    assert isinstance(r["cibles"], list) and isinstance(r["sources"], list)


def test_empty_window_is_safe():
    r = correlation_attaque_distribuee([], {}, [])
    assert r["verdict"] in ("normal", "pic_legitime", "attaque")
    assert REQUIRED_KEYS <= set(r)


def test_scales_under_10s():
    flux, met, al = _simple_signals(5000, 2000, http=False)
    t0 = time.time()
    r = correlation_attaque_distribuee(flux, met, al)
    dt = time.time() - t0
    assert dt < 10.0, f"took {dt:.1f}s"
    assert REQUIRED_KEYS <= set(r)


def test_deterministic():
    flux, met, al = _simple_signals(40, 1500, http=True)
    r1 = correlation_attaque_distribuee(flux, met, al)
    r2 = correlation_attaque_distribuee(flux, met, al)
    assert r1["verdict"] == r2["verdict"] and r1["confiance"] == r2["confiance"]


def test_attack_signals_populate_sources():
    flux, met, al = _simple_signals(60, 3000, http=False)
    r = correlation_attaque_distribuee(flux, met, al)
    if r["verdict"] == "attaque":
        assert r["explication"]
        assert all({"sous_reseau", "score"} <= set(s) for s in r["sources"])


# --------------------------- model quality --------------------------- #
def _predict_window(model, stats, w):
    return predict_window(model, window_to_data(w, stats))[0]


def test_normal_not_flagged(model_stats):
    model, stats = model_stats
    fired = sum(_predict_window(model, stats, make_window("normal", seed=1000 + s))["verdict"] == "attaque"
                for s in range(10))
    assert fired <= 1


def test_peaks_not_flagged(model_stats):
    model, stats = model_stats
    fired = sum(_predict_window(model, stats, make_window("pic_legitime", seed=2000 + s))["verdict"] == "attaque"
                for s in range(10))
    assert fired <= 2


def test_floods_detected(model_stats):
    model, stats = model_stats
    for atype in ("ddos_syn_flood", "ddos_http_flood", "ddos_udp_flood"):
        hits = sum(_predict_window(model, stats, make_window("attaque", atype, seed=3000 + s))["verdict"] == "attaque"
                   for s in range(5))
        assert hits >= 4, f"{atype} only {hits}/5"


def test_target_identified(model_stats):
    model, stats = model_stats
    ok = 0
    for s in range(10):
        w = make_window("attaque", "ddos_http_flood", seed=4000 + s)
        r = _predict_window(model, stats, w)
        if r["verdict"] == "attaque" and r["cibles"]:
            top = max(r["cibles"], key=lambda k: r["cibles"][k])
            ok += top in w["labels"]["cibles"]
    assert ok >= 7
