"""Tests for the two-probe Suricata correlation. Run: pytest -q ids/tests"""
from ids.common import pipeline, normalise, is_dos
from ids.correlation_ids import correlation_ids_suricata
from ids.synth_eve import scenario_alerts, noise_alerts
from ids.metrics import summarise

INCIDENT_KEYS = {"incident", "type", "confiance", "cible", "debut", "fin",
                 "sondes", "sources", "impactes", "explication"}


def test_normalise_and_filter():
    i1, i2, _ = scenario_alerts("ddos_syn_flood", n_src=20, seed=1)
    noise = noise_alerts(n=30, seed=2)
    alerts = pipeline(i1 + noise, i2)
    assert alerts, "should keep DoS alerts"
    assert all(is_dos(a) for a in alerts), "non-DoS must be filtered"


def test_dedup_reduces_volume():
    i1, i2, _ = scenario_alerts("ddos_http_flood", n_src=40, seed=3)
    raw = [a for a in (normalise(e, "ids1") for e in i1) if a]
    raw += [a for a in (normalise(e, "ids2") for e in i2) if a]
    deduped = pipeline(i1, i2)
    assert len(deduped) <= len(raw)


def test_rules_mode_finds_incident():
    i1, i2, truth = scenario_alerts("ddos_syn_flood", n_src=80, seed=4)
    incidents = correlation_ids_suricata(i1, i2, mode="regles")
    assert incidents, "a clear SYN flood must produce an incident"
    inc = incidents[0]
    assert INCIDENT_KEYS <= set(inc)
    assert inc["cible"] == truth["cible"]
    assert 0.0 <= inc["confiance"] <= 1.0
    assert "ddos" in inc["type"] or inc["type"] == "attaque_lente"


def test_distributed_flag_and_sources():
    i1, i2, truth = scenario_alerts("ddos_syn_flood", n_src=120, seed=5)
    incidents = correlation_ids_suricata(i1, i2, mode="regles")
    inc = incidents[0]
    # most attacking sources should be recovered
    overlap = set(inc["sources"]) & set(truth["sources"])
    assert len(overlap) >= 0.5 * len(truth["sources"])


def test_cross_confirmation_http():
    i1, i2, _ = scenario_alerts("ddos_http_flood", n_src=80, seed=6)
    incidents = correlation_ids_suricata(i1, i2, mode="regles")
    assert incidents
    # across the incidents, both probes must appear (perimeter + internal),
    # which is exactly the cross-confirmation (R3) / XFF-rapprochement (R4) the
    # two-probe setup is for. Dedup may merge both probes under one community_id,
    # so we check the union rather than a single incident's first record.
    probes = {s for inc in incidents for s in inc["sondes"]}
    assert {"ids1", "ids2"} <= probes or any("R4" in inc["explication"] for inc in incidents)
    assert any(inc["type"] == "ddos_http_flood" for inc in incidents)


def test_compression_metric():
    i1, i2, truth = scenario_alerts("ddos_udp_flood", n_src=100, seed=7)
    n_in = len(pipeline(i1, i2))
    incidents = correlation_ids_suricata(i1, i2, mode="regles")
    m = summarise(incidents, n_in, [truth])
    assert m["taux_compression"] >= 1.0
    assert m["n_incidents"] >= 1


def test_ia_mode_fallback_runs():
    # mode="ia" without a model falls back to the convergence rule; must still work
    i1, i2, _ = scenario_alerts("ddos_syn_flood", n_src=80, seed=8)
    incidents = correlation_ids_suricata(i1, i2, mode="ia", model=None)
    assert isinstance(incidents, list)
    if incidents:
        assert INCIDENT_KEYS <= set(incidents[0])


def test_no_alerts_is_empty():
    assert correlation_ids_suricata([], [], mode="regles") == []
