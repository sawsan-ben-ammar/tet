"""Unit tests for the Phase-7 correlation engine (no cluster/model needed)."""
from collect.align import WindowBundle
from collect.hubble import Flow
from correlate.engine import correlate


def _bundle(ts, attack=False):
    b = WindowBundle(t_start=ts, t_end=ts + 10)
    if attack:
        b.flows = [Flow(ts + 1, "10.8.1.0/24", "boutique/frontend", True, False, 80, "TCP", "FORWARDED", True, 0.0)
                   for _ in range(20)]
        b.alerts = [{"ts": ts + 1, "src_ip": "10.8.1.5", "dest_ip": "10.0.0.1", "severity": 1,
                     "signature_id": 9000002, "category": "attempted-dos", "proto": "TCP",
                     "dest_port": 80, "community_id": "c", "flow_id": "1", "timestamp": "t", "xff": None}]
    else:
        b.flows = [Flow(ts + 1, "boutique/frontend", "boutique/cartservice", False, False, 7070, "TCP", "FORWARDED", False, 0.0)]
    return b


def _pred(verdict, atype="none", cibles=None, sources=None):
    return {"verdict": verdict, "type": atype, "confiance": 0.8, "p_attack": 0.8 if verdict == "attaque" else 0.1,
            "cibles": cibles or {}, "sources": sources or {}, "impactes": []}


def test_attack_run_becomes_one_incident():
    items = []
    for i in range(8):
        atk = 2 <= i <= 5
        b = _bundle(i * 5.0, attack=atk)
        p = _pred("attaque", "ddos_http_flood", {"boutique/frontend": 0.9}, {"10.8.1.0/24": 0.9}) if atk else _pred("normal")
        items.append(({"labels": {}}, p, b))
    inc = correlate(items, [], capture_id="t")
    assert len(inc) == 1
    i0 = inc[0]
    assert i0["categorie_predite"] == "ddos_http_flood"
    assert i0["faits_observes"]["n_sources_externes_observees"] >= 1
    assert any("usurp" in l or "causalite" in l for l in i0["limites_preuve"])
    assert i0["capteurs_disponibles"]["hubble_flows"] is True
    assert i0["etapes_recommandees"]


def test_no_attack_no_incident():
    items = [({"labels": {}}, _pred("normal"), _bundle(i * 5.0)) for i in range(5)]
    assert correlate(items, [], capture_id="t") == []


def test_gap_merging():
    # one non-attack window inside an attack run must not split the incident
    verdicts = ["attaque", "attaque", "normal", "attaque", "attaque"]
    items = []
    for i, v in enumerate(verdicts):
        b = _bundle(i * 5.0, attack=(v == "attaque"))
        items.append(({"labels": {}}, _pred(v, "ddos_syn_flood" if v == "attaque" else "none",
                      {"boutique/frontend": 0.9} if v == "attaque" else {}), b))
    inc = correlate(items, [], capture_id="t")
    assert len(inc) == 1
