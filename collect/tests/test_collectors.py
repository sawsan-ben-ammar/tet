"""Unit tests for the Phase-3 collectors and the Phase-4 graph builder, using
in-memory fixtures (no cluster needed)."""
import json

from collect.hubble import parse_flow, workload_of, subnet_of
from collect.suricata import to_eve_record
from collect.align import align, WindowBundle
from collect.model import parse_iso
from graph.build import build_window
from schema.validate import check


def test_workload_and_subnet():
    assert workload_of("frontend-6788b898c4-whqc5") == "frontend"
    assert workload_of("redis-cart-65d9f58868-75d4s") == "redis-cart"
    assert subnet_of("45.33.12.7") == "45.33.12.0/24"


def test_parse_hubble_flow():
    obj = {"flow": {"time": "2026-01-01T00:00:01.5Z",
                    "IP": {"source": "45.0.0.9", "destination": "10.244.0.5"},
                    "l4": {"TCP": {"destination_port": 80, "flags": {"SYN": True}}},
                    "source": {}, "destination": {"namespace": "boutique", "pod_name": "frontend-6788b898c4-whqc5"},
                    "verdict": "FORWARDED"}}
    f = parse_flow(obj)
    assert f.src == "45.0.0.0/24" and f.src_external
    assert f.dst == "boutique/frontend" and not f.dst_external
    assert f.port == 80 and f.proto == "TCP" and f.syn


def _flow(ts, src, dst, se, de, port=80, proto="TCP", verdict="FORWARDED", syn=False):
    from collect.hubble import Flow
    return Flow(ts=ts, src=src, dst=dst, src_external=se, dst_external=de,
                port=port, proto=proto, verdict=verdict, syn=syn, bytes=0.0)


def test_align_and_build_valid_window():
    flows = [_flow(1.0, "45.0.0.0/24", "boutique/frontend", True, False, syn=True),
             _flow(2.0, "45.0.0.0/24", "boutique/frontend", True, False),
             _flow(2.5, "boutique/frontend", "boutique/cartservice", False, False)]
    alerts = [{"ts": 1.2, "src_ip": "45.0.0.9", "dest_ip": "10.0.0.1", "severity": 1,
               "signature_id": 9000001, "category": "attempted-dos", "proto": "TCP",
               "dest_port": 80, "community_id": "x", "flow_id": "1", "timestamp": "t", "xff": None}]
    prom = {"boutique/frontend": {"cpu_seconds_rate": [(2.0, 0.5)],
                                   "mem_working_bytes": [(2.0, 1e8)],
                                   "net_rx_rate": [(2.0, 1000.0)], "net_tx_rate": [(2.0, 500.0)]}}
    pods = {"boutique/frontend": {"type": "gateway", "cpu_limit": 1.0, "mem_limit": 2e8}}
    bundles = align(flows, alerts, prom, pods, 0.0, 5.0, width=10.0, step=5.0)
    assert bundles
    w = build_window(bundles[0], "test", verdict="attaque", attack_type="ddos_syn_flood",
                     cibles=["boutique/frontend"], sources_lbl=["45.0.0.0/24"])
    check(w)  # must satisfy the schema + referential rules
    fe = [n for n in w["noeuds"] if n["id"] == "45.0.0.0/24"][0]["features"]
    assert fe["ratio_syn"] == 0.5 and fe["nb_alertes"] == 1
    fi = [n for n in w["noeuds"] if n["id"] == "boutique/frontend"][0]["features"]
    assert abs(fi["cpu"] - 0.5) < 1e-9 and abs(fi["memoire"] - 0.5) < 1e-9
    assert fi["octets_s"] == 1500.0


def test_iso_parsing():
    assert parse_iso("2026-01-01T00:00:00Z") > 0
    assert parse_iso("2026-01-01T00:00:00.123456+00:00") > 0
