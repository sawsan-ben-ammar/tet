"""Synthetic Suricata EVE JSON alerts for two probes, labelled by scenario.

Models what each probe sees: IDS1 (perimeter) sees real source IPs and volumetric/
SYN/scan signatures; IDS2 (internal) sees the ingress as source but carries the real
client in X-Forwarded-For and fires on HTTP-flood / slow-attack signatures.
"""
from __future__ import annotations

import random


def _eve(ts, src, dst, port, proto, sid, cat, sev, cid, xff=None):
    rec = {"event_type": "alert", "timestamp": ts, "src_ip": src, "dest_ip": dst,
           "dest_port": port, "proto": proto, "community_id": cid, "flow_id": cid,
           "alert": {"signature_id": sid, "category": cat, "severity": sev}}
    if xff:
        rec["http"] = {"xff": xff}
    return rec


def scenario_alerts(kind="ddos_syn_flood", n_src=80, t0=0.0, duration=40.0,
                    target="10.0.0.5", seed=0):
    """Return (eve_ids1, eve_ids2, truth) for one scenario."""
    rng = random.Random(seed)
    ids1, ids2 = [], []
    sources = [f"45.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}" for _ in range(n_src)]

    sid1, cat1, proto, port = {
        "ddos_syn_flood": (9000001, "attempted-dos", "TCP", 80),
        "ddos_udp_flood": (9000010, "attempted-dos", "UDP", 80),
        "ddos_icmp_flood": (9000011, "attempted-dos", "ICMP", 0),
        "ddos_http_flood": (9000002, "attempted-dos", "TCP", 80),
        "slowloris": (9000003, "attempted-dos", "TCP", 80),
        "slow_post": (9000004, "attempted-dos", "TCP", 80),
        "scan_distribue": (9000020, "attempted-recon", "TCP", 0),
        "bruteforce_distribue": (9000030, "attempted-dos", "TCP", 80),
    }.get(kind, (9000001, "attempted-dos", "TCP", 80))

    http_like = kind in ("ddos_http_flood", "slowloris", "slow_post", "bruteforce_distribue")
    t = t0
    while t < t0 + duration:
        for s in sources:
            cid = f"1:{abs(hash((s, round(t,1)))) % 10**12}"
            # perimeter probe sees the real source
            ids1.append(_eve(f"2026-01-01T00:00:{t%60:06.3f}Z", s, target, port, proto, sid1, cat1,
                             rng.choice([1, 2]), cid))
            # internal probe, only for application-layer attacks, sees ingress + XFF, slightly later
            if http_like and rng.random() < 0.6:
                ids2.append(_eve(f"2026-01-01T00:00:{(t+6)%60:06.3f}Z", "10.0.0.1", "10.0.1.20",
                                 80, "TCP", 9000002, "attempted-dos", rng.choice([1, 2]),
                                 cid, xff=s))
        t += rng.uniform(4.0, 6.0)

    truth = {"type": kind, "cible": target, "debut": t0, "fin": t0 + duration,
             "sources": sorted(set(sources))}
    return ids1, ids2, truth


def noise_alerts(n=20, t0=0.0, duration=40.0, seed=1):
    """Benign-but-noisy non-DoS alerts (should be filtered out)."""
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        t = t0 + rng.uniform(0, duration)
        out.append(_eve(f"2026-01-01T00:00:{t%60:06.3f}Z",
                        f"80.0.{rng.randint(0,5)}.{rng.randint(1,254)}", "10.0.0.5", 443, "TCP",
                        2100498, "not-suspicious", 3, f"1:{rng.randint(0,10**12)}"))
    return out
