"""Suricata EVE collection (Phase 3).

Reads EVE JSON produced by the two probes (ids1 edge, ids2 internal) and returns
normalised alert records tagged with the probe. This reuses the exact same alert
schema as the existing two-probe correlation (ids/common.py), so the correlation
engine consumes live alerts unchanged. Only `alert` events are kept.
"""
from __future__ import annotations

import json
from collect.model import parse_iso


def read_eve(path, probe):
    """Yield normalised alert dicts from one probe's eve.json. Non-alert and
    malformed lines are skipped. The returned shape matches ids/common.normalise."""
    try:
        fh = open(path)
    except FileNotFoundError:
        return
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") != "alert":
                continue
            a = e.get("alert", {})
            http = e.get("http", {})
            yield {
                "timestamp": e.get("timestamp"),
                "ts": parse_iso(e.get("timestamp")),
                "sonde": probe,
                "src_ip": e.get("src_ip", ""),
                "dest_ip": e.get("dest_ip", ""),
                "dest_port": int(e.get("dest_port", 0) or 0),
                "proto": e.get("proto", ""),
                "signature_id": int(a.get("signature_id", 0) or 0),
                "category": a.get("category", ""),
                "severity": int(a.get("severity", 3) or 3),
                "community_id": e.get("community_id", ""),
                "flow_id": str(e.get("flow_id", "")),
                "xff": http.get("xff") or http.get("http_x_forwarded_for"),
            }


def to_eve_record(norm):
    """Reshape a normalised alert back into an EVE dict for ids.common.normalise,
    so the existing correlation pipeline (ids/) consumes live alerts unchanged."""
    rec = {"event_type": "alert", "timestamp": norm["timestamp"],
           "src_ip": norm["src_ip"], "dest_ip": norm["dest_ip"],
           "dest_port": norm["dest_port"], "proto": norm["proto"],
           "community_id": norm["community_id"], "flow_id": norm["flow_id"],
           "alert": {"signature_id": norm["signature_id"], "category": norm["category"],
                     "severity": norm["severity"]}}
    if norm.get("xff"):
        rec["http"] = {"xff": norm["xff"]}
    return rec
