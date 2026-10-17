"""Common chain for the two-probe Suricata correlation (Section 14.2 of the brief).

Normalise EVE JSON alerts from both probes to one schema, filter to DoS, dedup by
community_id, then cut into the same sliding windows as the main project.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Optional

WINDOW_S = 10.0
STEP_S = 5.0
DEDUP_DT = 2.0  # seconds: same community_id + signature within this = one alert


@dataclass
class Alert:
    ts: float                  # epoch seconds
    sonde: str                 # "ids1" | "ids2"
    src_ip: str
    dest_ip: str
    port: int
    proto: str
    signature_id: int
    categorie: str
    gravite: int
    community_id: str
    flow_id: Optional[str] = None
    xff: Optional[str] = None  # X-Forwarded-For (from http events)
    cible: Optional[str] = None


def _parse_ts(raw) -> float:
    if isinstance(raw, (int, float)):
        return float(raw)
    s = str(raw).replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(s).timestamp()
    except ValueError:
        return 0.0


def normalise(eve: dict, sonde: str) -> Optional[Alert]:
    """Turn one EVE JSON record into an Alert, or None if not an alert event."""
    if eve.get("event_type") != "alert":
        return None
    a = eve.get("alert", {})
    http = eve.get("http", {})
    return Alert(
        ts=_parse_ts(eve.get("timestamp", 0)),
        sonde=sonde,
        src_ip=eve.get("src_ip", ""),
        dest_ip=eve.get("dest_ip", ""),
        port=int(eve.get("dest_port", 0) or 0),
        proto=eve.get("proto", ""),
        signature_id=int(a.get("signature_id", 0) or 0),
        categorie=a.get("category", ""),
        gravite=int(a.get("severity", 3) or 3),
        community_id=eve.get("community_id", ""),
        flow_id=str(eve.get("flow_id", "")),
        xff=http.get("xff") or http.get("http_x_forwarded_for"),
        cible=eve.get("dest_ip", ""),
    )


DOS_CATEGORIES = {"attempted-dos", "denial of service", "dos"}
DOS_SIGN_PREFIX = 9000000  # our home rules sid range


def is_dos(a: Alert) -> bool:
    return (a.categorie.lower() in DOS_CATEGORIES) or (a.signature_id >= DOS_SIGN_PREFIX)


def dedup(alerts) -> list:
    """Merge same-community_id + same-signature alerts within DEDUP_DT, keeping the
    origin probes and the max severity."""
    alerts = sorted(alerts, key=lambda a: a.ts)
    kept: list = []
    seen = {}  # (community_id, signature_id) -> index in kept
    for a in alerts:
        key = (a.community_id, a.signature_id)
        j = seen.get(key)
        if j is not None and a.ts - kept[j].ts <= DEDUP_DT:
            kept[j].gravite = max(kept[j].gravite, a.gravite)
            # remember both probes saw it by promoting the sonde set on the merged record
            if isinstance(kept[j].sonde, str) and kept[j].sonde != a.sonde:
                kept[j].sonde = ",".join(sorted({kept[j].sonde, a.sonde}))
        else:
            kept.append(a)
            seen[key] = len(kept) - 1
    return kept


def pipeline(eve_ids1, eve_ids2):
    """Raw EVE records from both probes -> normalised, DoS-only, deduped alerts."""
    alerts = []
    for e in eve_ids1:
        a = normalise(e, "ids1")
        if a and is_dos(a):
            alerts.append(a)
    for e in eve_ids2:
        a = normalise(e, "ids2")
        if a and is_dos(a):
            alerts.append(a)
    return dedup(alerts)


def windows(alerts, width=WINDOW_S, step=STEP_S):
    """Yield (t_start, [alerts in window]) over the alert stream."""
    if not alerts:
        return
    alerts = sorted(alerts, key=lambda a: a.ts)
    t0, t_end = alerts[0].ts, alerts[-1].ts
    t = t0
    while t <= t_end:
        chunk = [a for a in alerts if t <= a.ts < t + width]
        if chunk:
            yield t, chunk
        t += step
