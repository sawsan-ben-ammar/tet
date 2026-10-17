"""correlation_ids_suricata: fuse the alerts of two Suricata probes into DoS/DDoS
incidents. Two modes (Section 14 of the brief):

- mode="regles": explicit rules R1-R6, no training data.
- mode="ia":     an XGBoost per-window classifier + DBSCAN grouping (level 1 of the
                 brief). Falls back to rules if no model is provided.

Both return the same shape, so they are directly comparable.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict

from ids.common import pipeline, windows, DEDUP_DT

# Rule thresholds (starting values, tuned on the lab).
N_CONVERGENCE = 50       # distinct sources to the same target -> distributed
DT_CROSS = 30.0          # seconds: IDS1 then IDS2 confirmation
K_CLOSE = 3              # consecutive empty windows -> incident closed

SIG_TYPE = {  # dominant signature family -> incident type (R5)
    "syn": "ddos_syn_flood",
    "udp": "ddos_volumetrique",
    "icmp": "ddos_volumetrique",
    "http": "ddos_http_flood",
    "slow": "attaque_lente",
}


def _iso(ts):
    return dt.datetime.utcfromtimestamp(ts).strftime("%H:%M:%S")


def _infer_type(alerts):
    text = " ".join((a.categorie + " " + str(a.signature_id)) for a in alerts).lower()
    # prefer explicit signatures; order matters (slow before http, syn before udp)
    for key in ("slow", "syn", "http", "udp", "icmp"):
        if key in text:
            return SIG_TYPE[key]
    # fall back on ports/proto
    protos = [a.proto.lower() for a in alerts]
    if any("udp" in p for p in protos):
        return "ddos_volumetrique"
    return "ddos_http_flood"


def _sources(alerts):
    srcs = set()
    for a in alerts:
        srcs.add(a.src_ip)
        if a.xff:
            srcs.update(x.strip() for x in a.xff.split(","))
    return sorted(s for s in srcs if s)


def _confidence_rules(alerts, n_src, cross):
    probes = {s for a in alerts for s in str(a.sonde).split(",")}
    grav = max((a.gravite for a in alerts), default=3)
    score = 0.0
    score += 0.3 if len(probes) >= 2 else 0.0          # both probes
    score += 0.3 if n_src >= N_CONVERGENCE else 0.15   # convergence
    score += 0.2 if cross else 0.0                     # cross confirmation
    score += 0.2 * (4 - grav) / 3.0                    # severity (1 best)
    return round(min(1.0, score), 2)


def _correlate_rules(alerts_by_window):
    """R1-R6 over the stream of windows. Groups by target, opens/extends/closes."""
    open_incidents = {}   # target -> incident dict
    closed = []
    empty_count = defaultdict(int)
    seq = 0

    all_targets = set()
    for _, chunk in alerts_by_window:
        for a in chunk:
            all_targets.add(a.cible)

    for t, chunk in alerts_by_window:
        by_target = defaultdict(list)
        for a in chunk:
            by_target[a.cible].append(a)

        for target in all_targets:
            al = by_target.get(target, [])
            if al:
                n_src = len({a.src_ip for a in al})
                probes = {s for a in al for s in str(a.sonde).split(",")}
                # R3 cross confirmation: IDS1 on ingress then IDS2 internal within DT
                cross = ("ids1" in probes and "ids2" in probes)
                if target not in open_incidents:
                    # R1 grouping + R2 convergence open a (distributed) incident
                    seq += 1
                    open_incidents[target] = dict(
                        incident=f"inc-{seq:04d}", cible=target, debut=t,
                        alerts=list(al), distribue=n_src >= N_CONVERGENCE, cross=cross)
                else:
                    inc = open_incidents[target]
                    inc["alerts"].extend(al)
                    inc["distribue"] = inc["distribue"] or n_src >= N_CONVERGENCE
                    inc["cross"] = inc["cross"] or cross
                empty_count[target] = 0
            else:
                if target in open_incidents:
                    empty_count[target] += 1
                    if empty_count[target] >= K_CLOSE:  # R6 closure
                        closed.append(_finalise(open_incidents.pop(target), t))

    for target, inc in list(open_incidents.items()):
        closed.append(_finalise(inc, inc["alerts"][-1].ts))
    return closed


def _finalise(inc, fin_ts):
    alerts = inc["alerts"]
    n_src = len({a.src_ip for a in alerts})
    cross = inc["cross"]
    srcs = _sources(alerts)
    rules = ["R1"]
    if inc["distribue"]:
        rules.append("R2")
    if cross:
        rules.append("R3")
    if any(a.xff for a in alerts):
        rules.append("R4")
    rules.append("R5")
    rules.append("R6")
    itype = _infer_type(alerts)
    conf = _confidence_rules(alerts, n_src, cross)
    impactes = sorted({a.dest_ip for a in alerts if any(s == "ids2" for s in str(a.sonde).split(","))}
                      - {inc["cible"]})
    expl = (f"{'+'.join(rules)} : {n_src} sources vers {inc['cible']}"
            + (f", confirme par IDS 2" if cross else "")
            + f" ({len(alerts)} alertes fusionnees).")
    return {
        "incident": inc["incident"], "type": itype, "confiance": conf,
        "cible": inc["cible"], "debut": _iso(inc["debut"]), "fin": _iso(fin_ts),
        "sondes": sorted({s for a in alerts for s in str(a.sonde).split(",")}),
        "sources": srcs, "impactes": impactes, "explication": expl,
    }


# ------------------------------- IA mode ------------------------------- #
def window_features(chunk):
    """Aggregated features per (target, window) for the XGBoost level-1 model."""
    probes = defaultdict(int)
    for a in chunk:
        for s in str(a.sonde).split(","):
            probes[s] += 1
    sigs = {a.signature_id for a in chunk}
    srcs = {a.src_ip for a in chunk}
    grav = [a.gravite for a in chunk]
    t_ids1 = min((a.ts for a in chunk if "ids1" in str(a.sonde)), default=None)
    t_ids2 = min((a.ts for a in chunk if "ids2" in str(a.sonde)), default=None)
    delta = (t_ids2 - t_ids1) if (t_ids1 is not None and t_ids2 is not None) else -1.0
    return [
        probes.get("ids1", 0), probes.get("ids2", 0), len(sigs), len(srcs),
        sum(grav) / len(grav) if grav else 3.0, min(grav) if grav else 3.0,
        delta, len(chunk),
    ]


def _correlate_ia(alerts_by_window, model):
    """Level 1: classify each (target, window), then group positive windows with
    DBSCAN over (time, target). Here grouping is by target + temporal gap, which is
    DBSCAN with eps=gap on a 1-D time axis per target."""
    chunks = list(alerts_by_window)
    pos_by_target = defaultdict(list)  # target -> list of (t, chunk)
    for t, chunk in chunks:
        by_target = defaultdict(list)
        for a in chunk:
            by_target[a.cible].append(a)
        for target, al in by_target.items():
            x = window_features(al)
            is_pos = model.predict([x])[0] == 1 if model is not None else (len({a.src_ip for a in al}) >= N_CONVERGENCE)
            if is_pos:
                pos_by_target[target].append((t, al))

    incidents, seq = [], 0
    for target, seqw in pos_by_target.items():
        seqw.sort(key=lambda z: z[0])
        group = []
        last_t = None
        for t, al in seqw:
            if last_t is not None and t - last_t > K_CLOSE * 5.0:
                seq += 1
                incidents.append(_finalise_group(f"inc-{seq:04d}", target, group))
                group = []
            group.extend([(t, a) for a in al])
            last_t = t
        if group:
            seq += 1
            incidents.append(_finalise_group(f"inc-{seq:04d}", target, group))
    return incidents


def _finalise_group(incident_id, target, pairs):
    alerts = [a for _, a in pairs]
    ts = [t for t, _ in pairs]
    inc = dict(incident=incident_id, cible=target, debut=min(ts),
               alerts=alerts, distribue=len({a.src_ip for a in alerts}) >= N_CONVERGENCE,
               cross=len({s for a in alerts for s in str(a.sonde).split(",")}) >= 2)
    out = _finalise(inc, max(ts))
    out["explication"] = out["explication"].replace("R1+", "IA + ")
    return out


def correlation_ids_suricata(alertes_ids1, alertes_ids2, metriques=None,
                             fenetre="10s", mode="regles", model=None) -> list:
    """Fuse two probes' EVE alerts into DoS/DDoS incidents.

    alertes_ids1/2: lists of EVE JSON dicts.
    mode: "regles" (R1-R6) or "ia" (XGBoost + grouping; needs a fitted model, else
          falls back to the convergence rule).
    Returns a list of incidents, each: incident, type, confiance, cible, debut, fin,
    sondes, sources, impactes, explication.
    """
    alerts = pipeline(alertes_ids1, alertes_ids2)
    by_window = list(windows(alerts))
    if mode == "ia":
        return _correlate_ia(by_window, model)
    return _correlate_rules(by_window)
