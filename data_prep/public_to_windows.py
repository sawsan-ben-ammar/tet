"""Convert a public flow dataset (CIC-DDoS2019 / CIC-IDS2017 style CSV produced by
CICFlowMeter) into windows in the common format.

Public captures have only network flows: we build the flow graph (external source
subnets -> destination hosts), compute the features we can, and leave internal-only
features (CPU, latency...) and dependency edges absent. The internal-node head does
not train on these; the graph and external-source heads do.

    python -m data_prep.public_to_windows --csv path/to/day.csv --out data/windows/cic_ddos2019

The column mapping is kept in one dict so a new dataset is one edit, not a rewrite.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os

import pandas as pd

from schema.features import FEATURES, WINDOW_S, STEP_S

# CICFlowMeter column names (after stripping leading spaces). Adjust per dataset.
COLS = {
    "ts": "Timestamp",
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "dst_port": "Destination Port",
    "protocol": "Protocol",
    "fwd_pkts": "Total Fwd Packets",
    "fwd_bytes": "Total Length of Fwd Packets",
    "syn": "SYN Flag Count",
    "duration": "Flow Duration",
    "label": "Label",
}
# Map dataset labels to our attack types. Anything not listed is treated as normal.
LABEL_MAP = {
    "BENIGN": ("normal", "none"),
    "DrDoS_UDP": ("attaque", "ddos_udp_flood"),
    "UDP": ("attaque", "ddos_udp_flood"),
    "DrDoS_MSSQL": ("attaque", "ddos_udp_flood"),
    "Syn": ("attaque", "ddos_syn_flood"),
    "DrDoS_SYN": ("attaque", "ddos_syn_flood"),
    "DrDoS_HTTP": ("attaque", "ddos_http_flood"),
    "Slowloris": ("attaque", "slowloris"),
    "DoS slowloris": ("attaque", "slowloris"),
    "DoS Slowhttptest": ("attaque", "slow_post"),
    "PortScan": ("attaque", "scan_distribue"),
    "FTP-Patator": ("attaque", "bruteforce_distribue"),
    "SSH-Patator": ("attaque", "bruteforce_distribue"),
}


def subnet(ip: str) -> str:
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def _blank():
    return {f: None for f in FEATURES}


def clean(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip() for c in df.columns]
    df = df.rename(columns={v: k for k, v in COLS.items()})
    df = df.dropna(subset=["ts", "src_ip", "dst_ip"])
    df = df[~df[["fwd_pkts", "fwd_bytes"]].isin([float("inf"), float("-inf")]).any(axis=1)]
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts"]).drop_duplicates()
    for c in ("fwd_pkts", "fwd_bytes", "syn", "duration", "dst_port", "protocol"):
        if c in df:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    return df.sort_values("ts")


def build_window(flows: pd.DataFrame, debut, scenario, origine) -> dict:
    span = max(WINDOW_S, 1.0)
    flows = flows.assign(src_node=flows.src_ip.map(subnet), dst_node=flows.dst_ip)
    nodes, edges = {}, []

    # destination hosts -> internal nodes
    for dst, g in flows.groupby("dst_node"):
        f = _blank()
        f.update(
            paquets_s=float(g.fwd_pkts.sum()) / span,
            octets_s=float(g.fwd_bytes.sum()) / span,
            requetes_s=float(len(g)) / span,
            nb_flux=int(len(g)),
            connexions_ouvertes=float(len(g)),
            ratio_syn=float(g.get("syn", pd.Series([0])).sum()) / max(1.0, g.fwd_pkts.sum()),
            duree_moy_connexion=float(g.get("duration", pd.Series([0])).mean()) / 1e6,
            nb_sources_uniques=int(g.src_node.nunique()),
            nb_destinations=1,
            nb_ports=int(g.get("dst_port", pd.Series([0])).nunique()),
            entropie_url=0.0, entropie_ua=0.0,
            nb_alertes=0, gravite_max_alerte=0,
            instant_premiere_anomalie=WINDOW_S,
        )
        nodes[dst] = {"id": dst, "role": "interne", "type": "service", "features": f}

    # source subnets -> external nodes
    for src, g in flows.groupby("src_node"):
        f = _blank()
        pps = float(g.fwd_pkts.sum()) / span
        f.update(
            paquets_s=pps,
            octets_s=float(g.fwd_bytes.sum()) / span,
            requetes_s=float(len(g)) / span,
            nb_flux=int(len(g)),
            connexions_ouvertes=float(len(g)),
            ratio_syn=float(g.get("syn", pd.Series([0])).sum()) / max(1.0, g.fwd_pkts.sum()),
            duree_moy_connexion=float(g.get("duration", pd.Series([0])).mean()) / 1e6,
            nb_sources_uniques=1,
            nb_destinations=int(g.dst_node.nunique()),
            nb_ports=int(g.get("dst_port", pd.Series([0])).nunique()),
            entropie_url=0.0, entropie_ua=0.0,
            variabilite_intervalles=0.0,
            taille_moy_paquets=float(g.fwd_bytes.sum()) / max(1.0, g.fwd_pkts.sum()),
            nb_alertes=0, gravite_max_alerte=0,
            instant_premiere_anomalie=WINDOW_S,
        )
        nodes[src] = {"id": src, "role": "externe", "type": "externe", "features": f}
        for dst, gg in g.groupby("dst_node"):
            edges.append({"src": src, "dst": dst, "type": "flux",
                          "octets": float(gg.fwd_bytes.sum()), "paquets": float(gg.fwd_pkts.sum()),
                          "flux": int(len(gg))})

    # label: attack if enough flows are attack flows
    verdicts = flows["label"].map(lambda x: LABEL_MAP.get(str(x).strip(), ("normal", "none")))
    attack_rows = flows[[v[0] == "attaque" for v in verdicts]]
    share = len(attack_rows) / max(1, len(flows))
    if share > 0.05:
        atypes = [LABEL_MAP.get(str(x).strip(), ("normal", "none"))[1] for x in attack_rows["label"]]
        atype = max(set(atypes), key=atypes.count)
        verdict = "attaque"
        sources = sorted({subnet(ip) for ip in attack_rows.src_ip})
        cibles = [attack_rows.dst_ip.map(subnet).mode().iat[0]] if len(attack_rows) else []
        cibles = [attack_rows.dst_ip.value_counts().idxmax()]
    else:
        verdict, atype, sources, cibles = "normal", "none", [], []

    ids = set(nodes)
    sources = [s for s in sources if s in ids]
    cibles = [c for c in cibles if c in ids]
    return {
        "fenetre": {"debut": str(debut), "duree_s": WINDOW_S, "pas_s": STEP_S},
        "origine": origine, "scenario": scenario,
        "noeuds": list(nodes.values()), "aretes": edges,
        "labels": {"verdict": verdict, "type": atype, "cibles": cibles, "sources": sources, "impactes": []},
    }


def to_windows(df: pd.DataFrame, origine: str):
    df = clean(df)
    t0, t_end = df.ts.min(), df.ts.max()
    t, i = t0, 0
    step = pd.Timedelta(seconds=STEP_S)
    width = pd.Timedelta(seconds=WINDOW_S)
    while t < t_end:
        chunk = df[(df.ts >= t) & (df.ts < t + width)]
        if len(chunk):
            yield build_window(chunk, t, f"{origine}_{t0.date()}", origine)
        t += step
        i += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--origine", default="cic_ddos2019")
    ap.add_argument("--out", default="data/windows/cic_ddos2019")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    df = pd.read_csv(args.csv, low_memory=False)
    n = 0
    for w in to_windows(df, args.origine):
        with open(os.path.join(args.out, f"w{n:05d}.json"), "w") as fh:
            json.dump(w, fh)
        n += 1
    print(f"{n} windows -> {args.out}")


if __name__ == "__main__":
    main()
