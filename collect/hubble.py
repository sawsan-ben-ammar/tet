"""Hubble flow collection (Phase 3).

Hubble is the source of the communication edges. We read flows as JSON (one
object per line, Hubble's `-o json`/`jsonpb`) and keep only what the graph needs:
source/destination identity (namespace/pod or external IP), L4 port and protocol,
verdict (FORWARDED/DROPPED), TCP flags, and the event time. Raw lines are kept on
disk; this module only parses and summarises.

Design choices documented:
  * identity: internal endpoints are keyed by "<namespace>/<pod>" collapsed to the
    workload (strip the replica hash) so nodes are services, not pods; external
    endpoints are keyed by their /24 subnet (addresses may be spoofed).
  * a flow with no L4/identity is dropped (recorded as skipped).
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

from collect.model import parse_iso

_HASH = re.compile(r"-[0-9a-f]{8,10}-[0-9a-z]{5}$|-[0-9a-f]{8,10}$|-[0-9a-z]{5}$")


def workload_of(name: str) -> str:
    """frontend-6788b898c4-whqc5 -> frontend (strip ReplicaSet/pod suffixes)."""
    if not name:
        return name
    return _HASH.sub("", name)


def subnet_of(ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return ip


@dataclass
class Flow:
    ts: float
    src: str            # node id (service name or external subnet)
    dst: str
    src_external: bool
    dst_external: bool
    port: int
    proto: str          # TCP/UDP/ICMPv4...
    verdict: str        # FORWARDED/DROPPED/...
    syn: bool
    bytes: float        # may be 0 if Hubble didn't sample L7/length


def sim_subnet_label(ep: dict):
    """If the endpoint pod carries a gnn-lab/sim-subnet label, return the subnet
    it simulates (e.g. '10-8-3-0' -> '10.8.3.0/24'); else None."""
    for l in (ep or {}).get("labels", []) or []:
        s = str(l)
        if "gnn-lab/sim-subnet=" in s:
            val = s.split("gnn-lab/sim-subnet=", 1)[1]
            return val.replace("-", ".") + "/24" if val.count("-") == 3 else val
    return None


def _endpoint(ep: dict, ip: str, names_ns: str):
    """Return (node_id, is_external). Internal if it has a namespace/identity,
    EXCEPT a pod with a gnn-lab/sim-subnet label, which models an external
    attacker/client on that simulated subnet (the lab's distributed-source model)."""
    sim = sim_subnet_label(ep)
    if sim:
        return sim, True
    ns = (ep or {}).get("namespace")
    pods = (ep or {}).get("pod_name") or (ep or {}).get("podName")
    if ns and pods:
        return f"{ns}/{workload_of(pods)}", False
    labels = (ep or {}).get("labels") or []
    if any(str(l).startswith("k8s:io.kubernetes.pod.namespace") for l in labels) and pods:
        return f"{ns or 'k8s'}/{workload_of(pods)}", False
    # no identity -> external, keyed by subnet
    return subnet_of(ip), True


def parse_flow(obj: dict) -> Optional[Flow]:
    # Hubble wraps the flow as {"flow": {...}} in jsonpb stream output
    f = obj.get("flow", obj)
    if not f or f.get("Type") == "L7" and not f.get("l4"):
        pass
    ts = parse_iso(f.get("time") or f.get("timestamp"))
    ip = f.get("IP") or f.get("ip") or {}
    src_ip = ip.get("source", ""); dst_ip = ip.get("destination", "")
    l4 = f.get("l4") or f.get("L4") or {}
    tcp = l4.get("TCP") or l4.get("tcp") or {}
    udp = l4.get("UDP") or l4.get("udp") or {}
    icmp = l4.get("ICMPv4") or l4.get("icmpv4") or {}
    if tcp:
        proto, port = "TCP", int(tcp.get("destination_port") or tcp.get("destinationPort") or 0)
        flags = tcp.get("flags") or {}
        syn = bool(flags.get("SYN")) and not bool(flags.get("ACK"))
    elif udp:
        proto, port = "UDP", int(udp.get("destination_port") or udp.get("destinationPort") or 0)
        syn = False
    elif icmp:
        proto, port, syn = "ICMP", 0, False
    else:
        proto, port, syn = (f.get("l4_protocol") or "OTHER"), 0, False
    if not src_ip and not dst_ip:
        return None
    src, se = _endpoint(f.get("source"), src_ip, src_ip)
    dst, de = _endpoint(f.get("destination"), dst_ip, dst_ip)
    verdict = f.get("verdict", "FORWARDED")
    return Flow(ts=ts, src=src, dst=dst, src_external=se, dst_external=de,
                port=port, proto=proto, verdict=str(verdict), syn=syn, bytes=0.0)


def read_flows(path: str):
    """Yield Flow from a Hubble json-lines file. Bad lines are skipped."""
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            fl = parse_flow(obj)
            if fl is not None:
                yield fl
