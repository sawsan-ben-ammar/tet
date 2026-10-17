"""Capture data model (Phase 3).

A *capture* is one recording session over a time interval. It stores the raw
per-source data (never discarded) plus a manifest describing exactly how and when
it was collected, which sources were present, and what was missing. Everything is
UTC. Phase 4 reads a capture and builds schema windows from it; nothing here makes
graphs or labels.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
from dataclasses import dataclass, field
from typing import Optional

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"


def utcnow() -> float:
    return dt.datetime.now(dt.timezone.utc).timestamp()


def iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime(ISO)


def parse_iso(s: str) -> float:
    """Parse RFC3339 / ISO8601 with optional fractional seconds and Z or offset."""
    if s is None:
        return 0.0
    s = str(s).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        # last resort: seconds epoch
        try:
            return float(s)
        except ValueError:
            return 0.0
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.timestamp()


@dataclass
class SourceStatus:
    """One telemetry source's outcome for a capture."""
    name: str
    present: bool = False
    n_records: int = 0
    t_first: Optional[float] = None
    t_last: Optional[float] = None
    errors: list = field(default_factory=list)

    def note(self, msg: str) -> None:
        self.errors.append(msg)


@dataclass
class CaptureManifest:
    capture_id: str
    scenario: str
    origine: str = "labo"
    window_s: float = 10.0
    step_s: float = 5.0
    t_start: float = 0.0            # capture start (UTC epoch)
    t_end: float = 0.0
    clock_notes: str = ("all sources stamped in UTC; Hubble/EVE carry their own "
                        "event time, Prometheus is server-time; max skew assumed < step_s")
    sources: dict = field(default_factory=dict)   # name -> SourceStatus
    config: dict = field(default_factory=dict)
    schema_version: str = "2.0"

    def add_source(self, st: SourceStatus) -> None:
        self.sources[st.name] = st

    def to_json(self, path: str) -> None:
        obj = dataclasses.asdict(self)
        obj["t_start_iso"] = iso(self.t_start) if self.t_start else None
        obj["t_end_iso"] = iso(self.t_end) if self.t_end else None
        with open(path, "w") as fh:
            json.dump(obj, fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "CaptureManifest":
        with open(path) as fh:
            obj = json.load(fh)
        obj.pop("t_start_iso", None); obj.pop("t_end_iso", None)
        srcs = {k: SourceStatus(**v) for k, v in obj.pop("sources", {}).items()}
        m = cls(**obj)
        m.sources = srcs
        return m


def capture_dir(root: str, capture_id: str) -> str:
    return os.path.join(root, capture_id)
