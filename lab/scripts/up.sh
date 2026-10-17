#!/usr/bin/env bash
# Bring the whole lab up, in order, idempotently (Phase 2 orchestrator).
#   bash lab/scripts/up.sh [--check]
set -euo pipefail
D="$(dirname "$0")"
bash "$D/00-check-host.sh" || { echo "host check failed"; exit 1; }
bash "$D/10-cluster.sh"
bash "$D/20-cilium.sh"
bash "$D/30-boutique.sh"
bash "$D/40-monitoring.sh"
bash "$D/50-suricata.sh"
bash "$D/60-isolation.sh" "${1:-}"
echo "lab is up."
