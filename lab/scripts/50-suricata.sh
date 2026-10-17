#!/usr/bin/env bash
# Phase 2: deploy the two-probe Suricata sensor. Idempotent (kubectl apply).
source "$(dirname "$0")/lib.sh"
python3 "$LAB_DIR/k8s/suricata/render.py" "$SURICATA_IMAGE" > "$LAB_DIR/k8s/suricata/suricata.gen.yaml"
preload "$SURICATA_IMAGE"
k apply -f "$LAB_DIR/k8s/suricata/suricata.gen.yaml"
k -n security rollout status ds/suricata --timeout=5m
k -n security get pods -o wide
log "Suricata up. EVE JSON on the node at /var/log/suricata/{ids1,ids2}/eve.json"
