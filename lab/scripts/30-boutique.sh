#!/usr/bin/env bash
# Phase 2: deploy Online Boutique into its namespace. Idempotent (kubectl apply).
source "$(dirname "$0")/lib.sh"
k create namespace "$APP_NAMESPACE" --dry-run=client -o yaml | k apply -f -
mapfile -t IMGS < <(grep -E '^\s*image:' "$LAB_DIR/k8s/boutique/boutique.yaml" | sed -E 's/.*image:\s*//' | sort -u)
preload "${IMGS[@]}"
k -n "$APP_NAMESPACE" apply -f "$LAB_DIR/k8s/boutique/boutique.yaml"
log "waiting for Online Boutique deployments to become available"
k -n "$APP_NAMESPACE" wait --for=condition=Available deploy --all --timeout=12m
k -n "$APP_NAMESPACE" get deploy
