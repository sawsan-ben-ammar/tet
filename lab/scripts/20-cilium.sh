#!/usr/bin/env bash
# Phase 2: install Cilium (CNI) + Hubble relay. Idempotent (helm upgrade --install).
source "$(dirname "$0")/lib.sh"
helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
helm repo update cilium >/dev/null
CHART=(cilium/cilium --version "$CILIUM_CHART_VERSION" -n kube-system -f "$LAB_DIR/helm/cilium-values.yaml")
mapfile -t IMGS < <(chart_images "${CHART[@]}")
preload "${IMGS[@]}"
helm --kube-context "$KCTX" upgrade --install cilium "${CHART[@]}" --wait --timeout 10m
k -n kube-system rollout status ds/cilium --timeout=5m
k -n kube-system rollout status deploy/hubble-relay --timeout=5m
k wait --for=condition=Ready node --all --timeout=5m
log "Cilium + Hubble ready"
