#!/usr/bin/env bash
# Phase 2: Prometheus + Grafana. Idempotent (helm upgrade --install).
source "$(dirname "$0")/lib.sh"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
helm repo add grafana https://grafana.github.io/helm-charts >/dev/null 2>&1 || true
helm repo update prometheus-community grafana >/dev/null
k create namespace monitoring --dry-run=client -o yaml | k apply -f -
PCHART=(prometheus-community/prometheus --version "$PROMETHEUS_CHART_VERSION" -n monitoring -f "$LAB_DIR/helm/prometheus-values.yaml")
GCHART=(grafana/grafana --version "$GRAFANA_CHART_VERSION" -n monitoring -f "$LAB_DIR/helm/grafana-values.yaml")
mapfile -t IMGS < <({ chart_images "${PCHART[@]}"; chart_images "${GCHART[@]}"; } | sort -u)
preload "${IMGS[@]}"
helm --kube-context "$KCTX" upgrade --install prometheus "${PCHART[@]}" --wait --timeout 8m
helm --kube-context "$KCTX" upgrade --install grafana "${GCHART[@]}" --wait --timeout 6m
k -n monitoring rollout status deploy/prometheus-server --timeout=5m
k -n monitoring get pods
log "Prometheus + Grafana ready (grafana: kubectl -n monitoring port-forward svc/grafana 3000:80)"
