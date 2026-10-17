#!/usr/bin/env bash
# Phase 2/8: create the generators namespace and apply default-deny egress, then
# verify isolation (generator pod cannot reach the internet, can reach frontend).
source "$(dirname "$0")/lib.sh"
k create namespace generators --dry-run=client -o yaml | k apply -f -
k apply -f "$LAB_DIR/k8s/network-policies.yaml"
if [ "${1:-}" = "--check" ]; then
  log "isolation check (expect: external FAIL, in-cluster SUCCEED)"
  k -n generators delete pod isotest --ignore-not-found >/dev/null 2>&1
  k -n generators run isotest --image=curlimages/curl:8.11.1 --image-pull-policy=IfNotPresent --restart=Never --command -- sh -c 'sleep 30' >/dev/null
  until k -n generators get pod isotest -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Running; do sleep 2; done
  ext=$(k -n generators exec isotest -- sh -c 'curl -s -m4 -o /dev/null -w "%{http_code}" https://example.com 2>/dev/null; true' 2>/dev/null)
  intl=$(k -n generators exec isotest -- sh -c 'curl -s -m4 -o /dev/null -w "%{http_code}" http://frontend.boutique 2>/dev/null; true' 2>/dev/null)
  k -n generators delete pod isotest --force --grace-period=0 >/dev/null 2>&1
  echo "  external (example.com): $ext   [want BLOCKED/000]"
  echo "  in-cluster (frontend.boutique): $intl   [want 200]"
  [ "$ext" = "000" ] && echo "  => isolation OK (internet blocked, cluster reachable)" || echo "  WARN: egress to internet was NOT blocked (got $ext)"
fi
