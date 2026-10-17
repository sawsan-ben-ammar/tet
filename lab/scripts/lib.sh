#!/usr/bin/env bash
# Shared helpers for the lab scripts. Source, don't execute.
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$LAB_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$LAB_DIR/versions.env"
# Use `sudo` for docker/kind only if the current user cannot reach the daemon.
if docker info >/dev/null 2>&1; then SUDO=""; else SUDO="sudo -E env PATH=$PATH"; fi
KCTX="kind-${CLUSTER_NAME}"
k() { kubectl --context "$KCTX" "$@"; }
log() { printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(basename "$0")" "$*" >&2; }

# Render a Helm chart and print the unique container images it uses.
chart_images() { helm template x "$@" 2>/dev/null | grep -E '^\s*image:' | sed -E 's/.*image:\s*"?([^"]+)"?/\1/' | sort -u; }

# Pull images on the host and load them into the kind node(s). Idempotent: skips
# images already present in the node. Useful offline, behind proxies, and to
# avoid registry rate limits.
preload() {
  local nodes img
  nodes=$($SUDO kind get nodes --name "$CLUSTER_NAME" | head -1)
  for img in "$@"; do
    [ -z "$img" ] && continue
    if $SUDO docker exec "$nodes" crictl inspecti "$img" >/dev/null 2>&1; then
      log "already in node: $img"; continue; fi
    log "pull + load: $img"
    $SUDO docker pull -q "$img" >/dev/null
    # `docker save | ctr import --platform` instead of `kind load docker-image`:
    # kind's --all-platforms import fails with Docker's containerd image store
    # when only the host platform's layers were pulled.
    $SUDO docker save "$img" | $SUDO docker exec -i "$nodes" \
      ctr -n k8s.io images import --platform linux/amd64 --digests --snapshotter=overlayfs - >/dev/null
  done
}

# "yes" if root lacks CAP_SYS_RESOURCE (bit 24) in its bounding set.
restricted_host() {
  local bnd; bnd=$(awk '/CapBnd/{print $2}' /proc/self/status)
  if (( (16#$bnd >> 24) & 1 )); then echo no; else echo yes; fi
}
