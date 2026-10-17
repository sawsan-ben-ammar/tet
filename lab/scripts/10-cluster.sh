#!/usr/bin/env bash
# Phase 2: create the kind cluster. Idempotent: an existing cluster is reused, never recreated.
source "$(dirname "$0")/lib.sh"
if $SUDO kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  log "cluster $CLUSTER_NAME already exists - reusing it"
else
  cfg="$LAB_DIR/kind-config.yaml"
  if [ "$(restricted_host)" = yes ]; then cfg="$LAB_DIR/sandbox/kind-config-restricted.yaml"; log "restricted host: using $cfg"; fi
  (cd "$REPO_DIR" && $SUDO kind create cluster --config "$cfg" --image "$KIND_NODE_IMAGE" --wait 0s)
fi
# kind writes the kubeconfig of the user who ran it; make it available to the caller too.
if [ -n "$SUDO" ]; then mkdir -p "$HOME/.kube"; $SUDO kind get kubeconfig --name "$CLUSTER_NAME" > "$HOME/.kube/config"; fi
k get nodes -o wide
