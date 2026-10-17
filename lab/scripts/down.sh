#!/usr/bin/env bash
# Delete the kind cluster (destroys everything in it). Captures on disk are kept.
source "$(dirname "$0")/lib.sh"
$SUDO kind delete cluster --name "$CLUSTER_NAME"
