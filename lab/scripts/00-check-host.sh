#!/usr/bin/env bash
# Phase 1: verify the host. Prints a report; exits non-zero if a hard requirement fails.
source "$(dirname "$0")/lib.sh"
fail=0
need() { if command -v "$1" >/dev/null 2>&1; then printf '  %-10s %s\n' "$1" "$($2 2>&1 | head -1)"; else printf '  %-10s MISSING\n' "$1"; fail=1; fi; }
echo "== tools"
need docker "docker --version"; need kind "kind version"; need kubectl "kubectl version --client"
need helm "helm version --short"; need hubble "hubble version"; need python3 "python3 --version"
echo "== docker daemon"
if $SUDO docker info >/dev/null 2>&1; then echo "  reachable"; else echo "  NOT reachable"; fail=1; fi
echo "== resources"
echo "  cpus=$(nproc) mem_gib=$(awk '/MemTotal/{printf "%.1f",$2/1048576}' /proc/meminfo) disk_free=$(df -h "$REPO_DIR" | awk 'NR==2{print $4}')"
[ "$(nproc)" -ge 2 ] || { echo "  need >= 2 CPUs"; fail=1; }
echo "== kernel"
echo "  $(uname -r)  cgroup=$(stat -fc %T /sys/fs/cgroup)"
if [ "$(restricted_host)" = yes ]; then echo "  CAP_SYS_RESOURCE missing -> restricted mode (lab/sandbox/)"; else echo "  CAP_SYS_RESOURCE present -> standard mode"; fi
exit $fail
