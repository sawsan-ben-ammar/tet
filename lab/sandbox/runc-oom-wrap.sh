#!/bin/sh
# OPTIONAL workaround, only for restricted hosts whose root lacks CAP_SYS_RESOURCE
# (seen in some cloud sandboxes / Firecracker VMs). On a normal Ubuntu host with
# Docker you do NOT need this file; use lab/kind-config.yaml.
#
# Symptoms without it:
#  * every pod sandbox with a negative OOM score (static control-plane pods,
#    hostNetwork pods) fails: "can't get final child's PID from pipe: EOF",
#    because runc cannot lower oom_score_adj;
#  * containers / exec hooks asking for CAP_SYS_RESOURCE (Cilium) fail:
#    "unable to apply caps: operation not permitted".
#
# Fix: before handing over to the real runc, rewrite the OCI bundle config
# (create/run: --bundle DIR) and the exec process spec (exec: --process FILE):
# clamp negative oomScoreAdj to 0 and drop CAP_SYS_RESOURCE.
patch_json() {
  [ -f "$1" ] || return 0
  sed -i -E -e 's/"oomScoreAdj":[[:space:]]*-[0-9]+/"oomScoreAdj":0/g' \
            -e 's/"CAP_SYS_RESOURCE",[[:space:]]*//g' \
            -e 's/,[[:space:]]*"CAP_SYS_RESOURCE"//g' \
            -e 's/\[[[:space:]]*"CAP_SYS_RESOURCE"[[:space:]]*\]/[]/g' "$1"
}
prev=""
for a in "$@"; do
  case "$prev" in
    --bundle|-b) patch_json "$a/config.json" ;;
    --process|-p) patch_json "$a" ;;
  esac
  case "$a" in
    --bundle=*) patch_json "${a#--bundle=}/config.json" ;;
    --process=*) patch_json "${a#--process=}" ;;
  esac
  prev="$a"
done
exec /usr/local/sbin/runc "$@"
