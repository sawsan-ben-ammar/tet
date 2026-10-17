#!/usr/bin/env bash
# Phase 3: record one live capture of all telemetry into data/captures/<id>/raw/.
#   bash lab/scripts/capture.sh <scenario> <duration_s> [capture_id] [namespace]
# Pulls: Hubble flows (relay), Prometheus range, Suricata EVE (both probes),
# pod metadata. All timestamps UTC. Raw files are never overwritten.
source "$(dirname "$0")/lib.sh"
export REPO_DIR
SCN="${1:?scenario}"; DUR="${2:-60}"; CID="${3:-cap-$(date -u +%Y%m%d-%H%M%S)}"; NS="${4:-$APP_NAMESPACE}"
OUT="$REPO_DIR/data/captures/$CID"; RAW="$OUT/raw"
if [ -d "$RAW" ]; then log "capture $CID already exists - refusing to overwrite"; exit 3; fi
mkdir -p "$RAW"
WIN=10; STEP=5

cleanup() { for p in "${PF[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
PF=()
# port-forwards (background)
k -n monitoring port-forward svc/prometheus-server 19090:80 >/dev/null 2>&1 & PF+=($!)
k -n kube-system port-forward svc/hubble-relay 14245:80 >/dev/null 2>&1 & PF+=($!)
sleep 4

T0=$(date -u +%s.%N)
log "capture $CID scenario=$SCN dur=${DUR}s ns=$NS"
# Hubble: follow for the duration into the raw file (jsonpb stream).
( hubble observe --server localhost:14245 --namespace "$NS" --follow -o jsonpb \
    >"$RAW/hubble.jsonl" 2>>"$OUT/collect.err" ) & HUB=$!
# ... also capture external->cluster flows (any namespace touching the app)
sleep "$DUR"
kill "$HUB" 2>/dev/null || true
T1=$(date -u +%s.%N)

# Prometheus range over [T0,T1]
for m in cpu mem; do :; done
python3 - "$T0" "$T1" "$NS" "$STEP" "$RAW/prometheus.json" <<'PY' 2>>"$OUT/collect.err" || echo "prom pull failed" >>"$OUT/collect.err"
import sys, os
sys.path.insert(0, os.environ["REPO_DIR"])
from collect.prometheus import collect
t0,t1,ns,step,out = float(sys.argv[1]),float(sys.argv[2]),sys.argv[3],float(sys.argv[4]),sys.argv[5]
data, errs = collect("http://localhost:19090", ns, t0, t1, step)
import json
json.dump({k:{m:v for m,v in s.items()} for k,s in data.items()}, open(out,"w"))
open(out+".err","w").write("\n".join(errs))
PY

# Pods metadata snapshot
k -n "$NS" get pods -o json > "$RAW/pods.json" 2>>"$OUT/collect.err"

# Suricata EVE from both probes (filter to [T0,T1] is done at align time)
SPOD=$(k -n security get pod -l app=suricata -o name | head -1)
for probe in ids1 ids2; do
  k -n security exec "${SPOD##*/}" -c "$probe" -- sh -c "cat /var/log/suricata/$probe/eve.json 2>/dev/null" \
    > "$RAW/eve.$probe.jsonl" 2>>"$OUT/collect.err" || true
done

# Write the manifest seed (times + config); run_capture fills source status.
python3 - "$CID" "$SCN" "$T0" "$T1" "$WIN" "$STEP" "$NS" "$OUT/manifest.seed.json" <<'PY'
import sys, json
cid,scn,t0,t1,win,step,ns,out = sys.argv[1:9]
json.dump({"capture_id":cid,"scenario":scn,"t_start":float(t0),"t_end":float(t1),
           "window_s":float(win),"step_s":float(step),
           "config":{"namespace":ns,"hubble":"relay:follow","prometheus":"range@localhost:19090"}},
          open(out,"w"), indent=2)
PY
log "raw capture written -> $OUT"
echo "$CID"
