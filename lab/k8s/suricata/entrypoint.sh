#!/bin/sh
# Render the per-probe Suricata config and run it. Env:
#   PROBE         probe name (ids1|ids2), also the EVE subdir
#   CAPTURE_MODE  afpacket|pcap
#   IFACE         interface (eth0, or "any" for pcap)
set -eu
mkdir -p "/var/log/suricata/${PROBE}"
if [ "${CAPTURE_MODE}" = afpacket ]; then
  CAP="af-packet:
  - interface: ${IFACE}
    cluster-id: ${CLUSTER_ID:-99}
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes"
else
  CAP="pcap:
  - interface: ${IFACE}
    buffer-size: 16777216"
fi
sed -e "s/__PROBE__/${PROBE}/g" /etc/suricata/suricata.yaml.tmpl > /tmp/suricata.yaml
# inject the capture block in place of the __CAPTURE__ marker
awk -v cap="$CAP" '/__CAPTURE__/{print cap; next} {print}' /tmp/suricata.yaml > /tmp/suricata.final.yaml
echo "[entrypoint] probe=${PROBE} mode=${CAPTURE_MODE} iface=${IFACE}"
if [ "${CAPTURE_MODE}" = afpacket ]; then
  exec suricata -c /tmp/suricata.final.yaml --af-packet
else
  exec suricata -c /tmp/suricata.final.yaml --pcap
fi
