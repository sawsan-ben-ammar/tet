# The isolated lab

Everything here runs on one host, in a kind cluster, on a closed network. The lab
produces windows in the common format (`schema/window.schema.json`); the model and
evaluation never change when these replace the synthetic windows.

## Bring it up

```bash
make lab-up                      # kind create cluster --config lab/kind-config.yaml
# install Cilium as the CNI (gives NetworkPolicy enforcement + Hubble flow logs):
helm repo add cilium https://helm.cilium.io && helm repo update
helm install cilium cilium/cilium -n kube-system \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=gnn-lab-control-plane --set k8sServicePort=6443 \
  --set hubble.enabled=true --set hubble.relay.enabled=true
kubectl create ns shop generators monitoring
make lab-net                     # default-deny egress BEFORE any generator is deployed
```

Then deploy Online Boutique into `shop`, an ingress controller, and remove its
bundled load generator (you run your own Locust):

```bash
git clone https://github.com/GoogleCloudPlatform/microservices-demo
kubectl -n shop apply -f microservices-demo/release/kubernetes-manifests.yaml
kubectl -n shop delete deploy loadgenerator
```

## Monitoring (the signal sources, Section 9)

| Signal | Tool | Note |
| --- | --- | --- |
| Flows (who talks to whom, bytes, packets, flags) | Cilium Hubble | `hubble observe --follow -o jsonpb`, or the static exporter to a file |
| Metrics (CPU, memory, latency p95, HTTP errors) | kube-prometheus-stack | `helm install mon prometheus-community/kube-prometheus-stack -n monitoring` |
| Alerts | Suricata (two probes) + Alertmanager | see `ids/rules/dos-home.rules`; Suricata as a DaemonSet on the ingress node |
| Dependencies (A calls B) | OpenTelemetry + Jaeger, or Hubble | if tracing is slow to set up, derive edges from Hubble pod-to-pod flows |

## Generating traffic and attacks

Normal traffic and legitimate peaks use **Locust** (distributed mode, many small
worker pods, 3 profiles: browsing, cart+checkout, mixed; ramp user count ×5–×10 for a
peak). Attacks use the **standard tools named in the brief** (hping3, k6, slowhttptest,
Hydra), each run per its own published documentation, **always rate-capped** and
**always against the in-cluster ingress service only**, from pods on the isolated
`generators` node behind the default-deny egress policy. A scenario is declared in a
YAML (`lab/scenarios/example_syn_flood.yaml`); the runner reads it, drives the tool,
and writes the labels. The scenario YAML is the label source of truth.

**Always run the isolation check before a session** (it is in the network-policy file):
a generator pod must fail to reach the internet and succeed to reach `frontend.shop`.

## Simulated source subnets

Inside kind, all pods on a node share one pod CIDR, so a /24 grouping would mix
generators and clients. Fix it once in the exporter: label every client/generator pod
with `sim-subnet: 10.8.3.0/24` and map the pod IP to that simulated subnet when
building windows. Relabelling is simpler and fully reproducible; Cilium multi-pool
IPAM is an alternative.

## Tear down when idle

```bash
make lab-down                    # kind delete cluster --name gnn-lab
```
