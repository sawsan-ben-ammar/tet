# Deployment

## Local (docker compose)

```bash
# train the models first so the artifacts exist
make data && make train && make train-ids
docker compose -f deploy/docker-compose.yml up --build
# API  -> http://localhost:8000/health
# Demo -> http://localhost:8501
```

## API

```
GET  /health
POST /correlation/attaque   body: {flux, metriques?, alertes?, fenetre?}
POST /correlation/ids       body: {alertes_ids1, alertes_ids2, mode?, fenetre?}
```

Example:

```bash
curl -s localhost:8000/health
curl -s -X POST localhost:8000/correlation/attaque \
  -H 'content-type: application/json' \
  -d '{"flux":[{"src_ip":"45.0.0.7","dst":"ingress","octets":500000,"paquets":3000,"flux":3,"http":false}],
       "metriques":{"ingress":{"cpu":0.95,"latence_p95":800,"taux_erreurs":0.6,"type":"gateway"}},
       "alertes":[{"node":"ingress","gravite":3}]}'
```

## Kubernetes

Build and load the API image, then apply the manifests. The trained artifacts are
baked into the image at build time (train before `docker build`), or mount a PVC.

```bash
docker build -f deploy/Dockerfile.api -t gnn-ddos/api:1.0 .
kind load docker-image gnn-ddos/api:1.0 --name gnn-lab   # if deploying into the lab
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/api.yaml
kubectl -n correlation get pods
kubectl -n correlation port-forward svc/correlation-api 8000:80
```

The service exposes `/health` for readiness and liveness probes; it runs 2 replicas
and requests modest CPU/memory (CPU-only inference is well under the 10 s per-window
budget).
