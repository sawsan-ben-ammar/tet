"""Run one authorized lab scenario end to end (Phase 5).

Orchestrates: background benign load -> (warmup) -> attack -> (cooldown), while
capturing all telemetry, then writes a raw capture + scenario timeline for
labeling. Attacks are rate-capped, in-cluster only, from the isolated generators
namespace (default-deny egress). Reuses collect.prometheus in-process.

    sudo env PATH=$PATH HOME=/root python lab/scenario_runner.py lab/scenarios/<f>.yaml

Scenario YAML keys: id, verdict, type, target(service), target_port,
warmup_s, attack_s, cooldown_s, background{pods,rate,subnets},
attack{mode,pods,rate,subnets,path}. target/sources are recorded for labels.
"""
from __future__ import annotations
import json, os, subprocess, sys, time, tempfile
import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from collect.prometheus import collect as prom_collect  # noqa: E402
from collect.model import utcnow  # noqa: E402

KCTX = "kind-gnn-lab"
NS = "generators"
APP_NS = "boutique"
SEC_NS = "security"
ATTACKER_IMAGE = "us-central1-docker.pkg.dev/google-samples/microservices-demo/recommendationservice:v0.10.2"
SUBNETS = ["10-8-1-0", "10-8-2-0", "10-8-3-0", "10-8-4-0", "10-8-5-0",
           "10-8-6-0", "10-8-7-0", "10-8-8-0"]


def k(*args, check=True, capture=False):
    cmd = ["kubectl", "--context", KCTX, *args]
    return subprocess.run(cmd, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def ensure_attacker_cm():
    src = open(os.path.join(REPO, "lab/generators/attacker.py")).read()
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"name": "attacker", "namespace": NS},
          "data": {"attacker.py": src}}
    _apply(cm)


def _apply(obj):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        yaml.safe_dump(obj, fh)
        p = fh.name
    k("apply", "-f", p)
    os.unlink(p)


def launch_fleet(name, mode, host, port, secs, rate, pods, subnets, path="/"):
    """Create one Job per simulated subnet; pods in a job share its sim-subnet."""
    per = max(1, pods // max(1, subnets))
    chosen = SUBNETS[:subnets]
    jobs = []
    for i, sub in enumerate(chosen):
        jn = f"{name}-{i}"
        job = {"apiVersion": "batch/v1", "kind": "Job",
               "metadata": {"name": jn, "namespace": NS, "labels": {"gnn-scn": name}},
               "spec": {"parallelism": per, "completions": per, "backoffLimit": 0,
                 "ttlSecondsAfterFinished": 120,
                 "template": {"metadata": {"labels": {"app": "attacker", "gnn-scn": name,
                                                      "gnn-lab/sim-subnet": sub}},
                   "spec": {"restartPolicy": "Never",
                     "containers": [{"name": "a", "image": ATTACKER_IMAGE,
                       "imagePullPolicy": "IfNotPresent",
                       "command": ["python", "/g/attacker.py", "--mode", mode,
                                   "--host", host, "--port", str(port), "--secs", str(secs),
                                   "--rate", str(rate), "--path", path],
                       "resources": {"requests": {"cpu": "20m", "memory": "32Mi"},
                                     "limits": {"cpu": "200m", "memory": "128Mi"}},
                       "volumeMounts": [{"name": "g", "mountPath": "/g"}]}],
                     "volumes": [{"name": "g", "configMap": {"name": "attacker"}}]}}}}
        _apply(job)
        jobs.append(jn)
    return jobs


def delete_fleet(name):
    k("-n", NS, "delete", "job", "-l", f"gnn-scn={name}", "--force", "--grace-period=0",
      check=False, capture=True)


def main():
    spec = yaml.safe_load(open(sys.argv[1]))
    sid = spec["id"]
    cap_dir = os.path.join(REPO, "data", "captures", sid)
    raw = os.path.join(cap_dir, "raw")
    if os.path.exists(raw):
        print(f"capture {sid} exists; refusing to overwrite"); sys.exit(3)
    os.makedirs(raw)
    host = f"{spec['target']}.{APP_NS}"
    port = int(spec.get("target_port", 80))
    warm, atk, cool = spec.get("warmup_s", 60), spec.get("attack_s", 90), spec.get("cooldown_s", 45)
    total = warm + atk + cool
    bg = spec.get("background", {})
    ensure_attacker_cm()

    # port-forwards
    pf = []
    pf.append(subprocess.Popen(["kubectl", "--context", KCTX, "-n", "kube-system",
              "port-forward", "svc/hubble-relay", "14245:80"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(4)
    # background benign load for the whole scenario
    if bg:
        launch_fleet(f"{sid}-bg", "benign", host, port, total, bg.get("rate", 10),
                     bg.get("pods", 4), bg.get("subnets", 3))
    # hubble follow -> raw
    t0 = utcnow()
    hub = subprocess.Popen(["hubble", "observe", "--server", "localhost:14245",
            "--namespace", APP_NS, "--follow", "-o", "jsonpb"],
            stdout=open(os.path.join(raw, "hubble.jsonl"), "w"),
            stderr=open(os.path.join(cap_dir, "collect.err"), "w"))
    print(f"[scenario {sid}] warmup {warm}s", flush=True); time.sleep(warm)
    atk_start = utcnow()
    jobs = []
    if spec.get("verdict") == "attaque":
        a = spec["attack"]
        print(f"[scenario {sid}] ATTACK {a['mode']} {atk}s rate={a['rate']}/pod", flush=True)
        jobs = launch_fleet(sid, a["mode"], host, port, atk, a.get("rate", 30),
                            a.get("pods", 8), a.get("subnets", 6), a.get("path", "/"))
    time.sleep(atk)
    atk_end = utcnow()
    if jobs:
        delete_fleet(sid)
    print(f"[scenario {sid}] cooldown {cool}s", flush=True); time.sleep(cool)
    t1 = utcnow()
    hub.terminate(); time.sleep(2); hub.kill()

    # prometheus range (in-process)
    data, errs = prom_collect("http://localhost:19090", APP_NS, t0, t1, step=5.0) \
        if _prom_up(pf) else ({}, ["prometheus not port-forwarded"])
    json.dump({kk: {m: v for m, v in s.items()} for kk, s in data.items()},
              open(os.path.join(raw, "prometheus.json"), "w"))
    open(os.path.join(raw, "prometheus.json.err"), "w").write("\n".join(errs))
    # pods + eve
    r = k("-n", APP_NS, "get", "pods", "-o", "json", capture=True)
    open(os.path.join(raw, "pods.json"), "w").write(r.stdout)
    spod = k("-n", SEC_NS, "get", "pod", "-l", "app=suricata", "-o", "name", capture=True).stdout.strip().split("/")[-1]
    for probe in ("ids1", "ids2"):
        rr = k("-n", SEC_NS, "exec", spod, "-c", probe, "--",
               "sh", "-c", f"cat /var/log/suricata/{probe}/eve.json 2>/dev/null", check=False, capture=True)
        open(os.path.join(raw, f"eve.{probe}.jsonl"), "w").write(rr.stdout or "")
    for p in pf:
        p.terminate()

    # manifest seed + scenario timeline (label source of truth)
    json.dump({"capture_id": sid, "scenario": sid, "t_start": t0, "t_end": t1,
               "window_s": 10.0, "step_s": 5.0,
               "config": {"namespace": APP_NS, "scenario_file": sys.argv[1]}},
              open(os.path.join(cap_dir, "manifest.seed.json"), "w"), indent=2)
    json.dump({"id": sid, "verdict": spec.get("verdict", "normal"),
               "type": spec.get("type", "none"), "target": f"{APP_NS}/{spec['target']}",
               "phases": {"warmup": [t0, atk_start], "attack": [atk_start, atk_end],
                          "cooldown": [atk_end, t1]},
               "sim_subnets": SUBNETS[:spec.get("attack", {}).get("subnets", 0)]},
              open(os.path.join(cap_dir, "scenario.json"), "w"), indent=2)
    print(f"[scenario {sid}] done -> {cap_dir}", flush=True)


def _prom_up(pf):
    # start prometheus port-forward lazily here (kept simple: always try)
    try:
        import urllib.request
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        op.open("http://localhost:19090/-/ready", timeout=2)
        return True
    except Exception:
        p = subprocess.Popen(["kubectl", "--context", KCTX, "-n", "monitoring",
             "port-forward", "svc/prometheus-server", "19090:80"],
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pf.append(p); time.sleep(5)
        try:
            import urllib.request
            op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            op.open("http://localhost:19090/-/ready", timeout=3); return True
        except Exception:
            return False


if __name__ == "__main__":
    main()
