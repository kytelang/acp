#!/usr/bin/env python3
"""ACP load / soak harness (P1 #12). Fires concurrent model-call requests at the gateway (or any ACP
endpoint) and reports the status-code distribution, throughput, and latency percentiles. Use it to
exercise the concurrency cap (expect some 503 shed above the limit), budgets, and streaming, and to
soak for stability. Usage:
  python3 scripts/loadtest.py --url http://127.0.0.1:8799/v1/chat/completions \
      --requests 2000 --concurrency 64 --model gpt-3.5-turbo --app svc
"""
import argparse, concurrent.futures, json, time, urllib.request, urllib.error, collections

def one(url, model, app):
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": "ping"}]}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"content-type": "application/json", "x-acp-app": app})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:
        code = 0
    return code, (time.perf_counter() - t0) * 1000.0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--requests", type=int, default=1000)
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--model", default="gpt-3.5-turbo")
    ap.add_argument("--app", default="svc")
    a = ap.parse_args()
    codes = collections.Counter()
    lat = []
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.concurrency) as ex:
        for code, ms in ex.map(lambda _: one(a.url, a.model, a.app), range(a.requests)):
            codes[code] += 1
            lat.append(ms)
    dur = time.perf_counter() - start
    lat.sort()
    pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))] if lat else 0.0
    print(f"requests={a.requests} concurrency={a.concurrency} in {dur:.2f}s -> {a.requests/dur:.0f} rps")
    print("status codes:", dict(codes))
    print(f"latency ms: p50={pct(0.50):.1f} p95={pct(0.95):.1f} p99={pct(0.99):.1f} max={lat[-1]:.1f}")
    # 2xx or governed 4xx are expected; a 0 (connection error) or 5xx spike is a failure signal.
    bad = sum(v for k, v in codes.items() if k == 0 or (500 <= k < 600 and k != 503))
    print("HEALTHY" if bad == 0 else f"UNHEALTHY: {bad} connection/5xx errors")

if __name__ == "__main__":
    main()
