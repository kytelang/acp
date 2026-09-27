#!/usr/bin/env python3
"""ACP load / soak harness (P1 #12, extended for R8). Fires concurrent requests at an ACP endpoint and
reports the status-code distribution, throughput, and latency percentiles. It drives two body shapes:

  --body chat   OpenAI-style chat/completions (the LLM gateway). Default.
  --body mcp    JSON-RPC tools/call (the MCP proxy).

Either a fixed request count (--requests) or a sustained duration (--duration seconds). Use it to
exercise the concurrency cap (expect some 503 shed above the limit), budgets, and streaming, and to soak
for stability. Examples:
  python3 scripts/loadtest.py --url http://127.0.0.1:8799/v1/chat/completions --requests 2000 --concurrency 64
  python3 scripts/loadtest.py --url http://127.0.0.1:8794/ --body mcp --duration 10 --concurrency 32
"""
import argparse, concurrent.futures, itertools, json, time, urllib.request, urllib.error, collections, threading

def build(body_mode, model, app, n):
    if body_mode == "mcp":
        data = json.dumps({"jsonrpc": "2.0", "id": n, "method": "tools/call",
                           "params": {"name": "echo", "arguments": {"q": "ping"}}}).encode()
        headers = {"content-type": "application/json"}
    else:
        data = json.dumps({"model": model, "messages": [{"role": "user", "content": "ping"}]}).encode()
        headers = {"content-type": "application/json", "x-acp-app": app}
    return data, headers

def one(url, body_mode, model, app, n):
    data, headers = build(body_mode, model, app, n)
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
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
    ap.add_argument("--duration", type=float, default=0.0, help="if >0, run for this many seconds instead of a fixed count")
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--body", choices=["chat", "mcp"], default="chat")
    ap.add_argument("--model", default="gpt-3.5-turbo")
    ap.add_argument("--app", default="svc")
    a = ap.parse_args()
    codes = collections.Counter()
    lat = []
    lock = threading.Lock()
    start = time.perf_counter()

    if a.duration > 0:
        stop = start + a.duration
        counter = itertools.count()
        def worker():
            while time.perf_counter() < stop:
                code, ms = one(a.url, a.body, a.model, a.app, next(counter))
                with lock:
                    codes[code] += 1; lat.append(ms)
        threads = [threading.Thread(target=worker) for _ in range(a.concurrency)]
        for t in threads: t.start()
        for t in threads: t.join()
        total = sum(codes.values())
    else:
        total = a.requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.concurrency) as ex:
            for code, ms in ex.map(lambda n: one(a.url, a.body, a.model, a.app, n), range(a.requests)):
                codes[code] += 1; lat.append(ms)

    dur = time.perf_counter() - start
    lat.sort()
    pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))] if lat else 0.0
    print(f"body={a.body} requests={total} concurrency={a.concurrency} in {dur:.2f}s -> {total/dur:.0f} rps")
    print("status codes:", dict(codes))
    print(f"latency ms: p50={pct(0.50):.1f} p95={pct(0.95):.1f} p99={pct(0.99):.1f} max={(lat[-1] if lat else 0):.1f}")
    bad = sum(v for k, v in codes.items() if k == 0 or (500 <= k < 600 and k != 503))
    print("HEALTHY" if bad == 0 else f"UNHEALTHY: {bad} connection/5xx errors")
    return 0 if bad == 0 else 1

if __name__ == "__main__":
    raise SystemExit(main())
