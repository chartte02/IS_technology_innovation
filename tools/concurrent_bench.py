#!/usr/bin/env python3
# ============================================================
# 并发压力测试 — 多线程 match_packet 吞吐量
# ============================================================
# 用法:
#   python tools/concurrent_bench.py
#   python tools/concurrent_bench.py --threads 8
# ============================================================

import sys, os, time, random, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.misuse_detector import SignatureMatcher


def worker(matcher: SignatureMatcher, payloads: list, count: int) -> tuple:
    """工作线程：匹配 count 个包"""
    base = {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1',
            'src_port': 12345, 'dst_port': 80,
            'app_protocol': 'HTTP', 'timestamp': time.time()}
    alerts = 0
    start = time.perf_counter()
    for _ in range(count):
        p = random.choice(payloads)
        r = matcher.match_packet({**base, 'payload': p})
        alerts += len(r)
    elapsed = time.perf_counter() - start
    return count, alerts, elapsed


def main():
    parser = argparse.ArgumentParser(description='并发压力测试')
    parser.add_argument('--threads', type=int, default=4, help='线程数')
    parser.add_argument('--per-thread', type=int, default=5000, help='每线程包数')
    args = parser.parse_args()

    # 每个线程独立创建 matcher（避免锁竞争）
    def make_matcher():
        m = SignatureMatcher('./signatures')
        m.load_all()
        return m

    payloads = [
        b"GET /?id=1 UNION SELECT * FROM users-- HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: x\r\n\r\nuser=admin&pass=test",
        b"GET /../../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
    ]

    print(f"并发测试: {args.threads} 线程 x {args.per_thread:,} 包/线程")
    print(f"总包数: {args.threads * args.per_thread:,}")

    # 单线程基线
    print("\n[1/3] 单线程基线...")
    m = make_matcher()
    t0 = time.perf_counter()
    c, a, e = worker(m, payloads, args.per_thread)
    t1 = time.perf_counter() - t0
    print(f"  单线程: {c/e:,.0f} pps, {a} 告警, {e:.2f}s")

    # 多线程（每个线程独立实例）
    print(f"\n[2/3] {args.threads} 线程并发...")
    matchers = [make_matcher() for _ in range(args.threads)]
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [
            pool.submit(worker, matchers[i], payloads, args.per_thread)
            for i in range(args.threads)
        ]
        results = [f.result() for f in as_completed(futures)]
    t_multi = time.perf_counter() - t0

    total_pkts = sum(r[0] for r in results)
    total_alerts = sum(r[1] for r in results)
    avg_pps = total_pkts / t_multi
    best_pps = max(r[0] / r[2] for r in results)

    print(f"  总吞吐: {avg_pps:,.0f} pps ({total_alerts} 告警)")
    print(f"  最佳线程: {best_pps:,.0f} pps")

    # 单线程 x N 对比
    single_scaled = (args.per_thread / t1) * args.threads
    speedup = avg_pps / (single_scaled / args.threads) if single_scaled > 0 else 0

    print(f"\n{'='*60}")
    print(f"  并发性能总结")
    print(f"{'='*60}")
    print(f"  单线程吞吐:    {args.per_thread/t1:,.0f} pps")
    print(f"  {args.threads}线程吞吐:    {avg_pps:,.0f} pps")
    print(f"  线性扩展预期:  {args.per_thread/t1 * args.threads:,.0f} pps (理想)")
    print(f"  实际加速比:    {avg_pps / (args.per_thread/t1):.1f}x")
    print(f"  效率:          {avg_pps / (args.per_thread/t1) / args.threads * 100:.0f}%")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
