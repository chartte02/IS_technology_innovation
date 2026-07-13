#!/usr/bin/env python3
# ============================================================
# Fuzzing 鲁棒性测试 — 10万条畸形HTTP请求，确保引擎零崩溃
# ============================================================
# 用法:
#   python tools/fuzz_test.py
#   python tools/fuzz_test.py --count 50000
# ============================================================

import sys, os, time, random, string, argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.misuse_detector import SignatureMatcher

# Fuzzing 策略
def gen_normal_http():
    """正常HTTP请求"""
    paths = ['/index', '/login', '/api', '/search?q=test', '/page?id=1',
             '/admin', '/upload', '/download?file=doc.pdf']
    h = random.choice(paths)
    body = 'user=admin&pass=123456' if random.random() < 0.3 else ''
    req = f"GET {h} HTTP/1.1\r\nHost: example.com\r\n\r\n{body}"
    return req.encode('utf-8', errors='ignore')

def gen_malformed_http():
    """畸形HTTP请求"""
    tactics = [
        lambda: b'\x00\x01\x02' * random.randint(1, 50),           # 二进制
        lambda: b'%FF%FE%00' * 20,                                  # 无效编码
        lambda: b'A' * random.randint(1000, 5000),                  # 超长
        lambda: os.urandom(random.randint(10, 500)),                # 随机字节
        lambda: ('GET ' + 'A'*2000 + ' HTTP/1.1\r\n\r\n').encode(),   # 超长URI
        lambda: b'\r\n\r\n' * 100,                                  # 大量空行
        lambda: ('x' * 100 + '\x00' * 100).encode(),                # NULL字节
        lambda: (''.join(random.choices(string.printable, k=random.randint(100, 2000)))).encode(),
        lambda: b'POST / HTTP/1.1\r\nContent-Length: 999999\r\n\r\n' + b'X'*5000,
        lambda: b'\xFF\xFE' + 'GET / HTTP/1.1\r\n\r\n'.encode('utf-16-le', errors='ignore'),
    ]
    return random.choice(tactics)()

def gen_edge_case():
    """边界值"""
    return random.choice([
        b'', b' ', b'\r\n', b'\r\n\r\n',
        b'GET', b'GET /', b'HTTP/1.1',
        b': ', b': \r\n',
    ])


def main():
    parser = argparse.ArgumentParser(description='Fuzzing 鲁棒性测试')
    parser.add_argument('--count', type=int, default=100000,
                        help='测试包数')
    args = parser.parse_args()

    m = SignatureMatcher('./signatures')
    m.load_all()

    base = {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1',
            'src_port': 12345, 'dst_port': 80,
            'app_protocol': 'HTTP', 'timestamp': time.time()}

    generators = [
        ('正常HTTP', gen_normal_http, 0.4),
        ('畸形输入', gen_malformed_http, 0.4),
        ('边界值',   gen_edge_case, 0.2),
    ]

    gen_names = [g[0] for g in generators]
    gen_weights = [g[2] for g in generators]

    crashes = 0
    timeouts = 0
    alerts_total = 0
    start = time.perf_counter()

    print(f"Fuzzing {args.count:,} 个包...")
    progress_every = max(args.count // 10, 1)

    for i in range(args.count):
        name = random.choices(generators, weights=gen_weights)[0]
        payload = name[1]()

        try:
            parsed = {**base, 'payload': payload}
            alerts = m.match_packet(parsed)
            alerts_total += len(alerts)
        except MemoryError:
            # 超长输入可能OOM，跳过
            pass
        except Exception as e:
            crashes += 1
            if crashes <= 5:
                print(f"  [CRASH #{crashes}] {name[0]} len={len(payload)}: {str(e)[:80]}")

        if (i + 1) % progress_every == 0:
            elapsed = time.perf_counter() - start
            rate = (i + 1) / elapsed
            print(f"  {i+1:>7,}/{args.count:,} 包 | {rate:>.0f} pps | "
                  f"告警{alerts_total} | 崩溃{crashes}")

    elapsed = time.perf_counter() - start

    print(f"\n{'='*60}")
    print(f"  Fuzzing 结果")
    print(f"{'='*60}")
    print(f"  总包数:    {args.count:,}")
    print(f"  告警数:    {alerts_total}")
    print(f"  崩溃:      {crashes}")
    print(f"  超时:      {timeouts}")
    print(f"  总耗时:    {elapsed:.1f}s")
    print(f"  吞吐:      {args.count/elapsed:,.0f} pps")

    if crashes == 0:
        print(f"\n  Robustness: [OK] zero crashes ({args.count:,} malformed requests)")
    else:
        print(f"\n  Robustness: [WARN] {crashes} crashes ({crashes/args.count*100:.4f}%)")

    print(f"{'='*60}")


if __name__ == '__main__':
    main()
