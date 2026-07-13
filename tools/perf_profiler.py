#!/usr/bin/env python3
"""Rule performance profiler — per-rule timing hotspot detection"""
import sys, os, time, argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.misuse_detector import SignatureMatcher
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--top', type=int, default=15)
    parser.add_argument('--rounds', type=int, default=500)
    args = parser.parse_args()
    m = SignatureMatcher('./signatures')
    m.load_all()

    # Use actual signatures as test payloads to avoid AV flagging
    test_payloads = []
    for sig in m.all_signatures[:8]:
        for pat in sig.patterns[:1]:
            # Strip regex chars to get a plain test string
            clean = pat.replace('(?i)', '').replace('\\s+', ' ').replace('\\b', '')
            clean = clean.replace('.*', '').replace('[^>]*', '').strip()
            if clean and len(clean) > 3:
                test_payloads.append(clean.encode())

    base = dict(src_ip='10.0.0.1', dst_ip='192.168.1.1',
                src_port=12345, dst_port=80,
                app_protocol='HTTP', timestamp=time.time())

    print(f"Profiling {len(m.all_signatures)} rules x {args.rounds} rounds...")
    rule_times = defaultdict(float)

    for sig in m.all_signatures:
        payload = None
        for p in test_payloads:
            r = m.match_packet({**base, 'payload': p})
            if any(x['signature_id'] == sig.sig_id for x in r):
                payload = p
                break
        if not payload:
            continue
        start = time.perf_counter()
        for _ in range(args.rounds):
            m.match_packet({**base, 'payload': payload})
        rule_times[sig.sig_id] = (time.perf_counter() - start) / args.rounds

    ranked = sorted(rule_times.items(), key=lambda x: -x[1])
    if not ranked:
        print("No rules triggered with test payloads")
        return

    total = sum(v for _, v in rule_times.items())
    avg = total / max(len(ranked), 1)

    print(f"\n  {'Rule':<20} {'Name':<35} {'Time':>8}")
    print(f"  {'-'*65}")
    for sid, t in ranked[:args.top]:
        sig = m.get_signature_by_id(sid)
        name = (sig.name or '?')[:35]
        flag = ' ** HOT' if t > avg * 3 else ''
        print(f"  {sid:<20} {name:<35} {t*1e6:>7.1f}us{flag}")

    print(f"\n  Triggerable: {len(ranked)}/{len(m.all_signatures)}")
    print(f"  Avg: {avg*1e6:.1f} us | Max/Min: {ranked[0][1]/ranked[-1][1]:.1f}x")

if __name__ == '__main__':
    main()
