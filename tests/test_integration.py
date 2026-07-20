#!/usr/bin/env python3
"""End-to-end integration test: PCAP replay -> detection -> alerts"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.packet_capture import PacketCapture
from core.protocol_parser import ProtocolParser
from core.tcp_reassembler import TCPStreamReassembler
from core.misuse_detector import SignatureMatcher
from core.anomaly_detector import AnomalyDetector
from core.alert_manager import AlertManager


def test_full_pipeline(pcap_name):
    """Single PCAP end-to-end test"""
    pcap_path = os.path.join(os.path.dirname(__file__),
                             'test_pcaps', pcap_name)
    if not os.path.exists(pcap_path):
        print(f"SKIP {pcap_name}: file not found")
        return None

    parser = ProtocolParser()
    reasm = TCPStreamReassembler(timeout=300)
    matcher = SignatureMatcher('./signatures')
    matcher.load_all()
    anomaly = AnomalyDetector()
    mgr = AlertManager(dedup_window=10)
    parsed = [0]; misuse = [0]; anomaly_count = [0]
    last_check = [time.time()]

    def cb(pkt):
        p = parser.parse(pkt)
        if not p: return
        parsed[0] += 1
        ma = matcher.match_packet(p)
        s = reasm.feed(p)
        if s:
            f = dict(src_ip=p['src_ip'], dst_ip=p['dst_ip'],
                     src_port=p['src_port'], dst_port=p['dst_port'])
            ma.extend(matcher.match_stream(s, f))
        if ma:
            misuse[0] += len(ma)
            mgr.submit_batch(ma, source='misuse')
        anomaly.update(p)
        now_ = time.time()
        if now_ - last_check[0] >= 5:
            last_check[0] = now_
            aa = anomaly.check_all()
            if aa:
                anomaly_count[0] += len(aa)
                mgr.submit_batch(aa, source='anomaly')

    cap = PacketCapture()
    cap.add_callback(cb)
    cap.replay_pcap(pcap_path)
    aa = anomaly.check_all()
    if aa:
        anomaly_count[0] += len(aa)
        mgr.submit_batch(aa, source='anomaly')

    stats = mgr.get_statistics()
    dedup = sum(stats.get('by_severity', {}).values())
    return {
        'name': pcap_name,
        'parsed': parsed[0],
        'misuse_raw': misuse[0],
        'anomaly_raw': anomaly_count[0],
        'dedup': dedup,
        'categories': stats.get('by_category', {}),
        'severities': stats.get('by_severity', {}),
    }


if __name__ == '__main__':
    pcaps = [
        'synthetic_attacks.pcap',
        'extended_attacks.pcap',
        'demo_sqli.pcap',
        'demo_xss.pcap',
        'demo_bruteforce.pcap',
        'demo_webattack.pcap',
        'demo_mixed.pcap',
    ]

    total_alerts = 0
    passed = 0
    for name in pcaps:
        r = test_full_pipeline(name)
        if r is None:
            continue
        passed += 1
        total_alerts += r['dedup']
        cats = ', '.join(f'{k}({v})' for k, v in r['categories'].items())
        print(f"{r['name']:<30}: {r['parsed']:>3} pkts, "
              f"{r['dedup']:>3} alerts [{cats}]")

    print(f"\n=== {passed}/{len(pcaps)} PCAPs tested, "
          f"{total_alerts} total deduplicated alerts ===")
    print("PASS" if passed >= 5 and total_alerts > 0 else "FAIL")
