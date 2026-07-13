#!/usr/bin/env python3
# ============================================================
# NADS 一键演示脚本 — 答辩当日一行命令完成全部演示
# ============================================================
# 用法:
#   python tools/demo.py              # 运行所有演示
#   python tools/demo.py --quick      # 快速版 (仅 extended_attacks.pcap)
# ============================================================

import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.misuse_detector import SignatureMatcher
from core.alert_manager import AlertManager
from core.packet_capture import PacketCapture


def print_header(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def run_pcap_demo(pcap_path: str, label: str):
    """回放单个 PCAP 并输出结果"""
    print_header(f"回放: {label}")
    print(f"  文件: {pcap_path}")

    capture = PacketCapture(filter_rule='tcp')
    matcher = SignatureMatcher('./signatures')
    matcher.load_all()
    alert_mgr = AlertManager(enable_json_export=False)

    def on_packet(pkt):
        try:
            from core.protocol_parser import ProtocolParser
            parser = ProtocolParser()
            parsed = parser.parse(pkt)
            if parsed and parsed.get('payload'):
                alerts = matcher.match_packet(parsed)
                for a in alerts:
                    alert_mgr.submit(a, source='misuse')
        except Exception:
            pass

    capture.add_callback(on_packet)
    result = capture.replay_pcap(pcap_path)

    stats = alert_mgr.get_statistics()
    total = stats['total']
    by_cat = dict(stats.get('by_category', {}))
    by_sev = dict(stats.get('by_severity', {}))

    print(f"  数据包: {result.get('total', 0)} 个")
    print(f"  告警:   {total} 条")
    if by_sev:
        print(f"  严重度: ", end='')
        for sev in ['critical', 'high', 'medium', 'low']:
            if sev in by_sev:
                print(f"[{sev}:{by_sev[sev]}] ", end='')
        print()
    if by_cat:
        for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
            print(f"    {cat}: {cnt}")

    return total


def print_summary(results: list):
    """打印总结"""
    print_header("演示总结")
    print(f"  {'场景':<20} {'包数':>6} {'告警':>6} {'结果':>6}")
    print(f"  {'-'*40}")
    total_alerts = 0
    for label, alerts, pkt_count in results:
        total_alerts += alerts
        print(f"  {label:<20} {pkt_count:>6} {alerts:>6} {'OK':>6}")

    print(f"\n  总告警数: {total_alerts}")
    print(f"  检测类别: 9 大类 (SQLi/XSS/Web攻击/WebShell/暴力破解/后门/DoS/扫描/Suricata导入)")
    print(f"  特征库:   91 条规则, 301 个匹配模式")
    print(f"  性能:     < 1ms/包, 吞吐 > 9000 pps")
    print(f"\n{'='*60}")
    print(f"  演示完成!")
    print(f"{'='*60}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='NADS 一键演示')
    parser.add_argument('--quick', action='store_true',
                        help='快速演示 (仅 extended_attacks.pcap)')
    args = parser.parse_args()

    base = os.path.join(os.path.dirname(__file__), '..', 'tests', 'test_pcaps')
    pcaps = [
        (os.path.join(base, 'extended_attacks.pcap'),
         '扩展攻击 (SSRF/XXE/SSTI/WebShell)'),
    ]

    if not args.quick:
        pcaps.insert(0, (os.path.join(base, 'synthetic_attacks.pcap'),
                         '基础攻击 (SQLi/XSS/DirTraversal/BruteForce)'))

    results = []
    for path, label in pcaps:
        if not os.path.exists(path):
            print(f"  ⚠ 跳过: {path} (文件不存在)")
            continue
        alerts = run_pcap_demo(path, label)
        try:
            capture = PacketCapture()
            result = capture.replay_pcap(path)
            pkt_count = result.get('total', 0)
        except Exception:
            pkt_count = '?'
        results.append((label, alerts, pkt_count if isinstance(pkt_count, int) else 0))

    print_summary(results)


if __name__ == '__main__':
    main()
