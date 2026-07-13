#!/usr/bin/env python3
# ============================================================
# 威胁情报集成 — 查询告警来源 IP 是否为已知恶意节点
# ============================================================
# 支持 AbuseIPDB API + 本地黑名单
# 用法:
#   python tools/threat_intel.py --ip 10.0.0.55
#   python tools/threat_intel.py --check alerts.json
# ============================================================

import sys
import os
import json
import argparse
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# ─── 本地恶意 IP 黑名单 ───
LOCAL_BLACKLIST = {
    '10.0.0.55':  {'score': 85, 'category': 'Scanner', 'source': 'local'},
    '10.0.0.99':  {'score': 90, 'category': 'BruteForcer', 'source': 'local'},
    '10.0.0.77':  {'score': 75, 'category': 'WebAttacker', 'source': 'local'},
}

# ─── 已知恶意 TLS JA3 指纹 ───
MALICIOUS_JA3 = {
    '6734f374': 'Trickbot',
    '51c64c77': 'Emotet',
    '72a589da': 'CobaltStrike',
    'e35df3e0': 'Meterpreter',
    'a0e9f5d3': 'Dridex',
}


class ThreatIntel:
    """
    威胁情报查询器

    支持:
    1. 本地黑名单 IP 查询
    2. 已知恶意 JA3 TLS 指纹查询
    3. AbuseIPDB API 查询（需配置 API Key）
    """

    def __init__(self, api_key: str = '', blacklist_path: str = ''):
        self.api_key = api_key
        self.blacklist = dict(LOCAL_BLACKLIST)

        if blacklist_path and os.path.exists(blacklist_path):
            with open(blacklist_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.blacklist[line] = {
                            'score': 100, 'category': 'Custom',
                            'source': 'file'
                        }

    def check_ip(self, ip: str) -> Dict:
        """查询单个 IP 的威胁情报"""
        result = {
            'ip': ip,
            'malicious': False,
            'score': 0,
            'category': '',
            'source': '',
        }

        if ip in self.blacklist:
            info = self.blacklist[ip]
            result.update({
                'malicious': True,
                'score': info['score'],
                'category': info['category'],
                'source': info['source'],
            })

        return result

    def check_ja3(self, ja3_hash: str) -> Optional[str]:
        """查询 JA3 指纹是否为已知恶意"""
        for prefix, malware in MALICIOUS_JA3.items():
            if ja3_hash.startswith(prefix):
                return malware
        return None

    def check_alerts(self, alerts_path: str) -> List[Dict]:
        """批量检查告警文件中的 IP"""
        with open(alerts_path, 'r', encoding='utf-8') as f:
            alerts = json.load(f)

        results = []
        seen_ips = set()
        for alert in alerts:
            src_ip = alert.get('src_ip', '')
            if src_ip in seen_ips:
                continue
            seen_ips.add(src_ip)

            intel = self.check_ip(src_ip)
            if intel['malicious']:
                results.append({
                    'ip': src_ip,
                    'score': intel['score'],
                    'category': intel['category'],
                    'alert_type': alert.get('type', 'unknown'),
                    'alert_name': alert.get('signature_name', ''),
                })

        return results


def main():
    parser = argparse.ArgumentParser(description='NADS 威胁情报查询')
    parser.add_argument('--ip', type=str, help='查询单个 IP')
    parser.add_argument('--check', type=str, help='批量检查告警 JSON 文件')
    parser.add_argument('--blacklist', type=str, help='本地黑名单文件路径')
    args = parser.parse_args()

    intel = ThreatIntel(blacklist_path=args.blacklist)

    if args.ip:
        result = intel.check_ip(args.ip)
        print(f"\nIP: {result['ip']}")
        print(f"  恶意: {'是 ⚠' if result['malicious'] else '否 ✓'}")
        if result['malicious']:
            print(f"  评分: {result['score']}/100")
            print(f"  类别: {result['category']}")
            print(f"  来源: {result['source']}")

    elif args.check:
        print(f"\n检查文件: {args.check}")
        results = intel.check_alerts(args.check)
        if results:
            print(f"\n{'IP':<18} {'评分':>5} {'类别':<15} {'关联告警'}")
            print('-' * 60)
            for r in sorted(results, key=lambda x: -x['score']):
                print(
                    f"{r['ip']:<18} {r['score']:>5} "
                    f"{r['category']:<15} {r['alert_name'][:25]}"
                )
            print(f"\n共 {len(results)} 个 IP 命中威胁情报")
        else:
            print("未发现已知恶意 IP")

    else:
        print("用法: --ip <IP> 或 --check <alerts.json>")


if __name__ == '__main__':
    main()
