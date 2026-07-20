#!/usr/bin/env python3
# ============================================================
# 威胁情报集成 — 查询告警来源 IP 是否为已知恶意节点
# 参考: R5 Slips (Stratosphere IPS) 的威胁情报集成思路
# ============================================================
# 支持:
#   1. 本地黑名单 IP 查询（file/local）
#   2. AbuseIPDB API 查询（需配置 API Key）
#   3. 已知恶意 JA3 TLS 指纹查询
#   4. 结果缓存（避免重复查询相同 IP）
#
# 用法:
#   python tools/threat_intel.py --ip 10.0.0.55
#   python tools/threat_intel.py --check alerts.json
#   python tools/threat_intel.py --api <KEY> --ip 8.8.8.8   # 在线查询
# ============================================================

import sys
import os
import json
import time
import argparse
import logging
from typing import Dict, List, Optional, Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

logger = logging.getLogger(__name__)

# ─── 本地恶意 IP 黑名单 ───
LOCAL_BLACKLIST = {
    '10.0.0.55':  {'score': 85, 'category': 'Scanner', 'source': 'local'},
    '10.0.0.99':  {'score': 90, 'category': 'BruteForcer', 'source': 'local'},
    '10.0.0.77':  {'score': 75, 'category': 'WebAttacker', 'source': 'local'},
    '10.0.0.200': {'score': 88, 'category': 'PortScanner', 'source': 'local'},
    '10.0.0.150': {'score': 92, 'category': 'DoS_Attacker', 'source': 'local'},
}

# ─── 已知恶意 TLS JA3 指纹 ───
MALICIOUS_JA3 = {
    '6734f374': 'Trickbot',
    '51c64c77': 'Emotet',
    '72a589da': 'CobaltStrike',
    'e35df3e0': 'Meterpreter',
    'a0e9f5d3': 'Dridex',
}

# AbuseIPDB API
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'


class ThreatIntel:
    """
    威胁情报查询器

    支持:
    1. 本地黑名单 IP 查询
    2. 已知恶意 JA3 TLS 指纹查询
    3. AbuseIPDB API 查询（需配置 API Key）
    4. 结果 LRU 缓存（避免重复查询）

    与 AnomalyDetector 集成:
        intel = ThreatIntel(api_key='...')
        alert['threat_intel'] = intel.check_ip(alert['src_ip'])
    """

    def __init__(self, api_key: str = '', blacklist_path: str = '',
                 cache_size: int = 1000, cache_ttl: int = 3600):
        """
        Args:
            api_key: AbuseIPDB API Key
            blacklist_path: 本地黑名单文件路径（每行一个 IP）
            cache_size: LRU 缓存最大条数
            cache_ttl: 缓存有效期（秒）
        """
        self.api_key = api_key
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl

        # 加载本地黑名单
        self.blacklist = dict(LOCAL_BLACKLIST)
        if blacklist_path and os.path.exists(blacklist_path):
            with open(blacklist_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.blacklist[line] = {
                            'score': 100, 'category': 'Custom',
                            'source': 'file'
                        }

        # LRU 缓存: {ip: (timestamp, result)}
        self._cache: Dict[str, tuple] = {}

        if api_key:
            logger.info("威胁情报: AbuseIPDB API 已配置")
        logger.info(f"威胁情报: {len(self.blacklist)} 条本地黑名单, "
                     f"缓存 TTL={cache_ttl}s")

    # ─── 核心查询 ───

    def check_ip(self, ip: str, use_api: bool = True) -> Dict:
        """
        查询单个 IP 的威胁情报。

        查询顺序: 缓存 → 本地黑名单 → AbuseIPDB API

        Args:
            ip: 要查询的 IP 地址
            use_api: 是否允许调用 AbuseIPDB API

        Returns:
            {
                'ip': str,
                'malicious': bool,
                'score': int (0-100),
                'confidence': int,       # AbuseIPDB 置信度
                'category': str,
                'source': 'cache' | 'local' | 'abuseipdb' | '',
                'cached': bool,
                'timestamp': float,
            }
        """
        now = time.time()
        result: Dict[str, Any] = {
            'ip': ip,
            'malicious': False,
            'score': 0,
            'confidence': 0,
            'category': '',
            'source': '',
            'cached': False,
            'timestamp': now,
        }

        # 1. 检查缓存
        cached = self._cache.get(ip)
        if cached:
            ts, cached_result = cached
            if now - ts < self.cache_ttl:
                cached_result['cached'] = True
                cached_result['timestamp'] = now
                return cached_result
            else:
                del self._cache[ip]

        # 2. 本地黑名单
        if ip in self.blacklist:
            info = self.blacklist[ip]
            result.update({
                'malicious': True,
                'score': info['score'],
                'confidence': info['score'],
                'category': info['category'],
                'source': 'local',
            })
            self._add_to_cache(ip, result)
            return result

        # 3. AbuseIPDB API
        if use_api and self.api_key:
            api_result = self._query_abuseipdb(ip)
            if api_result:
                result.update(api_result)
                self._add_to_cache(ip, result)
                return result

        # 未命中
        self._add_to_cache(ip, result)
        return result

    # ─── AbuseIPDB API ───

    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """调用 AbuseIPDB API 查询 IP 信誉"""
        if not self.api_key:
            return None

        try:
            req = Request(
                f'{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays=90',
                headers={
                    'Key': self.api_key,
                    'Accept': 'application/json',
                    'User-Agent': 'NADS/1.0',
                }
            )
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            raw = data.get('data', {})
            abuse_score = raw.get('abuseConfidenceScore', 0)

            if abuse_score > 0:
                return {
                    'malicious': abuse_score >= 50,
                    'score': abuse_score,
                    'confidence': abuse_score,
                    'category': ', '.join(
                        self._category_names(raw.get('categories', []))
                    ) or 'Unknown',
                    'source': 'abuseipdb',
                }
            return {
                'malicious': False, 'score': 0, 'confidence': 0,
                'category': '', 'source': 'abuseipdb',
            }

        except HTTPError as e:
            if e.code == 429:
                logger.warning("AbuseIPDB API 速率超限")
            elif e.code == 404:
                pass  # IP 不在数据库中
            else:
                logger.error(f"AbuseIPDB API 错误: {e.code}")
        except URLError as e:
            logger.debug(f"AbuseIPDB API 连接失败: {e.reason}")
        except Exception as e:
            logger.error(f"AbuseIPDB API 异常: {e}")

        return None

    @staticmethod
    def _category_names(cats: List[int]) -> List[str]:
        """AbuseIPDB 分类编号 → 可读名称"""
        cat_map = {
            1: 'DNS_Compromise', 2: 'DNS_Poisoning',
            3: 'Fraud_Orders', 4: 'DDoS_Attack', 5: 'FTP_BruteForce',
            6: 'Ping_Flood', 7: 'Phishing', 8: 'Fraud_VoIP',
            9: 'Open_Proxy', 10: 'Web_Spam', 11: 'Email_Spam',
            12: 'Blog_Spam', 13: 'VPN_IP', 14: 'Port_Scan',
            15: 'Hacking', 16: 'SQL_Injection', 17: 'Spoofing',
            18: 'Brute_Force', 19: 'Bad_Web_Bot', 20: 'Exploited_Host',
            21: 'Web_App_Attack', 22: 'SSH', 23: 'IoT_Targeted',
        }
        return [cat_map.get(c, f'Category_{c}') for c in cats]

    # ─── JA3 查询 ───

    def check_ja3(self, ja3_hash: str) -> Optional[str]:
        """查询 JA3 指纹是否为已知恶意"""
        for prefix, malware in MALICIOUS_JA3.items():
            if ja3_hash.startswith(prefix):
                return malware
        return None

    # ─── 缓存管理 ───

    def _add_to_cache(self, ip: str, result: Dict):
        """将查询结果加入 LRU 缓存"""
        if len(self._cache) >= self.cache_size:
            # 丢弃最早的条目
            oldest = min(self._cache.keys(),
                        key=lambda k: self._cache[k][0])
            del self._cache[oldest]
        self._cache[ip] = (time.time(), result)

    def clear_cache(self):
        """清空缓存"""
        self._cache.clear()

    def get_cache_size(self) -> int:
        """获取当前缓存条目数"""
        return len(self._cache)

    # ─── 批量查询 ───

    def enrich_alert(self, alert: Dict) -> Dict:
        """
        为单条告警补充威胁情报信息。
        返回告警的副本，增加了 'threat_intel' 字段。
        """
        alert = dict(alert)
        src_ip = alert.get('src_ip', '')
        if src_ip:
            intel = self.check_ip(src_ip)
            if intel['malicious']:
                alert['threat_intel'] = intel
                # 如果告警来自恶意 IP，升级严重度
                if intel['score'] >= 80:
                    alert['severity'] = self._upgrade_severity(
                        alert.get('severity', 'low'))
        return alert

    def enrich_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """批量补充威胁情报，自动跳过 None"""
        return [self.enrich_alert(a) for a in alerts if a is not None]

    @staticmethod
    def _upgrade_severity(sev: str) -> str:
        """升级严重度"""
        order = ['low', 'medium', 'high', 'critical']
        ranks = {s: i for i, s in enumerate(order)}
        rank = ranks.get(sev, 0)
        return order[min(rank + 1, 3)]

    # ─── 统计 ───

    def get_statistics(self) -> Dict:
        """获取运行统计"""
        local_count = len(self.blacklist)
        cache_count = len(self._cache)
        return {
            'local_blacklist_entries': local_count,
            'cache_entries': cache_count,
            'api_enabled': bool(self.api_key),
            'cache_ttl_seconds': self.cache_ttl,
        }


# ════════════════════════════════════════════════════════════
#  命令行入口
# ════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='NADS 威胁情报查询')
    parser.add_argument('--ip', type=str, help='查询单个 IP')
    parser.add_argument('--api', type=str, default='', help='AbuseIPDB API Key')
    parser.add_argument('--check', type=str, help='批量检查告警 JSON 文件')
    parser.add_argument('--blacklist', type=str, help='本地黑名单文件路径')
    args = parser.parse_args()

    intel = ThreatIntel(api_key=args.api, blacklist_path=args.blacklist)

    if args.ip:
        result = intel.check_ip(args.ip, use_api=bool(args.api))
        print(f"\nIP: {result['ip']}")
        print(f"  Malicious: {'YES' if result['malicious'] else 'NO'}")
        if result['malicious']:
            print(f"  Score:     {result['score']}/100")
            print(f"  Category:  {result['category']}")
            print(f"  Source:    {result['source']}")

    elif args.check:
        print(f"\nChecking: {args.check}")
        results = intel.check_alerts(args.check)
        if results:
            print(f"\n{'IP':<18} {'Score':>5} {'Category':<18} {'Alert'}")
            print('-' * 60)
            for r in sorted(results, key=lambda x: -x['score']):
                print(f"{r['ip']:<18} {r['score']:>5} "
                      f"{r['category']:<18} {r['alert_name'][:25]}")
            print(f"\nTotal: {len(results)} IPs matched threat intel")
        else:
            print("No known malicious IPs found")
    else:
        print("Usage: --ip <IP> or --check <alerts.json>")


if __name__ == '__main__':
    main()
