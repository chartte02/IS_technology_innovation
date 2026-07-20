#!/usr/bin/env python3
"""
威胁情报集成测试

测试覆盖:
  1. 本地黑名单命中 / 未命中
  2. 缓存正确性
  3. 恶意 JA3 指纹查询
  4. 告警 enrichment
  5. 严重度升级
  6. 缓存 TTL 过期

运行:
  python tests/test_threat_intel.py
"""

import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import logging
logging.basicConfig(level=logging.WARNING)

from tools.threat_intel import ThreatIntel

passed = 0
failed = 0

def check(name, condition, detail=''):
    global passed, failed
    if condition:
        passed += 1
        print(f'  [OK] {name}')
    else:
        failed += 1
        print(f'  [FAIL] {name} {detail}')

# ════════════════════════════════════════════════════════════

def test_1_local_blacklist():
    """本地黑名单命中/未命中"""
    intel = ThreatIntel()
    r = intel.check_ip('10.0.0.55')
    check('黑名单 IP 被标记为恶意', r['malicious'])
    check('评分 > 0', r['score'] > 0)
    check('来源 = local', r['source'] == 'local')

    r2 = intel.check_ip('192.168.1.1')
    check('非黑名单 IP 未被标记', not r2['malicious'])


def test_2_cache():
    """缓存正确性"""
    intel = ThreatIntel()
    r1 = intel.check_ip('10.0.0.55')
    check('首次查询未缓存', not r1.get('cached'))

    r2 = intel.check_ip('10.0.0.55')
    check('二次查询命中缓存', r2.get('cached'))


def test_3_ja3_fingerprint():
    """恶意 JA3 指纹查询"""
    intel = ThreatIntel()
    r1 = intel.check_ja3('6734f3740000')
    check('Trickbot JA3 识别', r1 == 'Trickbot')

    r2 = intel.check_ja3('aaaaaaaa')
    check('未知 JA3 返回 None', r2 is None)


def test_4_enrich_alert():
    """告警 enrichment"""
    intel = ThreatIntel()
    alert = {
        'src_ip': '10.0.0.55',
        'severity': 'low',
        'type': 'port_scan',
        'description': 'test',
    }
    enriched = intel.enrich_alert(alert)
    check('enrich 增加 threat_intel', 'threat_intel' in enriched)
    check('恶意 IP 告警被升级', enriched['severity'] == 'medium',
          f'got {enriched["severity"]}')

    alert2 = {'src_ip': '192.168.1.1', 'severity': 'low'}
    enriched2 = intel.enrich_alert(alert2)
    check('非恶意 IP 不添加 intel', 'threat_intel' not in enriched2)
    check('非恶意 IP 不升级', enriched2['severity'] == 'low')


def test_5_severity_upgrade():
    """严重度升级逻辑"""
    intel = ThreatIntel()

    for ip, expected in [('10.0.0.55', 'medium'),   # 85 >= 80 → +1
                          ('10.0.0.99', 'medium'),    # 90 >= 80 → +1
                          ('192.168.1.1', 'low')]:    # 正常 → 不变
        a = intel.enrich_alert({'src_ip': ip, 'severity': 'low'})
        check(f'{ip} 告警严重度={expected}', a['severity'] == expected,
              f'got {a["severity"]}')


def test_6_cache_ttl():
    """缓存 TTL 过期"""
    intel = ThreatIntel(cache_ttl=0)  # 立即过期
    r1 = intel.check_ip('10.0.0.55')
    check('TTL=0 首次查询正常', r1['malicious'])
    r2 = intel.check_ip('10.0.0.55')
    check('TTL=0 二次未缓存', not r2.get('cached'))


def test_7_api_mock():
    """API Key 配置（不实际调用 API）"""
    intel = ThreatIntel(api_key='test_key_123')
    check('API Key 已配置', intel.api_key == 'test_key_123')
    # 本地黑名单优先于 API
    r = intel.check_ip('10.0.0.55')
    check('本地优先于 API', r['source'] == 'local')


def test_8_enrich_batch():
    """批量 enrichment"""
    intel = ThreatIntel()
    alerts = [
        {'src_ip': '10.0.0.55', 'severity': 'low'},
        {'src_ip': '10.0.0.99', 'severity': 'medium'},
        None,
        {'src_ip': '192.168.1.1', 'severity': 'high'},
    ]
    results = intel.enrich_alerts(alerts)
    check('批量结果数正确', len(results) == 3)
    check('批量中恶意 IP 被 enrich',
          any('threat_intel' in r for r in results))
    check('批量中正常 IP 无 intel',
          not any('threat_intel' in r for r in results
                  if r['src_ip'] == '192.168.1.1'))


def test_9_statistics():
    """统计信息"""
    intel = ThreatIntel(api_key='test')
    stats = intel.get_statistics()
    check('统计含黑名单数', 'local_blacklist_entries' in stats)
    check('统计含缓存数', 'cache_entries' in stats)
    check('统计含 API 状态', 'api_enabled' in stats)
    check('API 启用', stats['api_enabled'])
    check('黑名单 > 0', stats['local_blacklist_entries'] > 0)


# ════════════════════════════════════════════════════════════

def main():
    print('=' * 55)
    print('  ThreatIntel 威胁情报测试')
    print('  R5: Slips 威胁情报集成思路')
    print('=' * 55)
    print()

    tests = [
        ('本地黑名单', test_1_local_blacklist),
        ('缓存', test_2_cache),
        ('JA3 指纹', test_3_ja3_fingerprint),
        ('告警 enrichment', test_4_enrich_alert),
        ('严重度升级', test_5_severity_upgrade),
        ('缓存 TTL', test_6_cache_ttl),
        ('API 配置', test_7_api_mock),
        ('批量 enrichment', test_8_enrich_batch),
        ('统计信息', test_9_statistics),
    ]

    for name, fn in tests:
        print(f'[{name}]')
        fn()
        print()

    total = passed + failed
    print(f'{"=" * 55}')
    print(f'  结果: {passed}/{total} 通过'
          f'  [{"OK" if failed == 0 else "FAIL"}]')
    print(f'{"=" * 55}')

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
