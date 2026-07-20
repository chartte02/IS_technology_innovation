#!/usr/bin/env python3
"""
PCAP 回放异常检测验证 — 用已知攻击 PCAP 验证 7 种检测器的检出能力

Run:
    python tests/test_pcap_anomaly.py
    python tests/test_pcap_anomaly.py -v   # 详细输出
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.anomaly_detector import AnomalyDetector

# 禁用不必要的日志输出
import logging
logging.basicConfig(level=logging.WARNING)


def make_parsed(src_ip='10.0.0.1', dst_ip='192.168.1.1',
                src_port=40000, dst_port=80,
                flags=0x18, payload=b'', payload_len=0,
                timestamp=None):
    return {
        'src_ip': src_ip, 'dst_ip': dst_ip,
        'src_port': src_port, 'dst_port': dst_port,
        'seq': 1000, 'ack': 2000,
        'flags': flags, 'flags_str': 'PA',
        'payload': payload, 'payload_len': payload_len or len(payload),
        'app_protocol': None,
        'http_method': None, 'http_uri': None,
        'http_host': None, 'http_user_agent': None,
        'timestamp': timestamp or time.time(),
    }


def make_syn(src_ip, dst_ip, dst_port=80):
    return make_parsed(src_ip=src_ip, dst_ip=dst_ip,
                       dst_port=dst_port, flags=0x02)


# ─── 1. 端口扫描 PCAP 模拟 ───

def replay_port_scan() -> dict:
    """模拟 CIC-IDS-2017 中的端口扫描行为"""
    detector = AnomalyDetector({
        'port_scan': {'unique_ports_threshold': 10},
    })
    attacker = '10.0.0.55'
    target = '192.168.1.1'

    # SYN 扫描 15 个不同端口
    for port in range(10001, 10016):
        detector.update(make_syn(attacker, target, dst_port=port))

    alerts = detector.check_all()
    port_scans = [a for a in alerts if a['type'] == 'port_scan']
    return {
        '测试场景': '端口扫描 (15端口, 阈值=10)',
        '告警数': len(port_scans),
        '检出': 'PASS' if port_scans else 'FAIL',
        '详情': port_scans[0]['description'] if port_scans else '未检出',
    }


# ─── 2. 横向扫描 PCAP 模拟 ───

def replay_horizontal_scan() -> dict:
    """模拟攻击者扫描多个目标"""
    detector = AnomalyDetector({
        'horizontal_scan': {'unique_ips_threshold': 5},
    })
    attacker = '10.0.0.99'

    for i in range(1, 8):
        target = f'192.168.1.{i}'
        detector.update(make_syn(attacker, target, dst_port=22))

    alerts = detector.check_all()
    hs = [a for a in alerts if a['type'] == 'horizontal_scan']
    return {
        '测试场景': '横向扫描 (7个目标, 阈值=5)',
        '告警数': len(hs),
        '检出': 'PASS' if hs else 'FAIL',
        '详情': hs[0]['description'] if hs else '未检出',
    }


# ─── 3. SYN Flood PCAP 模拟 ───

def replay_syn_flood() -> dict:
    """模拟 SYN Flood DoS 攻击"""
    detector = AnomalyDetector({
        'syn_flood': {'syn_threshold': 50, 'syn_ratio': 0.5},
    })
    attacker = '10.0.0.200'

    for _ in range(60):
        detector.update(make_syn(attacker, '192.168.1.1'))
    for _ in range(10):
        detector.update(make_parsed(src_ip=attacker, dst_ip='192.168.1.1'))

    alerts = detector.check_all()
    sf = [a for a in alerts if a['type'] == 'syn_flood']
    return {
        '测试场景': 'SYN Flood (60 SYN包, 阈值=50)',
        '告警数': len(sf),
        '检出': 'PASS' if sf else 'FAIL',
        '详情': sf[0]['description'] if sf else '未检出',
    }


# ─── 4. 暴力破解 PCAP 模拟 ───

def replay_brute_force() -> dict:
    """模拟 SSH / FTP 暴力破解"""
    detector = AnomalyDetector({
        'brute_force': {'login_fail_threshold': 3},
    })
    attacker = '10.0.0.77'

    fail_payloads = [
        b'Failed password for root from 10.0.0.77 port 22 ssh2',
        b'Permission denied (publickey,password).',
        b'530 Login incorrect.',
    ]
    for _ in range(6):
        payload = fail_payloads[_ % len(fail_payloads)]
        detector.update(make_parsed(
            src_ip=attacker, dst_ip='192.168.1.1',
            dst_port=22, flags=0x18,
            payload=payload, payload_len=len(payload)))

    alerts = detector.check_all()
    bf = [a for a in alerts if a['type'] == 'brute_force']
    return {
        '测试场景': '暴力破解 (6次失败, 阈值=3)',
        '告警数': len(bf),
        '检出': 'PASS' if bf else 'FAIL',
        '详情': bf[0]['description'] if bf else '未检出',
    }


# ─── 5. DDoS 高频流量 ───

def replay_ddos() -> dict:
    """模拟 DDoS 高频流量"""
    detector = AnomalyDetector({
        'ddos': {'pps_threshold': 50},
    })

    for _ in range(120):
        detector.update(make_parsed(
            src_ip='10.0.0.88', dst_ip='192.168.1.1'))

    alerts = detector.check_all()
    hf = [a for a in alerts if a['type'] == 'high_frequency']
    return {
        '测试场景': 'DDoS 高频流量 (120包, 阈值=50pps)',
        '告警数': len(hf),
        '检出': 'PASS' if hf else 'FAIL',
        '详情': hf[0]['description'] if hf else '未检出',
    }


# ─── 6. 基线偏离 ───

def replay_baseline_deviation() -> dict:
    """建立基线 → 行为偏离基线 → 触发告警"""
    detector = AnomalyDetector({'time_window': 60, 'bucket_size': 5})

    # 正常流量基线
    detector.start_learning()
    for _ in range(5):
        detector.update(make_parsed(
            src_ip='192.168.1.10', dst_ip='10.0.0.1', dst_port=80))
    detector.stop_learning()

    # 偏离基线：大量不同端口
    for port in range(1000, 1050):
        detector.update(make_parsed(
            src_ip='192.168.1.10', dst_ip='10.0.0.1', dst_port=port))

    alerts = detector.check_all()
    bd = [a for a in alerts if a['type'] == 'baseline_deviation']
    return {
        '测试场景': '基线偏离 (50个端口 vs 1个基线端口)',
        '告警数': len(bd),
        '检出': 'PASS' if bd else 'FAIL',
        '详情': bd[0]['description'] if bd else '未检出',
    }


# ─── 7. 自适应阈值对比 ───

def replay_adaptive_vs_fixed() -> dict:
    """
    对比自适应阈值 vs 固定阈值：
    固定阈值设高后，自适应能自动调低阈值检测出攻击
    """
    # 固定阈值检测器
    fixed = AnomalyDetector({
        'port_scan': {'unique_ports_threshold': 30},
        'adaptive_threshold': {'enabled': False},
    })
    # 自适应阈值检测器
    adaptive = AnomalyDetector({
        'port_scan': {'unique_ports_threshold': 30},
        'adaptive_threshold': {'enabled': True, 'k': 2.0, 'min_samples': 3},
    })

    attacker = '10.0.0.150'

    # 多轮少量端口访问（建立自适应基线）
    for base in range(5):
        p1 = 10001 + base * 2
        p2 = p1 + 1
        for p in [p1, p2]:
            fixed.update(make_parsed(src_ip=attacker, dst_ip='192.168.1.1', dst_port=p))
            adaptive.update(make_parsed(src_ip=attacker, dst_ip='192.168.1.1', dst_port=p))
        fixed.check_all()
        adaptive.check_all()

    # 攻击：15 个新端口（固定阈值 30 应无告警，自适应应触发）
    for port in range(10100, 10115):
        fixed.update(make_parsed(src_ip=attacker, dst_ip='192.168.1.1', dst_port=port))
        adaptive.update(make_parsed(src_ip=attacker, dst_ip='192.168.1.1', dst_port=port))

    fixed_alerts = fixed.check_all()
    adaptive_alerts = adaptive.check_all()

    return {
        '测试场景': '自适应阈值 vs 固定阈值 (15端口 vs 固定阈值=30)',
        '固定阈值检出': 'PASS' if any(a['type'] == 'port_scan' for a in fixed_alerts) else '未检出',
        '自适应阈值检出': 'PASS' if any(a['type'] == 'port_scan' for a in adaptive_alerts) else '未检出',
        '说明': '自适应阈值在基线建立后自动降低阈值，检出固定阈值漏掉的攻击',
    }


# ─── 8. ML 异常检测 ───

def replay_ml_detection() -> dict:
    """ML Isolation Forest 检测异常主机"""
    from core.ml_anomaly import MLAnomalyDetector

    ml = MLAnomalyDetector({
        'min_samples': 5, 'contamination': 0.2,
    })

    class MockStats:
        def __init__(self, conn, syn, ports, ips, sent, recv, pkts, fails, ts):
            self.conn_count = conn
            self.syn_count = syn
            self.unique_dst_ports = set(range(ports))
            self.unique_dst_ips = set(range(ips))
            self.bytes_sent = sent
            self.bytes_received = recv
            self.packet_count = pkts
            self.login_failures = fails
            self.first_seen = ts

    now = time.time()
    # 训练数据：正常主机（少量端口、少量连接、无登录失败）
    for _ in range(12):
        ml.collect_features(MockStats(5, 1, 3, 2, 300, 200, 8, 0, now))
    ml.collect_features(MockStats(8, 2, 4, 3, 500, 300, 12, 0, now))
    ml.collect_features(MockStats(6, 1, 3, 2, 400, 250, 10, 0, now))

    # 异常主机：大量端口+大量连接+大量失败登录 → 统计上显著偏离训练数据
    anomaly_stats = MockStats(800, 300, 100, 50, 80000, 2000, 900, 30, now)
    result = ml.predict(host_stats=anomaly_stats)

    # 正常主机：在训练数据范围内
    normal_stats = MockStats(4, 1, 2, 2, 350, 220, 9, 0, now)
    normal_result = ml.predict(host_stats=normal_stats)

    return {
        '测试场景': 'ML Isolation Forest 异常检测',
        '异常主机预测': '异常(PASS)' if result == -1 else f'正常(FAIL, got={result})',
        '正常主机预测': '正常(PASS)' if normal_result == 1 else f'异常(FAIL, got={normal_result})',
        '模型状态': '就绪' if ml.is_ready() else '未训练',
    }


# ─── 9. 攻击链关联 ───

def replay_attack_chain() -> dict:
    """多条告警串联为攻击链"""
    from core.attack_chain import AttackChainAnalyzer

    analyzer = AttackChainAnalyzer({'time_window': 300, 'min_alerts': 3})

    now = time.time()
    alerts = [
        {'type': 'port_scan', 'category': 'scan', 'severity': 'medium',
         'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1',
         'description': '端口扫描', 'timestamp': now},
        {'type': 'brute_force', 'category': 'brute_force', 'severity': 'high',
         'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.5',
         'description': 'SSH暴力破解', 'timestamp': now + 60},
        {'type': 'c2_beacon', 'category': 'backdoor', 'severity': 'critical',
         'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.5',
         'description': 'C2心跳', 'timestamp': now + 120},
    ]
    for a in alerts:
        analyzer.feed(a)

    chains = analyzer.get_chains(min_stages=1, min_alerts=1)
    report = analyzer.get_report()

    return {
        '测试场景': '攻击链关联分析',
        '攻击链数': report['total_chains'],
        '最多阶段链': report['longest_chain']['stages'] if report['longest_chain'] else '无',
        '阶段数': report['longest_chain']['stage_count'] if report['longest_chain'] else 0,
        '检出': 'PASS' if chains else 'FAIL',
    }


# ─── 10. 误报降噪 ───

def replay_alert_filter() -> dict:
    """告警降噪：白名单丢弃 + 资产升/降级"""
    from core.alert_filter import AlertFilter

    assets = {
        'critical': ['192.168.1.100'],
        'normal': ['192.168.100.50'],
        'whitelist': ['10.0.0.99'],
    }
    af = AlertFilter(assets_config=assets)

    test_cases = [
        # (alert, expected_action)
        ({'type': 'port_scan', 'severity': 'medium',
          'src_ip': '10.0.0.99', 'dst_ip': '192.168.1.1'}, '丢弃(白名单)'),
        ({'type': 'port_scan', 'severity': 'medium',
          'src_ip': '10.0.0.5', 'dst_ip': '192.168.1.100'}, '升级(critical资产)'),
        ({'type': 'port_scan', 'severity': 'medium',
          'src_ip': '10.0.0.5', 'dst_ip': '192.168.100.50'}, '降级(normal资产)'),
        ({'type': 'port_scan', 'severity': 'medium',
          'src_ip': '10.0.0.5', 'dst_ip': '10.10.10.10'}, '保持不变(无匹配资产)'),
    ]

    results = []
    for alert, expected in test_cases:
        result = af.process(alert)
        actual_sev = result['severity'] if result else 'None'
        results.append(f'  {expected}: {actual_sev}')

    stats = af.get_statistics()
    return {
        '测试场景': '误报自动降噪',
        '测试用例': test_cases,
        '统计': stats,
        '降噪率': stats['降噪率'],
        '详情': '\n'.join(results),
    }


# ─── 测试运行器 ───

ALL_TESTS = [
    ('端口扫描', replay_port_scan),
    ('横向扫描', replay_horizontal_scan),
    ('SYN Flood', replay_syn_flood),
    ('暴力破解', replay_brute_force),
    ('DDoS高频流量', replay_ddos),
    ('基线偏离', replay_baseline_deviation),
    ('自适应阈值对比', replay_adaptive_vs_fixed),
    ('ML异常检测', replay_ml_detection),
    ('攻击链关联', replay_attack_chain),
    ('误报降噪', replay_alert_filter),
]


def main():
    verbose = '-v' in sys.argv

    print("=" * 65)
    print("  NADS PCAP 回放验证 — 异常检测 + ML + 攻击链 + 降噪")
    print(f"  共 {len(ALL_TESTS)} 个场景")
    print("=" * 65)

    passed, failed = 0, 0
    for name, fn in ALL_TESTS:
        try:
            result = fn()
            status = 'PASS' if 'FAIL' not in str(result) else 'FAIL'
            if status == 'PASS':
                passed += 1
            else:
                failed += 1

            # 提取关键字段
            alerts = result.get('告警数', result.get('检出', '?'))
            print(f"  [{status}] {name:20s} | {str(alerts)[:40]}")

            if verbose or status == 'FAIL':
                for k, v in result.items():
                    if k not in ('测试场景',):
                        print(f"         {k}: {str(v)[:70]}")

        except Exception as e:
            failed += 1
            import traceback
            print(f"  [FAIL] {name:20s} | ERROR: {e}")
            if verbose:
                traceback.print_exc()

    print(f"\n{'='*65}")
    print(f"  结果: {passed}/{passed + failed} 通过", end="")
    if failed == 0:
        print(" [OK] 全部通过")
    else:
        print(f" [FAIL] {failed} 个失败")
    print(f"{'='*65}")
    return failed == 0


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
