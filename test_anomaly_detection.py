#!/usr/bin/env python3
"""
异常检测引擎测试 — 7 种检测器的准确率验证

测试内容:
  1. 端口扫描检测 (port_scan)
  2. 横向扫描检测 (horizontal_scan)
  3. SYN Flood 检测 (syn_flood)
  4. 暴力破解检测 (brute_force)
  5. 高频流量/DDoS 检测 (high_frequency)
  6. 基线偏离检测 (baseline_deviation)
  7. 正常流量不误报 (false_positive)
  8. 白名单跳过 (whitelist)

Run:
    python tests/test_anomaly_detection.py
    python tests/test_anomaly_detection.py -v
"""

import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.anomaly_detector import AnomalyDetector
from core.baseline_learner import BaselineLearner


def _make_parsed(src_ip: str = '10.0.0.1', dst_ip: str = '192.168.1.1',
                 src_port: int = 40000, dst_port: int = 80,
                 flags: int = 0x18, payload: bytes = b'',
                 payload_len: int = 0) -> dict:
    """构造模拟 parsed_packet（按 5.1 节接口约定）"""
    return {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'seq': 1000,
        'ack': 2000,
        'flags': flags,
        'flags_str': 'PA',
        'payload': payload,
        'payload_len': payload_len or len(payload),
        'app_protocol': None,
        'http_method': None,
        'http_uri': None,
        'http_host': None,
        'http_user_agent': None,
        'timestamp': time.time(),
    }


def _make_syn(src_ip: str, dst_ip: str, dst_port: int = 80) -> dict:
    """构造 SYN 包 (flags=0x02)"""
    return _make_parsed(src_ip=src_ip, dst_ip=dst_ip,
                        dst_port=dst_port, flags=0x02)


def assert_alert_type(alerts: list, alert_type: str) -> dict:
    """从告警列表中找出指定类型的告警"""
    for a in alerts:
        if a['type'] == alert_type:
            return a
    raise AssertionError(f"未发现 {alert_type} 类型告警")


def assert_no_alert_type(alerts: list, alert_type: str):
    """确认告警列表中不包含指定类型"""
    for a in alerts:
        if a['type'] == alert_type:
            raise AssertionError(f"不应出现 {alert_type} 告警: {a}")


# ============================================================
# 1. 端口扫描检测
# ============================================================

def test_port_scan_detection() -> dict:
    """模拟攻击者访问大量不同端口 → 期望 port_scan 告警"""
    detector = AnomalyDetector({'port_scan': {'unique_ports_threshold': 10}})

    attacker = '10.0.0.55'
    target = '192.168.1.1'

    # 访问 15 个不同端口（超过阈值 10）
    for port in range(10001, 10016):
        pkt = _make_parsed(src_ip=attacker, dst_ip=target, dst_port=port)
        detector.update(pkt)

    alerts = detector.check_all()
    assert_alert_type(alerts, 'port_scan')
    return {'测试项': '端口扫描检测', '结果': 'PASS'}


def test_port_scan_low_threshold_no_false() -> dict:
    """模拟正常客户端访问少量端口 → 不应触发"""
    detector = AnomalyDetector({'port_scan': {'unique_ports_threshold': 20}})

    client = '192.168.1.100'
    server = '10.0.0.1'

    for port in [80, 443]:
        pkt = _make_parsed(src_ip=client, dst_ip=server, dst_port=port)
        detector.update(pkt)

    alerts = detector.check_all()
    assert_no_alert_type(alerts, 'port_scan')
    return {'测试项': '端口扫描-正常不误报', '结果': 'PASS'}


# ============================================================
# 2. 横向扫描检测
# ============================================================

def test_horizontal_scan_detection() -> dict:
    """攻击者扫描多个目标 IP 同一端口 → 期望 horizontal_scan 告警"""
    detector = AnomalyDetector({'horizontal_scan': {'unique_ips_threshold': 5}})

    attacker = '10.0.0.99'

    for i in range(1, 8):
        target = f'192.168.1.{i}'
        pkt = _make_parsed(src_ip=attacker, dst_ip=target, dst_port=22)
        detector.update(pkt)

    alerts = detector.check_all()
    assert_alert_type(alerts, 'horizontal_scan')
    return {'测试项': '横向扫描检测', '结果': 'PASS'}


# ============================================================
# 3. SYN Flood 检测
# ============================================================

def test_syn_flood_detection() -> dict:
    """短时间内大量 SYN 包 → 期望 syn_flood 告警"""
    detector = AnomalyDetector({
        'syn_flood': {'syn_threshold': 50, 'syn_ratio': 0.5},
    })

    attacker = '10.0.0.200'
    target = '192.168.1.1'

    # 发送 60 个 SYN 包（超过阈值 50），混入少量非 SYN
    for i in range(60):
        pkt = _make_syn(attacker, target, dst_port=80)
        detector.update(pkt)
    for i in range(10):
        pkt = _make_parsed(src_ip=attacker, dst_ip=target, dst_port=80)
        detector.update(pkt)

    alerts = detector.check_all()
    assert_alert_type(alerts, 'syn_flood')
    return {'测试项': 'SYN Flood 检测', '结果': 'PASS'}


# ============================================================
# 4. 暴力破解检测
# ============================================================

def test_brute_force_detection() -> dict:
    """模拟 SSH 登录失败 → 期望 brute_force 告警"""
    detector = AnomalyDetector({'brute_force': {'login_fail_threshold': 3}})

    attacker = '10.0.0.77'
    target = '192.168.1.1'

    # 发送 5 次 SSH 登录失败（使用代码中匹配的关键字）
    fail_payloads = [
        b'Permission denied (publickey,password).',
        b'Authentication failed for user root.',
        b'Invalid user admin from 10.0.0.77',
    ]
    for _ in range(5):
        payload = fail_payloads[_ % len(fail_payloads)]
        pkt = _make_parsed(src_ip=attacker, dst_ip=target,
                           dst_port=22, flags=0x18,
                           payload=payload,
                           payload_len=len(payload))
        detector.update(pkt)

    alerts = detector.check_all()
    assert_alert_type(alerts, 'brute_force')
    return {'测试项': '暴力破解检测（SSH）', '结果': 'PASS'}


def test_brute_force_ftp() -> dict:
    """模拟 FTP 登录失败 → 期望 brute_force 告警"""
    detector = AnomalyDetector({'brute_force': {'login_fail_threshold': 3}})

    attacker = '10.0.0.78'
    target = '192.168.1.1'

    fail_payload = b'530 Login incorrect.'
    for _ in range(4):
        pkt = _make_parsed(src_ip=attacker, dst_ip=target,
                           dst_port=21, flags=0x18,
                           payload=fail_payload,
                           payload_len=len(fail_payload))
        detector.update(pkt)

    alerts = detector.check_all()
    assert_alert_type(alerts, 'brute_force')
    return {'测试项': '暴力破解检测（FTP）', '结果': 'PASS'}


def test_normal_login_no_alert() -> dict:
    """正常登录成功 → 不应触发暴力破解告警"""
    detector = AnomalyDetector({'brute_force': {'login_fail_threshold': 5}})

    ok_payload = b'Accepted password for root from 192.168.1.100 port 22 ssh2'
    for _ in range(3):
        pkt = _make_parsed(src_ip='192.168.1.100', dst_ip='10.0.0.1',
                           dst_port=22, flags=0x18,
                           payload=ok_payload,
                           payload_len=len(ok_payload))
        detector.update(pkt)

    alerts = detector.check_all()
    assert_no_alert_type(alerts, 'brute_force')
    return {'测试项': '暴力破解-正常登录不误报', '结果': 'PASS'}


# ============================================================
# 5. 高频流量/DDoS 检测
# ============================================================

def test_high_frequency_detection() -> dict:
    """异常高包率 → 期望 high_frequency 告警"""
    detector = AnomalyDetector({'ddos': {'pps_threshold': 50}})

    attacker = '10.0.0.88'

    # 发送 100 个包
    for i in range(100):
        pkt = _make_parsed(src_ip=attacker, dst_ip='192.168.1.1',
                           dst_port=80 + (i % 5))
        detector.update(pkt)

    alerts = detector.check_all()
    assert_alert_type(alerts, 'high_frequency')
    return {'测试项': '高频流量/DDoS 检测', '结果': 'PASS'}


# ============================================================
# 6. 基线偏离检测
# ============================================================

def test_baseline_deviation_detection() -> dict:
    """行为偏离已建立的基线 → 期望 baseline_deviation 告警"""
    detector = AnomalyDetector({'time_window': 60, 'bucket_size': 5})

    # 建立基线：少量正常流量
    detector.start_learning()
    for i in range(5):
        pkt = _make_parsed(src_ip='192.168.1.10', dst_ip='10.0.0.1',
                           dst_port=80)
        detector.update(pkt)
    detector.stop_learning()

    # 偏离：突然大量不同端口
    for port in range(1000, 1050):
        pkt = _make_parsed(src_ip='192.168.1.10', dst_ip='10.0.0.1',
                           dst_port=port)
        detector.update(pkt)

    alerts = detector.check_all()
    assert_alert_type(alerts, 'baseline_deviation')
    return {'测试项': '基线偏离检测', '结果': 'PASS'}


# ============================================================
# 7. 白名单跳过
# ============================================================

def test_whitelist_bypass() -> dict:
    """白名单中的 IP 不应产生异常告警"""
    detector = AnomalyDetector({'port_scan': {'unique_ports_threshold': 5}})

    # 添加白名单
    detector.add_whitelist(ip='10.0.0.66')

    # 大量不同端口 → 白名单应阻止告警
    for port in range(20001, 20020):
        pkt = _make_parsed(src_ip='10.0.0.66', dst_ip='192.168.1.1',
                           dst_port=port)
        detector.update(pkt)

    alerts = detector.check_all()
    assert_no_alert_type(alerts, 'port_scan')
    return {'测试项': '白名单跳过', '结果': 'PASS'}


# ============================================================
# 8. 基线学习器集成测试
# ============================================================

def test_baseline_learner_save_load() -> dict:
    """BaselineLearner 保存和加载基线"""
    learner = BaselineLearner()

    learner.start_learning()
    for i in range(20):
        pkt = _make_parsed(src_ip='192.168.1.10', dst_ip='10.0.0.1', dst_port=80)
        learner.feed(pkt)
    # 手动触发采样（模拟定时器）
    learner._sample()
    learner.stop_learning()

    assert learner.baseline is not None, "基线不应为 None"
    assert learner.baseline.sample_count >= 0
    assert learner.baseline.learning_duration >= 0

    # 保存和加载
    save_path = os.path.join(os.path.dirname(__file__), 'test_baseline.tmp.json')
    learner.save_baseline(save_path)

    learner2 = BaselineLearner()
    loaded = learner2.load_baseline(save_path)
    assert loaded is not None, "加载基线失败"

    os.remove(save_path)
    return {'测试项': '基线学习器保存与加载', '结果': 'PASS'}


# ============================================================
# 测试运行器
# ============================================================

ALL_TESTS = [
    test_port_scan_detection,
    test_port_scan_low_threshold_no_false,
    test_horizontal_scan_detection,
    test_syn_flood_detection,
    test_brute_force_detection,
    test_brute_force_ftp,
    test_normal_login_no_alert,
    test_high_frequency_detection,
    test_baseline_deviation_detection,
    test_whitelist_bypass,
    test_baseline_learner_save_load,
]


def main():
    verbose = '-v' in sys.argv

    print("=" * 60)
    print("  异常检测引擎准确率测试")
    print(f"  共 {len(ALL_TESTS)} 个测试用例")
    print("=" * 60)

    passed = 0
    failed = 0
    results = []

    for test_fn in ALL_TESTS:
        name = test_fn.__name__.replace('test_', '').replace('_', ' ')
        try:
            result = test_fn()
            passed += 1
            status = "PASS"
            if verbose:
                print(f"  [PASS] {result.get('测试项', name)}")
        except AssertionError as e:
            failed += 1
            status = "FAIL"
            print(f"  [FAIL] {name}: {e}")
        except Exception as e:
            failed += 1
            status = "ERROR"
            print(f"  [ERROR] {name}: {e}")

    print(f"\n{'=' * 60}")
    print(f"  结果: {passed}/{passed + failed} 通过", end="")
    if failed == 0:
        print(" [OK] 全部通过")
    else:
        print(f" [FAIL] {failed} 个失败")
    print(f"{'=' * 60}")

    return failed == 0


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
