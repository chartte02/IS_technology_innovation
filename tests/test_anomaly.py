#!/usr/bin/env python3
"""Anomaly detector integration test — simulate attacks and verify detection"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.anomaly_detector import AnomalyDetector


def test_port_scan():
    """端口扫描: 30 unique ports in 60s window"""
    d = AnomalyDetector()
    for port in range(1, 31):
        d.update(dict(src_ip='10.0.1.1', dst_ip='192.168.1.1',
                       src_port=12345, dst_port=port, flags=0x02,
                       payload=b'', payload_len=0,
                       timestamp=time.time(), app_protocol=None))
    alerts = d.check_all()
    assert any(a['type'] == 'port_scan' for a in alerts), "Port scan NOT detected"
    print("PASS: port_scan")


def test_horizontal_scan():
    """横向扫描: 60 unique destination IPs"""
    d = AnomalyDetector()
    for i in range(60):
        ip = f'192.168.{i // 256}.{i % 256}'
        d.update(dict(src_ip='10.0.2.1', dst_ip=ip, src_port=12345,
                       dst_port=80, flags=0x02, payload=b'',
                       payload_len=0, timestamp=time.time(), app_protocol=None))
    alerts = d.check_all()
    assert any(a['type'] == 'horizontal_scan' for a in alerts), "Horizontal scan NOT detected"
    print("PASS: horizontal_scan")


def test_syn_flood():
    """SYN Flood: 1200 SYN packets"""
    d = AnomalyDetector()
    for i in range(1200):
        d.update(dict(src_ip='10.0.3.1', dst_ip='192.168.1.1',
                       src_port=50000 + i, dst_port=80, flags=0x02,
                       payload=b'', payload_len=0,
                       timestamp=time.time(), app_protocol=None))
    alerts = d.check_all()
    assert any(a['type'] == 'syn_flood' for a in alerts), "SYN flood NOT detected"
    print("PASS: syn_flood")


def test_brute_force():
    """暴力破解: 6 SSH failed password attempts"""
    d = AnomalyDetector()
    for i in range(6):
        d.update(dict(src_ip='10.0.4.1', dst_ip='192.168.1.1',
                       src_port=45678, dst_port=22, flags=0x18,
                       payload=b'Failed password for root from 10.0.4.1 port 22 ssh2',
                       payload_len=55, timestamp=time.time(),
                       app_protocol='SSH'))
    alerts = d.check_all()
    assert any(a['type'] == 'brute_force' for a in alerts), "Brute force NOT detected"
    print("PASS: brute_force")


def test_high_frequency():
    """DDoS高频: 50 sources x 300 packets each"""
    d = AnomalyDetector()
    for src_id in range(50):
        src_ip = f'10.0.{src_id // 256}.{src_id % 256}'
        for _ in range(300):
            d.update(dict(src_ip=src_ip, dst_ip='192.168.1.100',
                           src_port=12345, dst_port=80, flags=0x10,
                           payload=b'x' * 50, payload_len=50,
                           timestamp=time.time(), app_protocol='HTTP'))
    alerts = d.check_all()
    has_ddos = any('ddos' in a.get('type', '').lower()
                   or 'high_frequency' in a.get('type', '').lower()
                   for a in alerts)
    assert has_ddos, "High frequency / DDoS NOT detected"
    print("PASS: high_frequency / DDoS")


def test_baseline_learn_and_save():
    """Baseline learner: learn, save, load"""
    from core.baseline_learner import BaselineLearner
    import tempfile

    l = BaselineLearner()
    l.start_learning()
    for i in range(100):
        l.feed(dict(
            src_ip=f'192.168.1.{i % 10 + 10}', dst_ip='192.168.1.1',
            dst_port=[80, 443, 22, 53][i % 4],
            payload_len=[500, 1000, 200, 80][i % 4],
            app_protocol=['HTTP', 'HTTPS', 'SSH', 'DNS'][i % 4],
        ))
        if i % 20 == 0:
            l._sample()
    l._sample()
    baseline = l.stop_learning()
    assert baseline is not None, "Baseline is None"
    assert baseline.sample_count > 0, "No samples in baseline"

    # Save/load
    tmp = os.path.join(tempfile.gettempdir(), '_test_nads_baseline.json')
    l.save_baseline(tmp)
    l2 = BaselineLearner()
    l2.load_baseline(tmp)
    assert abs(l2.baseline.http_ratio - baseline.http_ratio) < 0.01
    os.remove(tmp)
    print("PASS: baseline_learner save/load")


if __name__ == '__main__':
    results = []
    for test in [test_port_scan, test_horizontal_scan, test_syn_flood,
                 test_brute_force, test_high_frequency,
                 test_baseline_learn_and_save]:
        try:
            test()
            results.append(True)
        except Exception as e:
            print(f"FAIL: {test.__name__}: {e}")
            results.append(False)
    passed = sum(results)
    print(f"\n=== {passed}/{len(results)} tests passed ===")
    sys.exit(0 if passed == len(results) else 1)
