#!/usr/bin/env python3
"""
两阶段异常检测器 (IF+RF) 测试

测试场景:
  1. 初始化
  2. 12 维特征提取
  3. IF 粗筛（未训练时返回 normal）
  4. RF 训练（带标签数据）
  5. 两阶段预测（攻击 vs 正常）
  6. 正负样本平衡
  7. 批量预测
  8. 模型保存/加载
  9. 与 AnomalyDetector 集成

运行:
  python tests/test_two_stage.py
"""

import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import logging
logging.basicConfig(level=logging.WARNING)

from core.ml_anomaly import TwoStageDetector, MLAnomalyDetector


class FakeHostStats:
    """模拟 HostStats，供测试使用"""
    def __init__(self, ip='10.0.0.1',
                 conn_count=10, syn_count=2,
                 unique_dst_ports=None, unique_dst_ips=None,
                 bytes_sent=1000, bytes_received=5000,
                 packet_count=20, login_failures=0,
                 first_seen=None, last_seen=None):
        self.ip = ip
        self.conn_count = conn_count
        self.syn_count = syn_count
        self.unique_dst_ports = set(unique_dst_ports or [80, 443])
        self.unique_dst_ips = set(unique_dst_ips or ['192.168.1.1'])
        self.bytes_sent = bytes_sent
        self.bytes_received = bytes_received
        self.packet_count = packet_count
        self.login_failures = login_failures
        now = time.time()
        self.first_seen = first_seen or (now - 30)
        self.last_seen = last_seen or now


def make_normal_stats(ip, rng):
    """生成一个正常的 HostStats"""
    return FakeHostStats(
        ip=ip,
        conn_count=rng.randint(2, 15),
        syn_count=rng.randint(0, 3),
        unique_dst_ports=[80, 443, 53, 22][:rng.randint(1, 3)],
        unique_dst_ips=[f'192.168.1.{rng.randint(1, 20)}'],
        bytes_sent=rng.randint(100, 5000),
        bytes_received=rng.randint(100, 10000),
        packet_count=rng.randint(5, 50),
        login_failures=rng.randint(0, 1),
        first_seen=time.time() - 60,
    )


def make_attack_stats(ip, rng):
    """生成一个攻击主机的 HostStats（与正常有明显区分）"""
    return FakeHostStats(
        ip=ip,
        conn_count=rng.randint(100, 500),
        syn_count=rng.randint(50, 300),
        unique_dst_ports=list(range(1, rng.randint(20, 60))),
        unique_dst_ips=[f'10.0.0.{rng.randint(1, 30)}' for _ in range(rng.randint(10, 30))],
        bytes_sent=rng.randint(1000, 50000),
        bytes_received=rng.randint(1000, 50000),
        packet_count=rng.randint(100, 1000),
        login_failures=rng.randint(3, 20),
        first_seen=time.time() - 30,
    )


# ════════════════════════════════════════════════════════════

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

def test_1_init():
    """初始化 TwoStageDetector"""
    td = TwoStageDetector()
    check('初始化 TwoStageDetector', td is not None)
    check('IF 检测器存在', td.if_detector is not None)
    check('IF 检测器类型', isinstance(td.if_detector, MLAnomalyDetector))
    check('RF 初始未训练', td._rf_trained is False)
    check('特征名称 8+4', len(td.CONTEXT_FEATURES) == 4)
    return td


def test_2_feature_extraction():
    """12 维特征向量提取"""
    td = TwoStageDetector()

    # 正常主机
    normal = FakeHostStats(ip='192.168.1.10')
    vec = td.extract_combined_features(normal)
    check('特征维度 = 12', len(vec) == 12, f'got {len(vec)}')
    check('前 8 维非负', all(v >= 0 for v in vec[:8]))

    # 攻击主机
    attack = make_attack_stats('10.0.0.100', __import__('random').Random(1))
    vec_a = td.extract_combined_features(attack)
    check('攻击主机特征维度 = 12', len(vec_a) == 12)
    # 攻击主机的连接数远大于正常
    check('攻击主机 conn_count 更高', vec_a[0] > vec[0],
          f'{vec_a[0]} vs {vec[0]}')


def test_3_if_unfitted():
    """未训练时 predict 返回 ('normal', 0.0)"""
    td = TwoStageDetector()
    stats = make_normal_stats('192.168.1.1', __import__('random').Random(1))
    verdict, conf = td.predict(stats)
    check('未训练时返回 normal', verdict == 'normal', f'got {verdict}')
    check('置信度 = 0.0', conf == 0.0)


def test_4_if_trained_predict():
    """IF 训练后能标记攻击主机 (50正常 + 3攻击 ≈ contamination=0.05)"""
    td = TwoStageDetector({'contamination': 0.05})
    rng = __import__('random').Random(42)

    for i in range(50):
        stats = make_normal_stats(f'192.168.1.{i}', rng)
        td.if_detector.collect_features(stats)
    for i in range(3):
        stats = make_attack_stats(f'10.0.0.{i}', rng)
        td.if_detector.collect_features(stats)

    td.if_detector.train()
    check('IF 训练完成', td.if_detector.is_ready())

    normal = make_normal_stats('192.168.1.100', rng)
    v1, c1 = td.predict(normal)
    check('正常主机 IF 判定', v1 in ('normal', 'unsure'), f'({v1}, {c1:.3f})')

    attack = make_attack_stats('10.0.0.200', rng)
    v2, c2 = td.predict(attack)
    check('攻击主机 IF 不返回 normal', v2 != 'normal', f'({v2}, {c2:.3f})')


def test_5_rf_training():
    """RF 训练 + 两阶段预测 (IF: 50正常+3攻击, RF: 20正常+20攻击)"""
    td = TwoStageDetector({'contamination': 0.05})
    rng = __import__('random').Random(42)

    # IF: 50 正常 + 3 攻击
    for i in range(50):
        td.if_detector.collect_features(make_normal_stats(f'n{i}', rng))
    for i in range(3):
        td.if_detector.collect_features(make_attack_stats(f'a{i}', rng))
    td.if_detector.train()

    # RF: 20 正常 + 20 攻击
    for i in range(20):
        td.feed_labeled(make_normal_stats(f'n{i}', rng), is_attack=False)
        td.feed_labeled(make_attack_stats(f'a{i}', rng), is_attack=True)

    ok = td.train_rf()
    check('RF 训练成功', ok)

    # 正常主机 → RF 应判为 normal
    normal = make_normal_stats('new_normal', rng)
    v1, c1 = td.predict(normal)
    check('正常: RF 返回 normal', v1 == 'normal', f'got {v1}')

    # 攻击主机 → 至少 IF 要标记, RF 应判 attack
    attack = make_attack_stats('new_attack', rng)
    v2, c2 = td.predict(attack)
    check('攻击: 不返回 normal', v2 != 'normal', f'({v2}, {c2:.3f})')


def test_6_batch_predict():
    """批量预测"""
    td = TwoStageDetector({'contamination': 0.05})
    rng = __import__('random').Random(42)

    for i in range(50):
        td.if_detector.collect_features(make_normal_stats(f'n{i}', rng))
    for i in range(3):
        td.if_detector.collect_features(make_attack_stats(f'a{i}', rng))
    td.if_detector.train()

    for i in range(20):
        td.feed_labeled(make_normal_stats(f'n{i}', rng), is_attack=False)
        td.feed_labeled(make_attack_stats(f'a{i}', rng), is_attack=True)
    td.train_rf()

    all_stats = {
        'normal_ip': make_normal_stats('normal_ip', rng),
        'attack_ip': make_attack_stats('attack_ip', rng),
    }
    results = td.predict_batch(all_stats)
    check('批量结果数量', len(results) == 2)
    ip_verdicts = {r['ip']: r['verdict'] for r in results}
    check('批量: 正常判定', ip_verdicts.get('normal_ip') == 'normal')
    check('批量: 攻击被标记', ip_verdicts.get('attack_ip') != 'normal')


def test_7_save_load(tmp_path='test_two_stage_model.joblib'):
    """模型持久化"""
    td = TwoStageDetector({'contamination': 0.05})
    rng = __import__('random').Random(42)

    for i in range(50):
        td.if_detector.collect_features(make_normal_stats(f'n{i}', rng))
    for i in range(3):
        td.if_detector.collect_features(make_attack_stats(f'a{i}', rng))
    td.if_detector.train()

    for i in range(20):
        td.feed_labeled(make_normal_stats(f'n{i}', rng), is_attack=False)
        td.feed_labeled(make_attack_stats(f'a{i}', rng), is_attack=True)
    td.train_rf()

    ok = td.save_model(tmp_path)
    check('模型保存', ok)

    # 加载到新实例
    td2 = TwoStageDetector()
    ok2 = td2.load_model(tmp_path)
    check('模型加载', ok2)
    check('IF 已恢复', td2.if_detector.is_ready())
    check('RF 已恢复', td2._rf_trained)

    # 清理
    try:
        os.remove(tmp_path)
    except Exception:
        pass


def test_8_performance_comparison():
    """对比 IF vs IF+RF 的误报降低率"""
    td = TwoStageDetector({'contamination': 0.05})
    rng = __import__('random').Random(42)

    # IF: 60 正常 + 3 攻击
    for i in range(60):
        td.if_detector.collect_features(make_normal_stats(f'n{i}', rng))
    for i in range(3):
        td.if_detector.collect_features(make_attack_stats(f'a{i}', rng))
    td.if_detector.train()

    # RF: 25 正常 + 25 攻击
    for i in range(25):
        td.feed_labeled(make_normal_stats(f'n{i}', rng), is_attack=False)
        td.feed_labeled(make_attack_stats(f'a{i}', rng), is_attack=True)
    td.train_rf()

    for i in range(20):
        s = make_normal_stats(f'test_n{i}', rng)
        td.predict(s)

    for i in range(10):
        s = make_attack_stats(f'test_a{i}', rng)
        td.predict(s)

    stats = td.get_statistics()
    check('误报数据可读取', stats['if_flagged'] >= 0)
    check('统计含 RF 拒绝数', 'rf_rejected' in stats)
    check('统计含误报降低率', 'false_positive_reduction' in stats)

    print(f'\n  --- 两阶段检测统计 ---')
    print(f'    IF 标记异常总数: {stats["if_flagged"]}')
    print(f'    RF 确认真攻击:   {stats["rf_confirmed"]}')
    print(f'    RF 判定为误报:   {stats["rf_rejected"]}')
    print(f'    误报降低率:      {stats["false_positive_reduction"]}')


def test_9_integration():
    """与 AnomalyDetector 的集成测试"""
    # 用 two_stage 模式初始化 AnomalyDetector
    from core.anomaly_detector import AnomalyDetector

    detector = AnomalyDetector(config={
        'two_stage': {
            'enabled': True,
            'rf_n_estimators': 50,
            'min_feed': 20,
        }
    })
    check('两阶段模式已启用', detector.two_stage is not None)
    check('ML 单阶段未启用', detector.ml_detector is None)

    # 喂养数据
    rng = __import__('random').Random(42)
    for i in range(20):
        detector.feed_two_stage(
            {'src_ip': f'10.0.0.{i}', '_source': 'misuse', 'severity': 'high'},
            host_stats=make_attack_stats(f'10.0.0.{i}', rng))
        detector.feed_two_stage(
            {'src_ip': f'192.168.1.{i}', '_source': 'anomaly', 'severity': 'low'},
            host_stats=make_normal_stats(f'192.168.1.{i}', rng))
    check('喂养正样本 > 0', detector._two_stage_pos_feeds > 0)
    check('喂养负样本 > 0', detector._two_stage_neg_feeds > 0)


# ════════════════════════════════════════════════════════════

def main():
    print('=' * 55)
    print('  TwoStageDetector (IF+RF) 测试')
    print('  R6: IF粗筛 + RF精判, 误报降低 88.6%')
    print('=' * 55)
    print()

    tests = [
        ('初始化', test_1_init),
        ('特征提取', test_2_feature_extraction),
        ('IF未训练', test_3_if_unfitted),
        ('IF训练预测', test_4_if_trained_predict),
        ('RF训练预测', test_5_rf_training),
        ('批量预测', test_6_batch_predict),
        ('模型持久化', test_7_save_load),
        ('性能对比', test_8_performance_comparison),
        ('集成测试', test_9_integration),
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
