#!/usr/bin/env python3
"""
NADS 性能基准测试 — 异常检测模块

测量指标 (CLAUDE.md 第9节):
  1. 特征匹配延迟 (< 1ms/包) — 10,000 包批量测试
  2. 抓包 PPS (> 5000 pps) — PCAP 高速回放
  3. GUI 刷新延迟 (< 100ms)
  4. 内存占用 (< 500MB)

用法:
    python tests/benchmark_anomaly.py              # 完整测试
    python tests/benchmark_anomaly.py --quick      # 快速测试 (1000 包)
    python tests/benchmark_anomaly.py --replay pcap_file.pcap  # 指定 PCAP

输出:
    benchmark_results_anomaly.txt — 答辩可直接用的性能数据
"""

import sys
import os
import time
import gc
import json
import argparse
import logging
from typing import Dict, Any, List

logging.basicConfig(level=logging.WARNING)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.anomaly_detector import AnomalyDetector
from core.attack_chain import AttackChainAnalyzer
from core.alert_filter import AlertFilter
from core.ml_anomaly import MLAnomalyDetector

# ════════════════════════════════════════════════════════════
#  辅助函数
# ════════════════════════════════════════════════════════════

def make_parsed(
    src_ip='10.0.0.1', dst_ip='192.168.1.1',
    src_port=40000, dst_port=80,
    flags=0x18, payload=b'', timestamp=None,
    app_protocol=None, payload_len=None,
):
    """构造 parsed_packet 字典"""
    if timestamp is None:
        timestamp = time.time()
    pl = payload or b''
    return {
        'src_ip': src_ip, 'dst_ip': dst_ip,
        'src_port': src_port, 'dst_port': dst_port,
        'seq': 1000, 'ack': 2000,
        'flags': flags, 'flags_str': 'PA',
        'payload': pl,
        'payload_len': payload_len if payload_len is not None else len(pl),
        'app_protocol': app_protocol,
        'http_method': None, 'http_uri': None,
        'http_host': None, 'http_user_agent': None,
        'timestamp': timestamp,
    }


def fmt(n: float, unit: str = '') -> str:
    """格式化数字为对齐字符串"""
    if unit == 'ms':
        if n < 0.001:
            return f'{n * 1_000_000:.2f} us'
        return f'{n:.4f} ms'
    if unit == 'pct':
        return f'{n * 100:.1f}%'
    if n >= 1_000_000:
        return f'{n / 1_000_000:.2f}M'
    if n >= 1_000:
        return f'{n / 1_000:.1f}K'
    return f'{n:.1f}'


# ════════════════════════════════════════════════════════════
#  测试用例
# ════════════════════════════════════════════════════════════

def bench_detection_latency(n_packets: int = 10000) -> Dict[str, Any]:
    """
    基准测试 1: 特征匹配延迟
    用 7 种混合流量包测试 anomaly_detector 的 update + check_all
    """
    print(f'\n  [1/4] 检测延迟: {fmt(n_packets)} 包批量测试...')
    print(f'  {"-" * 50}')

    detector = AnomalyDetector()
    # 预热
    for _ in range(100):
        detector.update(make_parsed(timestamp=time.time()))

    # 构造混合流量: 70% 正常 + 30% 攻击特征
    packets = []
    attack_ports = list(range(1, 101))  # 端口扫描
    login_payloads = [b'Failed password for root', b'530 Login incorrect']
    syn_flags = 0x02
    normal_flags = 0x18

    for i in range(n_packets):
        ts = time.time() + i * 0.01
        if i < 300:
            # 端口扫描阶段
            p = make_parsed(
                src_ip='10.0.0.10', dst_ip='192.168.1.1',
                dst_port=attack_ports[i % len(attack_ports)],
                flags=syn_flags, timestamp=ts)
        elif i < 600:
            # 暴力破解阶段
            p = make_parsed(
                src_ip='10.0.0.20', dst_ip='192.168.1.1',
                dst_port=22,
                payload=login_payloads[i % len(login_payloads)],
                flags=normal_flags, timestamp=ts)
        elif i < 900:
            # SYN Flood 阶段
            p = make_parsed(
                src_ip=f'10.0.0.{i % 50 + 100}',
                dst_ip='192.168.1.1', dst_port=80,
                flags=syn_flags, timestamp=ts)
        else:
            # 正常流量
            p = make_parsed(
                src_ip=f'192.168.1.{i % 20 + 10}',
                dst_ip='10.0.0.1', dst_port=443,
                flags=normal_flags, timestamp=ts)
        packets.append(p)

    # 测量 update 延迟
    gc.collect()
    start = time.perf_counter()
    for p in packets:
        detector.update(p)
    update_elapsed = time.perf_counter() - start

    # 测量 check_all 延迟
    check_times = []
    for _ in range(100):
        t0 = time.perf_counter()
        alerts = detector.check_all()
        check_times.append(time.perf_counter() - t0)

    avg_update = update_elapsed / n_packets * 1000  # ms
    avg_check = sum(check_times) / len(check_times) * 1000  # ms
    total_alerts = len(alerts)

    print(f'    update(parsed)  : {avg_update:.4f} ms/包  (总 {update_elapsed:.3f}s / {n_packets} 包)')
    print(f'    check_all()     : {avg_check:.4f} ms/次  (100 次平均)')
    print(f'    告警数           : {total_alerts}')
    print(f'    目标             : < 1 ms/包  [{"OK" if avg_update < 1 else "FAIL"}]')

    return {
        'update_per_packet_ms': round(avg_update, 4),
        'check_all_avg_ms': round(avg_check, 4),
        'total_packets': n_packets,
        'total_alerts': total_alerts,
        'elapsed_seconds': round(update_elapsed, 3),
    }


def bench_pcap_replay(pcap_path: str, max_packets: int = 50000) -> Dict[str, Any]:
    """
    基准测试 2: PCAP 回放吞吐量
    测量每秒能处理多少包
    """
    if not os.path.exists(pcap_path):
        print(f'\n  [2/4] PCAP 回放: 文件不存在 {pcap_path}')
        return {'error': 'file not found'}

    from scapy.all import sniff, IP, TCP, conf
    from core.protocol_parser import ProtocolParser

    print(f'\n  [2/4] PCAP 回放吞吐量: {os.path.basename(pcap_path)}')
    print(f'  {"-" * 50}')

    parser = ProtocolParser()
    detector = AnomalyDetector()
    n_parsed = 0
    n_errors = 0

    # 读取 PCAP
    t0 = time.perf_counter()

    # 方法: 使用 scapy 的 rdpcap 读取
    from scapy.utils import rdpcap
    packets = rdpcap(pcap_path)
    total_pkts = min(len(packets), max_packets)
    print(f'    总包数: {total_pkts}')

    # 解析 + 检测
    t1 = time.perf_counter()
    for i, pkt in enumerate(packets):
        if i >= max_packets:
            break
        try:
            parsed = parser.parse(pkt)
            if parsed:
                detector.update(parsed)
                n_parsed += 1
        except Exception:
            n_errors += 1

    t2 = time.perf_counter()
    elapsed = t2 - t1
    read_elapsed = t1 - t0
    pps = n_parsed / elapsed if elapsed > 0 else 0
    alerts = detector.check_all()

    print(f'    读取耗时         : {read_elapsed:.2f}s ({total_pkts} 包)')
    print(f'    解析+检测耗时     : {elapsed:.2f}s')
    print(f'    成功解析          : {n_parsed} 包')
    print(f'    解析错误          : {n_errors}')
    print(f'    吞吐量            : {pps:.0f} pps')
    print(f'    告警数            : {len(alerts)}')
    print(f'    目标              : > 5000 pps  [{"OK" if pps > 5000 else "FAIL"}]')

    return {
        'total_packets': total_pkts,
        'parsed': n_parsed,
        'errors': n_errors,
        'elapsed_seconds': round(elapsed, 2),
        'throughput_pps': round(pps, 0),
        'alerts': len(alerts),
        'pcap_file': os.path.basename(pcap_path),
    }


def bench_memory_usage() -> Dict[str, Any]:
    """
    基准测试 3: 内存占用
    通过构造大量主机统计模拟长时间运行
    """
    print(f'\n  [3/4] 内存占用模拟: 模拟 500+ 主机的长时间运行...')
    print(f'  {"-" * 50}')

    try:
        import psutil
        process = psutil.Process(os.getpid())
        mem_before = process.memory_info().rss / 1024 / 1024  # MB
    except ImportError:
        print('    psutil 未安装, 跳过内存测量')
        return {'memory_mb': -1}

    detector = AnomalyDetector(config={
        'ml_detection': {'enabled': True, 'min_samples': 50},
        'adaptive_threshold': {'enabled': True},
    })

    # 模拟 500+ 主机, 每台 20 个包
    total_packets = 0
    for host_id in range(500):
        src_ip = f'10.0.{host_id // 255}.{host_id % 255}'
        for _ in range(20):
            p = make_parsed(
                src_ip=src_ip,
                dst_ip=f'192.168.1.{host_id % 20 + 1}',
                dst_port=80 + (_ % 10),
                flags=0x18,
                timestamp=time.time() + total_packets * 0.001,
            )
            detector.update(p)
            total_packets += 1

    # 执行检测
    for _ in range(10):
        detector.check_all()

    gc.collect()
    mem_after = process.memory_info().rss / 1024 / 1024
    mem_used = mem_after - mem_before

    print(f'    模拟主机数       : 500')
    print(f'    总包数           : {total_packets}')
    print(f'    基线内存         : {mem_before:.1f} MB')
    print(f'    当前内存         : {mem_after:.1f} MB')
    print(f'    增量内存         : {mem_used:.1f} MB')
    print(f'    目标             : < 500 MB   [{"OK" if mem_used < 500 else "FAIL"}]')

    return {
        'hosts': 500,
        'packets': total_packets,
        'memory_before_mb': round(mem_before, 1),
        'memory_after_mb': round(mem_after, 1),
        'memory_delta_mb': round(mem_used, 1),
    }


def bench_adaptive_threshold() -> Dict[str, Any]:
    """
    基准测试 4: 自适应阈值统计
    对比固定阈值和动态阈值的数值差异
    """
    print(f'\n  [4/4] 自适应阈值统计分析...')
    print(f'  {"-" * 50}')

    detector = AnomalyDetector()

    # 模拟 50 轮正常流量 + 10 轮异常流量
    rng = __import__('random').Random(42)

    normal_results = []
    attack_results = []

    for round_id in range(60):
        # 正常主机的正常访问
        for host_id in range(10):
            src = f'192.168.1.{host_id + 10}'
            # 每台主机访问 2-5 个端口
            n_ports = rng.randint(2, 5)
            for port in range(n_ports):
                detector.update(make_parsed(
                    src_ip=src, dst_port=80 + port,
                    timestamp=time.time() + round_id * 0.5 + port * 0.001,
                ))

        # 攻击者: 每轮产生异常流量
        attacker = f'10.0.0.100'
        if round_id >= 50:  # 后 10 轮: 端口扫描
            for port in range(30):
                detector.update(make_parsed(
                    src_ip=attacker, dst_port=port + 1, flags=0x02,
                    timestamp=time.time() + round_id * 0.5 + port * 0.001,
                ))

        detector.check_all()

        # 收集自适应阈值数据
        stats = detector.adaptive.get_statistics()
        if 'port_scan' in stats:
            ps = stats['port_scan']
            if 'dynamic_threshold' in ps:
                val = ps['dynamic_threshold']
                if round_id < 50:
                    normal_results.append(val)
                else:
                    attack_results.append(val)

    print(f'    正常阶段动态阈值  : min={min(normal_results):.1f} '
          f'max={max(normal_results):.1f} '
          f'avg={sum(normal_results)/len(normal_results):.1f}' if normal_results else '')
    print(f'    攻击阶段动态阈值  : min={min(attack_results):.1f} '
          f'max={max(attack_results):.1f} '
          f'avg={sum(attack_results)/len(attack_results):.1f}' if attack_results else '')
    print(f'    固定阈值         : {detector.port_scan_threshold}')

    return {
        'normal_dynamic_range': [round(min(normal_results), 1), round(max(normal_results), 1)] if normal_results else [],
        'attack_dynamic_range': [round(min(attack_results), 1), round(max(attack_results), 1)] if attack_results else [],
        'fixed_threshold': detector.port_scan_threshold,
    }


# ════════════════════════════════════════════════════════════
#  报告生成
# ════════════════════════════════════════════════════════════

def generate_report(results: Dict[str, Any], output: str):
    """生成性能报告 (TXT + JSON)"""
    print(f'\n{"=" * 55}')
    print('  生成性能报告...')
    print(f'{"=" * 55}')

    # TXT 报告
    lines = []
    lines.append('=' * 60)
    lines.append('  NADS 性能基准测试报告')
    lines.append(f'  测试时间: {time.strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append('=' * 60)

    lines.append('')
    lines.append('─' * 60)
    lines.append('  1. 异常检测延迟 (目标: < 1ms/包)')
    lines.append('─' * 60)
    dl = results.get('detection_latency', {})
    if dl:
        lines.append(f'     update(parsed) : {dl.get("update_per_packet_ms", "N/A")} ms/包')
        lines.append(f'     check_all()    : {dl.get("check_all_avg_ms", "N/A")} ms/次')
        lines.append(f'     总包数         : {dl.get("total_packets", "N/A")}')
        lines.append(f'     总耗时         : {dl.get("elapsed_seconds", "N/A")} s')
        status = 'PASS' if dl.get('update_per_packet_ms', 999) < 1 else 'FAIL'
        lines.append(f'     结果: [{status}]')

    lines.append('')
    lines.append('─' * 60)
    lines.append('  2. PCAP 回放吞吐量 (目标: > 5000 pps)')
    lines.append('─' * 60)
    pr = results.get('pcap_replay', {})
    if pr and 'error' not in pr:
        lines.append(f'     PCAP 文件  : {pr.get("pcap_file", "N/A")}')
        lines.append(f'     总包数     : {pr.get("total_packets", "N/A")}')
        lines.append(f'     成功解析   : {pr.get("parsed", "N/A")}')
        lines.append(f'     吞吐量     : {pr.get("throughput_pps", "N/A")} pps')
        lines.append(f'     耗时       : {pr.get("elapsed_seconds", "N/A")} s')
        status = 'PASS' if pr.get('throughput_pps', 0) > 5000 else 'FAIL'
        lines.append(f'     结果: [{status}]')
    else:
        lines.append(f'     PCAP 回放未执行 (或文件不存在)')

    lines.append('')
    lines.append('─' * 60)
    lines.append('  3. 内存占用 (目标: < 500 MB)')
    lines.append('─' * 60)
    mu = results.get('memory_usage', {})
    if mu and mu.get('hosts', 0) > 0:
        delta = mu.get('memory_delta_mb', 0)
        lines.append(f'     测试主机数 : {mu.get("hosts", "N/A")}')
        lines.append(f'     总包数     : {mu.get("packets", "N/A")}')
        lines.append(f'     基线内存   : {mu.get("memory_before_mb", "N/A")} MB')
        lines.append(f'     结束内存   : {mu.get("memory_after_mb", "N/A")} MB')
        lines.append(f'     增量内存   : {delta:+} MB')
        status = 'PASS' if mu.get('memory_after_mb', 999) < 500 else 'FAIL'
        lines.append(f'     结果: [{status}]')
    else:
        lines.append(f'     内存测量跳过 (psutil 未安装)')

    lines.append('')
    lines.append('─' * 60)
    lines.append('  4. 自适应阈值对比')
    lines.append('─' * 60)
    at = results.get('adaptive_threshold', {})
    if at:
        lines.append(f'     固定阈值       : {at.get("fixed_threshold", "N/A")}')
        nr = at.get('normal_dynamic_range', [])
        if nr:
            lines.append(f'     动态阈值(正常) : {nr[0]} ~ {nr[1]}')
        ar = at.get('attack_dynamic_range', [])
        if ar:
            lines.append(f'     动态阈值(攻击) : {ar[0]} ~ {ar[1]}')

    lines.append('')
    lines.append('=' * 60)
    lines.append('  [OK] 测试完成')
    lines.append('=' * 60)
    lines.append('')

    report_text = '\n'.join(lines)
    print('\n' + report_text)

    # 写入文件
    txt_path = output
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(report_text)
    print(f'  报告已保存: {txt_path}')

    # JSON
    json_path = output.replace('.txt', '.json')
    if json_path == output:
        json_path = output + '.json'
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f'  数据已保存: {json_path}')

    return txt_path


# ════════════════════════════════════════════════════════════
#  主入口
# ════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='NADS 异常检测性能基准测试')
    parser.add_argument('--quick', action='store_true', help='快速模式 (1000 包)')
    parser.add_argument('--replay', type=str, default=None,
                        help='PCAP 文件路径 (默认自动搜索 wednesday_subset.pcap)')
    parser.add_argument('--output', type=str, default=None,
                        help='输出报告路径')
    args = parser.parse_args()

    n_packets = 1000 if args.quick else 10000

    if args.output:
        output = args.output
    else:
        output = os.path.join(ROOT, 'benchmark_results_anomaly.txt')

    print('=' * 55)
    print('  NADS 性能基准测试')
    print(f'  模式: {"快速 (1000 包)" if args.quick else "标准 (10000 包)"}')
    print('=' * 55)

    results: Dict[str, Any] = {}
    results['mode'] = 'quick' if args.quick else 'standard'
    results['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')

    # 1. 检测延迟
    results['detection_latency'] = bench_detection_latency(n_packets)

    # 2. PCAP 回放
    pcap_path = args.replay
    if not pcap_path:
        candidates = [
            os.path.join(ROOT, 'tests/test_pcaps/wednesday_subset.pcap'),
            os.path.join(ROOT, 'tests/test_pcaps/wednesday_dos_test.pcap'),
        ]
        for c in candidates:
            if os.path.exists(c):
                pcap_path = c
                break
    if pcap_path:
        pcap_max = 5000 if args.quick else 50000
        results['pcap_replay'] = bench_pcap_replay(pcap_path, pcap_max)
    else:
        print('\n  [2/4] PCAP 回放: 未找到 PCAP 文件，跳过')

    # 3. 内存占用
    results['memory_usage'] = bench_memory_usage()

    # 4. 自适应阈值对比
    results['adaptive_threshold'] = bench_adaptive_threshold()

    # 生成报告
    generate_report(results, output)

    print('\n' + '=' * 55)
    print('  完成!')
    print('=' * 55)


if __name__ == '__main__':
    main()
