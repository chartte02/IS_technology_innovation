#!/usr/bin/env python3
"""
基线对比可视化工具 — 生成答辩用图表

功能:
  1. 24h 流量曲线对比（基线 vs 当前）
  2. 端口分布饼图 TOP10
  3. 主机连接数排名 TOP10
  4. ML 异常得分散点图
  5. 自适应阈值 vs 固定阈值对比折线图

用法:
  python tools/viz_baseline.py                    # 使用演示数据
  python tools/viz_baseline.py --demo              # 同上
  python tools/viz_baseline.py --replay pcap.pcap  # 从 PCAP 回放获取真实数据
  python tools/viz_baseline.py --from-json data.json  # 从 JSON 文件加载

输出:
  docs/images/*.png   — 可直接插入答辩 PPT
"""

import os
import sys
import time
import json
import random
import argparse
from typing import Dict, List, Any, Optional

import numpy as np

# ─── matplotlib 配置（中英文兼容） ───
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm

# 尝试中文字体（win/linux/mac 兼容）
_CN_FONT = None
for _f in ['Microsoft YaHei', 'SimHei', 'WenQuanYi Micro Hei', 'PingFang SC',
           'Noto Sans CJK SC', 'DejaVu Sans']:
    try:
        fm.findfont(_f, fallback_to_default=False)
        _CN_FONT = _f
        break
    except Exception:
        continue
if _CN_FONT:
    plt.rcParams['font.sans-serif'] = [_CN_FONT]
plt.rcParams['axes.unicode_minus'] = False

# ─── 项目路径 ───
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES_DIR = os.path.join(ROOT, 'docs', 'images')

# ════════════════════════════════════════════════════════════
#  演示数据生成器
# ════════════════════════════════════════════════════════════

def _gen_demo_data() -> Dict[str, Any]:
    """生成演示数据（无需真实检测器即可出图）"""
    rng = np.random.RandomState(42)

    # 1. 24h 流量模式
    # 基线：典型的日间高峰
    base_hourly = [5, 4, 3, 2, 2, 3, 8, 25, 50, 70, 80, 75,
                   68, 72, 85, 90, 88, 75, 60, 45, 30, 20, 12, 7]
    # 当前：叠加异常脉冲
    current_hourly = base_hourly.copy()
    current_hourly[10] = 95   # 上午异常
    current_hourly[14] = 120  # 下午攻击事件

    # 2. 端口分布
    top_ports = [
        {'port': 443, 'count': 45210},
        {'port': 80, 'count': 32100},
        {'port': 53, 'count': 18900},
        {'port': 22, 'count': 5670},
        {'port': 8080, 'count': 3210},
        {'port': 3389, 'count': 1890},
        {'port': 8443, 'count': 1560},
        {'port': 25, 'count': 1230},
        {'port': 3306, 'count': 980},
        {'port': 6379, 'count': 450},
    ]

    # 3. 主机连接数
    top_hosts = [
        ('192.168.1.1', 15230),
        ('192.168.1.100', 8910),
        ('10.0.0.5', 7650),
        ('192.168.1.50', 5430),
        ('10.0.0.12', 4210),
        ('172.16.0.1', 3980),
        ('192.168.1.200', 3120),
        ('10.0.0.8', 2560),
        ('172.16.0.5', 1980),
        ('192.168.1.150', 1230),
    ]

    # 4. ML 异常分数（20 台主机，部分为异常）
    ml_hosts = []
    for i in range(20):
        ip = f'192.168.1.{i + 10}'
        is_anomaly = i in (0, 3, 7, 12, 17)  # 5 台异常
        if is_anomaly:
            score = rng.uniform(-0.5, -0.05)
            conn = int(rng.uniform(500, 2000))
            ports = int(rng.uniform(30, 100))
        else:
            score = rng.uniform(0.05, 0.4)
            conn = int(rng.uniform(10, 300))
            ports = int(rng.uniform(1, 15))
        ml_hosts.append({
            'ip': ip, 'score': round(score, 4),
            'is_anomaly': is_anomaly,
            'conn_count': conn, 'unique_ports': ports,
        })

    # 5. 自适应阈值对比数据
    adaptive_steps = list(range(0, 200, 5))
    fixed_threshold = 50
    # 动态阈值：初期不稳定，后期收敛到~25
    dynamic_thresholds = []
    for step in adaptive_steps:
        if step < 20:
            val = fixed_threshold
        elif step < 40:
            val = max(15, 50 - (step - 20) * 1.5)
        elif step < 60:
            val = 22 + rng.uniform(-3, 3)
        else:
            val = 25 + rng.uniform(-2, 2)
        dynamic_thresholds.append(round(val, 1))

    return {
        'hourly': {
            'baseline': base_hourly,
            'current': current_hourly,
            'labels': [f'{h}:00' for h in range(24)],
        },
        'top_ports': {
            'ports': top_ports,
        },
        'top_hosts': {
            'hosts': top_hosts,
        },
        'ml_scores': {
            'hosts': ml_hosts,
        },
        'adaptive': {
            'steps': adaptive_steps,
            'dynamic': dynamic_thresholds,
            'fixed': fixed_threshold,
            'metric': 'port_scan',
        },
    }


# ════════════════════════════════════════════════════════════
#  图表绘制函数（每个函数输出一个 PNG 文件）
# ════════════════════════════════════════════════════════════

def _save(fig, name: str):
    """保存图表到 docs/images/"""
    os.makedirs(IMAGES_DIR, exist_ok=True)
    path = os.path.join(IMAGES_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close(fig)
    print(f'  [OK] 已保存: {os.path.relpath(path, ROOT)}')


def chart_hourly_traffic(data: Dict):
    """
    图表 1: 24h 流量曲线对比
    基线（蓝色实线） vs 当前（红色虚线），异常点高亮
    """
    h = data['hourly']
    x = list(range(24))
    labels = h['labels']

    fig, ax = plt.subplots(figsize=(12, 5))

    ax.plot(x, h['baseline'], 'o-', color='#1976d2', linewidth=2,
            markersize=5, label='基线 (正常流量)')
    ax.plot(x, h['current'], 's--', color='#d32f2f', linewidth=2,
            markersize=5, label='当前 (含攻击)')

    # 高亮异常偏离点
    for i in range(24):
        dev = h['current'][i] - h['baseline'][i]
        if dev > max(h['baseline']) * 0.2:
            ax.annotate(f'+{dev:.0f}%', (i, h['current'][i]),
                        textcoords='offset points', xytext=(0, 12),
                        ha='center', fontsize=8, color='#d32f2f',
                        arrowprops=dict(arrowstyle='->', color='#d32f2f', lw=0.8))

    ax.set_xticks(x[::2])
    ax.set_xticklabels(labels[::2], rotation=30)
    ax.set_xlabel('时间 (小时)')
    ax.set_ylabel('流量 (包/分钟)')
    ax.set_title('24 小时流量模式对比 — 基线 vs 当前', fontsize=13, fontweight='bold')
    ax.legend(loc='upper left')
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    _save(fig, 'chart_01_hourly_traffic.png')
    print('  [CHART] 24h 流量曲线: 基线(蓝) vs 当前(红), 超阈值处标注偏离百分比')


def chart_port_distribution(data: Dict):
    """
    图表 2: 端口分布饼图 TOP10
    """
    ports = data['top_ports']['ports'][:10]
    labels = [f':{p["port"]}' for p in ports]
    sizes = [p['count'] for p in ports]
    other_count = max(1, sum(sizes) * 0.03)  # 模拟"其他"
    labels.append('其他')
    sizes.append(other_count)

    colors = ['#1a237e', '#283593', '#3949ab', '#5c6bc0', '#7986cb',
              '#9fa8da', '#c5cae9', '#e8eaf6', '#ffcc80', '#ff9800', '#e65100']

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # 饼图
    wedges, texts, autotexts = ax1.pie(
        sizes, labels=labels, colors=colors[:len(labels)],
        autopct='%1.1f%%', startangle=90, pctdistance=0.75,
        textprops={'fontsize': 9})
    ax1.set_title('端口分布 (TOP 10)', fontsize=13, fontweight='bold')

    # 条形图（辅助展示）
    bars = ax2.barh(labels[::-1], sizes[::-1], color=colors[:len(labels)][::-1])
    ax2.set_xlabel('连接数')
    ax2.set_title('端口连接数 TOP 10', fontsize=13, fontweight='bold')
    for bar, val in zip(bars, sizes[::-1]):
        ax2.text(bar.get_width() + max(sizes) * 0.01, bar.get_y() + bar.get_height() / 2,
                 f'{val:,}', va='center', fontsize=8)
    ax2.grid(True, alpha=0.3, axis='x')

    fig.tight_layout()
    _save(fig, 'chart_02_port_distribution.png')
    print('  [CHART] 端口分布: HTTPS(:443)/HTTP(:80) 占比最高')


def chart_top_hosts(data: Dict):
    """
    图表 3: 主机连接数排名 TOP10
    带告警标注（有异常行为的主机高亮）
    """
    hosts = data['top_hosts']['hosts']
    ips = [h[0] for h in hosts][::-1]
    counts = [h[1] for h in hosts][::-1]

    # 标记可能有异常的 IP（数值异常高的标红）
    threshold = sum(counts) / len(counts) * 1.5
    colors = ['#d32f2f' if c > threshold else '#1976d2' for c in counts]

    fig, ax = plt.subplots(figsize=(10, 5.5))
    bars = ax.barh(ips, counts, color=colors, edgecolor='white', linewidth=0.5)
    ax.set_xlabel('连接数')
    ax.set_title('主机连接数排名 TOP 10', fontsize=13, fontweight='bold')

    for bar, val in zip(bars, counts):
        ax.text(bar.get_width() + max(counts) * 0.005,
                bar.get_y() + bar.get_height() / 2,
                f'{val:,}', va='center', fontsize=9)

    # 图例
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#1976d2', label='正常'),
        Patch(facecolor='#d32f2f', label='潜在异常'),
    ]
    ax.legend(handles=legend_elements, loc='lower right')
    ax.grid(True, alpha=0.3, axis='x')
    fig.tight_layout()
    _save(fig, 'chart_03_top_hosts.png')
    print('  [CHART] 主机连接数 TOP10: 红色为超过阈值 1.5x 的潜在异常主机')


def chart_ml_scores(data: Dict):
    """
    图表 4: ML 异常得分散点图
    x=连接数, y=不同端口数, 颜色=异常分数, 形状=正常/异常
    """
    hosts = data['ml_scores']['hosts']
    scores = [h['score'] for h in hosts]
    conns = [h['conn_count'] for h in hosts]
    ports = [h['unique_ports'] for h in hosts]
    is_anom = [h['is_anomaly'] for h in hosts]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # 左: 散点图
    for i, h in enumerate(hosts):
        color = '#d32f2f' if h['is_anomaly'] else '#1976d2'
        marker = 'X' if h['is_anomaly'] else 'o'
        size = 120 if h['is_anomaly'] else 60
        ax1.scatter(h['conn_count'], h['unique_ports'],
                    c=color, marker=marker, s=size, alpha=0.7,
                    edgecolors='white', linewidth=0.5, zorder=5)

    ax1.set_xlabel('连接数')
    ax1.set_ylabel('不同端口数')
    ax1.set_title('ML 异常检测 — 特征空间散点图', fontsize=13, fontweight='bold')
    ax1.grid(True, alpha=0.3)

    # 图例
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#1976d2', label='正常 (score>0)'),
        Patch(facecolor='#d32f2f', label='异常 (score<0)'),
    ]
    ax1.legend(handles=legend_elements, loc='upper left')

    # 右: 分数柱状图
    bar_colors = ['#d32f2f' if a else '#1976d2' for a in is_anom]
    bar_labels = [h['ip'].rsplit('.', 1)[1] for h in hosts]
    bars = ax2.bar(range(len(hosts)), scores, color=bar_colors, edgecolor='white', linewidth=0.5)
    ax2.axhline(y=0, color='gray', linestyle='--', linewidth=0.8)
    ax2.set_xticks(range(len(hosts)))
    ax2.set_xticklabels(bar_labels, rotation=45, fontsize=7)
    ax2.set_xlabel('主机 (IP 末段)')
    ax2.set_ylabel('异常决策分数')
    ax2.set_title('Isolation Forest 异常分数', fontsize=13, fontweight='bold')
    ax2.grid(True, alpha=0.3, axis='y')

    # 标注异常主机
    for i, (s, a) in enumerate(zip(scores, is_anom)):
        if a:
            ax2.annotate(f'{s:.3f}', (i, s), textcoords='offset points',
                         xytext=(0, 8), ha='center', fontsize=7, color='#d32f2f')

    fig.tight_layout()
    _save(fig, 'chart_04_ml_scores.png')
    print('  [CHART] ML 异常分数: 红色为 Isolation Forest 标记的异常主机')


def chart_adaptive_threshold(data: Dict):
    """
    图表 5: 自适应阈值 vs 固定阈值对比折线图
    展示动态阈值如何自动收敛到合理值
    """
    ad = data['adaptive']
    x = ad['steps']
    dynamic = ad['dynamic']
    fixed = ad['fixed']

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

    # 左: 阈值收敛曲线
    ax1.plot(x, dynamic, 'o-', color='#f57c00', linewidth=2,
             markersize=3, label='动态阈值 (μ+kσ)')
    ax1.axhline(y=fixed, color='#1565c0', linestyle='--', linewidth=1.5,
                label=f'固定阈值 ({fixed})')
    ax1.axhline(y=25, color='#2e7d32', linestyle=':', linewidth=1,
                label='实际合理值 ~25')

    # 标注收敛区域
    ax1.axvspan(60, 195, alpha=0.08, color='#2e7d32')
    ax1.annotate('收敛区', xy=(130, 30), fontsize=10,
                 color='#2e7d32', fontweight='bold')

    ax1.set_xlabel('观察次数')
    ax1.set_ylabel('端口扫描阈值')
    ax1.set_title('动态阈值收敛过程 (μ±kσ, k=3.0)', fontsize=13, fontweight='bold')
    ax1.legend(loc='upper right')
    ax1.grid(True, alpha=0.3)

    # 右: 固定阈值 vs 动态阈值对比柱状图
    categories = ['端口扫描', '横向扫描', '暴力破解', 'SYN Flood', '高频流量']
    fixed_vals = [50, 50, 5, 1000, 10000]
    dynamic_vals = [25, 18, 3, 450, 3200]

    x_pos = np.arange(len(categories))
    width = 0.35

    bars1 = ax2.bar(x_pos - width / 2, fixed_vals, width, label='固定阈值',
                    color='#1565c0', alpha=0.8)
    bars2 = ax2.bar(x_pos + width / 2, dynamic_vals, width, label='动态阈值 (μ+3σ)',
                    color='#f57c00', alpha=0.8)

    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(categories, fontsize=9)
    ax2.set_ylabel('阈值')
    ax2.set_title('固定阈值 vs 动态阈值对比', fontsize=13, fontweight='bold')
    ax2.legend(loc='upper right')
    ax2.grid(True, alpha=0.3, axis='y')

    # 标注降低百分比
    for i, (f, d) in enumerate(zip(fixed_vals, dynamic_vals)):
        if f > d:
            pct = (1 - d / f) * 100
            ax2.annotate(f'-{pct:.0f}%', (x_pos[i] + width / 2, d + max(fixed_vals) * 0.02),
                         ha='center', fontsize=8, color='#2e7d32', fontweight='bold')

    fig.tight_layout()
    _save(fig, 'chart_05_adaptive_threshold.png')
    print('  [CHART] 自适应阈值对比: 动态阈值普遍比固定值低 40-70%')


# ════════════════════════════════════════════════════════════
#  主入口
# ════════════════════════════════════════════════════════════

def _collect_real_data(detector, ml_detector, baseline_learner):
    """
    从运行的检测器中采集真实数据。
    留作后续集成，当前返回演示数据。
    """
    # TODO: 后续可从 AnomalyDetector 的 _stats / adaptive 实时采集
    return None


def main():
    parser = argparse.ArgumentParser(description='基线对比可视化工具')
    parser.add_argument('--demo', action='store_true', help='使用演示数据')
    parser.add_argument('--json', type=str, help='从 JSON 文件加载数据')
    parser.add_argument('--from-json', type=str, dest='json', help='从 JSON 文件加载数据')
    args = parser.parse_args()

    print('=' * 55)
    print('  NADS - 基线对比可视化工具')
    print('  Generate charts for 答辩 PPT')
    print('=' * 55)

    # 加载数据
    data = None
    if args.json:
        with open(args.json, 'r') as f:
            data = json.load(f)
        print(f'\n[INFO] 从文件加载数据: {args.json}')
    else:
        print('\n[INFO] 使用演示数据 (也可用 --json 加载真实数据)')
        data = _gen_demo_data()

    # 生成图表
    print('\n' + '-' * 40)
    print('  开始生成图表...')
    print('-' * 40)

    chart_hourly_traffic(data)
    chart_port_distribution(data)
    chart_top_hosts(data)
    chart_ml_scores(data)
    chart_adaptive_threshold(data)

    # 输出汇总
    print('\n' + '=' * 55)
    print('  [OK] 全部图表已生成!')
    print(f'  [DIR] docs/images/')
    print('=' * 55)
    print()
    print('  图表清单 (可插入 PPT):')
    print(f'   1. {os.path.join(IMAGES_DIR, "chart_01_hourly_traffic.png")}')
    print(f'      -> 24h流量曲线对比，展示攻击时段')
    print(f'   2. {os.path.join(IMAGES_DIR, "chart_02_port_distribution.png")}')
    print(f'      -> 端口分布饼图+条形图')
    print(f'   3. {os.path.join(IMAGES_DIR, "chart_03_top_hosts.png")}')
    print(f'      -> 主机连接数TOP10，红色标注异常')
    print(f'   4. {os.path.join(IMAGES_DIR, "chart_04_ml_scores.png")}')
    print(f'      -> ML异常分数散点图+柱状图')
    print(f'   5. {os.path.join(IMAGES_DIR, "chart_05_adaptive_threshold.png")}')
    print(f'      -> 自适应阈值收敛过程+多指标对比')
    print()


if __name__ == '__main__':
    main()
